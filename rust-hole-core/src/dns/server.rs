use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::Record;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;

use rust_hole_db::get_all_blocked_domains;

#[derive(Clone)]
struct DnsBlocker {
    blocked: Arc<Vec<String>>,
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsBlocker {
    async fn new(blocked: Vec<String>) -> anyhow::Result<Self> {
        // Configuration du résolveur pour forwarder vers 8.8.8.8
        let mut config = ResolverConfig::new();
        let name_server = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        };
        config.add_name_server(name_server);
        
        let resolver = TokioAsyncResolver::tokio(config, ResolverOpts::default());
        
        Ok(Self {
            blocked: Arc::new(blocked),
            resolver: Arc::new(resolver),
        })
    }

    fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.iter().any(|d| domain.ends_with(d))
    }

    async fn forward_query(&self, name: &hickory_proto::rr::Name, record_type: hickory_proto::rr::RecordType) -> anyhow::Result<Vec<Record>> {
        let lookup = self.resolver.lookup(name.clone(), record_type).await?;
        
        let mut records = Vec::new();
        for record in lookup.records() {
            records.push(record.clone());
        }
        
        Ok(records)
    }
}

#[async_trait]
impl RequestHandler for DnsBlocker {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = request.query();
        let domain = query.name().to_string().trim_end_matches('.').to_string();
        println!("<DNS> DNS query: {}", domain);

        // Préparer les records selon si c'est bloqué ou non
        let (answers, response_code) = if self.is_blocked(&domain) {
            println!("<DNS> Blocked domain: {}", domain);
            // Retourner NXDOMAIN pour les domaines bloqués
            (vec![], ResponseCode::NXDomain)
        } else {
            println!("<DNS> Authorized domain: {}", domain);
            // Forwarder vers 8.8.8.8
            let name = query.name().clone().into();
            let record_type = query.query_type();
            match self.forward_query(&name, record_type).await {
                Ok(records) => (records, ResponseCode::NoError),
                Err(e) => {
                    eprintln!("<DNS> Error forwarding DNS: {}", e);
                    (vec![], ResponseCode::ServFail)
                }
            }
        };

        // Construire le header avec le bon code de réponse
        let mut header = request.header().clone();
        header.set_response_code(response_code);

        let builder = MessageResponseBuilder::from_message_request(request);
        let response_msg = builder.build(
            header,
            answers.iter(),
            &[],
            &[],
            &[],
        );

        match response_handle.send_response(response_msg).await {
            Ok(info) => info,
            Err(e) => {
                eprintln!("<DNS> Error sending response: {}", e);
                ResponseInfo::from(request.header().clone())
            }
        }
    }
}

pub async fn run_dns() -> anyhow::Result<()> {
    let socket = match UdpSocket::bind("127.0.0.2:53").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("<DNS> Unable to bind to port 53: {}", e);
            return Err(anyhow::anyhow!("Échec du bind sur le port 53: {}", e));
        }
    };

    let blocked_domains = get_all_blocked_domains().await?;
    println!("<DNS> Loaded {} blocked domains", blocked_domains.len());
    let blocked_domains_vec = blocked_domains.iter().map(|domain| domain.domain.clone()).collect();
    let handler = DnsBlocker::new(blocked_domains_vec).await?;

    let mut server = ServerFuture::new(handler);
    server.register_socket(socket);

    server.block_until_done().await?;
    Ok(())
}