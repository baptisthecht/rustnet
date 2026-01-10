use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Mutex, oneshot};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Record, RecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

use rust_hole_db::get_all_blocked_domains;

// ================= Structures de cache =================
#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    domain: String,
    record_type: RecordType,
}

struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
}

struct PendingQuery {
    waiters: Vec<oneshot::Sender<Vec<Record>>>,
}

// ================= DnsBlocker =================
#[derive(Clone)]
struct DnsBlocker {
    blocked: Arc<Vec<String>>,
    cache: Arc<Mutex<HashMap<CacheKey, CacheEntry>>>,
    pending: Arc<Mutex<HashMap<CacheKey, PendingQuery>>>,
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsBlocker {
    pub async fn new(blocked: Vec<String>) -> anyhow::Result<Self> {
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
            cache: Arc::new(Mutex::new(HashMap::new())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            resolver: Arc::new(resolver),
        })
    }

    fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.iter().any(|d| domain.ends_with(d))
    }
}

// ================= RequestHandler =================
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

        let record_type = match query.query_type() {
            RecordType::HTTPS => RecordType::A, // fallback
            other => other,
        };
        let cache_key = CacheKey {
            domain: domain.clone(),
            record_type,
        };

        // -------- Lecture cache --------
        let cached_records = {
            let mut cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if Instant::now() < entry.expires_at {
                    Some(entry.records.clone())
                } else {
                    cache.remove(&cache_key);
                    None
                }
            } else {
                None
            }
        };

        if let Some(records) = cached_records {
            let mut header = request.header().clone();
            header.set_response_code(ResponseCode::NoError);
            let builder = MessageResponseBuilder::from_message_request(request);
            let response_msg = builder.build(header, records.iter(), &[], &[], &[]);
            let _ = response_handle.send_response(response_msg).await;
            println!("<DNS> Cache hit for domain: {} --> {}", domain, records.iter().map(|r: &Record| r.data().unwrap().to_string()).collect::<Vec<String>>().join(", "));
            return ResponseInfo::from(request.header().clone());
        }

        // -------- Blocage --------
        if self.is_blocked(&domain) {
            println!("<DNS> Blocked domain: {}", domain);
            let expires_at = Instant::now() + Duration::from_secs(60);
            let mut cache = self.cache.lock().await;
            cache.insert(cache_key.clone(), CacheEntry { records: vec![], expires_at });

            let mut header = request.header().clone();
            header.set_response_code(ResponseCode::NXDomain);
            let builder = MessageResponseBuilder::from_message_request(request);
            let response_msg = builder.build(header, &[], &[], &[], &[]);
            let _ = response_handle.send_response(response_msg).await;
            return ResponseInfo::from(request.header().clone());
        }

        println!("<DNS> Authorized domain: {}", domain);

        // -------- Anti-stampede --------
        let (receiver, do_forward) = {
            let mut pending = self.pending.lock().await;
            if let Some(p) = pending.get_mut(&cache_key) {
                let (tx, rx) = oneshot::channel();
                p.waiters.push(tx);
                (Some(rx), false)
            } else {
                pending.insert(cache_key.clone(), PendingQuery { waiters: vec![] });
                (None, true)
            }
        };

        if let Some(rx) = receiver {
            if let Ok(records) = rx.await {
                let mut header = request.header().clone();
                header.set_response_code(ResponseCode::NoError);
                let builder = MessageResponseBuilder::from_message_request(request);
                let response_msg = builder.build(header, records.iter(), &[], &[], &[]);
                let _ = response_handle.send_response(response_msg).await;
                println!("<DNS> NoError for domain: {}", domain);
                return ResponseInfo::from(request.header().clone());
            } else {
                let mut header = request.header().clone();
                header.set_response_code(ResponseCode::ServFail);
                let builder = MessageResponseBuilder::from_message_request(request);
                let response_msg = builder.build(header, &[], &[], &[], &[]);
                let _ = response_handle.send_response(response_msg).await;
                println!("<DNS> ServFail for domain: {}", domain);
                return ResponseInfo::from(request.header().clone());
            }
        }

        if do_forward {
            // -------- Forward via TokioAsyncResolver --------
            match self.resolver.lookup::<hickory_proto::rr::LowerName>(query.name().clone(), query.query_type()).await {
                Ok(records_lookup) => {
                    let records: Vec<Record> = records_lookup.records().iter().cloned().collect();

                    let expires_at = Instant::now() + Duration::from_secs(
                        records.iter().map(|r: &Record| r.ttl()).min().unwrap_or(60) as u64
                    );

                    let mut cache = self.cache.lock().await;
                    cache.insert(cache_key.clone(), CacheEntry { records: records.clone(), expires_at });

                    // réveiller tous les waiters
                    let mut pending = self.pending.lock().await;
                    if let Some(p) = pending.remove(&cache_key) {
                        for tx in p.waiters {
                            let _ = tx.send(records.clone());
                        }
                    }

                    // envoyer au client
                    let mut header = request.header().clone();
                    header.set_response_code(ResponseCode::NoError);
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response_msg = builder.build(header, records.iter(), &[], &[], &[]);
                    let _ = response_handle.send_response(response_msg).await;
                    println!("<DNS> NoError for domain: {}", domain);
                    return ResponseInfo::from(request.header().clone());
                }
                Err(_) => {
                    let mut header = request.header().clone();
                    header.set_response_code(ResponseCode::ServFail);
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let response_msg = builder.build(header, &[], &[], &[], &[]);
                    let _ = response_handle.send_response(response_msg).await;
                    let mut pending = self.pending.lock().await;
                    pending.remove(&cache_key);
                    println!("<DNS> ServFail for domain: {}", domain);
                    return ResponseInfo::from(request.header().clone());
                }
            }
        }
        println!("<DNS> ResponseInfo for domain: {}", domain);
        ResponseInfo::from(request.header().clone())
    }
}

// ================= run_dns =================
pub async fn run_dns() -> anyhow::Result<()> {
    let socket = match tokio::net::UdpSocket::bind("127.0.0.2:53").await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("<DNS> Unable to bind to port 53: {}", e);
            return Err(anyhow::anyhow!("Échec du bind sur le port 53: {}", e));
        }
    };

    let blocked_domains = get_all_blocked_domains().await?;
    println!("<DNS> Loaded {} blocked domains", blocked_domains.len());
    let blocked_domains_vec = blocked_domains.iter().map(|d| d.domain.clone()).collect();
    let handler = DnsBlocker::new(blocked_domains_vec).await?;

    let mut server = hickory_server::ServerFuture::new(handler);
    server.register_socket(socket);

    server.block_until_done().await?;
    Ok(())
}
