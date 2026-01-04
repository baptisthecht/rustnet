use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tracing::info;

use trust_dns_server::authority::MessageResponse;
use trust_dns_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};
use trust_dns_server::proto::op::{Message, MessageType, OpCode};
use trust_dns_server::proto::rr::{Name, RData, Record, RecordType};
use trust_dns_server::proto::rr::rdata::A;

#[derive(Clone)]
pub struct DnsBlocker {
    blocked: Arc<Vec<String>>,
}

impl DnsBlocker {
    pub fn new(blocked: Vec<String>) -> Self {
        Self {
            blocked: Arc::new(blocked),
        }
    }

    fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.iter().any(|d| domain.ends_with(d))
    }
}

#[async_trait]
impl RequestHandler for DnsBlocker {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {

        let query = &request.queries()[0];
        let domain = query.name().to_utf8();

        info!("DNS query: {}", domain);

        let mut msg = Message::new();
        msg.set_id(request.id());
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.add_query(query.clone());

        if self.is_blocked(&domain) {
            info!("🚫 Bloqué: {}", domain);

            let record = Record::from_rdata(
                Name::from_ascii(&domain).unwrap(),
                60,
                RData::A(A::new(0, 0, 0, 0)),
            );

            msg.add_answer(record);
        }

        response.send_response(msg).await.unwrap()
    }
}

pub async fn run_dns() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:5353").await?;

    let mut server = ServerFuture::new(
        DnsBlocker::new(vec![
            "ads.google.com".into(),
            "doubleclick.net".into(),
        ]),
    );

    server.register_socket(socket);
    info!("DNS server lancé sur :5353");

    server.block_until_done().await?;
    Ok(())
}
