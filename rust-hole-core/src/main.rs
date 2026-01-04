use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = "0.0.0.0:5354".parse()?;
    let socket = UdpSocket::bind(addr).await?;
    println!("Mini DNS server with blocklist & forwarding on {}", addr);

    let blocklist: HashSet<String> = vec![
        "ads.example.com".to_string(),
        "tracking.example.org".to_string(),
        "doubleclick.net".to_string(),
    ].into_iter().collect();

    let google_dns: SocketAddr = "8.8.8.8:53".parse()?; 

    let mut buf = [0u8; 512];

    loop {
        let (len, src) = socket.recv_from(&mut buf).await?;
        let request_bytes = &buf[..len];

        if let Ok(request) = Message::from_bytes(request_bytes) {
            if let Some(query) = request.queries().first() {
                let mut domain = query.name().to_utf8();
                if domain.ends_with('.') {
                    domain.pop(); // enlever le point final
                }
                println!("Received query for domain: {}", domain);

                let response_bytes = if blocklist.contains(&domain) {
                    println!("Blocked domain: {}", domain);
                    // réponse NXDOMAIN
                    let mut response = Message::new();
                    response.set_id(request.id());
                    response.set_message_type(MessageType::Response);
                    response.set_op_code(OpCode::Query);
                    response.set_response_code(ResponseCode::NXDomain);
                    response.add_query(query.clone());

                    let mut resp_buf = Vec::with_capacity(512);
                    let mut encoder = BinEncoder::new(&mut resp_buf);
                    response.emit(&mut encoder)?;
                    resp_buf
                } else {
                    println!("Forwarding domain: {}", domain);
                    // Forward la requête à Google DNS
                    let forward_socket = UdpSocket::bind("0.0.0.0:0").await?;
                    forward_socket.send_to(request_bytes, google_dns).await?;

                    // On attend la réponse max 2 secondes
                    let mut fwd_buf = [0u8; 512];
                    match timeout(Duration::from_secs(2), forward_socket.recv_from(&mut fwd_buf)).await {
                        Ok(Ok((fwd_len, _))) => fwd_buf[..fwd_len].to_vec(),
                        _ => {
                            println!("Timeout forwarding {}", domain);
                            // Timeout → NXDOMAIN
                            let mut response = Message::new();
                            response.set_id(request.id());
                            response.set_message_type(MessageType::Response);
                            response.set_op_code(OpCode::Query);
                            response.set_response_code(ResponseCode::NXDomain);
                            response.add_query(query.clone());

                            let mut resp_buf = Vec::with_capacity(512);
                            let mut encoder = BinEncoder::new(&mut resp_buf);
                            response.emit(&mut encoder)?;
                            resp_buf
                        }
                    }
                };

                socket.send_to(&response_bytes, src).await?;
            }
        }
    }
}
