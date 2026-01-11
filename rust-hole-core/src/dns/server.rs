use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;

use rust_hole_db::get_all_blocked_domains;

// ================= Cache =================

#[derive(Hash, Eq, PartialEq)]
struct CacheKey {
    name: String,
    record_type: RecordType,
}

struct CacheEntry {
    bytes: Vec<u8>,
    expires_at: Instant,
}

// ================= DNS Server =================

pub async fn run_dns() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.2:53").await?;
    let upstream: SocketAddr = "8.8.8.8:53".parse()?;

    let blocked: Vec<String> = get_all_blocked_domains()
        .await?
        .into_iter()
        .map(|d| d.domain)
        .collect();

    let blocked = Arc::new(blocked);
    let cache = Arc::new(Mutex::new(HashMap::<CacheKey, CacheEntry>::new()));

    let mut buf = [0u8; 4096];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let req_bytes = &buf[..len];

        let msg = match Message::from_vec(req_bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };

        println!("<DNS> Message id: {:?}", msg.id());

        let query = match msg.queries().first() {
            Some(q) => q,
            None => continue,
        };

        let name = query.name().to_utf8().trim_end_matches('.').to_string();
        let rtype = query.query_type();

        println!("<DNS> {} {:?}", name, rtype);

        // ---------- BLOCK ----------
        if blocked.iter().any(|d| name.ends_with(d)) {
            let mut resp = Message::new();
            resp.set_id(msg.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_response_code(ResponseCode::NXDomain);

            let bytes = resp.to_vec()?;
            socket.send_to(&bytes, peer).await?;
            continue;
        }

        // ---------- CACHE ----------
        let key = CacheKey { name: name.clone(), record_type: rtype };

        if let Some(entry) = cache.lock().await.get(&key) {
            if Instant::now() < entry.expires_at {
                println!("<DNS> Cache hit for {} {:?}", name, rtype);
        
                let mut cached_msg = Message::from_vec(&entry.bytes)?;
                cached_msg.set_id(msg.id()); // ← ID DU CLIENT ACTUEL
        
                let out = cached_msg.to_vec()?;
                socket.send_to(&out, peer).await?;
                continue;
            }
        }

        println!("<DNS> Cache miss for {} {:?}", name, rtype);

        // ---------- FORWARD RAW ----------
        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await?;
        upstream_socket.send_to(req_bytes, upstream).await?;

        let mut resp_buf = [0u8; 4096];
        let (resp_len, _) = upstream_socket.recv_from(&mut resp_buf).await?;
        let resp_bytes = resp_buf[..resp_len].to_vec();

        // ---------- CACHE STORE ----------
        let ttl = Message::from_vec(&resp_bytes)
            .ok()
            .and_then(|m| m.answers().iter().map(|r| r.ttl()).min())
            .unwrap_or(60);

        let new_id = Message::from_vec(&resp_bytes)?.id();

        println!("<DNS> Google ID: {:?}", new_id);

        cache.lock().await.insert(
            key,
            CacheEntry {
                bytes: resp_bytes.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );

        let mut resp_msg = Message::from_vec(&resp_bytes)?;

        println!("<DNS> Local ID: {:?}", resp_msg.id());

        resp_msg.set_id(msg.id());

        println!("<DNS> Fixed ID: {:?}", resp_msg.id());
        let fixed_bytes: Vec<u8> = resp_msg.to_vec()?;

        println!("<DNS> Fixed bytes: {:?}", fixed_bytes);

        socket.send_to(&fixed_bytes, peer).await?;
    }
}
