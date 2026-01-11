use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;

use rust_hole_db::get_all_blocked_domains;

// ================= Cache =================
struct CacheEntry {
    msg: Message,
    expires_at: Instant,
}

// ================= DNS Server =================
pub async fn run_dns() -> anyhow::Result<()> {
    let socket = UdpSocket::bind("127.0.0.2:53").await?;
    let upstream: SocketAddr = "8.8.8.8:53".parse()?;

    // Upstream socket réutilisé
    let upstream_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let blocked: Vec<String> = get_all_blocked_domains()
        .await?
        .into_iter()
        .map(|d| d.domain)
        .collect();

    let blocked = Arc::new(blocked);
    let cache = Arc::new(DashMap::<(String, RecordType), CacheEntry>::new());

    let mut buf = [0u8; 4096];

    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        let req_bytes = &buf[..len];

        let msg = match Message::from_vec(req_bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let query = match msg.queries().first() {
            Some(q) => q,
            None => continue,
        };

        let name = query.name().to_utf8().trim_end_matches('.').to_string();
        let rtype = query.query_type();

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
        let key = (name.clone(), rtype);
        if let Some(entry) = cache.get(&key) {
            if Instant::now() < entry.expires_at {
                let mut resp_msg = entry.msg.clone();
                resp_msg.set_id(msg.id()); // Fix ID
                let bytes = resp_msg.to_vec()?;
                socket.send_to(&bytes, peer).await?;
                continue;
            } else {
                cache.remove(&key);
            }
        }

        // ---------- FORWARD RAW ----------
        upstream_socket.send_to(req_bytes, upstream).await?;

        let mut resp_buf = [0u8; 4096];
        let (resp_len, _) = upstream_socket.recv_from(&mut resp_buf).await?;
        let resp_bytes = &resp_buf[..resp_len];

        let mut resp_msg = Message::from_vec(resp_bytes)?;

        // ---------- CACHE STORE ----------
        let ttl = resp_msg
            .answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(60);

        let cache_entry = CacheEntry {
            msg: resp_msg.clone(),
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
        };
        cache.insert(key, cache_entry);

        // Fix ID et envoyer
        resp_msg.set_id(msg.id());
        let fixed_bytes = resp_msg.to_vec()?;
        socket.send_to(&fixed_bytes, peer).await?;
    }
}
