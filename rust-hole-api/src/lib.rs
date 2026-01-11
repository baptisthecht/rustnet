use axum::{
    routing::{get},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use rust_hole_db::get_all_blocked_domains;
use rust_hole_db::models::blocked_domains::Model as BlockedDomainModel;

#[derive(Serialize)]
struct HelloResponse {
    message: String,
}


#[derive(Deserialize)]
struct CreateBlockedDomain {
    domain: String,
}

#[derive(Serialize)]
struct BlockedDomain {
    id: u32,
    domain: String,
}

async fn get_blocked_domains() -> Json<Vec<BlockedDomainModel>> {
    let blocked_domains = get_all_blocked_domains().await.unwrap();
        Json(blocked_domains)
}


pub async fn run_api() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/blocklist", get(get_blocked_domains));

    let addr = SocketAddr::from(([0, 0, 0, 0], 4000));
    let listener = TcpListener::bind(addr).await
        .map_err(|e| anyhow::anyhow!("Impossible de lier le port 4000: {}. Le port est peut-être déjà utilisé.", e))?;

    println!("<API> Serveur API démarré sur 0.0.0.0:4000");
    axum::serve(listener, app).await?;
    Ok(())
}
