use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Serialize)]
struct HelloResponse {
    message: String,
}

async fn hello() -> Json<HelloResponse> {
    Json(HelloResponse {
        message: "Hello from Rust API 🚀".to_string(),
    })
}

#[derive(Deserialize)]
struct CreateUser {
    name: String,
}

#[derive(Serialize)]
struct User {
    id: u32,
    name: String,
}

async fn create_user(Json(payload): Json<CreateUser>) -> Json<User> {
    Json(User {
        id: 1,
        name: payload.name,
    })
}

pub async fn run_api() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/hello", get(hello))
        .route("/users", post(create_user));

    let addr = SocketAddr::from(([0, 0, 0, 0], 4000));
    let listener = TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await?;
    Ok(())
}
