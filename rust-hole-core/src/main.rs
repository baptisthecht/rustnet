mod dns;

use dns::server::run_dns;
use rust_hole_db::init_db;

use warp::{Filter, http::Response};
use rust_embed::RustEmbed;
use mime_guess::from_path;
use rust_hole_api::run_api;

#[derive(RustEmbed)]
#[folder = "../rust-hole-dashboard/dist"]
struct Frontend;

async fn serve_frontend() {
    let routes = warp::path::full().map(|path: warp::path::FullPath| {
        let path = path.as_str().trim_start_matches('/');

        let path = if path.is_empty() {
            "index.html"
        } else {
            path
        };

        match Frontend::get(path) {
            Some(file) => {
                let mime = from_path(path).first_or_octet_stream();
                Response::builder()
                    .header("content-type", mime.as_ref())
                    .body(file.data.to_vec())
            }
            None => {
                // SPA fallback (React Router)
                let index = Frontend::get("index.html").unwrap();
                Response::builder()
                    .header("content-type", "text/html")
                    .body(index.data.into())
            }
        }
    });

    warp::serve(routes)
        .run(([0, 0, 0, 0], 3000))
        .await;
}

fn ascii_art() {
    println!(
r#"
██████╗ ██╗   ██╗███████╗████████╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║███████╗   ██║     ╚████╔╝ 
██╔══██╗██║   ██║╚════██║   ██║      ╚██╔╝  
██║  ██║╚██████╔╝███████║   ██║       ██║   
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝   

        ┌────────────────────────────────┐
        │  made with ♥ by                │
        │                                │
        │   Baptist Hecht                │
        │   Software Developer           │
        └────────────────────────────────┘
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ascii_art();

    init_db().await?;

    println!("<Core> Starting servers…");
    println!("<Core> DNS  : 127.0.0.2:53");
    println!("<Core> HTTP : 0.0.0.0:3000");
    println!("<Core> API  : 0.0.0.0:4000");

    // Lancer les serveurs en parallèle dans des tâches séparées
    let dns_handle = tokio::spawn(run_dns());
    let api_handle = tokio::spawn(run_api());
    let frontend_handle = tokio::spawn(serve_frontend());

    // Attendre qu'une des tâches se termine avec une erreur
    tokio::select! {
        result = dns_handle => {
            match result {
                Ok(Ok(())) => {
                    eprintln!("<Core> Le serveur DNS s'est terminé de manière inattendue");
                    return Err(anyhow::anyhow!("Serveur DNS terminé"));
                }
                Ok(Err(e)) => {
                    eprintln!("<Core> ERREUR DNS: {:#}", e);
                    return Err(e);
                }
                Err(e) => {
                    eprintln!("<Core> ERREUR lors de l'exécution du serveur DNS: {:#}", e);
                    return Err(anyhow::anyhow!("Erreur d'exécution DNS: {}", e));
                }
            }
        }
        result = api_handle => {
            match result {
                Ok(Ok(())) => {
                    eprintln!("<Core> Le serveur API s'est terminé de manière inattendue");
                    return Err(anyhow::anyhow!("Serveur API terminé"));
                }
                Ok(Err(e)) => {
                    eprintln!("<Core> ERREUR API: {:#}", e);
                    return Err(e);
                }
                Err(e) => {
                    eprintln!("<Core> ERREUR lors de l'exécution du serveur API: {:#}", e);
                    return Err(anyhow::anyhow!("Erreur d'exécution API: {}", e));
                }
            }
        }
        _ = frontend_handle => {
            eprintln!("<Core> Le serveur frontend s'est terminé de manière inattendue");
            return Err(anyhow::anyhow!("Serveur frontend terminé"));
        }
    }
}
