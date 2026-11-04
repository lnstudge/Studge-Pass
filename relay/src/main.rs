#![forbid(unsafe_code)]

//! The Studge Pass sync relay.
//!
//! Phase 0 ships only the health endpoint. The sync API, authentication and
//! storage arrive in Phase 4, per docs/SPEC.md.

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// The body served by `GET /health`.
#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8787));

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            println!("studge-relay listening on http://127.0.0.1:8787");
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("studge-relay stopped with an error: {err}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("studge-relay could not bind 127.0.0.1:8787: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_reports_ok_and_version() {
        let Json(body) = health().await;
        assert_eq!(body.status, "ok");
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    }
}
