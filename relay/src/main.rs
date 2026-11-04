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

/// The relay only ever listens on the loopback interface. Phase 4 keeps this
/// invariant; the test below fails if someone widens it by accident.
const BIND_ADDRESS: ([u8; 4], u16) = ([127, 0, 0, 1], 8787);

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));
    let addr = std::net::SocketAddr::from(BIND_ADDRESS);

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

    #[test]
    fn binds_to_loopback_only() {
        let (octets, port) = BIND_ADDRESS;
        assert_eq!(
            octets,
            [127, 0, 0, 1],
            "the relay must never listen on a public interface"
        );
        assert_eq!(port, 8787);
    }
}
