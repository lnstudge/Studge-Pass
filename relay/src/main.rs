#![forbid(unsafe_code)]

//! The Studge Pass sync relay (SPEC §7).
//!
//! The relay is a **zero-knowledge, untrusted** store: it holds ciphertext,
//! wrapped keys and public metadata, and it never learns the master password,
//! the Secret Key, the MUK, the auth secret or any item plaintext (SPEC §3.2,
//! §7.11). Every log line and every error goes through that rule.
//!
//! Layout:
//!
//! - [`config`] — the TOML file and `STUDGE_RELAY_*` variables;
//! - [`error`] — the closed error set of §7.8;
//! - [`routes`] — the endpoints of §7.4;
//! - [`state`] — what the handlers share.

mod config;
mod error;
mod routes;
mod state;

use axum::Router;
use config::RelayConfig;
use state::RelayState;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;

/// Reads the config path from the first argument or `STUDGE_RELAY_CONFIG`.
fn config_path(args: &[String]) -> Option<PathBuf> {
    if let Some(path) = args.get(1) {
        return Some(PathBuf::from(path));
    }
    std::env::var("STUDGE_RELAY_CONFIG").ok().map(PathBuf::from)
}

/// Applies the headers every response carries (SPEC §7 hardening).
pub(crate) async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::HeaderValue;
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

/// A stalled request is dropped with the generic `unavailable` error, not an
/// empty 504, so every failure keeps the §7.8 shape.
pub(crate) async fn request_timeout(
    axum::extract::State(state): axum::extract::State<RelayState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let duration = Duration::from_secs(state.config().request_timeout_seconds);
    match tokio::time::timeout(duration, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!("request timed out");
            use axum::response::IntoResponse;
            crate::error::ApiError::Unavailable.into_response()
        }
    }
}

/// Builds the full application: routes and the body limit. The security
/// headers and the timeout live inside the router.
pub fn app(state: RelayState) -> Router {
    let config = state.config().clone();
    routes::router(state).layer(RequestBodyLimitLayer::new(config.max_body_bytes))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let config = match RelayConfig::load(config_path(&args).as_deref()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("studge-relay: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if config.log_json {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .try_init();
    }

    let address: SocketAddr = config.listen;
    let router = app(RelayState::new(config));
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(_) => {
            tracing::error!("listener could not bind");
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(%address, "studge-relay listening");

    if axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// Waits for Ctrl-C so in-flight requests finish.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn the_default_listen_address_is_loopback() {
        // Phase 0 invariant: the defaults never expose the relay on a LAN.
        let config = RelayConfig::default();
        assert!(config.listen.ip().is_loopback());
    }

    #[tokio::test]
    async fn the_app_carries_the_security_headers() {
        let app = app(RelayState::new(RelayConfig::default()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let value = response
            .headers()
            .get("x-content-type-options")
            .map(|value| value.to_str().expect("ascii"))
            .unwrap_or("");
        assert_eq!(value, "nosniff");
    }
}
