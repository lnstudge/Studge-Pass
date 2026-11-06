//! Library target for `studge-relay`.
//!
//! All application code lives here. The binary target (`src/main.rs`) is a
//! thin wrapper around `run()`. Integration tests in `relay/tests/` import
//! `studge_relay::test_helpers` to spawn real relay instances.

#![forbid(unsafe_code)]

pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod extract;
pub(crate) mod routes;
pub(crate) mod state;
// The `#[allow(dead_code)]` here can be removed once every store method is
// called by an endpoint or a test — checked before the phase ends.
#[allow(dead_code)]
pub(crate) mod store;

pub use config::RelayConfig;
pub use error::ApiError;
pub use routes::router;
pub use state::RelayState;
pub use store::RelayStore;

use axum::Router;
use std::time::Duration;
use tower_http::limit::RequestBodyLimitLayer;

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

/// Helpers for integration tests in `relay/tests/`. Always compiled so that
/// `tests/helpers.rs` can import `studge_relay::test_helpers` without needing
/// the test cfg (integration tests use the non-test build of the library).
pub mod test_helpers {
    use super::*;
    use std::net::SocketAddr;
    use studge_core::crypto::opaque::ServerSetupKey;

    /// Opens an in-memory SQLite database and runs migrations.
    pub async fn in_memory_store() -> RelayStore {
        RelayStore::open_in_memory().await.expect("in-memory store")
    }

    /// Builds the full axum `Router` for the given address, store and OPAQUE
    /// setup. The caller wraps it in `into_make_service_with_connect_info`.
    pub fn build_app(listen: SocketAddr, store: RelayStore, setup: ServerSetupKey) -> Router {
        let config = RelayConfig {
            listen,
            ..RelayConfig::default()
        };
        let state = RelayState::new(config, store, setup);
        app(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn the_default_listen_address_is_loopback() {
        let config = RelayConfig::default();
        assert!(config.listen.ip().is_loopback());
    }

    #[tokio::test]
    async fn the_app_carries_the_security_headers() {
        let store = store::RelayStore::open_in_memory().await.expect("store");
        let setup = studge_core::crypto::opaque::ServerSetupKey::generate().expect("setup");
        let the_app = app(RelayState::new(RelayConfig::default(), store, setup));
        let response = the_app
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
