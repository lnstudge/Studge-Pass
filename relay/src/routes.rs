//! Route assembly. Every endpoint of SPEC §7.4 hangs off `/v1`; `/health` is
//! the only unversioned route.

use crate::error::ApiError;
use crate::state::RelayState;
use axum::routing::get;
use axum::{Json, Router};
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

/// Builds the router. Unknown paths fall through to the generic error shape.
/// The security headers live here so every route — including fallbacks —
/// carries them.
pub fn router(state: RelayState) -> Router {
    Router::new()
        .route("/health", get(health))
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn(crate::security_headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::request_timeout,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_answers_ok() {
        let app = router(RelayState::new(RelayConfig::default()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn an_unknown_path_is_the_generic_error() {
        let app = router(RelayState::new(RelayConfig::default()));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/nope")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 404);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .expect("body"),
        )
        .expect("json");
        assert_eq!(body["error"], "not_found");
    }

    #[tokio::test]
    async fn security_headers_are_set_on_every_response() {
        let app = router(RelayState::new(RelayConfig::default()));
        for path in ["/health", "/v1/nope"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            let headers = response.headers();
            let text = |name: &str| {
                headers
                    .get(name)
                    .map(|value| value.to_str().expect("ascii"))
                    .unwrap_or("")
            };
            assert_eq!(text("x-content-type-options"), "nosniff");
            assert_eq!(text("cache-control"), "no-store");
            assert_eq!(text("referrer-policy"), "no-referrer");
            assert_eq!(text("x-frame-options"), "DENY");
            assert!(text("content-security-policy").contains("default-src 'none'"));
        }
    }
}
