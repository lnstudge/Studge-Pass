//! Route assembly. Every endpoint of SPEC §7.4 hangs off `/v1`; `/health` is
//! the only unversioned route.

use crate::error::ApiError;
use crate::state::RelayState;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Serialize;

pub mod account;
pub mod login;
pub mod register;
pub mod shared;
pub mod vault;

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
    use crate::routes::{account, login, register, vault};
    Router::new()
        .route("/health", get(health))
        .route("/v1/register/start", post(register::start))
        .route("/v1/register/finish", post(register::finish))
        .route("/v1/login/start", post(login::start))
        .route("/v1/login/finish", post(login::finish))
        .route("/v1/sessions/current", delete(login::logout))
        .route("/v1/account", get(account::get_account))
        .route("/v1/account", put(account::put_account))
        .route("/v1/account", delete(account::delete_account))
        .route("/v1/devices", post(account::enrol_device))
        .route("/v1/devices/{device_id}", delete(account::revoke_device))
        .route("/v1/vaults/{vault_id}/ops", post(vault::push_ops))
        .route("/v1/vaults/{vault_id}/ops", get(vault::fetch_ops))
        .route("/v1/vaults/{vault_id}/head", get(vault::get_head))
        .route("/v1/vaults/{vault_id}/head", put(vault::put_head))
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn(crate::security_headers))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::request_timeout,
        ))
        .with_state(state)
}
