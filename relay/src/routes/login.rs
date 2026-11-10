//! Login and sessions (SPEC §7.3).
//!
//! Two OPAQUE messages, then a 256-bit bearer token stored only as its
//! SHA-256. Unknown accounts get a dummy exchange (D-0113): the response shape
//! and status are identical, and only the finish step fails.

use crate::error::{ApiError, ApiResult};
use crate::extract::{client_ip, hex_id16, Session};
use crate::routes::shared::{b64_decode, b64_encode};
use crate::state::RelayState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use studge_core::crypto::opaque;
use studge_core::crypto::random;

/// Session lifetime (SPEC §7.3): 24 hours.
pub const SESSION_SECONDS: i64 = 24 * 3600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartIn {
    /// Hex account id.
    pub account_id: String,
    /// Hex device id.
    pub device_id: String,
    /// Hex OPAQUE CredentialRequest.
    pub credential_request: String,
}

#[derive(Debug, Serialize)]
pub struct LoginStartOut {
    /// Hex OPAQUE CredentialResponse.
    pub credential_response: String,
}

/// `POST /v1/login/start`.
pub async fn start(
    State(state): State<RelayState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginStartIn>,
) -> ApiResult<Json<LoginStartOut>> {
    // SPEC §7.7: 10 login attempts per hour per account, 60 per IP. Counting
    // every attempt (not only failures) is stricter and cannot be probed.
    // Uses the real client IP, taking X-Forwarded-For into account only when
    // the TCP peer is a configured trusted proxy.
    let ip = client_ip(peer.ip(), &headers, &state.config().trusted_proxies);
    state
        .check_rate(
            "login-account",
            &body.account_id,
            3600,
            state.config().login_per_account_hour,
        )
        .await?;
    state
        .check_rate(
            "login-ip",
            &ip.to_string(),
            3600,
            state.config().login_per_ip_hour,
        )
        .await?;

    let account_id = hex_id16(&body.account_id)?;
    let device_id = hex_id16(&body.device_id)?;
    let request = b64_decode(&body.credential_request, 4096)?;

    // An unknown or tombstoned account gets the dummy exchange: same shape,
    // same work, no information (D-0113).
    let password_file = match state.store().account(&account_id).await? {
        Some(account) if account.deleted_at.is_none() => Some(account.password_file),
        _ => None,
    };
    let (response, server_state) = opaque::server_login_start(
        state.setup(),
        password_file.as_deref(),
        &request,
        &account_id,
    )?;
    state
        .store()
        .put_login_state(
            &account_id,
            &device_id,
            &server_state,
            state.now()?.as_str(),
        )
        .await?;
    Ok(Json(LoginStartOut {
        credential_response: b64_encode(&response),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishIn {
    /// Hex account id.
    pub account_id: String,
    /// Hex device id.
    pub device_id: String,
    /// Hex OPAQUE CredentialFinalization.
    pub credential_finalization: String,
}

#[derive(Debug, Serialize)]
pub struct LoginFinishOut {
    /// The bearer token, returned exactly once (64 hex characters).
    pub token: String,
    /// Expiry, RFC 3339 UTC.
    pub expires_at: String,
}

/// `POST /v1/login/finish`.
pub async fn finish(
    State(state): State<RelayState>,
    Json(body): Json<LoginFinishIn>,
) -> ApiResult<Json<LoginFinishOut>> {
    let account_id = hex_id16(&body.account_id)?;
    let device_id = hex_id16(&body.device_id)?;
    let finalization = b64_decode(&body.credential_finalization, 4096)?;

    let server_state = state
        .store()
        .take_login_state(&account_id, &device_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    // A wrong password, an unknown account and a replayed finalization all
    // look the same from here (SPEC §7.8).
    opaque::server_login_finish(&server_state, &finalization)
        .map_err(|_| ApiError::Unauthorized)?;

    // A revoked device cannot log in, even with a valid password (SPEC §7.3).
    let device = state
        .store()
        .device(&account_id, &device_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if device.revoked_at.is_some() {
        return Err(ApiError::Unauthorized);
    }

    let token_bytes: [u8; 32] = random::array().map_err(|_| ApiError::Unavailable)?;
    let mut token_hash = [0u8; 32];
    token_hash.copy_from_slice(&sha2::Sha256::digest(token_bytes));
    let now = state.now()?;
    let expires = studge_core::crypto::signing::Timestamp::from_unix_seconds(
        now.unix_seconds() + SESSION_SECONDS,
    )
    .map_err(|_| ApiError::Unavailable)?;
    state
        .store()
        .create_session(
            &token_hash,
            &account_id,
            &device_id,
            now.as_str(),
            expires.as_str(),
        )
        .await?;
    Ok(Json(LoginFinishOut {
        token: hex_32(&token_bytes),
        expires_at: expires.as_str().to_string(),
    }))
}

/// `DELETE /v1/sessions/current` (D-0112).
pub async fn logout(
    State(state): State<RelayState>,
    session: Session,
) -> ApiResult<axum::http::StatusCode> {
    state.store().delete_session(&session.token_hash).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

fn hex_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
