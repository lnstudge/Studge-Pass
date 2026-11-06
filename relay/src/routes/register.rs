//! Registration (SPEC Â§7.2): two OPAQUE messages plus the account record.
//!
//! The start endpoint never consults the account table â€” registration cannot
//! enumerate accounts. The finish endpoint creates the account atomically and
//! answers `409` for a duplicate (the one place existence is visible, as the
//! SPEC sanctions).

use crate::error::{ApiError, ApiResult};
use crate::extract::{hex_id16, AccountRecordIn};
use crate::routes::shared::{b64_decode, b64_encode};
use crate::state::RelayState;
use axum::extract::{ConnectInfo, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use studge_core::crypto::opaque;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartIn {
    /// Hex account id.
    pub account_id: String,
    /// Hex OPAQUE RegistrationRequest.
    pub registration_request: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterStartOut {
    /// Hex OPAQUE RegistrationResponse.
    pub registration_response: String,
}

/// `POST /v1/register/start`.
pub async fn start(
    State(state): State<RelayState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(body): Json<RegisterStartIn>,
) -> ApiResult<Json<RegisterStartOut>> {
    // SPEC Â§7.7: five registrations per hour per IP, checked before any work.
    state
        .check_rate(
            "register",
            &peer.ip().to_string(),
            3600,
            state.config().register_per_ip_hour,
        )
        .await?;
    let account_id = hex_id16(&body.account_id)?;
    let request = b64_decode(&body.registration_request, 4096)?;
    let response = opaque::server_registration_start(state.setup(), &request, &account_id)?;
    Ok(Json(RegisterStartOut {
        registration_response: b64_encode(&response),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishIn {
    /// Hex account id.
    pub account_id: String,
    /// Hex OPAQUE RegistrationUpload.
    pub registration_upload: String,
    /// The account record (SPEC Â§7.5), validated strictly.
    pub account_record: AccountRecordIn,
    /// The first device: id, public key and certificate, all hex.
    pub first_device: FirstDeviceIn,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstDeviceIn {
    /// Hex device id.
    pub device_id: String,
    /// Hex Ed25519 public key.
    pub device_pubkey: String,
    /// Hex device certificate (SPEC Â§4.7).
    pub certificate: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterFinishOut {
    /// The created account id, hex.
    pub account_id: String,
}

/// `POST /v1/register/finish`.
pub async fn finish(
    State(state): State<RelayState>,
    Json(body): Json<RegisterFinishIn>,
) -> ApiResult<(axum::http::StatusCode, Json<RegisterFinishOut>)> {
    let account_id = hex_id16(&body.account_id)?;
    body.account_record.validate(&account_id)?;
    let upload = b64_decode(&body.registration_upload, 8192)?;
    let password_file = opaque::server_registration_finish(&upload)?;

    // The first device is stored with its certificate; the relay checks that
    // the certificate chains to the account's identity key (SPEC Â§4.7) using
    // the identity public key from the account record.
    let device_id = hex_id16(&body.first_device.device_id)?;
    let public_key = crate::extract::hex_bytes(&body.first_device.device_pubkey, 32)?;
    let certificate = b64_decode(&body.first_device.certificate, 8192)?;
    let parsed = studge_core::crypto::signing::DeviceCertificate::from_cbor(&certificate)
        .map_err(|_| ApiError::InvalidRequest)?;
    let identity_public =
        crate::extract::hex_bytes(&body.account_record.identity_keys.ed25519, 32)?;
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&identity_public);
    let now = state.now()?;
    parsed
        .verify(&identity, &account_id, &now, None)
        .map_err(|_| ApiError::InvalidRequest)?;
    if parsed.device_public_key().as_slice() != public_key.as_slice()
        || parsed.device_id().as_slice() != device_id.as_slice()
    {
        return Err(ApiError::InvalidRequest);
    }

    // The record travels as opaque bytes: the exact JSON the client sent,
    // re-serialised deterministically so `GET /v1/account` returns stable data.
    let record_bytes = serde_json::to_vec(&serde_json::json!({
        "account_id": body.account_record.account_id,
        "account_salt": body.account_record.account_salt,
        "kdf": {
            "version": body.account_record.kdf.version,
            "m": body.account_record.kdf.m,
            "t": body.account_record.kdf.t,
            "p": body.account_record.kdf.p,
        },
        "ak_envelope": body.account_record.ak_envelope,
        "bundle_envelope": body.account_record.bundle_envelope,
        "identity_keys": {
            "ed25519": body.account_record.identity_keys.ed25519,
            "x25519": body.account_record.identity_keys.x25519,
            "mlkem768": body.account_record.identity_keys.mlkem768,
        },
        "version": body.account_record.version,
    }))
    .map_err(|_| ApiError::Unavailable)?;

    let created = state
        .store()
        .create_account(
            &account_id,
            &record_bytes,
            &password_file,
            state.now()?.as_str(),
        )
        .await?;
    if !created {
        return Err(ApiError::Conflict);
    }
    state
        .store()
        .add_device(
            &account_id,
            &device_id,
            &public_key,
            &certificate,
            state.now()?.as_str(),
        )
        .await?;
    let _ = Value::Null;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(RegisterFinishOut {
            account_id: body.account_id,
        }),
    ))
}
