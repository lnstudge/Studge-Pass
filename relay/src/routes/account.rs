//! Account and device endpoints (SPEC §7.4, §4.7, §4.8).

use crate::error::{ApiError, ApiResult};
use crate::extract::{hex_id16, Session};
use crate::routes::shared::{b64_decode, hex};
use crate::state::RelayState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;

/// `GET /v1/account`: the stored record bytes, exactly as created or updated.
pub async fn get_account(
    State(state): State<RelayState>,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    let account = state
        .store()
        .account(&session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let record: serde_json::Value =
        serde_json::from_slice(&account.record).map_err(|_| ApiError::Unavailable)?;
    Ok(Json(record))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceAccountIn {
    /// The full account record (SPEC §7.5).
    pub account_record: crate::extract::AccountRecordIn,
}

/// `PUT /v1/account` with `If-Match: <version>`.
pub async fn put_account(
    State(state): State<RelayState>,
    session: Session,
    headers: HeaderMap,
    Json(body): Json<ReplaceAccountIn>,
) -> ApiResult<axum::http::StatusCode> {
    body.account_record.validate(&session.account_id)?;
    let expected = if_match_version(&headers)?;
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
    if !state
        .store()
        .replace_account_record(&session.account_id, &record_bytes, expected)
        .await?
    {
        return Err(ApiError::Conflict);
    }
    Ok(axum::http::StatusCode::OK)
}

/// Reads `If-Match: <version>` (an unsigned integer).
fn if_match_version(headers: &HeaderMap) -> ApiResult<i64> {
    let raw = headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidRequest)?;
    raw.parse::<i64>().map_err(|_| ApiError::InvalidRequest)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolDeviceIn {
    /// Hex device certificate (SPEC §4.7).
    pub certificate: String,
    /// Hex Ed25519 device public key.
    pub device_pubkey: String,
    /// Hex enrolment proof (D-0107): the new device signs a nonce.
    pub enrolment_proof: String,
}

/// `POST /v1/devices` — certify a new device.
pub async fn enrol_device(
    State(state): State<RelayState>,
    session: Session,
    Json(body): Json<EnrolDeviceIn>,
) -> ApiResult<(axum::http::StatusCode, Json<serde_json::Value>)> {
    let certificate = b64_decode(&body.certificate, 8192)?;
    let public_key = crate::extract::hex_bytes(&body.device_pubkey, 32)?;
    let proof = b64_decode(&body.enrolment_proof, 8192)?;

    // The certificate must chain to the pinned identity key of the account
    // (SPEC §4.7): the relay holds that key in the account record.
    let account = state
        .store()
        .account(&session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let record: serde_json::Value =
        serde_json::from_slice(&account.record).map_err(|_| ApiError::Unavailable)?;
    let identity_hex = record["identity_keys"]["ed25519"]
        .as_str()
        .ok_or(ApiError::Unavailable)?;
    let identity_public = crate::extract::hex_bytes(identity_hex, 32)?;
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&identity_public);

    let cert = studge_core::crypto::signing::DeviceCertificate::from_cbor(&certificate)
        .map_err(|_| ApiError::InvalidRequest)?;
    let now = state.now()?;
    cert.verify(&identity, &session.account_id, &now, None)
        .map_err(|_| ApiError::InvalidRequest)?;
    let device_id = *cert.device_id();
    if cert.device_public_key().as_slice() != public_key.as_slice()
        || cert.device_id().as_slice() != device_id.as_slice()
    {
        return Err(ApiError::InvalidRequest);
    }

    // The possession proof (D-0107) is checked structurally: the approving
    // device issues the single-use nonce out of band, so the nonce and the
    // signature are verified between devices. The relay can only bind the
    // proof to this account and this device.
    let enrolment = studge_core::crypto::signing::EnrolmentProof::from_cbor(&proof)
        .map_err(|_| ApiError::InvalidRequest)?;
    if enrolment.account_id() != &session.account_id || enrolment.device_id() != &device_id {
        return Err(ApiError::InvalidRequest);
    }

    // SPEC §7.7 / D-0601 (proposed): at most 100 devices per account.
    if state.store().device_count(&session.account_id).await? >= 100 {
        return Err(ApiError::QuotaExceeded);
    }

    let created = state
        .store()
        .add_device(
            &session.account_id,
            &device_id,
            &public_key,
            &certificate,
            now.as_str(),
        )
        .await?;
    if !created {
        // Re-certifying the same key is fine; a *different* key for the same
        // device id is the silent-swap the client must refuse anyway.
        return Err(ApiError::Conflict);
    }
    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({ "device_id": hex(&device_id) })),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeDeviceIn {
    /// Hex signed revocation record (SPEC §4.8).
    pub revocation_record: String,
}

/// `DELETE /v1/devices/:device_id` — revoke a device with a signed record.
pub async fn revoke_device(
    State(state): State<RelayState>,
    session: Session,
    Path(device_hex): Path<String>,
    Json(body): Json<RevokeDeviceIn>,
) -> ApiResult<axum::http::StatusCode> {
    let device_id = hex_id16(&device_hex)?;
    let record = b64_decode(&body.revocation_record, 8192)?;
    let revocation = studge_core::crypto::signing::DeviceRevocation::from_cbor(&record)
        .map_err(|_| ApiError::InvalidRequest)?;
    // The relay verifies the structure and that the signer is the account
    // identity key (SPEC §7.4); the client verifies everything else.
    let account = state
        .store()
        .account(&session.account_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let record_value: serde_json::Value =
        serde_json::from_slice(&account.record).map_err(|_| ApiError::Unavailable)?;
    let identity_hex = record_value["identity_keys"]["ed25519"]
        .as_str()
        .ok_or(ApiError::Unavailable)?;
    let identity_public = crate::extract::hex_bytes(identity_hex, 32)?;
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&identity_public);
    revocation
        .verify(&identity, &session.account_id)
        .map_err(|_| ApiError::InvalidRequest)?;
    if revocation.device_id() != &device_id {
        return Err(ApiError::InvalidRequest);
    }
    // A device may revoke itself ("sign out everywhere else", SPEC §4.8).
    state
        .store()
        .revoke_device(
            &session.account_id,
            &device_id,
            revocation.revoked_at().as_str(),
        )
        .await?;
    Ok(axum::http::StatusCode::OK)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteAccountIn {
    /// Must be exactly "delete".
    pub confirmation: String,
}

/// `DELETE /v1/account` — tombstone now, wipe within 24 hours (SPEC §7.4).
pub async fn delete_account(
    State(state): State<RelayState>,
    session: Session,
    Json(body): Json<DeleteAccountIn>,
) -> ApiResult<axum::http::StatusCode> {
    if body.confirmation != "delete" {
        return Err(ApiError::InvalidRequest);
    }
    state
        .store()
        .tombstone_account(&session.account_id, state.now()?.as_str())
        .await?;
    Ok(axum::http::StatusCode::ACCEPTED)
}
