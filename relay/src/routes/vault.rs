//! Vault endpoints (SPEC §7.4): append-only ops and compare-and-swap heads.
//!
//! The relay validates structure, sizes and ownership; it never verifies op
//! signatures or interprets payloads (§7.6). Op bytes are stored exactly as
//! received.

use crate::error::{ApiError, ApiResult};
use crate::extract::{hex_hash32, hex_id16, parse_ops, Session};
use crate::routes::shared::hex;
use crate::state::RelayState;
use crate::store::OpRow;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use studge_core::oplog::head::VaultHead;

/// The size cap for one stored op: a 1 MiB payload plus header and envelope
/// overhead (SPEC §6.11, §7.7).
pub const MAX_OP_BODY_BYTES: usize = 1024 * 1024 + 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpsQuery {
    /// Page size, at most 1000.
    pub limit: Option<usize>,
    /// The last returned op hash, hex.
    pub since: Option<String>,
}

/// `POST /v1/vaults/:vault_id/ops` — append a batch of ops (CBOR body).
pub async fn push_ops(
    State(state): State<RelayState>,
    session: Session,
    Path(vault_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let vault_id = hex_id16(&vault_hex)?;
    require_media_type(&headers, "application/cbor")?;
    // SPEC §7.4: the first push creates the vault row implicitly (ensure_vault
    // is INSERT OR IGNORE, so it is a no-op on subsequent pushes).
    state
        .store()
        .ensure_vault(&session.account_id, &vault_id)
        .await?;

    // SPEC §7.7: pushes are limited per account per minute.
    let identity = hex(&session.account_id);
    state
        .check_rate(
            "push-account",
            &identity,
            60,
            state.config().push_per_account_minute,
        )
        .await?;

    let ops = parse_ops(&body, state.config().max_ops_per_push)?;

    // Quota: the stored bytes of this account must stay under the limit.
    let incoming: i64 = ops.iter().map(|op| op.body.len() as i64).sum();
    let used = state
        .store()
        .account_storage_bytes(&session.account_id)
        .await?;
    if used + incoming > state.config().storage_quota_bytes {
        tracing::warn!("storage quota exceeded");
        return Err(ApiError::QuotaExceeded);
    }

    // Idempotency (SPEC §7.4): the same bytes for the same (vault, op_id) are
    // accepted silently; different bytes under the same op_id are a conflict.
    let mut accepted = 0usize;
    let mut rejected: Vec<(String, &'static str)> = Vec::new();
    let mut rows: Vec<OpRow> = Vec::new();
    let mut max_lamport = 0i64;
    for op in ops {
        if op.body.len() > MAX_OP_BODY_BYTES {
            rejected.push((op.op_hash, "too_large"));
            continue;
        }
        match state
            .store()
            .op_hash_for_id(&vault_id, &hex_to_bytes(&op.op_id)?)
            .await?
        {
            Some(existing) if existing == hex_to_bytes(&op.op_hash)? => {
                accepted += 1;
            }
            Some(_) => {
                return Err(ApiError::Conflict);
            }
            None => {
                max_lamport = max_lamport.max(op.lamport);
                rows.push(OpRow {
                    op_hash: hex_to_bytes(&op.op_hash)?,
                    op_id: hex_to_bytes(&op.op_id)?,
                    lamport: op.lamport,
                    body: op.body.clone(),
                    size: op.body.len() as i64,
                });
            }
        }
    }
    if !rows.is_empty() {
        let inserted = state
            .store()
            .insert_ops(
                &session.account_id,
                &vault_id,
                &rows,
                max_lamport,
                state.now()?.as_str(),
            )
            .await?;
        accepted += inserted;
    }
    let vault = state
        .store()
        .vault(&session.account_id, &vault_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "accepted": accepted,
        "rejected": rejected.into_iter().map(|(op_hash, reason)| json!({
            "op_id": op_hash,
            "reason": reason,
        })).collect::<Vec<_>>(),
        "head": vault.head_hash.as_ref().map(|hash| hex(hash)).unwrap_or_default(),
    }))
    .into_response())
}

/// `GET /v1/vaults/:vault_id/ops?since=<hash>&limit=<n>` — CBOR array plus a
/// `next_cursor` header when more follow.
pub async fn fetch_ops(
    State(state): State<RelayState>,
    session: Session,
    Path(vault_hex): Path<String>,
    Query(query): Query<OpsQuery>,
) -> ApiResult<Response> {
    let vault_id = hex_id16(&vault_hex)?;
    require_vault(&state, &session, &vault_id).await?;
    let identity = hex(&session.account_id);
    state
        .check_rate(
            "read-account",
            &identity,
            60,
            state.config().read_per_account_minute,
        )
        .await?;

    let limit = query.limit.unwrap_or(100).clamp(1, 1000) as i64;
    let cursor = match query.since.as_deref() {
        None => None,
        Some(hash_hex) => {
            let hash = hex_hash32(hash_hex)?;
            let position = state
                .store()
                .op_position(&vault_id, &hash)
                .await?
                .ok_or(ApiError::InvalidRequest)?;
            Some(position)
        }
    };
    let rows = state.store().ops_after(&vault_id, cursor, limit).await?;
    let mut body = Vec::new();
    // A CBOR array of the stored op bytes, exactly as they arrived.
    use ciborium::value::Value;
    use studge_core::cbor::{bytes as cbor_bytes, text as cbor_text};
    use studge_core::crypto::aad::{canonical_bytes, canonical_map};
    let items: Vec<Value> = rows.iter().map(|row| cbor_bytes(&row.body)).collect();
    let array = Value::Array(items);
    body.extend_from_slice(&canonical_bytes(&canonical_map(vec![("ops", array)]))?);
    let _ = cbor_text;

    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        "content-type",
        "application/cbor"
            .parse()
            .map_err(|_| ApiError::Unavailable)?,
    );
    if rows.len() == usize::try_from(limit).unwrap_or(0) {
        if let Some(last) = rows.last() {
            response.headers_mut().insert(
                "next-cursor",
                hex(&last.op_hash)
                    .parse()
                    .map_err(|_| ApiError::Unavailable)?,
            );
        }
    }
    Ok(response)
}

/// `GET /v1/vaults/:vault_id/head`.
pub async fn get_head(
    State(state): State<RelayState>,
    session: Session,
    Path(vault_hex): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let vault_id = hex_id16(&vault_hex)?;
    require_vault(&state, &session, &vault_id).await?;
    let vault = state
        .store()
        .vault(&session.account_id, &vault_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    match (vault.head, vault.head_hash) {
        (Some(head), Some(head_hash)) => Ok(Json(json!({
            "head": b64_decode_strict(&hex(&head))?,
            "head_hash": hex(&head_hash),
        }))),
        _ => Err(ApiError::NotFound),
    }
}

/// `PUT /v1/vaults/:vault_id/head` with `If-Match: <head_hash>` (`*` for the
/// first head). A mismatch is `409` and the client re-reads (SPEC §6.8–6.9).
pub async fn put_head(
    State(state): State<RelayState>,
    session: Session,
    Path(vault_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let vault_id = hex_id16(&vault_hex)?;
    require_vault(&state, &session, &vault_id).await?;
    require_media_type(&headers, "application/cbor")?;

    // SPEC §6.11: a head is at most 16 KiB.
    if body.len() > 16 * 1024 {
        return Err(ApiError::TooLarge);
    }
    let head = VaultHead::from_cbor(&body).map_err(|_| ApiError::InvalidRequest)?;
    if head.vault_id() != &vault_id {
        return Err(ApiError::InvalidRequest);
    }
    let head_hash = head.hash().map_err(|_| ApiError::InvalidRequest)?;

    let expected = match headers
        .get("if-match")
        .and_then(|value| value.to_str().ok())
    {
        None => return Err(ApiError::InvalidRequest),
        Some("*") => None,
        Some(hash_hex) => Some(hex_hash32(hash_hex)?),
    };
    let swapped = state
        .store()
        .compare_and_swap_head(
            &session.account_id,
            &vault_id,
            expected.as_ref().map(|h| h.as_ref()),
            &body,
            &head_hash,
        )
        .await?;
    if !swapped {
        return Err(ApiError::Conflict);
    }
    Ok((
        StatusCode::OK,
        Json(json!({
            "head_hash": hex(&head_hash),
            "op_count": head.op_count(),
            "lamport_max": head.lamport_max(),
        })),
    ))
}

async fn require_vault(
    state: &RelayState,
    session: &Session,
    vault_id: &[u8; 16],
) -> Result<(), ApiError> {
    // §7.8: 404 covers both "no such vault" and "not yours".
    match state.store().vault(&session.account_id, vault_id).await? {
        Some(_) => Ok(()),
        None => Err(ApiError::NotFound),
    }
}

fn require_media_type(headers: &HeaderMap, expected: &str) -> Result<(), ApiError> {
    let media = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::InvalidRequest)?;
    if media.split(';').next().map(|part| part.trim()) == Some(expected) {
        Ok(())
    } else {
        Err(ApiError::InvalidRequest)
    }
}

fn hex_to_bytes(value: &str) -> Result<Vec<u8>, ApiError> {
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| ApiError::InvalidRequest)
        })
        .collect()
}

/// The head travels as CBOR bytes in a JSON string (base64) for readability.
fn b64_decode_strict(hex_text: &str) -> ApiResult<Vec<u8>> {
    hex_to_bytes(hex_text)
}
