//! Reading client input strictly (SPEC §7.1, §7.6, R-0305).
//!
//! JSON bodies are parsed with unknown fields rejected; CBOR bodies are parsed
//! with `studge-core`'s strict parser, which refuses non-canonical encodings
//! and unknown keys. Everything is validated before any expensive work.

use crate::error::ApiError;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use serde::Deserialize;
use sha2::Digest;
use studge_core::crypto::signing::Timestamp;
use studge_core::oplog::op::StoredOp;

/// The bearer token of a valid session, bound to a live device.
#[derive(Debug, Clone)]
pub struct Session {
    /// The account the session belongs to.
    pub account_id: [u8; 16],
    /// The device it is bound to. Stored for future per-device event emission.
    #[allow(dead_code)]
    pub device_id: [u8; 16],
    /// The token hash, so `DELETE /v1/sessions/current` can remove it.
    pub token_hash: [u8; 32],
}

/// Extracts `Authorization: Bearer <token>` and resolves it to a session.
impl FromRequestParts<crate::state::RelayState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::state::RelayState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or(ApiError::Unauthorized)?;
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ApiError::Unauthorized);
        }
        let mut token_bytes = [0u8; 32];
        for index in 0..32 {
            token_bytes[index] = u8::from_str_radix(&token[index * 2..index * 2 + 2], 16)
                .map_err(|_| ApiError::Unauthorized)?;
        }
        let mut token_hash = [0u8; 32];
        token_hash.copy_from_slice(&sha2::Sha256::digest(token_bytes));
        let (account_id_vec, device_id_vec, expires_at) = state
            .store()
            .session(&token_hash)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        let account_id: [u8; 16] = account_id_vec
            .try_into()
            .map_err(|_| ApiError::Unauthorized)?;
        let device_id: [u8; 16] = device_id_vec
            .try_into()
            .map_err(|_| ApiError::Unauthorized)?;
        // Expired sessions are unauthorized (and swept away in the background).
        let now = Timestamp::now().map_err(|_| ApiError::Unavailable)?;
        if expires_at.as_str() <= now.as_str() {
            return Err(ApiError::Unauthorized);
        }
        // A token for a revoked device is rejected (SPEC §7.3).
        let device = state
            .store()
            .device(&account_id, &device_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if device.revoked_at.is_some() {
            state.store().delete_session(&token_hash).await?;
            return Err(ApiError::Unauthorized);
        }
        // A tombstoned account answers forbidden everywhere.
        let account = state
            .store()
            .account(&account_id)
            .await?
            .ok_or(ApiError::Unauthorized)?;
        if account.deleted_at.is_some() {
            return Err(ApiError::Forbidden);
        }
        Ok(Self {
            account_id,
            device_id,
            token_hash,
        })
    }
}

/// Decodes a hex field of an exact length into bytes.
pub fn hex_bytes(value: &str, expected: usize) -> Result<Vec<u8>, ApiError> {
    if value.len() != expected * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::InvalidRequest);
    }
    (0..expected)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| ApiError::InvalidRequest)
        })
        .collect()
}

/// A 16-byte id sent as 32 hex characters.
pub fn hex_id16(value: &str) -> Result<[u8; 16], ApiError> {
    let bytes = hex_bytes(value, 16)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// A 32-byte hash sent as 64 hex characters.
pub fn hex_hash32(value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex_bytes(value, 32)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// The account record of SPEC §7.5, validated strictly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecordIn {
    /// Hex account id.
    pub account_id: String,
    /// Hex 16-byte salt.
    pub account_salt: String,
    /// KDF parameters.
    pub kdf: KdfIn,
    /// Hex AK envelope.
    pub ak_envelope: String,
    /// Hex key-bundle envelope.
    pub bundle_envelope: String,
    /// Identity public keys.
    pub identity_keys: IdentityKeysIn,
    /// Record version.
    pub version: u64,
}

/// KDF parameters (SPEC §4.3): the relay refuses anything below the floor.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfIn {
    /// Parameter-set version.
    pub version: u64,
    /// Memory cost in KiB.
    pub m: u64,
    /// Iterations.
    pub t: u64,
    /// Parallelism.
    pub p: u64,
}

impl KdfIn {
    /// SPEC §4.3: version 1 with m ≥ 64 MiB, t ≥ 3, p ≥ 1.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.version != 1
            || self.m < 65_536
            || self.t < 3
            || self.p < 1
            || self.m > 8 * 1024 * 1024
            || self.t > 64
            || self.p > 8
        {
            return Err(ApiError::InvalidRequest);
        }
        Ok(())
    }
}

/// The three identity public keys (SPEC §4.6).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeysIn {
    /// Hex Ed25519 public key.
    pub ed25519: String,
    /// Hex X25519 public key.
    pub x25519: String,
    /// Hex ML-KEM-768 encapsulation key.
    pub mlkem768: String,
}

impl AccountRecordIn {
    /// Validates every field (SPEC §7.5, §7.6).
    pub fn validate(&self, expected_account: &[u8; 16]) -> Result<(), ApiError> {
        if hex_id16(&self.account_id)? != *expected_account
            || hex_bytes(&self.account_salt, 16).is_err()
            || self.ak_envelope.is_empty()
            || self.ak_envelope.len() > 4096
            || self.bundle_envelope.is_empty()
            || self.bundle_envelope.len() > 1_048_576
            || self.version != 1
        {
            return Err(ApiError::InvalidRequest);
        }
        if hex_bytes(&self.identity_keys.ed25519, 32).is_err()
            || hex_bytes(&self.identity_keys.x25519, 32).is_err()
            || hex_bytes(&self.identity_keys.mlkem768, 1184).is_err()
        {
            return Err(ApiError::InvalidRequest);
        }
        self.kdf.validate()
    }
}

/// One op as received: parsed with the same strict parser the client used.
#[derive(Debug, Clone)]
pub struct OpIn {
    /// The op hash, hex.
    pub op_hash: String,
    /// The op id, hex.
    pub op_id: String,
    /// The Lamport clock.
    pub lamport: i64,
    /// The raw bytes as received.
    pub body: Vec<u8>,
}

/// Parses and validates a batch of ops from a CBOR body (SPEC §7.6).
///
/// The body is a CBOR array of at most `max_ops` stored ops. Every op is
/// parsed with `studge-core`'s strict parser, which refuses non-canonical
/// encodings and unknown keys; the raw bytes are kept exactly as received.
pub fn parse_ops(body: &[u8], max_ops: usize) -> Result<Vec<OpIn>, ApiError> {
    let value =
        studge_core::crypto::aad::parse_strict(body).map_err(|_| ApiError::InvalidRequest)?;
    let items = studge_core::cbor::as_array(&value).map_err(|_| ApiError::InvalidRequest)?;
    if items.is_empty() || items.len() > max_ops {
        return Err(ApiError::InvalidRequest);
    }
    let mut ops = Vec::with_capacity(items.len());
    for item in items {
        let bytes = studge_core::cbor::as_bytes(item).map_err(|_| ApiError::InvalidRequest)?;
        let stored = StoredOp::from_cbor(bytes).map_err(|_| ApiError::InvalidRequest)?;
        let op = stored.op();
        // §7.6: parents ≤ 16, sorted, no duplicates; lamport in range;
        // created_at parseable and within ±24 h.
        if op.parents().len() > 16
            || op.lamport() == 0
            || op.lamport() > i64::MAX as u64
            || !parents_sorted_unique(op.parents())
        {
            return Err(ApiError::InvalidRequest);
        }
        let created_at = op.created_at();
        let now = Timestamp::now().map_err(|_| ApiError::Unavailable)?;
        let skew = 24 * 3600;
        if created_at.unix_seconds() > now.unix_seconds() + skew
            || created_at.unix_seconds() < now.unix_seconds() - skew
        {
            return Err(ApiError::InvalidRequest);
        }
        ops.push(OpIn {
            op_hash: hex(&stored.hash().map_err(|_| ApiError::InvalidRequest)?),
            op_id: hex(op.op_id()),
            lamport: i64::try_from(op.lamport()).map_err(|_| ApiError::InvalidRequest)?,
            body: bytes.to_vec(),
        });
    }
    Ok(ops)
}

fn parents_sorted_unique(parents: &[[u8; 32]]) -> bool {
    parents.windows(2).all(|pair| pair[0] < pair[1])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::request::Parts;
    use axum::http::{HeaderMap, HeaderValue, Request};

    fn parts_with_auth(token: &str) -> Parts {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        let mut request = Request::builder()
            .method("GET")
            .uri("/")
            .body(())
            .expect("request");
        *request.headers_mut() = headers;
        let (parts, _) = request.into_parts();
        parts
    }

    #[test]
    fn hex_fields_are_strict() {
        assert!(hex_id16(&"a".repeat(32)).is_ok());
        assert!(hex_id16(&"a".repeat(31)).is_err());
        assert!(hex_id16(&"g".repeat(32)).is_err());
        assert!(hex_id16("").is_err());
        assert!(hex_hash32(&"b".repeat(64)).is_ok());
        assert!(hex_hash32(&"b".repeat(63)).is_err());
        assert!(hex_bytes("zz", 1).is_err());
    }

    #[test]
    fn kdf_parameters_have_a_floor_and_a_ceiling() {
        let good = KdfIn {
            version: 1,
            m: 65_536,
            t: 3,
            p: 1,
        };
        good.validate().expect("floor values");
        for bad in [
            KdfIn { version: 2, ..good },
            KdfIn { m: 1024, ..good },
            KdfIn { t: 2, ..good },
            KdfIn { p: 0, ..good },
            KdfIn {
                m: 99 * 1024 * 1024,
                ..good
            },
        ] {
            assert_eq!(
                bad.validate().expect_err("bad kdf"),
                ApiError::InvalidRequest
            );
        }
    }

    #[test]
    fn the_account_record_rejects_every_wrong_field() {
        let base = serde_json::json!({
            "account_id": "aa".repeat(16),
            "account_salt": "bb".repeat(16),
            "kdf": { "version": 1, "m": 65536, "t": 3, "p": 1 },
            "ak_envelope": "cc".repeat(32),
            "bundle_envelope": "dd".repeat(64),
            "identity_keys": {
                "ed25519": "ee".repeat(32),
                "x25519": "ff".repeat(32),
                "mlkem768": "11".repeat(1184),
            },
            "version": 1,
        });
        let account: [u8; 16] = [0xaa; 16];
        let parsed: AccountRecordIn = serde_json::from_value(base.clone()).expect("record");
        parsed.validate(&account).expect("valid record");

        // An unknown field is rejected (strict parsing).
        let mut extra = base.clone();
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AccountRecordIn>(extra).is_err());

        // A wrong account id is rejected.
        let mut other = base.clone();
        other["account_id"] = serde_json::json!("ab".repeat(16));
        let parsed: AccountRecordIn = serde_json::from_value(other).expect("parses");
        assert!(parsed.validate(&account).is_err());

        // A short salt is rejected.
        let mut short_salt = base.clone();
        short_salt["account_salt"] = serde_json::json!("bb".repeat(15));
        let parsed: AccountRecordIn = serde_json::from_value(short_salt).expect("parses");
        assert!(parsed.validate(&account).is_err());
    }

    #[tokio::test]
    async fn a_malformed_token_is_unauthorized_before_the_store() {
        let store = crate::store::RelayStore::open_in_memory()
            .await
            .expect("store");
        let state = crate::state::RelayState::new(
            crate::config::RelayConfig::default(),
            store,
            studge_core::crypto::opaque::ServerSetupKey::generate().expect("setup"),
        );
        for token in ["", "abc", &"z".repeat(64), &"A".repeat(63)] {
            let mut parts = parts_with_auth(token);
            assert_eq!(
                <Session as FromRequestParts<crate::state::RelayState>>::from_request_parts(
                    &mut parts, &state
                )
                .await
                .expect_err("reject"),
                ApiError::Unauthorized
            );
        }
    }

    #[test]
    fn parents_must_be_sorted_and_unique() {
        assert!(parents_sorted_unique(&[]));
        assert!(parents_sorted_unique(&[[1u8; 32], [2u8; 32]]));
        assert!(!parents_sorted_unique(&[[2u8; 32], [1u8; 32]]));
        assert!(!parents_sorted_unique(&[[1u8; 32], [1u8; 32]]));
    }
}
