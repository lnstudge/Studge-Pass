//! HTTP relay transport (SPEC §7.1–§7.9).
//!
//! Uses `reqwest` (blocking client, `rustls-tls`) to talk to a `studge-relay`
//! instance.  The bearer token is stored in a `Zeroizing<String>` and never
//! logged.  `rustls-tls` only; native TLS is never used (AGENTS.md rule 1).
//!
//! This crate is native-only: it must not be compiled for
//! `wasm32-unknown-unknown`.  The browser extension uses a different transport
//! (fetch API through the background service worker, Phase 10/13).

use studge_core::oplog::head::VaultHead;
use studge_core::oplog::op::StoredOp;
use studge_core::sync::transport::{SyncError, Transport, VaultOps, NO_HEAD};
use zeroize::Zeroizing;

fn hex_hash(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// HTTP relay transport.
///
/// The bearer token is the raw 256-bit session token returned by
/// `POST /v1/login/finish`; it is sent once per request and never cached in
/// logs or error messages.
pub struct HttpRelayTransport {
    base_url: String,
    /// Bearer token — never logged, never formatted into errors.
    token: Zeroizing<String>,
    client: reqwest::blocking::Client,
}

impl HttpRelayTransport {
    /// Creates a transport for `base_url` using `token` as the bearer token.
    ///
    /// `base_url` must end without a trailing slash, e.g.
    /// `https://relay.example.com`.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self, SyncError> {
        let client = reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .build()
            .map_err(|e| SyncError::Io(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into(),
            token: Zeroizing::new(token.into()),
            client,
        })
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.token.as_str())
    }

    fn get_head(&mut self, vault_id: [u8; 16]) -> Result<Option<VaultHead>, SyncError> {
        let url = format!("{}/v1/vaults/{}/head", self.base_url, hex_id(&vault_id));
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", "application/cbor")
            .send()
            .map_err(|e| SyncError::Io(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(SyncError::Io(format!("get_head: HTTP {}", resp.status())));
        }
        let body: serde_json::Value = resp.json().map_err(|_| SyncError::MalformedPayload)?;
        let head_b64 = body
            .get("head")
            .and_then(|v| v.as_str())
            .ok_or(SyncError::MalformedPayload)?;
        let head_bytes = studge_core::codec::base64_decode(head_b64)
            .map_err(|_| SyncError::MalformedPayload)?;
        let head = VaultHead::from_cbor(&head_bytes).map_err(|_| SyncError::MalformedPayload)?;
        Ok(Some(head))
    }
}

impl Transport for HttpRelayTransport {
    fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError> {
        let mut cbor_ops: Vec<Vec<u8>> = Vec::with_capacity(ops.len());
        for op in ops {
            cbor_ops.push(op.to_cbor().map_err(|_| SyncError::MalformedPayload)?);
        }
        let mut payload: Vec<u8> = Vec::new();
        let value = ciborium::value::Value::Array(
            cbor_ops
                .into_iter()
                .map(ciborium::value::Value::Bytes)
                .collect(),
        );
        ciborium::ser::into_writer(&value, &mut payload)
            .map_err(|_| SyncError::MalformedPayload)?;

        let url = format!("{}/v1/vaults/{}/ops", self.base_url, hex_id(&vault_id));
        let resp = self
            .client
            .post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/cbor")
            .body(payload)
            .send()
            .map_err(|e| SyncError::Io(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SyncError::Io(format!("push: HTTP {}", resp.status())));
        }
        let body: serde_json::Value = resp.json().map_err(|_| SyncError::MalformedPayload)?;
        // The "accepted" field is mandatory: a relay that omits it is malformed,
        // and a count that does not match the ops we sent means some ops are
        // still pending and must stay queued.
        let accepted = body
            .get("accepted")
            .and_then(|v| v.as_u64())
            .ok_or(SyncError::MalformedPayload)? as usize;
        if accepted != ops.len() {
            return Err(SyncError::MalformedPayload);
        }
        Ok(accepted)
    }

    fn pull(
        &mut self,
        vault_id: [u8; 16],
        cursor: Option<[u8; 32]>,
    ) -> Result<VaultOps, SyncError> {
        let mut url = format!(
            "{}/v1/vaults/{}/ops?limit=100",
            self.base_url,
            hex_id(&vault_id)
        );
        if let Some(hash) = cursor {
            url.push_str(&format!("&since={}", hex_hash(&hash)));
        }
        let resp = self
            .client
            .get(&url)
            .header("Authorization", self.auth_header())
            .header("Accept", "application/cbor")
            .send()
            .map_err(|e| SyncError::Io(e.to_string()))?;

        if resp.status().as_u16() == 404 {
            return Ok(VaultOps {
                ops: vec![],
                head: None,
            });
        }
        if !resp.status().is_success() {
            return Err(SyncError::Io(format!("pull: HTTP {}", resp.status())));
        }
        let bytes = resp.bytes().map_err(|e| SyncError::Io(e.to_string()))?;
        let mut cursor_r = std::io::Cursor::new(&bytes[..]);
        let value: ciborium::value::Value =
            ciborium::de::from_reader(&mut cursor_r).map_err(|_| SyncError::MalformedPayload)?;
        let arr = match value {
            ciborium::value::Value::Array(a) => a,
            _ => return Err(SyncError::MalformedPayload),
        };
        let mut ops = Vec::with_capacity(arr.len());
        for item in arr {
            let raw = match item {
                ciborium::value::Value::Bytes(b) => b,
                _ => return Err(SyncError::MalformedPayload),
            };
            let op = StoredOp::from_cbor(&raw).map_err(|_| SyncError::MalformedPayload)?;
            ops.push(op);
        }

        let head = self.get_head(vault_id)?;
        Ok(VaultOps { ops, head })
    }

    fn put_head(
        &mut self,
        vault_id: [u8; 16],
        head: &VaultHead,
        expected_hash: [u8; 32],
    ) -> Result<(), SyncError> {
        let head_bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
        let if_match = if expected_hash == NO_HEAD {
            "*".to_string()
        } else {
            hex_hash(&expected_hash)
        };
        let url = format!("{}/v1/vaults/{}/head", self.base_url, hex_id(&vault_id));
        let resp = self
            .client
            .put(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/cbor")
            .header("If-Match", if_match)
            .body(head_bytes)
            .send()
            .map_err(|e| SyncError::Io(e.to_string()))?;

        match resp.status().as_u16() {
            200 => Ok(()),
            409 => Err(SyncError::ForkDetected),
            s => Err(SyncError::Io(format!("put_head: HTTP {s}"))),
        }
    }
}

// Base64 decoding uses studge_core::codec (the project's single codec).
