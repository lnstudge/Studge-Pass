//! Test helpers: relay spawner and account builder for integration tests.
//!
//! The relay is spawned on a random OS port with an in-memory SQLite database.
//! The client side uses only `studge-core` and `reqwest`.

use reqwest::Client;
use serde_json::{json, Value};
use studge_core::crypto::{opaque, random, signing};
use studge_core::oplog::op::{Op, OpKind};

// ── relay spawner ─────────────────────────────────────────────────────────────

/// A relay process running on a random local port.
///
/// The relay uses an in-memory SQLite database and a fresh OPAQUE setup key, so
/// every test starts clean.
pub struct Relay {
    base: String,
    client: Client,
    // Keep the task alive for the duration of the test.
    _handle: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// Spawns a relay on a random OS port and returns when it is ready.
    pub async fn start() -> Self {
        use std::net::SocketAddr;

        // Bind first to get the actual port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("addr");

        let handle = tokio::spawn(async move {
            // Build an in-memory relay.
            let store = studge_relay::test_helpers::in_memory_store().await;
            let setup = opaque::ServerSetupKey::generate().expect("setup");
            let app = studge_relay::test_helpers::build_app(addr, store, setup);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve");
        });

        // Give the relay a moment to start.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        Self {
            base: format!("http://{addr}"),
            client: Client::builder().no_proxy().build().expect("client"),
            _handle: handle,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

// ── account builder ───────────────────────────────────────────────────────────

/// One account with freshly generated keys and a known auth secret.
pub struct TestAccount {
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    identity: signing::SigningKeyPair,
    device: signing::SigningKeyPair,
    auth_secret: [u8; 32],
}

impl Default for TestAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAccount {
    pub fn new() -> Self {
        let account_id = random::array::<16>().expect("account_id");
        let device_id = random::array::<16>().expect("device_id");
        let identity = signing::SigningKeyPair::generate().expect("identity");
        let device = signing::SigningKeyPair::generate().expect("device");
        let auth_secret: [u8; 32] = random::array().expect("auth_secret");
        Self {
            account_id,
            device_id,
            identity,
            device,
            auth_secret,
        }
    }

    /// Full OPAQUE register; panics on errors.
    pub async fn register(&self, relay: &Relay) {
        let status = self.register_raw(relay).await;
        assert!(
            status == 201 || status == 409,
            "register: unexpected {status}"
        );
    }

    /// Returns the HTTP status from /v1/register/finish.
    pub async fn register_raw(&self, relay: &Relay) -> u16 {
        // --- register/start ---
        let (req, client_state) =
            opaque::client_registration_start(&self.auth_secret).expect("reg start");
        let resp: Value = relay
            .client()
            .post(relay.url("/v1/register/start"))
            .json(&json!({
                "account_id": hex_id(&self.account_id),
                "registration_request": b64(&req),
            }))
            .send()
            .await
            .expect("register/start req")
            .json()
            .await
            .expect("register/start json");
        let server_response = b64d(
            resp["registration_response"]
                .as_str()
                .expect("registration_response field"),
        );
        let upload =
            opaque::client_registration_finish(client_state, &self.auth_secret, &server_response)
                .expect("reg finish client");

        // --- register/finish ---
        let now = signing::Timestamp::now().expect("now");
        let cert = signing::DeviceCertificate::create(
            &self.identity,
            self.account_id,
            self.device_id,
            self.device.public_bytes(),
            now,
        )
        .expect("cert");

        let identity_pub = self.identity.public_bytes();
        let device_pub = self.device.public_bytes();

        relay
            .client()
            .post(relay.url("/v1/register/finish"))
            .json(&json!({
                "account_id": hex_id(&self.account_id),
                "registration_upload": b64(&upload),
                "account_record": {
                    "account_id": hex_id(&self.account_id),
                    "account_salt": "bb".repeat(16),
                    "kdf": { "version": 1, "m": 65536, "t": 3, "p": 1 },
                    "ak_envelope": "cc".repeat(32),
                    "bundle_envelope": "dd".repeat(64),
                    "identity_keys": {
                        "ed25519": hex(&identity_pub),
                        "x25519": "ff".repeat(32),
                        "mlkem768": "11".repeat(1184),
                    },
                    "version": 1,
                },
                "first_device": {
                    "device_id": hex_id(&self.device_id),
                    "device_pubkey": hex(&device_pub),
                    "certificate": b64(&cert.to_cbor().expect("cert cbor")),
                },
            }))
            .send()
            .await
            .expect("register/finish req")
            .status()
            .as_u16()
    }

    /// Full OPAQUE login; returns the session token.
    pub async fn login(&self, relay: &Relay) -> String {
        self.login_secret(relay, &self.auth_secret)
            .await
            .expect("login ok")
    }

    /// Login with an arbitrary auth secret; returns the token or None on 401.
    pub async fn login_secret(&self, relay: &Relay, auth_secret: &[u8]) -> Option<String> {
        let (credential_request, client_state) =
            opaque::client_login_start(auth_secret).expect("login start");
        let resp: Value = relay
            .client()
            .post(relay.url("/v1/login/start"))
            .json(&json!({
                "account_id": hex_id(&self.account_id),
                "device_id": hex_id(&self.device_id),
                "credential_request": b64(&credential_request),
            }))
            .send()
            .await
            .expect("login/start req")
            .json()
            .await
            .expect("login/start json");
        let credential_response = b64d(
            resp["credential_response"]
                .as_str()
                .expect("credential_response field"),
        );
        // Wrong auth_secret fails at the client's OPAQUE finish step.
        let finalization =
            match opaque::client_login_finish(client_state, auth_secret, &credential_response) {
                Ok(f) => f,
                Err(_) => return None,
            };
        let finish_resp = relay
            .client()
            .post(relay.url("/v1/login/finish"))
            .json(&json!({
                "account_id": hex_id(&self.account_id),
                "device_id": hex_id(&self.device_id),
                "credential_finalization": b64(&finalization),
            }))
            .send()
            .await
            .expect("login/finish req");
        if finish_resp.status() == 200 {
            let body: Value = finish_resp.json().await.expect("login/finish json");
            Some(body["token"].as_str().expect("token field").to_string())
        } else {
            None
        }
    }
}

// ── op / head factories ──────────────────────────────────────────────────────

/// Builds a CBOR array of `count` valid, signed stored ops.
pub fn make_ops(vault_id: &[u8; 16], count: usize) -> Vec<u8> {
    let op_ids: Vec<[u8; 16]> = (0..count)
        .map(|_| random::array().expect("op_id"))
        .collect();
    make_ops_with_op_ids(vault_id, &op_ids)
}

/// Builds a CBOR array of valid, signed stored ops with caller-chosen op ids.
///
/// Naming the op ids lets a test replay one specific `op_id` (R-0601 squatting).
pub fn make_ops_with_op_ids(vault_id: &[u8; 16], op_ids: &[[u8; 16]]) -> Vec<u8> {
    use ciborium::value::Value;
    use studge_core::cbor::bytes as cbor_bytes;
    use studge_core::crypto::keys::VaultKey;

    let vk = VaultKey::from_bytes([0xEE; 32]);
    let device = signing::SigningKeyPair::generate().expect("device");
    let device_id: [u8; 16] = random::array().expect("device_id");
    let now = signing::Timestamp::now().expect("now");
    let mut items = Vec::with_capacity(op_ids.len());
    let mut parent: Option<[u8; 32]> = None;

    for (index, op_id) in op_ids.iter().enumerate() {
        let item_id: [u8; 16] = random::array().expect("item_id");
        let parents: Vec<[u8; 32]> = parent.into_iter().collect();
        let envelope = Op::seal_payload(&vk, vault_id, &item_id, OpKind::Create, b"test payload")
            .expect("seal");
        let op = Op::new(
            *vault_id,
            *op_id,
            parents,
            index as u64 + 1,
            device_id,
            now.clone(),
            OpKind::Create,
            Some(item_id),
            envelope,
        )
        .expect("op");
        let stored = op.sign(&device).expect("sign");
        parent = Some(stored.hash().expect("hash"));
        items.push(cbor_bytes(&stored.to_cbor().expect("cbor")));
    }

    // parse_ops expects a raw CBOR array, not a map.
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut buf).expect("cbor array");
    buf
}

/// Builds a signed VaultHead and returns (cbor_bytes, head_hash_hex).
pub fn make_head(vault_id: &[u8; 16], lamport_max: u64) -> (Vec<u8>, String) {
    use studge_core::oplog::head::VaultHead;

    let device = signing::SigningKeyPair::generate().expect("device");
    let device_id: [u8; 16] = random::array().expect("device_id");
    let now = signing::Timestamp::now().expect("now");
    let head = VaultHead::create(
        &device,
        *vault_id,
        device_id,
        vec![[0u8; 32]],
        lamport_max,
        lamport_max,
        now,
    )
    .expect("head");
    let hash = hex(&head.hash().expect("hash"));
    let bytes = head.to_cbor().expect("cbor");
    (bytes, hash)
}

// ── encoding helpers ──────────────────────────────────────────────────────────

pub fn random_id() -> [u8; 16] {
    random::array().expect("random id")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_id(id: &[u8; 16]) -> String {
    hex(id)
}

pub fn b64(bytes: &[u8]) -> String {
    studge_core::codec::base64_encode(bytes)
}

pub fn b64d(s: &str) -> Vec<u8> {
    studge_core::codec::base64_decode(s).expect("b64d")
}
