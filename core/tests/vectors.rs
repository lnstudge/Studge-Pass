//! Known-answer vectors (SPEC §5, `core/tests/vectors/v1.json`).
//!
//! The file is checked in so another language can verify the same bytes.
//!
//! Two kinds of entry live here:
//!
//! - **Deterministic** (`secret_key`, `aad_item_field`, `aead`, `muk`,
//!   `signing`): fixed inputs produce fixed bytes, so the tests compare them
//!   byte for byte. `aead` uses a fixed nonce through the `test-vectors`
//!   feature; `muk` uses the real Argon2id parameters.
//! - **`kind: "decrypt-only"`** (`hpke`, `ak_wrap`): these depend on freshly
//!   generated randomness (an ephemeral HPKE key, a random nonce), so they
//!   cannot be reproduced. The tests check that the stored bytes still decrypt
//!   and authenticate; they never compare ciphertext.
//!
//! The ignored `generate_vectors` test writes the file only when
//! `STUDGE_WRITE_VECTORS=1`; otherwise it recomputes the deterministic entries
//! and fails if any of them differs from the file.

#[cfg(feature = "test-vectors")]
use serde_json::json;
use serde_json::Value;
use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey, Envelope};
use studge_core::crypto::hpke::{self, HpkeRecipient, SealedKey};
use studge_core::crypto::keys::{account_key_wrapping_key, AccountKey, MasterUnlockKey};
use studge_core::crypto::secret_key::SecretKey;
use studge_core::crypto::signing::{
    DeviceCertificate, DeviceRevocation, SigningKeyPair, Timestamp,
};

const VAULT: [u8; 16] = [0x10; 16];
const ITEM: [u8; 16] = [0x20; 16];
const ACCOUNT: [u8; 16] = [0x30; 16];
const DEVICE: [u8; 16] = [0x31; 16];

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("v1.json")
}

fn load() -> Value {
    let text = std::fs::read_to_string(vectors_path()).expect("read v1.json");
    serde_json::from_str(&text).expect("parse v1.json")
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn array16(text: &str) -> [u8; 16] {
    let bytes = unhex(text);
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    out
}

fn array32(text: &str) -> [u8; 32] {
    let bytes = unhex(text);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn aad() -> Aad {
    Aad::builder(RecordType::ItemField)
        .vault(VAULT)
        .item(ITEM)
        .field("password")
        .build()
        .expect("valid aad")
}

#[test]
fn secret_key_vector_matches() {
    let v = load();
    let bytes = array16(v["secret_key"]["key_hex"].as_str().expect("key hex"));
    let key = SecretKey::from_bytes(bytes);
    assert_eq!(
        key.encode(),
        v["secret_key"]["printed"].as_str().expect("printed")
    );
    let decoded =
        SecretKey::decode(v["secret_key"]["printed"].as_str().expect("printed")).expect("decode");
    assert_eq!(decoded.as_bytes(), &bytes);
}

#[test]
fn aad_vector_matches() {
    let v = load();
    assert_eq!(
        hex(aad().as_bytes()),
        v["aad_item_field"]["cbor_hex"].as_str().expect("cbor hex")
    );
}

#[test]
fn aead_vector_opens_and_matches_its_context() {
    let v = load();
    let aead = &v["aead"];
    let key = AeadKey::from_bytes(array32(aead["key_hex"].as_str().expect("key")));
    let envelope_bytes = unhex(aead["envelope_cbor_hex"].as_str().expect("envelope"));
    let envelope = Envelope::from_cbor(&envelope_bytes).expect("parse envelope");
    assert_eq!(
        hex(envelope.nonce()),
        aead["nonce_hex"].as_str().expect("nonce"),
        "nonce must match the vector"
    );
    let plaintext = aead::open(&key, &aad(), &envelope).expect("open vector");
    assert_eq!(
        std::str::from_utf8(&plaintext).expect("utf8"),
        aead["plaintext_utf8"].as_str().expect("plaintext")
    );
    assert_eq!(
        hex(aad().as_bytes()),
        aead["aad_cbor_hex"].as_str().expect("aad"),
        "the vector's AAD must be built from the same context"
    );
}

#[cfg(feature = "test-vectors")]
#[test]
fn aead_vector_is_byte_exact() {
    let v = load();
    let aead = &v["aead"];
    let key = AeadKey::from_bytes(array32(aead["key_hex"].as_str().expect("key")));
    let nonce_bytes = unhex(aead["nonce_hex"].as_str().expect("nonce"));
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_bytes);
    let plaintext = aead["plaintext_utf8"]
        .as_str()
        .expect("plaintext")
        .as_bytes();
    let envelope = aead::seal_with_nonce(&key, &aad(), nonce, plaintext).expect("seal");
    assert_eq!(
        hex(&envelope.to_cbor().expect("encode")),
        aead["envelope_cbor_hex"].as_str().expect("envelope")
    );
}

#[test]
fn hpke_vector_opens() {
    let v = load();
    let hpke = &v["hpke"];
    let recipient = HpkeRecipient::from_bytes(array32(
        hpke["recipient_secret_hex"].as_str().expect("secret"),
    ));
    assert_eq!(
        hex(&recipient.public_bytes()),
        hpke["recipient_public_hex"].as_str().expect("public"),
        "the stored public key must derive from the stored secret"
    );
    let sealed_bytes = unhex(hpke["sealed_cbor_hex"].as_str().expect("sealed"));
    let sealed = SealedKey::from_cbor(&sealed_bytes).expect("parse sealed");
    let info = hpke["info_utf8"].as_str().expect("info").as_bytes();
    let aad = hpke["aad_utf8"].as_str().expect("aad").as_bytes();
    let plaintext = hpke::open_from(&recipient, info, aad, &sealed).expect("open");
    assert_eq!(
        std::str::from_utf8(&plaintext).expect("utf8"),
        hpke["plaintext_utf8"].as_str().expect("plaintext")
    );
}

#[test]
fn signing_vector_verifies() {
    let v = load();
    let signing = &v["signing"];
    let seed = array32(signing["seed_hex"].as_str().expect("seed"));
    let pair = SigningKeyPair::from_seed(seed);
    assert_eq!(
        hex(&pair.public_bytes()),
        signing["public_hex"].as_str().expect("public")
    );

    let device_seed = array32(signing["device_seed_hex"].as_str().expect("device seed"));
    let device_pair = SigningKeyPair::from_seed(device_seed);
    let created_at =
        Timestamp::parse(signing["created_at"].as_str().expect("created_at")).expect("timestamp");
    let cert = DeviceCertificate::create(
        &pair,
        ACCOUNT,
        DEVICE,
        device_pair.public_bytes(),
        created_at,
    )
    .expect("cert");
    let body = cert.body_bytes().expect("body");
    assert_eq!(hex(&body), signing["cert_body_hex"].as_str().expect("body"));
    // The signature covers BLAKE3(body), not the body itself (D-0207).
    assert_eq!(
        hex(blake3::hash(&body).as_bytes()),
        signing["cert_digest_hex"].as_str().expect("digest")
    );
    assert_eq!(
        hex(cert.signature_bytes()),
        signing["cert_sig_hex"].as_str().expect("signature")
    );
    cert.verify(
        &pair.public_bytes(),
        &ACCOUNT,
        &Timestamp::parse("2026-11-05T10:00:00Z").expect("now"),
        None,
    )
    .expect("verify vector certificate");

    // The revocation vector follows the same digest rule.
    let revoked_at = Timestamp::parse(signing["revoked_at"].as_str().expect("revoked_at"))
        .expect("revocation timestamp");
    let reason = signing["revocation_reason"].as_str().expect("reason");
    let revocation =
        DeviceRevocation::create(&pair, ACCOUNT, DEVICE, revoked_at, reason).expect("revocation");
    let revocation_body = revocation.body_bytes().expect("revocation body");
    assert_eq!(
        hex(&revocation_body),
        signing["revocation_body_hex"]
            .as_str()
            .expect("revocation body")
    );
    assert_eq!(
        hex(blake3::hash(&revocation_body).as_bytes()),
        signing["revocation_digest_hex"]
            .as_str()
            .expect("revocation digest")
    );
    assert_eq!(
        hex(revocation.signature_bytes()),
        signing["revocation_sig_hex"]
            .as_str()
            .expect("revocation sig")
    );
    revocation
        .verify(&pair.public_bytes(), &ACCOUNT)
        .expect("verify vector revocation");
}

#[test]
fn wrapped_account_key_vector_round_trips() {
    let v = load();
    let wrapping = &v["ak_wrap"];
    let muk = MasterUnlockKey::from_bytes(array32(wrapping["muk_hex"].as_str().expect("muk")));
    let ak = AccountKey::from_bytes(array32(wrapping["ak_hex"].as_str().expect("ak")));
    let envelope = Envelope::from_cbor(&unhex(
        wrapping["envelope_cbor_hex"].as_str().expect("envelope"),
    ))
    .expect("parse");
    // Rebuild the wrapping key and open.
    let key = account_key_wrapping_key(&muk).expect("wrapping key");
    let aad_value = Aad::builder(RecordType::Ak)
        .account(ACCOUNT)
        .build()
        .expect("aad");
    let plaintext = aead::open(&key, &aad_value, &envelope).expect("open");
    assert_eq!(plaintext.as_slice(), ak.as_bytes());
}

#[cfg(feature = "test-vectors")]
#[test]
#[ignore = "writes core/tests/vectors/v1.json; run with --features test-vectors -- --ignored"]
fn generate_vectors() {
    use studge_core::crypto::kdf::{derive_muk, KdfParams};
    use studge_core::crypto::keys::wrap_account_key;

    // Secret key: bytes 0x00..0x0f.
    let mut key_bytes = [0u8; 16];
    for (i, slot) in key_bytes.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let secret_key = SecretKey::from_bytes(key_bytes);

    // AAD.
    let aad = aad();

    // AEAD with a fixed nonce.
    let aead_key = AeadKey::from_bytes([0x33u8; 32]);
    let nonce = [0x44u8; 24];
    let plaintext = "DEMO ONLY: correct horse battery staple";
    let envelope =
        aead::seal_with_nonce(&aead_key, &aad, nonce, plaintext.as_bytes()).expect("seal");

    // MUK with the real parameters (slow, but this runs once).
    let salt = [0x5Au8; 16];
    let muk_secret = SecretKey::from_bytes([0x42u8; 16]);
    let muk = derive_muk(
        "correct horse battery staple",
        &salt,
        &muk_secret,
        KdfParams::V1,
    )
    .expect("muk");

    // HPKE to a fixed recipient.
    let recipient = HpkeRecipient::from_bytes([0x5Bu8; 32]);
    let sealed = hpke::seal_to(
        &recipient.public_bytes(),
        b"studge/v1/vk-share demo",
        b"demo aad",
        b"DEMO ONLY vault key",
    )
    .expect("seal");

    // A certificate signed by a fixed identity key.
    let identity = SigningKeyPair::from_seed([0x24u8; 32]);
    let device = SigningKeyPair::from_seed([0x25u8; 32]);
    let created_at = Timestamp::parse("2026-11-05T10:00:00Z").expect("timestamp");
    let cert = DeviceCertificate::create(
        &identity,
        ACCOUNT,
        DEVICE,
        device.public_bytes(),
        created_at.clone(),
    )
    .expect("cert");
    let cert_body = cert.body_bytes().expect("cert body");

    // A revocation signed by the same fixed identity key.
    let revoked_at = Timestamp::parse("2026-11-05T12:00:00Z").expect("timestamp");
    let revocation = DeviceRevocation::create(&identity, ACCOUNT, DEVICE, revoked_at, "lost phone")
        .expect("revocation");
    let revocation_body = revocation.body_bytes().expect("revocation body");

    // A wrapped account key with fixed inputs.
    let ak = AccountKey::from_bytes([0x66u8; 32]);
    let ak_muk = MasterUnlockKey::from_bytes([0x77u8; 32]);
    let ak_envelope = wrap_account_key(&ak_muk, &ACCOUNT, &ak).expect("wrap ak");

    let document = json!({
        "suite": "v1",
        "note": "DEMO DATA ONLY — generated by studge-core; no real secrets.",
        "generated_by": "cargo test -p studge-core --features test-vectors --test vectors -- --ignored generate",
        "secret_key": {
            "key_hex": hex(&key_bytes),
            "printed": secret_key.encode(),
        },
        "aad_item_field": {
            "vault_hex": hex(&VAULT),
            "item_hex": hex(&ITEM),
            "field": "password",
            "cbor_hex": hex(aad.as_bytes()),
        },
        "aead": {
            "key_hex": hex(aead_key.as_bytes()),
            "nonce_hex": hex(&nonce),
            "aad_cbor_hex": hex(aad.as_bytes()),
            "plaintext_utf8": plaintext,
            "envelope_cbor_hex": hex(&envelope.to_cbor().expect("encode")),
        },
        "muk": {
            "password": "correct horse battery staple",
            "salt_hex": hex(&salt),
            "secret_key_hex": hex(muk_secret.as_bytes()),
            "version": KdfParams::V1.version,
            "m": KdfParams::V1.m_kib,
            "t": KdfParams::V1.t,
            "p": KdfParams::V1.p,
            "muk_hex": hex(muk.as_bytes()),
        },
        "hpke": {
            "kind": "decrypt-only",
            "recipient_secret_hex": hex(&[0x5Bu8; 32]),
            "recipient_public_hex": hex(&recipient.public_bytes()),
            "info_utf8": "studge/v1/vk-share demo",
            "aad_utf8": "demo aad",
            "plaintext_utf8": "DEMO ONLY vault key",
            "sealed_cbor_hex": hex(&sealed.to_cbor().expect("encode")),
        },
        "signing": {
            "seed_hex": hex(&identity.seed_bytes()),
            "public_hex": hex(&identity.public_bytes()),
            "device_seed_hex": hex(&device.seed_bytes()),
            "device_public_hex": hex(&device.public_bytes()),
            "account_hex": hex(&ACCOUNT),
            "device_hex": hex(&DEVICE),
            "created_at": created_at.as_str(),
            "cert_body_hex": hex(&cert_body),
            "cert_digest_hex": hex(blake3::hash(&cert_body).as_bytes()),
            "cert_sig_hex": hex(cert.signature_bytes()),
            "revoked_at": "2026-11-05T12:00:00Z",
            "revocation_reason": "lost phone",
            "revocation_body_hex": hex(&revocation_body),
            "revocation_digest_hex": hex(blake3::hash(&revocation_body).as_bytes()),
            "revocation_sig_hex": hex(revocation.signature_bytes()),
        },
        "ak_wrap": {
            "kind": "decrypt-only",
            "muk_hex": hex(ak_muk.as_bytes()),
            "ak_hex": hex(ak.as_bytes()),
            "envelope_cbor_hex": hex(&ak_envelope.to_cbor().expect("encode")),
        }
    });

    let text = serde_json::to_string_pretty(&document).expect("serialise");
    let path = vectors_path();

    if std::env::var("STUDGE_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, format!("{text}\n")).expect("write v1.json");
        println!("wrote {}", path.display());
        return;
    }

    // Verification mode: every deterministic entry must match the file. The
    // decrypt-only entries (hpke, ak_wrap) use fresh randomness and are checked
    // by the decryption tests instead.
    let existing: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read existing v1.json"))
            .expect("parse existing v1.json");
    let mut mismatches: Vec<&str> = Vec::new();
    for section in ["secret_key", "aad_item_field", "aead", "muk", "signing"] {
        if existing.get(section) != document.get(section) {
            mismatches.push(section);
        }
    }
    assert!(
        mismatches.is_empty(),
        "v1.json differs in {mismatches:?}; set STUDGE_WRITE_VECTORS=1 to regenerate"
    );
    println!("v1.json matches the generator output");
}
