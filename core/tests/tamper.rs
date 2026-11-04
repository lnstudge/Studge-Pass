//! Tamper matrix (SPEC §5.3, §5.8): flipping any authenticated byte, changing
//! any AAD field, switching the suite or using the wrong key must fail.
//!
//! Envelopes are tampered through their CBOR form, i.e. through the same path a
//! malicious relay would use.

use ciborium::value::Value;
use studge_core::crypto::aad::{canonical_bytes, parse_strict, Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey, Envelope};
use studge_core::crypto::CryptoError;

const VAULT: [u8; 16] = [0x10; 16];
const ITEM: [u8; 16] = [0x20; 16];

fn key(byte: u8) -> AeadKey {
    AeadKey::from_bytes([byte; 32])
}

fn aad(field: &str) -> Aad {
    Aad::builder(RecordType::ItemField)
        .vault(VAULT)
        .item(ITEM)
        .field(field)
        .build()
        .expect("valid aad")
}

fn sealed() -> Envelope {
    aead::seal(&key(0x33), &aad("password"), b"correct horse battery staple").expect("seal")
}

/// Rewrites one of the envelope's byte strings and re-parses it.
fn retamper(envelope: &Envelope, field: &str, mutate: impl Fn(&mut Vec<u8>)) -> Envelope {
    let bytes = envelope.to_cbor().expect("encode");
    let value = parse_strict(&bytes).expect("canonical");
    let Value::Map(entries) = value else {
        panic!("envelope must be a map");
    };
    let entries: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| match (&k, field) {
            (Value::Text(name), f) if name == f => {
                let Value::Bytes(mut b) = v else {
                    panic!("field {f} must be bytes");
                };
                mutate(&mut b);
                (k, Value::Bytes(b))
            }
            _ => (k, v),
        })
        .collect();
    let value = Value::Map(entries);
    let tampered = canonical_bytes(&value).expect("encode");
    Envelope::from_cbor(&tampered).expect("parse")
}

#[test]
fn flipping_any_ciphertext_byte_fails() {
    let envelope = sealed();
    for index in 0..envelope.ciphertext().len() {
        let tampered = retamper(&envelope, "ct", |bytes| bytes[index] ^= 0x01);
        assert!(
            aead::open(&key(0x33), &aad("password"), &tampered).is_err(),
            "byte {index} of the ciphertext"
        );
    }
}

#[test]
fn flipping_any_tag_byte_fails() {
    let envelope = sealed();
    let ct_len = envelope.ciphertext().len();
    for offset in 1..=16 {
        let index = ct_len - offset;
        let tampered = retamper(&envelope, "ct", |bytes| bytes[index] ^= 0x80);
        assert!(
            aead::open(&key(0x33), &aad("password"), &tampered).is_err(),
            "tag byte {offset}"
        );
    }
}

#[test]
fn flipping_any_nonce_byte_fails() {
    let envelope = sealed();
    for index in 0..24 {
        let tampered = retamper(&envelope, "nonce", |bytes| bytes[index] ^= 0x01);
        assert!(
            aead::open(&key(0x33), &aad("password"), &tampered).is_err(),
            "nonce byte {index}"
        );
    }
}

#[test]
fn truncating_the_ciphertext_fails() {
    let envelope = sealed();
    let tampered = retamper(&envelope, "ct", |bytes| {
        bytes.pop();
    });
    assert!(aead::open(&key(0x33), &aad("password"), &tampered).is_err());
}

#[test]
fn a_shorter_than_tag_ciphertext_is_rejected_at_parse() {
    let envelope = sealed();
    let bytes = envelope.to_cbor().expect("encode");
    let value = parse_strict(&bytes).expect("canonical");
    let Value::Map(entries) = value else {
        panic!("map");
    };
    let entries: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| match &k {
            Value::Text(name) if name == "ct" => (k, Value::Bytes(vec![0u8; 8])),
            _ => (k, v),
        })
        .collect();
    let bytes = canonical_bytes(&Value::Map(entries)).expect("encode");
    assert_eq!(
        Envelope::from_cbor(&bytes).expect_err("short ct"),
        CryptoError::InvalidLength {
            expected: 16,
            actual: 8
        }
    );
}

#[test]
fn changing_any_aad_field_fails() {
    let envelope = sealed();
    let cases = [
        aad("username"), // field name
        Aad::builder(RecordType::ItemField)
            .vault(VAULT)
            .item([0x21; 16])
            .field("password")
            .build()
            .expect("aad"), // item id
        Aad::builder(RecordType::ItemField)
            .vault([0x11; 16])
            .item(ITEM)
            .field("password")
            .build()
            .expect("aad"), // vault id
        Aad::builder(RecordType::Ik)
            .vault(VAULT)
            .item(ITEM)
            .build()
            .expect("aad"), // record type
    ];
    for candidate in &cases {
        assert_eq!(
            aead::open(&key(0x33), candidate, &envelope).expect_err("aad mismatch"),
            CryptoError::DecryptionFailed
        );
    }
}

#[test]
fn swapping_two_fields_of_the_same_item_fails() {
    // Encrypt a password, then try to open it as the username field.
    let password = aead::seal(&key(0x33), &aad("password"), b"hunter2").expect("seal");
    assert!(aead::open(&key(0x33), &aad("username"), &password).is_err());
}

#[test]
fn wrong_key_fails() {
    let envelope = sealed();
    assert_eq!(
        aead::open(&key(0x34), &aad("password"), &envelope).expect_err("wrong key"),
        CryptoError::DecryptionFailed
    );
}

#[test]
fn unknown_suite_fails_at_parse() {
    let envelope = sealed();
    let bytes = envelope.to_cbor().expect("encode");
    let value = parse_strict(&bytes).expect("canonical");
    let Value::Map(entries) = value else {
        panic!("map");
    };
    let entries: Vec<(Value, Value)> = entries
        .into_iter()
        .map(|(k, v)| match &k {
            Value::Text(name) if name == "suite" => (k, Value::Text("v2".into())),
            _ => (k, v),
        })
        .collect();
    let bytes = canonical_bytes(&Value::Map(entries)).expect("encode");
    assert_eq!(
        Envelope::from_cbor(&bytes).expect_err("v2"),
        CryptoError::UnknownSuite
    );
}

#[test]
fn non_canonical_envelope_fails_at_parse() {
    let envelope = sealed();
    let bytes = envelope.to_cbor().expect("encode");
    let value: Value = ciborium::de::from_reader(&bytes[..]).expect("parse");
    // Encode the same map without canonicalising the key order.
    let mut raw = Vec::new();
    ciborium::ser::into_writer(&value, &mut raw).expect("encode");
    // The produced form is canonical here, so shuffle deliberately instead.
    let Value::Map(entries) = value else {
        panic!("map");
    };
    let mut reversed = entries;
    reversed.reverse();
    let mut raw = Vec::new();
    ciborium::ser::into_writer(&Value::Map(reversed), &mut raw).expect("encode");
    assert_eq!(
        Envelope::from_cbor(&raw).expect_err("order"),
        CryptoError::NonCanonicalCbor
    );
}

#[test]
fn wrapping_a_key_into_another_slot_fails() {
    // A vault key wrapped for vault A must not open under vault B or another AK.
    use studge_core::crypto::keys::{wrap_vault_key, unwrap_vault_key, AccountKey, VaultKey};
    let ak = AccountKey::from_bytes([0x44; 32]);
    let vk = VaultKey::from_bytes([0x55; 32]);
    let wrapped = wrap_vault_key(&ak, &VAULT, &vk).expect("wrap");
    assert!(unwrap_vault_key(&ak, &[0x99; 16], &wrapped).is_err());
    assert!(unwrap_vault_key(&AccountKey::from_bytes([0x45; 32]), &VAULT, &wrapped).is_err());
}
