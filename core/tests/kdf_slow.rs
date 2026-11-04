//! The one slow test: Argon2id at the real §4.3 parameters.
//!
//! Everyone runs the fast unit tests with tiny parameters; this one proves the
//! production parameters produce the published MUK vector.
//!
//! Run explicitly: `cargo test -p studge-core --test kdf_slow -- --ignored`

use studge_core::crypto::kdf::{derive_muk, KdfParams};
use studge_core::crypto::secret_key::SecretKey;

#[test]
#[ignore = "Argon2id at 64 MiB, t=3, p=1 takes a moment; run explicitly"]
fn real_parameters_match_the_published_vector() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("vectors/v1.json")).expect("vectors json");
    let muk = &vectors["muk"];
    let password = muk["password"].as_str().expect("password");
    let salt = decode_hex(muk["salt_hex"].as_str().expect("salt"));
    let secret = decode_hex(muk["secret_key_hex"].as_str().expect("secret key"));
    let expected = muk["muk_hex"].as_str().expect("muk hex");

    let mut salt_bytes = [0u8; 16];
    salt_bytes.copy_from_slice(&salt);
    let mut secret_bytes = [0u8; 16];
    secret_bytes.copy_from_slice(&secret);

    let derived = derive_muk(
        password,
        &salt_bytes,
        &SecretKey::from_bytes(secret_bytes),
        KdfParams::V1,
    )
    .expect("derivation with real parameters");

    assert_eq!(encode_hex(derived.as_bytes()), expected);
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
