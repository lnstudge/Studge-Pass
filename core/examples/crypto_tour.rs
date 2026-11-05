//! A guided tour of the Studge Pass v1 crypto primitives.
//!
//! **DEMO ONLY.** Every value here is fake, fixed, and safe to print or paste.
//! Nothing is generated from a real password and nothing touches the network.
//!
//! Run it with:
//!
//! ```text
//! .\x.ps1 "cargo run -p studge-core --example crypto_tour"
//! ```

use std::error::Error;
use std::time::Instant;

use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey};
use studge_core::crypto::hpke::{self, HpkeRecipient};
use studge_core::crypto::kdf::{derive_muk, KdfParams};
use studge_core::crypto::keys::{
    item_field_key, unwrap_account_key, unwrap_vault_key, wrap_account_key, wrap_vault_key,
    AccountKey, ItemKey, VaultKey,
};
use studge_core::crypto::secret_key::SecretKey;
use studge_core::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};

const ACCOUNT: [u8; 16] = [0xA1; 16];
const VAULT: [u8; 16] = [0xB2; 16];
const ITEM: [u8; 16] = [0xC3; 16];

fn main() -> Result<(), Box<dyn Error>> {
    println!("Studge Pass crypto tour - DEMO ONLY, fake data");
    println!("=============================================\n");

    secret_key_demo()?;
    kdf_demo()?;
    wrapping_demo()?;
    aead_demo()?;
    hpke_demo()?;
    signing_demo()?;

    println!("\nDone. Everything above is fake; rerun any time with:");
    println!("  .\\x.ps1 \"cargo run -p studge-core --example crypto_tour\"");
    Ok(())
}

fn heading(step: u8, title: &str) {
    println!("\n{step}. {title}");
    println!("{}", "-".repeat(title.len() + 3));
}

/// First eight bytes of a value, so output stays short.
fn short(bytes: &[u8]) -> String {
    let head: String = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{head}... ({} bytes)", bytes.len())
}

fn secret_key_demo() -> Result<(), Box<dyn Error>> {
    heading(1, "The Secret Key in the SP1 format");
    let secret = SecretKey::from_bytes([0x42; 16]);
    let printed = secret.encode();
    println!("  printed : {printed}");
    println!("            128 bits of key, then one BLAKE3 check character");
    println!("  never sent to the relay, only shown once and in the recovery kit");

    // Break one character to show what the checksum is for.
    let mut chars: Vec<char> = printed.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let broken: String = chars.into_iter().collect();
    match SecretKey::decode(&broken) {
        Ok(_) => println!("  PROBLEM: a broken checksum was accepted"),
        Err(err) => println!("  one typed character changed -> rejected: {err}"),
    }
    Ok(())
}

fn kdf_demo() -> Result<(), Box<dyn Error>> {
    heading(2, "Stretching the master password (Argon2id)");
    let salt = [0x5A; 16];
    let secret = SecretKey::from_bytes([0x42; 16]);
    println!("  parameters: Argon2id, 64 MiB, t=3, p=1, salt = 16 bytes");
    let started = Instant::now();
    let muk = derive_muk(
        "correct horse battery staple",
        &salt,
        &secret,
        KdfParams::V1,
    )?;
    let elapsed = started.elapsed();
    println!("  derived in {elapsed:?} (debug build; a release build is faster)");
    println!("  MUK      : {}", short(muk.as_bytes()));
    println!("  the MUK depends on the password AND the Secret Key");
    Ok(())
}

fn wrapping_demo() -> Result<(), Box<dyn Error>> {
    heading(3, "Wrapping the key hierarchy");
    let muk = derive_muk(
        "correct horse battery staple",
        &[0x5A; 16],
        &SecretKey::from_bytes([0x42; 16]),
        KdfParams::V1,
    )?;
    let ak = AccountKey::from_bytes([0x11; 32]);
    let vk = VaultKey::from_bytes([0x22; 32]);

    let ak_envelope = wrap_account_key(&muk, &ACCOUNT, &ak)?;
    let vk_envelope = wrap_vault_key(&ak, &VAULT, &vk)?;
    println!(
        "  AK envelope: {} (ciphertext + tag)",
        ak_envelope.ciphertext().len()
    );
    println!(
        "  VK envelope: {} bytes, bound to vault {}",
        vk_envelope.ciphertext().len(),
        short(&VAULT)
    );

    let unwrapped = unwrap_account_key(&muk, &ACCOUNT, &ak_envelope)?;
    println!(
        "  unwrap AK  : ok, matches = {}",
        unwrapped.as_bytes() == ak.as_bytes()
    );
    match unwrap_vault_key(&ak, &[0xEE; 16], &vk_envelope) {
        Ok(_) => println!("  PROBLEM: a vault key opened under the wrong vault id"),
        Err(err) => println!("  wrong vault id -> rejected: {err}"),
    }
    Ok(())
}

fn aead_demo() -> Result<(), Box<dyn Error>> {
    heading(4, "Encrypting one item field");
    let ik = ItemKey::from_bytes([0x33; 32]);
    let field_key = item_field_key(&ik, &ITEM)?;
    let aad = Aad::builder(RecordType::ItemField)
        .vault(VAULT)
        .item(ITEM)
        .field("password")
        .build()?;
    println!(
        "  AAD      : {} bytes of canonical CBOR",
        aad.as_bytes().len()
    );
    println!("             binds suite, vault, item, record type, field name");

    let plaintext = b"DEMO ONLY: correct horse battery staple";
    let envelope = aead::seal(&field_key, &aad, plaintext)?;
    println!("  nonce    : {} random bytes", envelope.nonce().len());
    println!("  ciphertext + tag: {} bytes", envelope.ciphertext().len());

    let opened = aead::open(&field_key, &aad, &envelope)?;
    println!(
        "  decrypt  : ok, plaintext matches = {}",
        opened.as_slice() == plaintext
    );

    // 5. Flip one ciphertext byte.
    heading(5, "Attack 1: flip one byte of the ciphertext");
    let tampered = flip_ciphertext_byte(&envelope)?;
    match aead::open(&field_key, &aad, &tampered) {
        Ok(_) => println!("  PROBLEM: a tampered envelope opened"),
        Err(err) => println!("  rejected: {err}"),
    }

    // 6. Swap the AAD field name.
    heading(6, "Attack 2: open the password as the username field");
    let other_aad = Aad::builder(RecordType::ItemField)
        .vault(VAULT)
        .item(ITEM)
        .field("username")
        .build()?;
    match aead::open(&field_key, &other_aad, &envelope) {
        Ok(_) => println!("  PROBLEM: a swapped field name opened"),
        Err(err) => println!("  rejected: {err}"),
    }

    // 7. Wrong key.
    heading(7, "Attack 3: use the wrong key");
    let wrong_key = AeadKey::from_bytes([0x99; 32]);
    match aead::open(&wrong_key, &aad, &envelope) {
        Ok(_) => println!("  PROBLEM: the wrong key opened the envelope"),
        Err(err) => println!("  rejected: {err}"),
    }
    Ok(())
}

fn hpke_demo() -> Result<(), Box<dyn Error>> {
    heading(8, "Sealing a vault key to a member (HPKE)");
    let recipient = HpkeRecipient::from_bytes([0x5B; 32]);
    let sealed = hpke::seal_to(
        &recipient.public_bytes(),
        b"studge/v1/vk-share demo",
        b"demo aad",
        b"DEMO ONLY vault key",
    )?;
    println!(
        "  sealed   : enc {} bytes, ct {} bytes",
        sealed.enc().len(),
        sealed.ciphertext().len()
    );
    let opened = hpke::open_from(&recipient, b"studge/v1/vk-share demo", b"demo aad", &sealed)?;
    println!("  opened   : {}", String::from_utf8_lossy(&opened));
    let other = HpkeRecipient::from_bytes([0x5C; 32]);
    match hpke::open_from(&other, b"studge/v1/vk-share demo", b"demo aad", &sealed) {
        Ok(_) => println!("  PROBLEM: another recipient opened the seal"),
        Err(err) => println!("  wrong recipient -> rejected: {err}"),
    }
    Ok(())
}

fn signing_demo() -> Result<(), Box<dyn Error>> {
    heading(9, "Certifying a device (Ed25519)");
    let identity = SigningKeyPair::from_seed([0x24; 32]);
    let device = SigningKeyPair::from_seed([0x25; 32]);
    let created_at = Timestamp::parse("2026-11-05T10:00:00Z")?;
    let cert = DeviceCertificate::create(
        &identity,
        ACCOUNT,
        [0xD4; 16],
        device.public_bytes(),
        created_at.clone(),
    )?;
    println!("  certificate signed by the account identity key");
    cert.verify(&identity.public_bytes(), &ACCOUNT, &created_at, None)?;
    println!("  verify   : ok");
    let impostor = SigningKeyPair::from_seed([0x99; 32]);
    match cert.verify(&impostor.public_bytes(), &ACCOUNT, &created_at, None) {
        Ok(()) => println!("  PROBLEM: the wrong identity key verified"),
        Err(err) => println!("  wrong identity key -> rejected: {err}"),
    }
    Ok(())
}

/// Flips one byte inside the ciphertext and re-parses the envelope, the way a
/// malicious relay would.
fn flip_ciphertext_byte(envelope: &aead::Envelope) -> Result<aead::Envelope, Box<dyn Error>> {
    use ciborium::value::Value;
    use studge_core::crypto::aad::{canonical_bytes, parse_strict};

    let value = parse_strict(&envelope.to_cbor()?)?;
    let Value::Map(entries) = value else {
        return Err("envelope is not a map".into());
    };
    let mut out = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        match (key, value) {
            (Value::Text(name), Value::Bytes(mut bytes)) if name == "ct" => {
                if let Some(last) = bytes.last_mut() {
                    *last ^= 0x01;
                }
                out.push((Value::Text(name), Value::Bytes(bytes)));
            }
            (key, value) => out.push((key, value)),
        }
    }
    let bytes = canonical_bytes(&Value::Map(out))?;
    Ok(aead::Envelope::from_cbor(&bytes)?)
}
