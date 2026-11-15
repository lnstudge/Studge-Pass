use anyhow::{Context, Result};
use keyring_core::Entry;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey, Envelope};
use studge_core::crypto::random;

const SERVICE: &str = "studge-pass-cli";

#[allow(unreachable_code)]
fn ensure_store() -> Result<()> {
    #[cfg(test)]
    {
        use keyring_core::sample::Store;
        let store = Store::new_with_configuration(&std::collections::HashMap::new())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(all(not(test), target_os = "windows"))]
    {
        use windows_native_keyring_store::Store;
        let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    #[cfg(all(not(test), target_os = "macos"))]
    {
        use apple_native_keyring_store::keychain;
        let store = keychain::Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    #[cfg(all(not(test), target_os = "linux"))]
    {
        use linux_keyutils_keyring_store::Store;
        let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    Ok(())
}

fn validate_account_id(account_id: &str) -> Result<()> {
    if account_id.len() != 32 || !account_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("invalid account id"));
    }
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow::anyhow!("bad hex"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow::anyhow!("bad hex"))?);
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Store the Secret Key in the OS credential store (SPEC section 4.2).
pub fn store_secret_key(account_id: &str, sk: &str) -> Result<()> {
    validate_account_id(account_id)?;
    ensure_store()?;
    let entry =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    entry.set_password(sk).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn load_secret_key(account_id: &str) -> Result<Option<Zeroizing<String>>> {
    validate_account_id(account_id)?;
    ensure_store()?;
    let entry =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    match entry.get_password() {
        Ok(p) => Ok(Some(Zeroizing::new(p))),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    }
}

/// Create a session: random 32-byte session key in OS store + sealed AK file.
pub fn create_session(
    account_id: &str,
    account_key_bytes: [u8; 32],
    device_id: [u8; 16],
    expiry_minutes: u64,
    session_path: &PathBuf,
) -> Result<()> {
    validate_account_id(account_id)?;
    ensure_store()?;

    let aid_bytes = hex_decode(account_id)?;
    let mut aid = [0u8; 16];
    aid.copy_from_slice(&aid_bytes);

    let session_key_bytes: [u8; 32] = random::array().map_err(|e| anyhow::anyhow!("{e}"))?;
    let session_key = AeadKey::from_bytes(session_key_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = now + expiry_minutes * 60;

    // plaintext: 32 bytes AK + 8 bytes expiry (little-endian) + 16 bytes device_id
    let mut plaintext = Zeroizing::new(Vec::with_capacity(32 + 8 + 16));
    plaintext.extend_from_slice(&account_key_bytes);
    plaintext.extend_from_slice(&expires_at.to_le_bytes());
    plaintext.extend_from_slice(&device_id);

    let aad = Aad::builder(RecordType::Session)
        .account(aid)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let envelope =
        aead::seal(&session_key, &aad, &plaintext).map_err(|e| anyhow::anyhow!("{e}"))?;

    let bytes = envelope.to_cbor().map_err(|e| anyhow::anyhow!("{e}"))?;
    fs::write(session_path, bytes).context("write session file")?;

    let entry = Entry::new(SERVICE, &format!("{account_id}:session"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sk_str = hex_encode(&session_key_bytes);
    entry
        .set_password(&sk_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Load session: returns (AccountKey bytes, device_id) if valid and not expired.
#[allow(clippy::type_complexity)]
pub fn load_session(
    account_id: &str,
    expected_device_id: [u8; 16],
    session_path: &PathBuf,
) -> Result<Option<(Zeroizing<[u8; 32]>, [u8; 16])>> {
    validate_account_id(account_id)?;
    ensure_store()?;

    let aid_bytes = hex_decode(account_id)?;
    let mut aid = [0u8; 16];
    aid.copy_from_slice(&aid_bytes);

    let entry = Entry::new(SERVICE, &format!("{account_id}:session"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sk_str = match entry.get_password() {
        Ok(p) => p,
        Err(keyring_core::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("{e}")),
    };
    let sk_bytes = hex_decode(&sk_str)?;
    if sk_bytes.len() != 32 {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    let mut skb = [0u8; 32];
    skb.copy_from_slice(&sk_bytes);
    let session_key = AeadKey::from_bytes(skb);

    if !session_path.exists() {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    let file_bytes = fs::read(session_path).context("read session file")?;
    let envelope = match Envelope::from_cbor(&file_bytes) {
        Ok(e) => e,
        Err(_) => {
            delete_session(account_id, session_path)?;
            return Ok(None);
        }
    };

    let aad = Aad::builder(RecordType::Session)
        .account(aid)
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let plaintext = match aead::open(&session_key, &aad, &envelope) {
        Ok(p) => p,
        Err(_) => {
            delete_session(account_id, session_path)?;
            return Ok(None);
        }
    };
    if plaintext.len() != 32 + 8 + 16 {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    let mut ak = Zeroizing::new([0u8; 32]);
    ak.copy_from_slice(&plaintext[0..32]);
    let expires_at = u64::from_le_bytes(
        plaintext[32..40]
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad expiry"))?,
    );
    let mut dev = [0u8; 16];
    dev.copy_from_slice(&plaintext[40..56]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if expires_at <= now {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    if dev != expected_device_id {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    Ok(Some((ak, dev)))
}

pub fn delete_session(account_id: &str, session_path: &PathBuf) -> Result<()> {
    validate_account_id(account_id)?;
    ensure_store()?;
    let entry = Entry::new(SERVICE, &format!("{account_id}:session"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = entry.delete_credential();
    let _ = fs::remove_file(session_path);
    Ok(())
}
