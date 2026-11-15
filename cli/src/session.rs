use anyhow::{Context, Result};
use keyring_core::Entry;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey, Envelope};
use studge_core::crypto::random;

const SERVICE: &str = "studge-pass-cli";
type LoadedSession = (Zeroizing<[u8; 32]>, [u8; 16]);

fn ensure_store() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use windows_native_keyring_store::Store;
        keyring_core::set_default_store(Store::new().map_err(|e| anyhow::anyhow!("{e}"))?);
    }
    #[cfg(target_os = "macos")]
    {
        use apple_native_keyring_store::keychain;
        keyring_core::set_default_store(
            keychain::Store::new().map_err(|e| anyhow::anyhow!("{e}"))?,
        );
    }
    #[cfg(target_os = "linux")]
    {
        use linux_keyutils_keyring_store::Store;
        keyring_core::set_default_store(Store::new().map_err(|e| anyhow::anyhow!("{e}"))?);
    }
    Ok(())
}

/// Store the Secret Key in the OS credential store (SPEC §4.2).
pub fn store_secret_key(account_id: &str, sk: &str) -> Result<()> {
    ensure_store()?;
    let entry =
        Entry::new(SERVICE, &format!("{account_id}:sk")).map_err(|e| anyhow::anyhow!("{e}"))?;
    entry.set_password(sk).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn load_secret_key(account_id: &str) -> Result<Option<Zeroizing<String>>> {
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
    account_key_bytes: Zeroizing<[u8; 32]>,
    device_id: [u8; 16],
    expiry_minutes: u64,
    session_path: &PathBuf,
) -> Result<()> {
    ensure_store()?;
    let aid = decode_account_id(account_id)?;
    let session_key_bytes =
        Zeroizing::new(random::array::<32>().map_err(|e| anyhow::anyhow!("{e}"))?);
    let session_key = AeadKey::from_bytes(*session_key_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let expires_at = expiry_minutes
        .checked_mul(60)
        .and_then(|seconds| now.checked_add(seconds))
        .context("session expiry overflow")?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(32 + 8 + 16));
    plaintext.extend_from_slice(&account_key_bytes[..]);
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
    let sk_str = hex_encode(&session_key_bytes[..]);
    entry
        .set_password(sk_str.as_str())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

/// Load session: returns (AccountKey bytes, device_id) if valid and not expired.
pub fn load_session(
    account_id: &str,
    expected_device_id: [u8; 16],
    session_path: &PathBuf,
) -> Result<Option<LoadedSession>> {
    ensure_store()?;
    let aid = decode_account_id(account_id)?;
    let entry = Entry::new(SERVICE, &format!("{account_id}:session"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let sk_str = match entry.get_password() {
        Ok(p) => Zeroizing::new(p),
        Err(keyring_core::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("{e}")),
    };
    let sk_bytes = match hex_decode(sk_str.as_str()) {
        Ok(bytes) => bytes,
        Err(_) => {
            delete_session(account_id, session_path)?;
            return Ok(None);
        }
    };
    if sk_bytes.len() != 32 {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    let mut skb = Zeroizing::new([0u8; 32]);
    skb.copy_from_slice(&sk_bytes);
    let session_key = AeadKey::from_bytes(*skb);

    if !session_path.exists() {
        delete_session(account_id, session_path)?;
        return Ok(None);
    }
    let file_bytes = fs::read(session_path).context("read session file")?;
    let envelope = Envelope::from_cbor(&file_bytes).map_err(|_| {
        let _ = delete_session(account_id, session_path);
        anyhow::anyhow!("bad session file")
    })?;

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
    let expiry_bytes: [u8; 8] = plaintext[32..40]
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad session expiry"))?;
    let expires_at = u64::from_le_bytes(expiry_bytes);
    let mut dev = [0u8; 16];
    dev.copy_from_slice(&plaintext[40..56]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
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
    ensure_store()?;
    let entry = Entry::new(SERVICE, &format!("{account_id}:session"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _ = entry.delete_credential();
    let _ = fs::remove_file(session_path);
    Ok(())
}

fn decode_account_id(account_id: &str) -> Result<[u8; 16]> {
    if account_id.len() != 32 || !account_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "account id must be exactly 32 ASCII hex characters"
        ));
    }
    let decoded = hex_decode(account_id)?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad account id length"))
}

fn hex_encode(bytes: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_decode(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("bad hex"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| anyhow::anyhow!("bad hex"))?);
    }
    Ok(out)
}
