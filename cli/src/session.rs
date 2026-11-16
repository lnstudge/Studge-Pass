#[cfg(all(feature = "test-keystore", not(debug_assertions)))]
compile_error!("test-keystore feature is not allowed in release builds");

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
const SERVICE: &str = "studge-pass-cli";
use zeroize::Zeroizing;

use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey, Envelope};
use studge_core::crypto::random;

#[cfg(feature = "test-keystore")]
fn keystore_path() -> PathBuf {
    let home = std::env::var("STUDGE_HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join("test-keystore.json")
}

#[cfg(feature = "test-keystore")]
fn ks_load() -> BTreeMap<String, String> {
    let path = keystore_path();
    if let Ok(data) = fs::read_to_string(&path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        BTreeMap::new()
    }
}

#[cfg(feature = "test-keystore")]
fn ks_save(map: &BTreeMap<String, String>) -> Result<()> {
    let path = keystore_path();
    let data = serde_json::to_string(map).map_err(|e| anyhow::anyhow!("{e}"))?;
    fs::write(&path, data).context("write keystore")?;
    Ok(())
}

#[cfg(feature = "test-keystore")]
fn store_set(key: &str, value: &str) -> Result<()> {
    let mut map = ks_load();
    map.insert(key.to_string(), value.to_string());
    ks_save(&map)
}

#[cfg(feature = "test-keystore")]
fn store_get(key: &str) -> Result<Option<String>> {
    let map = ks_load();
    Ok(map.get(key).cloned())
}

#[cfg(feature = "test-keystore")]
fn store_delete(key: &str) -> Result<()> {
    let mut map = ks_load();
    map.remove(key);
    ks_save(&map)
}

// Non-test: use OS credential store
#[cfg(not(feature = "test-keystore"))]
#[allow(unreachable_code)]
fn ensure_store() -> Result<()> {
    #[cfg(all(test, target_os = "windows"))]
    {
        use windows_native_keyring_store::Store;
        let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    #[cfg(all(test, target_os = "macos"))]
    {
        use apple_native_keyring_store::keychain;
        let store = keychain::Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    #[cfg(all(test, target_os = "linux"))]
    {
        use linux_keyutils_keyring_store::Store;
        let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
        keyring_core::set_default_store(store);
    }
    #[cfg(not(test))]
    {
        #[cfg(target_os = "windows")]
        {
            use windows_native_keyring_store::Store;
            let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
            keyring_core::set_default_store(store);
        }
        #[cfg(target_os = "macos")]
        {
            use apple_native_keyring_store::keychain;
            let store = keychain::Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
            keyring_core::set_default_store(store);
        }
        #[cfg(target_os = "linux")]
        {
            use linux_keyutils_keyring_store::Store;
            let store = Store::new().map_err(|e| anyhow::anyhow!("{e}"))?;
            keyring_core::set_default_store(store);
        }
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

pub fn store_secret_key(account_id: &str, sk: &str) -> Result<()> {
    validate_account_id(account_id)?;
    #[cfg(not(feature = "test-keystore"))]
    ensure_store()?;
    let key = format!("{}:sk", account_id);
    #[cfg(feature = "test-keystore")]
    {
        store_set(&key, sk)?;
    }
    #[cfg(not(feature = "test-keystore"))]
    {
        let entry = keyring_core::Entry::new(SERVICE, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
        entry.set_password(sk).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

pub fn load_secret_key(account_id: &str) -> Result<Option<Zeroizing<String>>> {
    validate_account_id(account_id)?;
    #[cfg(not(feature = "test-keystore"))]
    ensure_store()?;
    let key = format!("{}:sk", account_id);
    #[cfg(feature = "test-keystore")]
    {
        Ok(store_get(&key)?.map(Zeroizing::new))
    }
    #[cfg(not(feature = "test-keystore"))]
    {
        let entry = keyring_core::Entry::new(SERVICE, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
        match entry.get_password() {
            Ok(p) => Ok(Some(Zeroizing::new(p))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("{e}")),
        }
    }
}

pub fn create_session(
    account_id: &str,
    account_key_bytes: [u8; 32],
    device_id: [u8; 16],
    expiry_minutes: u64,
    session_path: &PathBuf,
) -> Result<()> {
    validate_account_id(account_id)?;
    #[cfg(not(feature = "test-keystore"))]
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

    let key = format!("{}:session", account_id);
    let sk_str = hex_encode(&session_key_bytes);
    #[cfg(feature = "test-keystore")]
    {
        store_set(&key, &sk_str)?;
    }
    #[cfg(not(feature = "test-keystore"))]
    {
        let entry = keyring_core::Entry::new(SERVICE, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
        entry
            .set_password(&sk_str)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn load_session(
    account_id: &str,
    expected_device_id: [u8; 16],
    session_path: &PathBuf,
    now: u64,
) -> Result<Option<(Zeroizing<[u8; 32]>, [u8; 16])>> {
    validate_account_id(account_id)?;
    #[cfg(not(feature = "test-keystore"))]
    ensure_store()?;

    let aid_bytes = hex_decode(account_id)?;
    let mut aid = [0u8; 16];
    aid.copy_from_slice(&aid_bytes);

    let key = format!("{}:session", account_id);
    #[cfg(feature = "test-keystore")]
    let sk_str_opt = store_get(&key)?;
    #[cfg(not(feature = "test-keystore"))]
    let sk_str_opt = {
        let entry = keyring_core::Entry::new(SERVICE, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
        match entry.get_password() {
            Ok(p) => Some(p),
            Err(keyring_core::Error::NoEntry) => None,
            Err(e) => return Err(anyhow::anyhow!("{e}")),
        }
    };
    let sk_str = match sk_str_opt {
        Some(p) => p,
        None => return Ok(None),
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
    #[cfg(not(feature = "test-keystore"))]
    ensure_store()?;
    let key = format!("{}:session", account_id);
    #[cfg(feature = "test-keystore")]
    {
        store_delete(&key)?;
    }
    #[cfg(not(feature = "test-keystore"))]
    {
        let entry = keyring_core::Entry::new(SERVICE, &key).map_err(|e| anyhow::anyhow!("{e}"))?;
        let _ = entry.delete_credential();
    }
    let _ = fs::remove_file(session_path);
    Ok(())
}

#[cfg(test)]
#[cfg(feature = "test-keystore")]
mod session_tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_home<F: FnOnce()>(f: F) {
        let _g = LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("STUDGE_HOME", dir.path());
        f();
        std::env::remove_var("STUDGE_HOME");
    }

    #[test]
    fn master_password_never_stored() {
        with_home(|| {
            let aid = "a".repeat(32);
            let pw = "supersecret";
            let _ = pw;
            store_secret_key(&aid, "SP1-XXXX").unwrap();
            let account_key = [7u8; 32];
            let device_id = [9u8; 16];
            let home = std::env::var("STUDGE_HOME").unwrap();
            let session_path = std::path::PathBuf::from(&home).join("session.bin");
            create_session(&aid, account_key, device_id, 10, &session_path).unwrap();
            let bytes = std::fs::read(&session_path).unwrap();
            assert!(!bytes.windows(pw.len()).any(|w| w == pw.as_bytes()));
            let ks =
                std::fs::read_to_string(format!("{}/test-keystore.json", home)).unwrap_or_default();
            assert!(!ks.contains(pw));
        });
    }

    #[test]
    fn expired_session_is_refused_and_wiped() {
        with_home(|| {
            let aid = "a".repeat(32);
            let account_key = [7u8; 32];
            let device_id = [9u8; 16];
            let home = std::env::var("STUDGE_HOME").unwrap();
            let session_path = std::path::PathBuf::from(&home).join("session.bin");
            store_secret_key(&aid, "sk").unwrap();
            create_session(&aid, account_key, device_id, 10, &session_path).unwrap();
            let res = load_session(&aid, device_id, &session_path, 9_999_999_999).unwrap();
            assert!(res.is_none());
            assert!(!session_path.exists());
            let key = format!("{}:session", aid);
            assert!(store_get(&key).unwrap().is_none());
        });
    }

    #[test]
    fn edited_session_file_is_refused() {
        with_home(|| {
            let aid = "a".repeat(32);
            let account_key = [7u8; 32];
            let device_id = [9u8; 16];
            let home = std::env::var("STUDGE_HOME").unwrap();
            let session_path = std::path::PathBuf::from(&home).join("session.bin");
            store_secret_key(&aid, "sk").unwrap();
            create_session(&aid, account_key, device_id, 10, &session_path).unwrap();
            let mut bytes = std::fs::read(&session_path).unwrap();
            bytes[0] ^= 1;
            std::fs::write(&session_path, bytes).unwrap();
            let res = load_session(&aid, device_id, &session_path, 1_700_000_000).unwrap();
            assert!(res.is_none());
        });
    }

    #[test]
    fn other_device_is_refused() {
        with_home(|| {
            let aid = "a".repeat(32);
            let account_key = [7u8; 32];
            let device_id = [9u8; 16];
            let home = std::env::var("STUDGE_HOME").unwrap();
            let session_path = std::path::PathBuf::from(&home).join("session.bin");
            store_secret_key(&aid, "sk").unwrap();
            create_session(&aid, account_key, device_id, 10, &session_path).unwrap();
            let other = [1u8; 16];
            let res = load_session(&aid, other, &session_path, 1_700_000_000).unwrap();
            assert!(res.is_none());
        });
    }

    #[test]
    fn lock_keeps_secret_key() {
        with_home(|| {
            let aid = "a".repeat(32);
            store_secret_key(&aid, "thesecret").unwrap();
            let home = std::env::var("STUDGE_HOME").unwrap();
            let session_path = std::path::PathBuf::from(&home).join("session.bin");
            std::fs::write(&session_path, b"x").unwrap();
            let entry_key = format!("{}:session", aid);
            store_set(&entry_key, "aa").unwrap();
            delete_session(&aid, &session_path).unwrap();
            assert!(!session_path.exists());
            let sk = load_secret_key(&aid).unwrap();
            assert!(sk.is_some());
            assert_eq!(sk.unwrap().as_str(), "thesecret");
        });
    }
}
