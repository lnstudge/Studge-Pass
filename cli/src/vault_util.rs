use anyhow::{Context, Result};
use studge_core::crypto::keys::AccountKey;
use studge_core::oplog::materialise;
use studge_core::storage::LocalStore;
use studge_core::vault::items::Item;
use zeroize::Zeroizing;

use crate::app::App;
use crate::config::Config;

pub fn load_session_pub(
    account_id: &str,
    device_id: [u8; 16],
    session_path: &std::path::PathBuf,
    now: u64,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 16])> {
    crate::session::load_session(account_id, device_id, session_path, now)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("locked; run unlock")
}

pub fn load_items(app: &App, cfg: &Config) -> Result<(Vec<Item>, [u8; 16])> {
    let vault_hex = cfg.vault_id.clone().context("no vault")?;
    let mut vid = [0u8; 16];
    let vb = hex_decode(&vault_hex)?;
    vid.copy_from_slice(&vb);

    let account_id = cfg.account_id.clone().context("no account")?;
    let device_id_hex = cfg.device_id.clone().context("no device")?;
    let mut device_id = [0u8; 16];
    let db = hex_decode(&device_id_hex)?;
    device_id.copy_from_slice(&db);

    let session_path = app.home.join("session.bin");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (ak_bytes, sess_dev) =
        crate::session::load_session(&account_id, device_id, &session_path, now)?
            .context("locked; run unlock")?;
    if sess_dev != device_id {
        return Err(anyhow::anyhow!("session device mismatch"));
    }
    let account_key = AccountKey::from_bytes(*ak_bytes);

    let store = app.open_store()?;
    let aid = hex_decode(&account_id)?;
    let mut aidb = [0u8; 16];
    aidb.copy_from_slice(&aid);
    let bundle = store
        .get_bundle(&aidb)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no bundle")?;

    // open vault key using account_key directly (no MUK needed)
    let vk_env = store
        .get_vault_key(&vid)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no vault key")?;
    // unwrap vault key manually via core helper that takes AccountKey
    let vk = studge_core::crypto::keys::unwrap_vault_key(&account_key, &vid, &vk_env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // build dag
    let mut dag = studge_core::oplog::Dag::new(vid);
    // devices: need registry; reconstruct from bundle? We don't have identity key without unlock.
    // For materialising ops we need DeviceRegistry for verification. Use a permissive empty?
    // Materialise requires devices for dag.add. Without identity key we cannot verify device certs.
    // Fallback: load bundle and unlock? We can't (no password).
    // Instead, use the devices from a stored registry? Not stored separately.
    // For read-only listing, skip verification? dag.add requires devices.
    // We'll attempt to build a registry from bundle using a helper if available.
    let devices = studge_core::account::device_registry_from_bundle(&account_key, &bundle)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    for op in store.list_ops(&vid).map_err(|e| anyhow::anyhow!("{e}"))? {
        let _ = dag.add(op, &devices);
    }
    let state = materialise(&dag, &vk).map_err(|e| anyhow::anyhow!("{e}"))?;
    let items: Vec<Item> = state.items().cloned().collect();
    let _ = bundle;
    Ok((items, vid))
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
