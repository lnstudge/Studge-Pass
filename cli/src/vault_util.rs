use anyhow::{Context, Result};
use studge_core::oplog::materialise;
use studge_core::storage::LocalStore;
use studge_core::vault::items::Item;

use crate::app::App;
use crate::config::Config;

pub fn load_items(app: &App, cfg: &Config) -> Result<(Vec<Item>, [u8; 16])> {
    let vault_hex = cfg.vault_id.clone().context("no vault")?;
    let mut vid = [0u8; 16];
    let vb = hex_decode(&vault_hex)?;
    vid.copy_from_slice(&vb);

    let account_id = cfg.account_id.clone().context("no account")?;
    let password = crate::session::load_password(&account_id)?.context("locked; run unlock")?;
    let store = app.open_store()?;
    let aid = hex_decode(&account_id)?;
    let mut aidb = [0u8; 16];
    aidb.copy_from_slice(&aid);
    let bundle = store
        .get_bundle(&aidb)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no bundle")?;
    let sk_entry = crate::session::load_secret_key(&account_id)?
        .context("no secret key in session; run unlock")?;
    let secret_key = studge_core::crypto::secret_key::SecretKey::decode(sk_entry.as_str())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let account = studge_core::account::unlock(&password, &secret_key, &bundle)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let vk_env = store
        .get_vault_key(&vid)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no vault key")?;
    let vk = account
        .open_vault(&vid, &vk_env)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // build dag
    let mut dag = studge_core::oplog::Dag::new(vid);
    let devices = account.devices().clone();
    for op in store.list_ops(&vid).map_err(|e| anyhow::anyhow!("{e}"))? {
        let _ = dag.add(op, &devices);
    }
    let state = materialise(&dag, &vk).map_err(|e| anyhow::anyhow!("{e}"))?;
    let items: Vec<Item> = state.items().cloned().collect();
    Ok((items, vid))
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).context("bad hex")?);
    }
    Ok(out)
}
