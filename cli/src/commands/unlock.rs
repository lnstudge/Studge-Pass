use anyhow::{Context, Result};
use rpassword::prompt_password;
use studge_core::account::unlock as unlock_account;
use studge_core::storage::LocalStore;

use crate::app::App;
use crate::config::Config;

pub fn run() -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let account_id = cfg
        .account_id
        .clone()
        .context("no account; run init first")?;
    let password = if let Ok(v) = std::env::var("STUDGE_PASSWORD") {
        eprintln!("WARNING: reading password from STUDGE_PASSWORD env var");
        v
    } else {
        prompt_password("Master password: ").context("read password")?
    };

    let store = app.open_store()?;
    let aid_bytes = hex_decode(&account_id)?;
    let mut aid = [0u8; 16];
    aid.copy_from_slice(&aid_bytes);
    let bundle = store
        .get_bundle(&aid)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no account bundle in store")?;
    let sk = cfg.device_key_seed.clone().unwrap_or_default();
    // secret key from recovery? We don't store secret key. Need it. Prompt?
    // For unlock we need secret key. Read from env or prompt.
    let secret_key_str = prompt_password("Secret Key: ").context("read secret key")?;
    let secret_key = studge_core::crypto::secret_key::SecretKey::decode(&secret_key_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let _account =
        unlock_account(&password, &secret_key, &bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    crate::session::store_password(&account_id, &password)?;
    crate::session::store_secret_key(&account_id, &secret_key.encode())?;
    println!("Unlocked.");
    let _ = sk;
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).context("bad hex")?);
    }
    Ok(out)
}
