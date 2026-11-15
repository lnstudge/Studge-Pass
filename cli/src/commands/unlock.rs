use anyhow::{Context, Result};
use rpassword::prompt_password;
use studge_core::account::unlock as unlock_account;
use studge_core::crypto::secret_key::SecretKey;
use studge_core::storage::LocalStore;

use crate::app::App;
use crate::config::Config;

pub fn run(password_stdin: bool) -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let account_id = cfg
        .account_id
        .clone()
        .context("no account; run init first")?;
    let device_id_hex = cfg.device_id.clone().context("no device")?;
    let mut device_id = [0u8; 16];
    let db = hex_decode(&device_id_hex)?;
    device_id.copy_from_slice(&db);

    let password = if password_stdin {
        let mut line = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut line).context("read stdin")?;
        line.trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string()
    } else {
        prompt_password("Master password: ").context("read password")?
    };

    let secret_key_str = if let Some(sk) = crate::session::load_secret_key(&account_id)? {
        sk.to_string()
    } else {
        prompt_password("Secret Key: ").context("read secret key")?
    };
    let secret_key = SecretKey::decode(&secret_key_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let store = app.open_store()?;
    let aid_bytes = hex_decode(&account_id)?;
    let mut aid = [0u8; 16];
    aid.copy_from_slice(&aid_bytes);
    let bundle = store
        .get_bundle(&aid)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no account bundle in store")?;
    let account =
        unlock_account(&password, &secret_key, &bundle).map_err(|e| anyhow::anyhow!("{e}"))?;
    let ak_bytes = account.account_key_bytes();

    let session_path = app.home.join("session.bin");
    let expiry = cfg.session_minutes;
    crate::session::create_session(&account_id, ak_bytes, device_id, expiry, &session_path)?;
    println!("Unlocked.");
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
