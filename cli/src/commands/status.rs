use anyhow::Result;

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

use crate::app::App;
use crate::config::Config;

pub fn run() -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    println!("home: {}", app.home.display());
    println!(
        "account_id: {}",
        cfg.account_id
            .clone()
            .unwrap_or_else(|| "(none)".to_string())
    );
    println!(
        "vault_id: {}",
        cfg.vault_id.clone().unwrap_or_else(|| "(none)".to_string())
    );
    println!(
        "relay_url: {}",
        cfg.relay_url
            .clone()
            .unwrap_or_else(|| "(none)".to_string())
    );
    println!(
        "folder_path: {}",
        cfg.folder_path
            .clone()
            .unwrap_or_else(|| "(none)".to_string())
    );
    if let Some(id) = &cfg.account_id {
        let session_path = app.home.join("session.bin");
        let device_id = cfg.device_id.clone().unwrap_or_default();
        let mut dev = [0u8; 16];
        if let Ok(db) = hex_decode(&device_id) {
            if db.len() == 16 {
                dev.copy_from_slice(&db);
            }
        }
        match crate::session::load_session(id, dev, &session_path) {
            Ok(Some(_)) => println!("session: unlocked"),
            _ => println!("session: locked"),
        }
    }
    Ok(())
}
