use anyhow::Result;

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
        match crate::session::load_password(id)? {
            Some(_) => println!("session: unlocked"),
            None => println!("session: locked"),
        }
    }
    Ok(())
}
