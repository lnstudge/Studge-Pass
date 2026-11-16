use anyhow::{Context, Result};

use crate::app::App;
use crate::config::Config;

pub fn run() -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let account_id = cfg.account_id.clone().context("no account")?;
    let session_path = app.home.join("session.bin");
    crate::session::delete_session(&account_id, &session_path)?;
    println!("Locked.");
    Ok(())
}
