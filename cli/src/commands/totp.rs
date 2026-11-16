use anyhow::{Context, Result};
use studge_core::totp::TotpConfig;

use crate::app::App;
use crate::config::Config;
use crate::vault_util::load_items;

pub fn run(query: String) -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let (items, _) = load_items(&app, &cfg)?;
    let item = items
        .iter()
        .find(|i| {
            i.field("title")
                .map(|t| t.to_lowercase().contains(&query.to_lowercase()))
                .unwrap_or(false)
        })
        .context("no matching item")?;
    let secret = item.field("totp").context("no totp field")?;
    let config = TotpConfig::from_field(secret).map_err(|e| anyhow::anyhow!("{e}"))?;
    let code = config.current().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", code.as_str());
    Ok(())
}
