use crate::app::App;
use crate::config::Config;
use crate::vault_util::load_items;
use anyhow::Result;

pub fn run() -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let (items, _) = load_items(&app, &cfg)?;
    println!("items: {}", items.len());
    println!("health scoring: not yet implemented in core");
    Ok(())
}
