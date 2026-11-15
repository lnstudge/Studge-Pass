use crate::app::App;
use crate::config::Config;
use crate::vault_util::load_items;
use anyhow::Result;

pub fn run(_vault: Option<String>) -> Result<()> {
    let app = App::new()?;
    let cfg = Config::load(&app.config_path)?;
    let (items, _) = load_items(&app, &cfg)?;
    for item in &items {
        println!(
            "{}  {}",
            item.kind().as_str(),
            item.field("title").unwrap_or("(untitled)")
        );
    }
    Ok(())
}
