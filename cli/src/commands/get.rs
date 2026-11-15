use crate::app::App;
use crate::config::Config;
use crate::vault_util::load_items;
use anyhow::{Context, Result};

pub fn run(query: String, field: Option<String>, print: bool) -> Result<()> {
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
    let field_name = field.unwrap_or_else(|| "password".to_string());
    let value = item
        .field(&field_name)
        .context("field not found")?
        .to_string();
    if print {
        println!("{}", value);
    } else {
        let mut cb = arboard::Clipboard::new().context("clipboard")?;
        cb.set_text(value.clone()).context("set clipboard")?;
        println!("Copied {} to clipboard (clears in 30s).", field_name);
        // clear after 30s in background thread
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text(String::new());
            }
            let _ = value;
        });
    }
    Ok(())
}
