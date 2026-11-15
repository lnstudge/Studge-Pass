use anyhow::{Context, Result};
use std::process::Command;

use crate::app::App;
use crate::config::Config;
use crate::vault_util::load_items;

pub fn run(query: String, field: Option<String>, print: bool, password_stdin: bool) -> Result<()> {
    let _ = password_stdin;
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
        let hash = blake3::hash(value.as_bytes()).to_hex().to_string();
        // spawn detached clearer
        let exe = std::env::current_exe().context("exe")?;
        let _ = Command::new(exe)
            .arg("__clear-clipboard")
            .arg(&hash)
            .spawn();
        let mut cb = arboard::Clipboard::new().context("clipboard")?;
        cb.set_text(value.clone()).context("set clipboard")?;
        println!("Copied {} to clipboard (clears in 30s).", field_name);
        // keep value zeroized? it goes out of scope
    }
    Ok(())
}
