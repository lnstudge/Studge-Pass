use anyhow::{Context, Result};
use std::io::Write;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

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
    let value = Zeroizing::new(
        item.field(&field_name)
            .context("field not found")?
            .to_string(),
    );
    if print {
        println!("{}", value.as_str());
    } else {
        let key = Zeroizing::new(
            studge_core::crypto::random::array::<32>().map_err(|e| anyhow::anyhow!("{e}"))?,
        );
        let hash = blake3::keyed_hash(&key, value.as_bytes());

        let exe = std::env::current_exe().context("locate current executable")?;
        match Command::new(exe)
            .arg("__clear-clipboard")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(mut child) => {
                let input_sent = child.stdin.take().is_some_and(|mut stdin| {
                    stdin
                        .write_all(&key[..])
                        .and_then(|()| stdin.write_all(hash.as_bytes()))
                        .is_ok()
                });
                if !input_sent {
                    eprintln!(
                        "warning: could not send data to clipboard clearer; clipboard will NOT be cleared automatically"
                    );
                }
            }
            Err(_) => {
                eprintln!(
                    "warning: could not spawn clipboard clearer; clipboard will NOT be cleared automatically"
                );
            }
        }

        let mut clipboard = arboard::Clipboard::new().context("open clipboard")?;
        clipboard
            .set_text(value.as_str().to_owned())
            .context("set clipboard")?;
        println!("Copied {} to clipboard (clears in 30s).", field_name);
    }
    Ok(())
}
