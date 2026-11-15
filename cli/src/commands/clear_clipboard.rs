use anyhow::Result;
use std::time::Duration;

pub fn run(hash: String) -> Result<()> {
    std::thread::sleep(Duration::from_secs(30));
    if let Ok(mut cb) = arboard::Clipboard::new() {
        if let Ok(text) = cb.get_text() {
            let h = blake3::hash(text.as_bytes()).to_hex().to_string();
            if h == hash {
                let _ = cb.set_text(String::new());
            }
        }
    }
    Ok(())
}
