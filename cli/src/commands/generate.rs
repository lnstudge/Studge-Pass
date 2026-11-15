use anyhow::Result;
use studge_core::generate::{generate_password, PasswordOptions};

pub fn run(length: usize, symbols: bool, no_symbols: bool) -> Result<()> {
    let opts = PasswordOptions {
        length,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: if no_symbols { false } else { true || symbols },
        exclude_ambiguous: false,
    };
    let pw = generate_password(&opts).map_err(|e| anyhow::anyhow!("{e}"))?;
    // copy to clipboard? just print for generate
    println!("{}", pw.as_str());
    // best-effort clipboard
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(pw.as_str().to_string());
    }
    Ok(())
}
