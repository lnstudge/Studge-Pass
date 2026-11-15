use anyhow::{Context, Result};
use std::io::Read;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn run() -> Result<()> {
    let mut input = Zeroizing::new([0u8; 64]);
    std::io::stdin()
        .read_exact(&mut input[..])
        .context("read clipboard clearer input")?;

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&input[..32]);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&input[32..]);

    std::thread::sleep(Duration::from_secs(30));

    if let Ok(mut clipboard) = arboard::Clipboard::new() {
        if let Ok(text) = clipboard.get_text() {
            if matches(&key, &expected, text.as_bytes()) {
                let _ = clipboard.set_text(String::new());
            }
        }
    }
    Ok(())
}

fn matches(key: &[u8; 32], expected: &[u8; 32], value: &[u8]) -> bool {
    let actual = blake3::keyed_hash(key, value);
    bool::from(actual.as_bytes().ct_eq(expected))
}
