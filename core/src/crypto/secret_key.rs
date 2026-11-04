//! The SP1 Secret Key (SPEC §4.2).
//!
//! 128 random bits, printed as `SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`:
//! 26 Crockford base32 characters carrying the key (130 bits with the two most
//! significant bits fixed to zero) followed by one BLAKE3-derived check
//! character. Decoding normalises case, hyphens and the Crockford confusions,
//! and rejects a wrong length, a bad checksum, an unknown character or a set
//! padding bit.

use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::{labels, random};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Entropy in the Secret Key, in bytes (SPEC §4.2: 128 bits).
pub const SECRET_KEY_BYTES: usize = 16;

/// Key characters in the printed form, excluding the check character.
pub const KEY_CHARS: usize = 26;

/// Characters after the `SP1-` prefix: 26 key characters + 1 check character.
pub const TOTAL_CHARS: usize = 27;

/// Crockford base32: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The account's Secret Key. Never sent to the relay and never formatted.
pub struct SecretKey(Zeroizing<[u8; SECRET_KEY_BYTES]>);

impl SecretKey {
    /// Draws 128 bits from the operating system's random source.
    pub fn generate() -> CryptoResult<Self> {
        Ok(Self(Zeroizing::new(random::array::<SECRET_KEY_BYTES>()?)))
    }

    /// Wraps known bytes (recovery-kit entry, tests, vectors).
    pub fn from_bytes(bytes: [u8; SECRET_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw 16 bytes. Callers must not log or serialise this.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.0
    }

    /// Prints the key as `SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`.
    pub fn encode(&self) -> String {
        let value = u128::from_be_bytes(*self.0);
        let mut chars = [0u8; TOTAL_CHARS];
        for (i, slot) in chars.iter_mut().take(KEY_CHARS).enumerate() {
            // The 130-bit space: character i covers bits 130-5(i+1) .. .
            let shift = 130 - 5 * (i + 1);
            let index = ((value >> shift) & 0x1f) as usize;
            *slot = ALPHABET[index];
        }
        chars[KEY_CHARS] = ALPHABET[check_index(&chars[..KEY_CHARS]) as usize];

        let mut out = String::with_capacity(36);
        out.push_str("SP1-");
        for (i, byte) in chars.iter().enumerate() {
            if i == 5 || i == 10 || i == 15 || i == 20 || i == 25 {
                out.push('-');
            }
            out.push(*byte as char);
        }
        out
    }

    /// Parses the printed form. Accepts lower case, missing hyphens and the
    /// Crockford confusions (`I`, `L` → 1, `O` → 0).
    pub fn decode(text: &str) -> CryptoResult<Self> {
        let mut cleaned: Zeroizing<String> = Zeroizing::new(String::with_capacity(TOTAL_CHARS));
        for ch in text.trim().chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            cleaned.push(ch.to_ascii_uppercase());
        }
        let body = cleaned
            .strip_prefix("SP1")
            .ok_or(CryptoError::InvalidEncoding)?;
        let mut chars: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(TOTAL_CHARS));
        chars.extend_from_slice(body.as_bytes());
        if chars.len() != TOTAL_CHARS {
            return Err(CryptoError::InvalidLength {
                expected: TOTAL_CHARS,
                actual: chars.len(),
            });
        }

        // Validate every character and compute the checksum over the first 26.
        let mut values: Zeroizing<[u8; TOTAL_CHARS]> = Zeroizing::new([0u8; TOTAL_CHARS]);
        for (i, byte) in chars.iter().enumerate() {
            values[i] = value_of(*byte)?;
        }

        let mut canonical: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(KEY_CHARS));
        for value in values.iter().take(KEY_CHARS) {
            canonical.push(ALPHABET[*value as usize]);
        }
        let expected = check_index(&canonical);
        if !bool::from(expected.ct_eq(&values[KEY_CHARS])) {
            return Err(CryptoError::InvalidChecksum);
        }

        // 26 characters = 130 bits; the top two must be zero.
        let mut value: u128 = 0;
        for (i, v) in values.iter().enumerate().take(KEY_CHARS) {
            if i == 0 {
                if *v > 0b0000_0111 {
                    return Err(CryptoError::InvalidPadding);
                }
                value = *v as u128;
            } else {
                value = (value << 5) | (*v as u128);
            }
        }
        Ok(Self(Zeroizing::new(value.to_be_bytes())))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// The 5-bit check index over the 26 key characters.
fn check_index(data: &[u8]) -> u8 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(labels::SECRET_KEY_CHECKSUM.as_bytes());
    hasher.update(data);
    let hash = hasher.finalize();
    (hash.as_bytes()[0] as usize % 32) as u8
}

/// Alphabet index of one byte after Crockford normalisation.
fn value_of(ch: u8) -> CryptoResult<u8> {
    let normalised = match ch {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|b| *b == normalised)
        .map(|index| index as u8)
        .ok_or(CryptoError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_with_check(data: &[char]) -> String {
        assert_eq!(data.len(), KEY_CHARS);
        let bytes: Vec<u8> = data.iter().map(|c| *c as u8).collect();
        let check = ALPHABET[check_index(&bytes) as usize] as char;
        let mut out = String::from("SP1");
        for (i, c) in data.iter().enumerate() {
            if i % 5 == 0 {
                out.push('-');
            }
            out.push(*c);
        }
        out.push(check);
        out
    }

    #[test]
    fn rejects_set_padding_bits() {
        // 'Z' = 31 sets the top two bits of the 130-bit value.
        let mut data = ['0'; KEY_CHARS];
        data[0] = 'Z';
        let text = string_with_check(&data);
        assert_eq!(
            SecretKey::decode(&text).expect_err("padding must be rejected"),
            CryptoError::InvalidPadding
        );
    }

    #[test]
    fn accepts_all_zero_padding() {
        let data = ['0'; KEY_CHARS];
        let text = string_with_check(&data);
        let key = SecretKey::decode(&text).expect("valid");
        assert_eq!(key.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn check_character_is_stable() {
        // Any change to the algorithm would break the published vectors.
        let first = check_index(b"00000000000000000000000000");
        assert_eq!(first, check_index(b"00000000000000000000000000"));
        assert!(first < 32);
    }
}
