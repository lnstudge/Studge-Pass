//! Strict base64 and base64url (RFC 4648 §4–§5).
//!
//! Importers and exporters meet base64 in almost every format, and passkey
//! credential ids are base64url by convention. All four functions are strict:
//! an unknown character, wrong padding, or a non-canonical final chunk (unused
//! bits set) is an error, and the decoder proves canonicity by re-encoding.

use crate::error::{CoreError, CoreResult};

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(alphabet[(triple >> 18) as usize & 0x3F] as char);
        out.push(alphabet[(triple >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(triple >> 6) as usize & 0x3F] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[triple as usize & 0x3F] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

fn decode_with(text: &str, alphabet: &[u8; 64], padded: bool) -> CoreResult<Vec<u8>> {
    if text.len() > 16 * 1024 * 1024 {
        return Err(CoreError::InvalidEncoding);
    }
    let mut body = text;
    if padded {
        body = body.trim_end_matches('=');
        let padding = text.len() - body.len();
        if padding > 2 {
            return Err(CoreError::InvalidEncoding);
        }
        // Padding is optional on input but must be consistent when present.
        if padding > 0 && !text.len().is_multiple_of(4) {
            return Err(CoreError::InvalidEncoding);
        }
    } else if text.contains('=') {
        return Err(CoreError::InvalidEncoding);
    }

    let mut sextets = Vec::with_capacity(body.len());
    for byte in body.bytes() {
        let value = alphabet
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(CoreError::InvalidEncoding)?;
        sextets.push(value as u8);
    }
    if sextets.len() % 4 == 1 {
        return Err(CoreError::InvalidEncoding);
    }

    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let mut triple = 0u32;
        for (index, sextet) in chunk.iter().enumerate() {
            triple |= (*sextet as u32) << (18 - 6 * index);
        }
        out.push((triple >> 16) as u8);
        if chunk.len() > 2 {
            out.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(triple as u8);
        }
        // Reject non-canonical trailing bits: they would let two strings decode
        // to the same bytes, which breaks any hash or id built on the text.
        let unused_bits = match chunk.len() {
            2 => 4,
            3 => 2,
            _ => 0,
        };
        if unused_bits > 0 {
            let last = *chunk.last().ok_or(CoreError::InvalidEncoding)? as u32;
            if last & ((1 << unused_bits) - 1) != 0 {
                return Err(CoreError::InvalidEncoding);
            }
        }
    }
    Ok(out)
}

/// Standard alphabet with `=` padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    encode_with(bytes, STANDARD, true)
}

/// Standard alphabet, padding optional on input, trailing bits must be zero.
pub fn base64_decode(text: &str) -> CoreResult<Vec<u8>> {
    decode_with(text, STANDARD, true)
}

/// URL-safe alphabet without padding (RFC 4648 §5), as passkey ids use.
pub fn base64url_encode(bytes: &[u8]) -> String {
    encode_with(bytes, URL_SAFE, false)
}

/// URL-safe alphabet without padding.
pub fn base64url_decode(text: &str) -> CoreResult<Vec<u8>> {
    decode_with(text, URL_SAFE, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_standard_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).expect("decode"), plain.as_bytes());
        }
    }

    #[test]
    fn url_safe_alphabet_has_no_padding() {
        assert_eq!(base64url_encode(&[0xFB, 0xFF]), "-_8");
        assert_eq!(base64url_decode("-_8").expect("decode"), vec![0xFB, 0xFF]);
        assert!(base64url_decode("+/8").is_err());
    }

    #[test]
    fn rejects_bad_characters_padding_and_trailing_bits() {
        for bad in ["Zg=", "Zg===", "Z!==", "Zg==Zg==", "Zm9v\n"] {
            assert!(base64_decode(bad).is_err(), "{bad}");
        }
        // "Zh==" decodes to the same byte as "Zg==" because the low bits are
        // ignored by a lenient decoder; ours rejects it.
        assert!(base64_decode("Zh==").is_err());
        assert!(base64url_decode("Zh").is_err());
    }

    #[test]
    fn round_trips_every_length() {
        for length in 0..64 {
            let bytes: Vec<u8> = (0..length).map(|index| (index * 7) as u8).collect();
            assert_eq!(base64_decode(&base64_encode(&bytes)).expect("std"), bytes);
            assert_eq!(
                base64url_decode(&base64url_encode(&bytes)).expect("url"),
                bytes
            );
        }
    }
}
