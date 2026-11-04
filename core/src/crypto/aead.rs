//! XChaCha20-Poly1305 envelopes (SPEC §5.2).
//!
//! Every ciphertext is a CBOR map `{suite, nonce, ct}` with a 24-byte random
//! nonce and the 16-byte tag appended to `ct`. `open` accepts only canonical
//! CBOR, rejects an unknown suite, and returns a single uniform error for every
//! authentication failure.

use crate::crypto::aad::{canonical_bytes, canonical_map, parse_strict, Aad};
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::labels::SUITE_V1;
use crate::crypto::random;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use ciborium::value::Value;
use std::fmt;
use zeroize::Zeroizing;

/// Nonce length mandated by SPEC §5.2.
pub const NONCE_BYTES: usize = 24;
/// Poly1305 tag length.
pub const TAG_BYTES: usize = 16;
/// Symmetric key length.
pub const KEY_BYTES: usize = 32;

/// A 32-byte AEAD key. Redacted `Debug`, zeroized on drop, never cloned by
/// accident (there is no `Clone`).
pub struct AeadKey(Zeroizing<[u8; KEY_BYTES]>);

impl AeadKey {
    /// Wraps 32 bytes (a derived key, an item key, …).
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The raw bytes. Callers must not log or serialise this.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey(<redacted>)")
    }
}

/// The stored form of one ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// The 24-byte nonce.
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Ciphertext including the 16-byte tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serialises as canonical CBOR `{suite, nonce, ct}`.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", Value::Text(SUITE_V1.to_string())),
            ("nonce", Value::Bytes(self.nonce.to_vec())),
            ("ct", Value::Bytes(self.ciphertext.clone())),
        ]);
        canonical_bytes(&map)
    }

    /// Parses an envelope strictly: exact key set, canonical CBOR, `v1`, a
    /// 24-byte nonce and at least a tag's worth of ciphertext.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value = parse_strict(bytes)?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::MalformedCbor);
        };

        let mut suite: Option<String> = None;
        let mut nonce: Option<Vec<u8>> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        for (key, value) in entries {
            let Value::Text(name) = key else {
                return Err(CryptoError::MalformedCbor);
            };
            match name.as_str() {
                "suite" => {
                    if suite.is_some() {
                        return Err(CryptoError::MalformedCbor);
                    }
                    match value {
                        Value::Text(text) => suite = Some(text),
                        _ => return Err(CryptoError::MalformedCbor),
                    }
                }
                "nonce" => {
                    if nonce.is_some() {
                        return Err(CryptoError::MalformedCbor);
                    }
                    match value {
                        Value::Bytes(bytes) => nonce = Some(bytes),
                        _ => return Err(CryptoError::MalformedCbor),
                    }
                }
                "ct" => {
                    if ciphertext.is_some() {
                        return Err(CryptoError::MalformedCbor);
                    }
                    match value {
                        Value::Bytes(bytes) => ciphertext = Some(bytes),
                        _ => return Err(CryptoError::MalformedCbor),
                    }
                }
                _ => return Err(CryptoError::MalformedCbor),
            }
        }

        match suite.as_deref() {
            Some(SUITE_V1) => {}
            Some(_) => return Err(CryptoError::UnknownSuite),
            None => return Err(CryptoError::MalformedCbor),
        }
        let nonce = nonce.ok_or(CryptoError::MalformedCbor)?;
        if nonce.len() != NONCE_BYTES {
            return Err(CryptoError::InvalidLength {
                expected: NONCE_BYTES,
                actual: nonce.len(),
            });
        }
        let ciphertext = ciphertext.ok_or(CryptoError::MalformedCbor)?;
        if ciphertext.len() < TAG_BYTES {
            return Err(CryptoError::InvalidLength {
                expected: TAG_BYTES,
                actual: ciphertext.len(),
            });
        }
        let mut fixed = [0u8; NONCE_BYTES];
        fixed.copy_from_slice(&nonce);
        Ok(Self {
            nonce: fixed,
            ciphertext,
        })
    }
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("nonce_len", &NONCE_BYTES)
            .field("ct_len", &self.ciphertext.len())
            .finish()
    }
}

/// Encrypts `plaintext` under `key` with a fresh random nonce and the given AAD.
pub fn seal(key: &AeadKey, aad: &Aad, plaintext: &[u8]) -> CryptoResult<Envelope> {
    let nonce: [u8; NONCE_BYTES] = random::array()?;
    seal_with_nonce_inner(key, aad, nonce, plaintext)
}

/// Encrypts with a caller-supplied nonce. Only for known-answer vectors and
/// tests: production code must call [`seal`], which draws a fresh nonce.
#[cfg(any(test, feature = "test-vectors"))]
pub fn seal_with_nonce(
    key: &AeadKey,
    aad: &Aad,
    nonce: [u8; NONCE_BYTES],
    plaintext: &[u8],
) -> CryptoResult<Envelope> {
    seal_with_nonce_inner(key, aad, nonce, plaintext)
}

fn seal_with_nonce_inner(
    key: &AeadKey,
    aad: &Aad,
    nonce: [u8; NONCE_BYTES],
    plaintext: &[u8],
) -> CryptoResult<Envelope> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| {
        CryptoError::InvalidLength {
            expected: KEY_BYTES,
            actual: key.as_bytes().len(),
        }
    })?;
    let nonce_ref = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_ref,
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Envelope { nonce, ciphertext })
}

/// Decrypts `envelope` and returns the plaintext in a zeroizing buffer.
///
/// Every failure — wrong key, wrong AAD, flipped byte, truncated ciphertext —
/// returns the same `DecryptionFailed` error.
pub fn open(key: &AeadKey, aad: &Aad, envelope: &Envelope) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| {
        CryptoError::InvalidLength {
            expected: KEY_BYTES,
            actual: key.as_bytes().len(),
        }
    })?;
    let nonce_ref = XNonce::from(envelope.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce_ref,
            Payload {
                msg: &envelope.ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aad::{Aad, RecordType};

    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];

    fn key() -> AeadKey {
        AeadKey::from_bytes([9u8; 32])
    }

    fn aad() -> Aad {
        Aad::builder(RecordType::ItemField)
            .vault(VAULT)
            .item(ITEM)
            .field("password")
            .build()
            .expect("valid")
    }

    #[test]
    fn round_trip() {
        let envelope = seal(&key(), &aad(), b"correct horse battery staple").expect("seal");
        let plaintext = open(&key(), &aad(), &envelope).expect("open");
        assert_eq!(&plaintext[..], b"correct horse battery staple");
    }

    #[test]
    fn cbor_round_trip_is_canonical() {
        let envelope = seal(&key(), &aad(), b"x").expect("seal");
        let bytes = envelope.to_cbor().expect("encode");
        let parsed = Envelope::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed, envelope);
        // Re-encoding a parsed envelope must reproduce the same bytes.
        assert_eq!(parsed.to_cbor().expect("encode"), bytes);
    }

    #[test]
    fn rejects_unknown_suite() {
        let map = canonical_map(vec![
            ("suite", Value::Text("v2".to_string())),
            ("nonce", Value::Bytes(vec![0u8; NONCE_BYTES])),
            ("ct", Value::Bytes(vec![0u8; TAG_BYTES])),
        ]);
        let bytes = canonical_bytes(&map).expect("encode");
        assert_eq!(
            Envelope::from_cbor(&bytes).expect_err("v2"),
            CryptoError::UnknownSuite
        );
    }

    #[test]
    fn rejects_extra_field_and_bad_lengths() {
        let map = canonical_map(vec![
            ("suite", Value::Text(SUITE_V1.to_string())),
            ("nonce", Value::Bytes(vec![0u8; 12])),
            ("ct", Value::Bytes(vec![0u8; TAG_BYTES])),
            ("extra", Value::Integer(1i64.into())),
        ]);
        let bytes = canonical_bytes(&map).expect("encode");
        assert!(Envelope::from_cbor(&bytes).is_err());

        let map = canonical_map(vec![
            ("suite", Value::Text(SUITE_V1.to_string())),
            ("nonce", Value::Bytes(vec![0u8; NONCE_BYTES])),
            ("ct", Value::Bytes(vec![0u8; 8])),
        ]);
        let bytes = canonical_bytes(&map).expect("encode");
        assert_eq!(
            Envelope::from_cbor(&bytes).expect_err("short ct"),
            CryptoError::InvalidLength {
                expected: TAG_BYTES,
                actual: 8
            }
        );
    }

    #[test]
    fn rejects_non_canonical_envelope() {
        // Correct fields but in the wrong order: suite before nonce before ct.
        let shuffled = Value::Map(vec![
            (
                Value::Text("suite".into()),
                Value::Text(SUITE_V1.into()),
            ),
            (
                Value::Text("nonce".into()),
                Value::Bytes(vec![0u8; NONCE_BYTES]),
            ),
            ("ct".into(), Value::Bytes(vec![0u8; TAG_BYTES])),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&shuffled, &mut bytes).expect("encode");
        assert_eq!(
            Envelope::from_cbor(&bytes).expect_err("order"),
            CryptoError::NonCanonicalCbor
        );
    }

    #[test]
    fn debug_never_prints_the_key() {
        let printed = format!("{:?}", key());
        assert!(printed.contains("redacted"));
        assert!(!printed.contains("0909"));
    }
}
