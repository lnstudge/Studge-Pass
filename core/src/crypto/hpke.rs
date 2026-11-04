//! HPKE (RFC 9180) sealing of keys to a recipient (SPEC §4.9, §9.2).
//!
//! Suite `v1` uses base mode with X25519 / HKDF-SHA256 / ChaCha20-Poly1305.
//! Every seal is bound with both the HPKE `info` context and an AEAD `aad`, so a
//! wrapped key cannot be replayed to another member, vault or epoch.
//!
//! **Post-quantum seam.** The HPKE crate version pinned here already ships an
//! X-Wing (X25519 + ML-KEM-768) KEM, but SPEC §9.2 and D-0105 keep v1 on X25519
//! and require Phase 11 to re-check before switching. [`KemChoice`] is the
//! seam: the hybrid variant returns [`CryptoError::UnsupportedKem`] today.
//! TODO(security): Phase 11 evaluates `hpke`'s `mlkem`/X-Wing feature and, if it
//! passes review, wires `KemChoice::XWingMlKem768` to it (R-0116).

use crate::crypto::aad::{canonical_bytes, canonical_map, parse_strict};
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::labels::SUITE_V1;
use crate::crypto::random;
use ciborium::value::Value;
use hpke::{
    aead::ChaCha20Poly1305 as HpkeAead, kdf::HkdfSha256 as HpkeKdf,
    kem::X25519HkdfSha256 as HpkeKem, Deserializable, Kem as KemTrait, OpModeR, OpModeS,
    Serializable,
};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Encapsulated-key length for the X25519 KEM.
pub const ENC_BYTES: usize = 32;
/// X25519 public key length.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Which KEM a seal should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemChoice {
    /// X25519 (suite `v1`).
    X25519,
    /// Hybrid X25519 + ML-KEM-768 (X-Wing). Reserved for Phase 11.
    XWingMlKem768,
}

/// A recipient keypair for HPKE (the account identity encryption key).
pub struct HpkeRecipient(StaticSecret);

impl HpkeRecipient {
    /// Generates a fresh X25519 keypair from `OsRng`.
    pub fn generate() -> CryptoResult<Self> {
        let bytes = Zeroizing::new(random::array::<PUBLIC_KEY_BYTES>()?);
        Ok(Self(StaticSecret::from(*bytes)))
    }

    /// Rebuilds a recipient from its 32-byte secret.
    pub fn from_bytes(secret: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self(StaticSecret::from(secret))
    }

    /// The public key to hand out.
    pub fn public_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        PublicKey::from(&self.0).to_bytes()
    }
}

impl fmt::Debug for HpkeRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeRecipient(<redacted>)")
    }
}

/// A sealed key: the encapsulated ephemeral key plus the ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey {
    enc: [u8; ENC_BYTES],
    ciphertext: Vec<u8>,
}

impl SealedKey {
    /// The encapsulated key.
    pub fn enc(&self) -> &[u8; ENC_BYTES] {
        &self.enc
    }

    /// The ciphertext, including the AEAD tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Canonical CBOR `{suite, enc, ct}`.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", Value::Text(SUITE_V1.to_string())),
            ("enc", Value::Bytes(self.enc.to_vec())),
            ("ct", Value::Bytes(self.ciphertext.clone())),
        ]);
        canonical_bytes(&map)
    }

    /// Strict parser for [`SealedKey::to_cbor`].
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value = parse_strict(bytes)?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::MalformedCbor);
        };
        let mut suite: Option<String> = None;
        let mut enc: Option<Vec<u8>> = None;
        let mut ciphertext: Option<Vec<u8>> = None;
        for (key, value) in entries {
            let Value::Text(name) = key else {
                return Err(CryptoError::MalformedCbor);
            };
            match name.as_str() {
                "suite" => match value {
                    Value::Text(text) if suite.is_none() => suite = Some(text),
                    _ => return Err(CryptoError::MalformedCbor),
                },
                "enc" => match value {
                    Value::Bytes(bytes) if enc.is_none() => enc = Some(bytes),
                    _ => return Err(CryptoError::MalformedCbor),
                },
                "ct" => match value {
                    Value::Bytes(bytes) if ciphertext.is_none() => ciphertext = Some(bytes),
                    _ => return Err(CryptoError::MalformedCbor),
                },
                _ => return Err(CryptoError::MalformedCbor),
            }
        }
        match suite.as_deref() {
            Some(SUITE_V1) => {}
            Some(_) => return Err(CryptoError::UnknownSuite),
            None => return Err(CryptoError::MalformedCbor),
        }
        let enc = enc.ok_or(CryptoError::MalformedCbor)?;
        if enc.len() != ENC_BYTES {
            return Err(CryptoError::InvalidLength {
                expected: ENC_BYTES,
                actual: enc.len(),
            });
        }
        let ciphertext = ciphertext.ok_or(CryptoError::MalformedCbor)?;
        if ciphertext.len() < 16 {
            return Err(CryptoError::InvalidLength {
                expected: 16,
                actual: ciphertext.len(),
            });
        }
        let mut fixed = [0u8; ENC_BYTES];
        fixed.copy_from_slice(&enc);
        Ok(Self {
            enc: fixed,
            ciphertext,
        })
    }
}

impl fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedKey")
            .field("enc_len", &ENC_BYTES)
            .field("ct_len", &self.ciphertext.len())
            .finish()
    }
}

/// Seals `plaintext` to `recipient_public` with the v1 KEM (X25519).
pub fn seal_to(
    recipient_public: &[u8; PUBLIC_KEY_BYTES],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<SealedKey> {
    seal_to_with(KemChoice::X25519, recipient_public, info, aad, plaintext)
}

/// Seals with an explicit KEM choice. Only [`KemChoice::X25519`] is wired in v1.
pub fn seal_to_with(
    kem: KemChoice,
    recipient_public: &[u8; PUBLIC_KEY_BYTES],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<SealedKey> {
    match kem {
        KemChoice::X25519 => {}
        KemChoice::XWingMlKem768 => return Err(CryptoError::UnsupportedKem),
    }

    let public = <HpkeKem as KemTrait>::PublicKey::from_bytes(recipient_public)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let (enc, mut context) =
        hpke::setup_sender::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeS::Base, &public, info)
            .map_err(|_| CryptoError::InvalidEncoding)?;
    let ciphertext = context
        .seal(plaintext, aad)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let enc_bytes = enc.to_bytes();
    let mut fixed = [0u8; ENC_BYTES];
    if enc_bytes.len() != ENC_BYTES {
        return Err(CryptoError::InvalidLength {
            expected: ENC_BYTES,
            actual: enc_bytes.len(),
        });
    }
    fixed.copy_from_slice(&enc_bytes);
    Ok(SealedKey {
        enc: fixed,
        ciphertext,
    })
}

/// Opens a sealed key with the recipient's secret.
pub fn open_from(
    recipient: &HpkeRecipient,
    info: &[u8],
    aad: &[u8],
    sealed: &SealedKey,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let secret = <HpkeKem as KemTrait>::PrivateKey::from_bytes(&recipient.0.to_bytes())
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let enc = <HpkeKem as KemTrait>::EncappedKey::from_bytes(&sealed.enc)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let mut context =
        hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &secret, &enc, info)
            .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext = context
        .open(&sealed.ciphertext, aad)
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"vk-share-info";
    const AAD: &[u8] = b"vk-share-aad";

    fn recipient() -> HpkeRecipient {
        HpkeRecipient::from_bytes([0x5Au8; 32])
    }

    #[test]
    fn round_trip() {
        let r = recipient();
        let sealed = seal_to(&r.public_bytes(), INFO, AAD, b"vault key material").expect("seal");
        let opened = open_from(&r, INFO, AAD, &sealed).expect("open");
        assert_eq!(&opened[..], b"vault key material");
    }

    #[test]
    fn wrong_recipient_fails() {
        let sealed = seal_to(&recipient().public_bytes(), INFO, AAD, b"x").expect("seal");
        let other = HpkeRecipient::from_bytes([0x5Bu8; 32]);
        assert_eq!(
            open_from(&other, INFO, AAD, &sealed).expect_err("wrong key"),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn wrong_info_or_aad_fails() {
        let r = recipient();
        let sealed = seal_to(&r.public_bytes(), INFO, AAD, b"x").expect("seal");
        assert_eq!(
            open_from(&r, b"other-info", AAD, &sealed).expect_err("info"),
            CryptoError::DecryptionFailed
        );
        assert_eq!(
            open_from(&r, INFO, b"other-aad", &sealed).expect_err("aad"),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn tampered_enc_or_ciphertext_fails() {
        let r = recipient();
        let sealed = seal_to(&r.public_bytes(), INFO, AAD, b"x").expect("seal");

        let mut enc = sealed.enc;
        enc[0] ^= 0x01;
        let tampered = SealedKey {
            enc,
            ciphertext: sealed.ciphertext.clone(),
        };
        assert!(open_from(&r, INFO, AAD, &tampered).is_err());

        let mut ciphertext = sealed.ciphertext.clone();
        ciphertext[0] ^= 0x01;
        let tampered = SealedKey {
            enc: sealed.enc,
            ciphertext,
        };
        assert!(open_from(&r, INFO, AAD, &tampered).is_err());
    }

    #[test]
    fn cbor_round_trip_and_strictness() {
        let r = recipient();
        let sealed = seal_to(&r.public_bytes(), INFO, AAD, b"x").expect("seal");
        let bytes = sealed.to_cbor().expect("encode");
        let parsed = SealedKey::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed, sealed);

        let map = canonical_map(vec![
            ("suite", Value::Text("v2".to_string())),
            ("enc", Value::Bytes(vec![0u8; ENC_BYTES])),
            ("ct", Value::Bytes(vec![0u8; 16])),
        ]);
        let bad = canonical_bytes(&map).expect("encode");
        assert_eq!(
            SealedKey::from_cbor(&bad).expect_err("v2"),
            CryptoError::UnknownSuite
        );
    }

    #[test]
    fn hybrid_kem_is_not_wired_yet() {
        assert_eq!(
            seal_to_with(KemChoice::XWingMlKem768, &[0u8; 32], INFO, AAD, b"x")
                .expect_err("hybrid"),
            CryptoError::UnsupportedKem
        );
    }

    #[test]
    fn debug_redacts_recipient() {
        assert!(format!("{:?}", recipient()).contains("redacted"));
    }
}
