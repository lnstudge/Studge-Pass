//! KDF (SPEC §4.3–§4.4): NFKC + Argon2id to the MUK, HKDF-SHA256 for every
//! sub-key.
//!
//! Parameter handling is deliberately strict: `derive_muk` refuses anything
//! below the §4.3 floor, so a recorded account cannot be downgraded to cheaper
//! parameters. Tests that need speed use the crate-internal `derive_muk_raw`.

use crate::crypto::aead::{AeadKey, KEY_BYTES};
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::keys::MasterUnlockKey;
use crate::crypto::labels;
use crate::crypto::secret_key::SecretKey;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The Argon2 algorithm version used by suite `v1`.
pub const ARGON2_VERSION: u32 = 0x13;
/// Minimum memory cost, in KiB (64 MiB).
pub const MIN_M_COST_KIB: u32 = 65_536;
/// Minimum iterations.
pub const MIN_T_COST: u32 = 3;
/// Minimum parallelism.
pub const MIN_P_COST: u32 = 1;
/// Account salt length.
pub const SALT_BYTES: usize = 16;
/// MUK length.
pub const MUK_BYTES: usize = 32;

/// Versioned Argon2id parameters, stored with the account record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Parameter-set version. Only `1` exists.
    pub version: u8,
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

impl KdfParams {
    /// The parameters SPEC §4.3 mandates for v1.
    pub const V1: Self = Self {
        version: 1,
        m_kib: MIN_M_COST_KIB,
        t: MIN_T_COST,
        p: MIN_P_COST,
    };

    /// Rejects unknown versions and anything weaker than the §4.3 floor.
    pub fn validate(&self) -> CryptoResult<()> {
        if self.version != 1 {
            return Err(CryptoError::UnsupportedKdfVersion);
        }
        if self.m_kib < MIN_M_COST_KIB || self.t < MIN_T_COST || self.p < MIN_P_COST {
            return Err(CryptoError::WeakKdfParameters);
        }
        Ok(())
    }
}

/// Derives the Master Unlock Key.
///
/// `MUK = HKDF-SHA256(ikm = Argon2id(NFKC(password), salt, params) || secret_key,
/// info = "studge/v1/muk", L = 32)`
pub fn derive_muk(
    password: &str,
    salt: &[u8; SALT_BYTES],
    secret_key: &SecretKey,
    params: KdfParams,
) -> CryptoResult<MasterUnlockKey> {
    params.validate()?;
    derive_muk_raw(password, salt, secret_key, params)
}

/// The Argon2 work without the policy check. Used by unit tests with small
/// parameters; never call it from product code.
pub(crate) fn derive_muk_raw(
    password: &str,
    salt: &[u8; SALT_BYTES],
    secret_key: &SecretKey,
    params: KdfParams,
) -> CryptoResult<MasterUnlockKey> {
    if params.version != 1 {
        return Err(CryptoError::UnsupportedKdfVersion);
    }

    // NFKC so that every client feeds the same bytes for the same password.
    let normalised: String = password.nfkc().collect();

    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(MUK_BYTES))
        .map_err(|_| CryptoError::WeakKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut argon_out = Zeroizing::new([0u8; MUK_BYTES]);
    argon
        .hash_password_into(normalised.as_bytes(), salt, argon_out.as_mut())
        .map_err(|_| CryptoError::WeakKdfParameters)?;

    let mut ikm = Zeroizing::new([0u8; MUK_BYTES + 16]);
    ikm[..MUK_BYTES].copy_from_slice(&argon_out[..]);
    ikm[MUK_BYTES..].copy_from_slice(secret_key.as_bytes());

    let mut okm = Zeroizing::new([0u8; MUK_BYTES]);
    let hk = Hkdf::<Sha256>::new(None, &ikm[..]);
    hk.expand(labels::MUK.as_bytes(), okm.as_mut())
        .map_err(|_| CryptoError::InvalidLength {
            expected: MUK_BYTES,
            actual: 0,
        })?;
    Ok(MasterUnlockKey::from_bytes(*okm))
}

/// HKDF-SHA256 expansion with an optional salt, returning 32 bytes as an
/// [`AeadKey`].
pub fn derive_subkey(ikm: &[u8], salt: Option<&[u8]>, label: &str) -> CryptoResult<AeadKey> {
    let mut okm = Zeroizing::new([0u8; KEY_BYTES]);
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(label.as_bytes(), okm.as_mut())
        .map_err(|_| CryptoError::InvalidLength {
            expected: KEY_BYTES,
            actual: 0,
        })?;
    Ok(AeadKey::from_bytes(*okm))
}

/// The OPAQUE password input (SPEC §4.4).
pub fn auth_secret(muk: &MasterUnlockKey) -> CryptoResult<AeadKey> {
    derive_subkey(muk.as_bytes(), None, labels::OPAQUE_PASSWORD)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_BYTES] = [0x5A; SALT_BYTES];

    fn fast() -> KdfParams {
        // Far below the production floor: this path is the raw one.
        KdfParams {
            version: 1,
            m_kib: 8,
            t: 1,
            p: 1,
        }
    }

    fn muk(password: &str, salt: &[u8; SALT_BYTES], sk: &SecretKey) -> MasterUnlockKey {
        derive_muk_raw(password, salt, sk, fast()).expect("raw derivation")
    }

    #[test]
    fn derivation_is_deterministic() {
        let sk = SecretKey::from_bytes([7u8; 16]);
        let a = muk("correct horse battery staple", &SALT, &sk);
        let b = muk("correct horse battery staple", &SALT, &sk);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn every_input_changes_the_muk() {
        let sk = SecretKey::from_bytes([7u8; 16]);
        let base = muk("password", &SALT, &sk);
        let other_password = muk("password ", &SALT, &sk);
        let other_salt = muk("password", &[0x5B; SALT_BYTES], &sk);
        let other_key = muk("password", &SALT, &SecretKey::from_bytes([8u8; 16]));
        assert_ne!(base.as_bytes(), other_password.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
        assert_ne!(base.as_bytes(), other_key.as_bytes());
    }

    #[test]
    fn nfkc_normalises_equivalent_passwords() {
        let sk = SecretKey::from_bytes([7u8; 16]);
        // U+00E9 (precomposed) vs e + U+0301 (decomposed).
        let composed = muk("caf\u{00e9}", &SALT, &sk);
        let decomposed = muk("cafe\u{0301}", &SALT, &sk);
        assert_eq!(composed.as_bytes(), decomposed.as_bytes());
    }

    #[test]
    fn rejects_weak_parameters_and_unknown_versions() {
        let sk = SecretKey::from_bytes([7u8; 16]);
        let weak = KdfParams {
            version: 1,
            m_kib: 1024,
            t: 3,
            p: 1,
        };
        assert_eq!(
            derive_muk("pw", &SALT, &sk, weak).expect_err("weak"),
            CryptoError::WeakKdfParameters
        );
        let future = KdfParams {
            version: 2,
            ..KdfParams::V1
        };
        assert_eq!(
            derive_muk("pw", &SALT, &sk, future).expect_err("v2"),
            CryptoError::UnsupportedKdfVersion
        );
        assert!(KdfParams::V1.validate().is_ok());
    }

    #[test]
    fn subkeys_differ_by_label_and_salt() {
        let ikm = [1u8; 32];
        let a = derive_subkey(&ikm, None, labels::AK_WRAP).expect("a");
        let b = derive_subkey(&ikm, None, labels::VK_WRAP).expect("b");
        let c = derive_subkey(&ikm, Some(&[2u8; 16]), labels::VK_WRAP).expect("c");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(c.as_bytes(), b.as_bytes());
    }

    #[test]
    fn auth_secret_is_not_the_muk() {
        let sk = SecretKey::from_bytes([7u8; 16]);
        let m = muk("pw", &SALT, &sk);
        let auth = auth_secret(&m).expect("auth secret");
        assert_ne!(m.as_bytes(), auth.as_bytes());
    }
}
