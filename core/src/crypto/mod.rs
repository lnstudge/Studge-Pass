//! Cryptography for Studge Pass v1.
//!
//! Implements `docs/SPEC.md` §4 (identities and keys) and §5 (encryption
//! format) exactly. Nothing here does I/O: callers pass bytes in and get bytes
//! out, and every failure is a `CryptoError`.
//!
//! Rules that apply to every module below:
//!
//! - randomness comes only from [`random`];
//! - every HKDF label lives in [`labels`];
//! - ciphertexts are only produced through [`aead`], which requires an [`aad::Aad`];
//! - secrets are wrapped in zeroizing types and their `Debug` is redacted.

pub mod aad;
pub mod aead;
pub mod error;
pub mod hpke;
pub mod kdf;
pub mod keys;
pub mod labels;
pub mod random;
pub mod secret_key;
pub mod signing;
