//! Error type shared by the crypto module.
//!
//! Two rules:
//!
//! 1. No variant carries secret or plaintext data — only lengths, names and
//!    fixed strings, so a `Debug` print of an error cannot leak anything.
//! 2. Decryption failures are deliberately uniform. The caller learns "it did
//!    not authenticate", never whether the tag, the AAD or the key was wrong.

use thiserror::Error;

/// Every failure mode of the crypto module.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A fixed-size input had the wrong length.
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// The length the format requires.
        expected: usize,
        /// The length that was supplied.
        actual: usize,
    },

    /// A character outside the encoding alphabet, or an otherwise malformed string.
    #[error("invalid encoding")]
    InvalidEncoding,

    /// The printed Secret Key checksum did not match.
    #[error("invalid checksum")]
    InvalidChecksum,

    /// The two padding bits of a 26-character Secret Key payload were set.
    #[error("invalid secret key padding")]
    InvalidPadding,

    /// The suite id was missing or not `v1`.
    #[error("unknown cipher suite")]
    UnknownSuite,

    /// A record type outside the closed enumeration of SPEC §5.3.
    #[error("unsupported record type")]
    UnsupportedRecordType,

    /// The AAD builder was not given a field the record type requires.
    #[error("AAD is missing a required field")]
    MissingAadField,

    /// The AAD builder was given a field the record type forbids.
    #[error("AAD has a field the record type does not allow")]
    UnexpectedAadField,

    /// Authentication failed. Deliberately uniform.
    #[error("decryption failed")]
    DecryptionFailed,

    /// A signature, certificate or revocation did not verify.
    #[error("signature verification failed")]
    VerificationFailed,

    /// KDF parameters below the floor in SPEC §4.3 (downgrade attempt).
    #[error("key derivation parameters are below the required minimum")]
    WeakKdfParameters,

    /// An unknown KDF parameter version.
    #[error("unsupported KDF version")]
    UnsupportedKdfVersion,

    /// A KEM the implementation does not provide (currently the hybrid).
    #[error("unsupported KEM")]
    UnsupportedKem,

    /// The operating system random source failed.
    #[error("randomness source failed")]
    RngFailure,

    /// CBOR could not be parsed.
    #[error("malformed CBOR")]
    MalformedCbor,

    /// CBOR parsed but was not in deterministic form.
    #[error("non-canonical CBOR")]
    NonCanonicalCbor,

    /// A timestamp was not in the fixed-width RFC 3339 UTC form.
    #[error("invalid timestamp")]
    InvalidTimestamp,

    /// A device was revoked at or before the object's timestamp.
    #[error("device is revoked")]
    Revoked,

    /// A timestamp is further in the future than the allowed skew.
    #[error("timestamp is too far in the future")]
    ClockSkew,
}

/// Convenient alias for crypto results.
pub type CryptoResult<T> = Result<T, CryptoError>;
