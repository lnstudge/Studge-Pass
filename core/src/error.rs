//! Error type for the vault, op log, storage and import/export layers.
//!
//! Two rules, same as `crypto::error`:
//!
//! 1. No variant carries a secret, a plaintext field value, an item title or a
//!    file path — only fixed strings and numbers. An error printed to a log can
//!    therefore never leak vault content.
//! 2. Failures are fail-closed. There is no "repair" or "skip" path: a record
//!    that does not verify stops the operation and says why.

use crate::crypto::CryptoError;
use thiserror::Error;

/// Every failure mode outside the crypto primitives themselves.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    /// A crypto primitive rejected the input.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// A field name outside the item template (SPEC §5.6).
    #[error("field name is not part of the item template")]
    UnknownField,

    /// A field the template requires was not set.
    #[error("required field is missing")]
    MissingField,

    /// A value longer than the 1 MiB cap (SPEC §5.6).
    #[error("field value is too long")]
    FieldTooLong,

    /// Too many tags, URLs, custom fields or passkeys on one item.
    #[error("too many entries on the item")]
    TooManyEntries,

    /// A tag, title or label empty or over its cap.
    #[error("text value is empty or too long")]
    InvalidText,

    /// An item kind or URL match rule this build does not know.
    #[error("unknown item kind or match rule")]
    UnknownKind,

    /// Item CBOR that is not the expected shape.
    #[error("malformed item payload")]
    MalformedPayload,

    /// The encoded payload is over the 1 MiB op cap (SPEC §6.11).
    #[error("payload exceeds the 1 MiB limit")]
    PayloadTooLarge,

    /// An op whose `kind` this version does not implement (D-0305).
    #[error("operation kind is not supported in v1")]
    UnsupportedOpKind,

    /// An op that breaks the DAG or Lamport rules (SPEC §6.4–6.5).
    #[error("operation is not a valid part of the history")]
    InvalidOp,

    /// A parent hash the client has not seen (SPEC §6.4).
    #[error("operation references an unknown parent")]
    UnknownParent,

    /// Two different ops claim the same id (SPEC §6.1).
    #[error("duplicate operation id with different content")]
    DuplicateOp,

    /// A stored op did not verify: hash, signature, device or payload.
    #[error("operation failed verification")]
    OpVerificationFailed,

    /// The vault head did not verify (SPEC §6.8).
    #[error("vault head failed verification")]
    HeadVerificationFailed,

    /// The relay served a history that does not descend from the pinned head
    /// (SPEC §6.9).
    #[error("history does not descend from the pinned head")]
    RollbackDetected,

    /// Two heads with the same op count, neither descending from the other.
    #[error("two conflicting histories for the same vault")]
    ForkDetected,

    /// `op_count` or `lamport_max` went backwards (SPEC §6.9).
    #[error("head counters went backwards")]
    HeadCountersRegressed,

    /// A vault key was not unlocked.
    #[error("vault is locked")]
    Locked,

    /// A vault id the account does not hold a key for.
    #[error("unknown vault")]
    UnknownVault,

    /// A key bundle entry that is missing or has an unknown name.
    #[error("key bundle is incomplete or malformed")]
    InvalidBundle,

    /// Storage failed.
    #[error("local storage failed")]
    StorageFailure,

    /// A store was opened with a schema version this build does not know.
    #[error("unsupported storage schema version")]
    UnsupportedSchemaVersion,

    /// A backup file that is not the `.studgevault` format.
    #[error("not a Studge Pass backup file")]
    InvalidBackup,

    /// Base64, hex or another text encoding was not in canonical form.
    #[error("invalid encoding")]
    InvalidEncoding,

    /// An import file whose shape is not recognised.
    #[error("unrecognised import format")]
    InvalidImport,

    /// An import entry that could not be mapped without guessing.
    #[error("import entry skipped")]
    ImportSkipped,

    /// A plaintext export was attempted without the explicit opt-in.
    #[error("plaintext export requires allow_plaintext")]
    PlaintextNotAllowed,

    /// A generator or TOTP parameter outside the accepted range.
    #[error("parameter out of range")]
    InvalidParameter,

    /// A key or id had the wrong length.
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Required length in bytes.
        expected: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
}

/// Convenient alias for core results.
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_never_format_secret_material() {
        let printed = format!("{}", CoreError::MalformedPayload);
        assert_eq!(printed, "malformed item payload");
        let printed = format!("{:?}", CoreError::Crypto(CryptoError::DecryptionFailed));
        assert!(printed.contains("DecryptionFailed"));
    }
}
