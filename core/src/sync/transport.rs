//! The `Transport` trait and its associated types (SPEC §7.10).
//!
//! Every backend (HTTP relay, synced folder, in-memory) implements this one
//! trait.  The sync engine only calls methods on a `dyn Transport`, so the
//! evil-relay harness can wrap any transport and inject faults.

use crate::oplog::head::VaultHead;
use crate::oplog::op::StoredOp;

/// Ops and head returned by [`Transport::pull`].
#[derive(Debug)]
pub struct VaultOps {
    /// All ops for the vault that the caller does not have yet.
    pub ops: Vec<StoredOp>,
    /// The head the backend claims is current, if any.
    pub head: Option<VaultHead>,
}

/// Everything that can go wrong in the sync layer.
///
/// Every variant maps one-to-one onto a detected attack in the threat model.
/// None of them carry plaintext data, vault content, or keys.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// The backend returned an op or head that failed cryptographic
    /// verification (signature, AAD, Lamport, or canonical encoding).
    #[error("transport returned an op that failed verification")]
    OpVerificationFailed,

    /// The backend returned a head that does not descend from the pinned head
    /// (SPEC §6.9 step 3) — a rollback attack.
    #[error("relay is serving a history that does not descend from the pinned head")]
    RollbackDetected,

    /// Two conflicting heads for the same vault, neither descending from the
    /// other (SPEC §6.9 fork rule).
    #[error("two conflicting histories for the same vault")]
    ForkDetected,

    /// `op_count` or `lamport_max` went backwards after the relay's head
    /// appeared to be a fast-forward (SPEC §6.9 step 4).
    #[error("head counters went backwards")]
    HeadCountersRegressed,

    /// A received op references a parent hash that is not present among the
    /// ops the backend returned (SPEC §6.4).
    #[error("relay withheld a parent op")]
    MissingParent,

    /// The backend returned an op or head with the wrong vault id.
    #[error("backend returned data for a different vault")]
    VaultMismatch,

    /// The backend returned structurally invalid CBOR — a malformed op or head.
    #[error("malformed op or head bytes")]
    MalformedPayload,

    /// The device certificate embedded in the received head or op is not
    /// signed by the pinned identity key.
    #[error("device certificate does not chain to the pinned identity key")]
    CertificateInvalid,

    /// The backend returned bytes that suggest a different suite id — a
    /// downgrade attempt.
    #[error("unknown or downgraded suite id")]
    UnknownSuite,

    /// A generic transport I/O error (network, file system, permission).
    #[error("transport I/O error: {0}")]
    Io(String),

    /// The backend returned a head whose `heads` entries include a hash we do
    /// not have — the relay is hiding ops (§6.4 detectable gap).
    #[error("head references ops that were not returned")]
    HeadReferencesUnknownOp,

    /// An op arrived with the right bytes but the payload AEAD failed — a
    /// ciphertext swap or byte-flip attack.
    #[error("op payload authentication failed")]
    PayloadAuthFailed,
}

impl From<crate::error::CoreError> for SyncError {
    fn from(e: crate::error::CoreError) -> Self {
        use crate::error::CoreError;
        match e {
            CoreError::RollbackDetected => SyncError::RollbackDetected,
            CoreError::ForkDetected => SyncError::ForkDetected,
            CoreError::HeadCountersRegressed => SyncError::HeadCountersRegressed,
            CoreError::UnknownParent => SyncError::MissingParent,
            CoreError::HeadVerificationFailed => SyncError::OpVerificationFailed,
            CoreError::OpVerificationFailed => SyncError::OpVerificationFailed,
            CoreError::MalformedPayload => SyncError::MalformedPayload,
            CoreError::Crypto(crate::crypto::CryptoError::UnknownSuite) => SyncError::UnknownSuite,
            _ => SyncError::MalformedPayload,
        }
    }
}

/// The transport backend.
///
/// Implementations are required to be **honest about their own errors**: a
/// transport that lies (wrong vault id, truncated ops, old head) is the
/// _attacker model_ tested by the evil-relay harness.  Implementations MUST
/// pass [`VaultOps`] bytes through unchanged — no re-encoding, no reordering.
pub trait Transport {
    /// Push `ops` to the backend.  Returns the number of ops the backend
    /// accepted.  Idempotent per `op_id` per SPEC §7.4.
    fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError>;

    /// Fetch ops for `vault_id` that come after `cursor` (the last op hash
    /// the caller has), and the current head.
    ///
    /// `cursor = None` means "give me everything".  The backend returns ops in
    /// topological order (each parent before its children); clients re-verify
    /// this by running them through the DAG.
    fn pull(&mut self, vault_id: [u8; 16], cursor: Option<[u8; 32]>)
        -> Result<VaultOps, SyncError>;

    /// Compare-and-swap the head.  `expected_hash` is the hash of the head
    /// the caller believes is current; `*` (all-zeros) for the first head.
    ///
    /// Returns `Ok(())` on success, `Err(SyncError::ForkDetected)` on a 409-
    /// equivalent (the server disagrees on the current head).
    fn put_head(
        &mut self,
        vault_id: [u8; 16],
        head: &VaultHead,
        expected_hash: [u8; 32],
    ) -> Result<(), SyncError>;
}

/// Helper: the all-zeros hash used as the "no previous head" sentinel for CAS.
pub const NO_HEAD: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_error_formats_without_secrets() {
        let e = SyncError::RollbackDetected;
        let s = format!("{e}");
        assert!(s.contains("pinned head"), "{s}");
        let e2 = SyncError::Io("permission denied".into());
        let s2 = format!("{e2}");
        assert!(s2.contains("permission denied"), "{s2}");
    }

    #[test]
    fn core_errors_convert_to_sync_errors() {
        let ce = crate::error::CoreError::RollbackDetected;
        let se: SyncError = ce.into();
        assert_eq!(se, SyncError::RollbackDetected);

        let ce2 = crate::error::CoreError::ForkDetected;
        let se2: SyncError = ce2.into();
        assert_eq!(se2, SyncError::ForkDetected);
    }
}
