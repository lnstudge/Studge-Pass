//! Local encrypted storage (task item 3, D-0306).
//!
//! The store holds exactly three kinds of record: op ciphertext with its signed
//! header, sealed key envelopes (account bundle, vault keys) and non-secret
//! metadata. There is no plaintext table and no plaintext column, so copying
//! the database of a locked device tells an attacker nothing it could not read
//! from the relay.
//!
//! Two implementations exist: [`MemoryStore`] for tests and the browser-shaped
//! clients, and the SQLite store (native targets) for the CLI and desktop.

pub mod memory;

#[cfg(not(target_arch = "wasm32"))]
pub mod sqlite;

pub use memory::MemoryStore;

#[cfg(not(target_arch = "wasm32"))]
pub use sqlite::SqliteStore;

use crate::account::AccountBundle;
use crate::crypto::aead::Envelope;
use crate::error::CoreResult;
use crate::oplog::head::VaultHead;
use crate::oplog::op::{OpHash, StoredOp};

/// The storage schema this build writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The metadata key that records [`SCHEMA_VERSION`].
pub const META_SCHEMA_VERSION: &str = "schema_version";

/// A local, append-only store of ciphertext.
pub trait LocalStore {
    /// The schema version recorded in the store.
    fn schema_version(&self) -> CoreResult<u32>;

    /// Stores an op by hash. Re-storing the same op is a no-op.
    fn put_op(&mut self, op: &StoredOp) -> CoreResult<()>;

    /// Reads an op by hash.
    fn get_op(&self, vault_id: &[u8; 16], hash: &OpHash) -> CoreResult<Option<StoredOp>>;

    /// Every op of a vault, ordered by `(lamport, hash)`.
    fn list_ops(&self, vault_id: &[u8; 16]) -> CoreResult<Vec<StoredOp>>;

    /// Number of stored ops for a vault.
    fn count_ops(&self, vault_id: &[u8; 16]) -> CoreResult<usize>;

    /// Stores the latest verified head for a vault.
    fn put_head(&mut self, head: &VaultHead) -> CoreResult<()>;

    /// The latest stored head for a vault.
    fn get_head(&self, vault_id: &[u8; 16]) -> CoreResult<Option<VaultHead>>;

    /// Stores the account record (all envelopes).
    fn put_bundle(&mut self, bundle: &AccountBundle) -> CoreResult<()>;

    /// The account record, if present.
    fn get_bundle(&self, account_id: &[u8; 16]) -> CoreResult<Option<AccountBundle>>;

    /// Stores a wrapped vault key.
    fn put_vault_key(&mut self, vault_id: &[u8; 16], envelope: &Envelope) -> CoreResult<()>;

    /// The wrapped vault key, if present.
    fn get_vault_key(&self, vault_id: &[u8; 16]) -> CoreResult<Option<Envelope>>;

    /// Stores non-secret metadata (schema version, UI preferences).
    fn put_meta(&mut self, key: &str, value: &[u8]) -> CoreResult<()>;

    /// Reads non-secret metadata.
    fn get_meta(&self, key: &str) -> CoreResult<Option<Vec<u8>>>;

    /// Removes every record of one vault (ops, head, wrapped key).
    fn delete_vault(&mut self, vault_id: &[u8; 16]) -> CoreResult<()>;
}

/// Rejects a store written by a newer build (no downgrade path).
pub(crate) fn check_schema(version: u32) -> CoreResult<()> {
    if version != SCHEMA_VERSION {
        return Err(crate::error::CoreError::UnsupportedSchemaVersion);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::Timestamp;

    #[test]
    fn the_schema_version_is_closed() {
        check_schema(1).expect("v1");
        assert!(check_schema(2).is_err());
        assert!(check_schema(0).is_err());
        assert!(!META_SCHEMA_VERSION.is_empty());
        let _ = Timestamp::now().expect("clock");
    }
}
