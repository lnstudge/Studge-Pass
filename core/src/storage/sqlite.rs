//! The SQLite [`LocalStore`] (native targets only).
//!
//! Four tables, all of them ciphertext or metadata: `ops` (canonical op bytes),
//! `heads`, `bundles`, `vault_keys`, plus a `meta` table for the schema
//! version. There is deliberately no table of item fields, titles or URLs
//! (D-0306), and the test at the bottom greps the database file for the demo
//! plaintext to prove it.

use crate::account::AccountBundle;
use crate::crypto::aead::Envelope;
use crate::error::{CoreError, CoreResult};
use crate::oplog::head::VaultHead;
use crate::oplog::op::{OpHash, StoredOp};
use crate::storage::{check_schema, LocalStore, META_SCHEMA_VERSION, SCHEMA_VERSION};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS ops (
    vault_id BLOB NOT NULL,
    hash     BLOB NOT NULL,
    lamport  INTEGER NOT NULL,
    body     BLOB NOT NULL,
    PRIMARY KEY (vault_id, hash)
) STRICT;
CREATE INDEX IF NOT EXISTS ops_by_vault ON ops (vault_id, lamport);
CREATE TABLE IF NOT EXISTS heads (
    vault_id BLOB PRIMARY KEY,
    body     BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS bundles (
    account_id BLOB PRIMARY KEY,
    body       BLOB NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vault_keys (
    vault_id BLOB PRIMARY KEY,
    envelope BLOB NOT NULL
) STRICT;
";

/// A SQLite-backed store.
pub struct SqliteStore {
    connection: Connection,
}

impl std::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStore(<connection>)")
    }
}

impl SqliteStore {
    /// Opens (or creates) the store at `path`.
    pub fn open(path: &Path) -> CoreResult<Self> {
        let connection = Connection::open(path).map_err(|_| CoreError::StorageFailure)?;
        Self::initialise(connection)
    }

    /// An in-memory SQLite store (tests).
    pub fn open_in_memory() -> CoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(|_| CoreError::StorageFailure)?;
        Self::initialise(connection)
    }

    fn initialise(connection: Connection) -> CoreResult<Self> {
        connection
            .execute_batch("PRAGMA secure_delete = ON;")
            .map_err(|_| CoreError::StorageFailure)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| CoreError::StorageFailure)?;
        let store = Self { connection };
        let existing: Option<Vec<u8>> = store
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![META_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)?;
        match existing {
            Some(raw) => {
                if raw.len() != 4 {
                    return Err(CoreError::UnsupportedSchemaVersion);
                }
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&raw);
                check_schema(u32::from_be_bytes(bytes))?;
            }
            None => {
                let mut store = store;
                store.put_meta_raw(SCHEMA_VERSION.to_be_bytes().to_vec())?;
                return Ok(store);
            }
        }
        Ok(store)
    }

    fn put_meta_raw(&mut self, value: Vec<u8>) -> CoreResult<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![META_SCHEMA_VERSION, value],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }
}

impl LocalStore for SqliteStore {
    fn schema_version(&self) -> CoreResult<u32> {
        let raw: Vec<u8> = self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![META_SCHEMA_VERSION],
                |row| row.get(0),
            )
            .map_err(|_| CoreError::StorageFailure)?;
        if raw.len() != 4 {
            return Err(CoreError::UnsupportedSchemaVersion);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&raw);
        let version = u32::from_be_bytes(bytes);
        check_schema(version)?;
        Ok(version)
    }

    fn put_op(&mut self, op: &StoredOp) -> CoreResult<()> {
        let hash = op.hash()?;
        let body = op.to_cbor()?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO ops (vault_id, hash, lamport, body) VALUES (?1, ?2, ?3, ?4)",
                params![
                    op.op().vault_id().to_vec(),
                    hash.to_vec(),
                    op.op().lamport() as i64,
                    body
                ],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }

    fn get_op(&self, vault_id: &[u8; 16], hash: &OpHash) -> CoreResult<Option<StoredOp>> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT body FROM ops WHERE vault_id = ?1 AND hash = ?2",
                params![vault_id.to_vec(), hash.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)?;
        match body {
            Some(bytes) => Ok(Some(StoredOp::from_cbor(&bytes)?)),
            None => Ok(None),
        }
    }

    fn list_ops(&self, vault_id: &[u8; 16]) -> CoreResult<Vec<StoredOp>> {
        let mut statement = self
            .connection
            .prepare("SELECT body FROM ops WHERE vault_id = ?1 ORDER BY lamport, hash")
            .map_err(|_| CoreError::StorageFailure)?;
        let rows = statement
            .query_map(params![vault_id.to_vec()], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| CoreError::StorageFailure)?;
        let mut ops = Vec::new();
        for row in rows {
            let bytes = row.map_err(|_| CoreError::StorageFailure)?;
            ops.push(StoredOp::from_cbor(&bytes)?);
        }
        Ok(ops)
    }

    fn count_ops(&self, vault_id: &[u8; 16]) -> CoreResult<usize> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM ops WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |row| row.get(0),
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(count as usize)
    }

    fn put_head(&mut self, head: &VaultHead) -> CoreResult<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO heads (vault_id, body) VALUES (?1, ?2)",
                params![head.vault_id().to_vec(), head.to_cbor()?],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }

    fn get_head(&self, vault_id: &[u8; 16]) -> CoreResult<Option<VaultHead>> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT body FROM heads WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)?;
        match body {
            Some(bytes) => Ok(Some(VaultHead::from_cbor(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_bundle(&mut self, bundle: &AccountBundle) -> CoreResult<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO bundles (account_id, body) VALUES (?1, ?2)",
                params![bundle.account_id().to_vec(), bundle.to_cbor()?],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }

    fn get_bundle(&self, account_id: &[u8; 16]) -> CoreResult<Option<AccountBundle>> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT body FROM bundles WHERE account_id = ?1",
                params![account_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)?;
        match body {
            Some(bytes) => Ok(Some(AccountBundle::from_cbor(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_vault_key(&mut self, vault_id: &[u8; 16], envelope: &Envelope) -> CoreResult<()> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO vault_keys (vault_id, envelope) VALUES (?1, ?2)",
                params![vault_id.to_vec(), envelope.to_cbor()?],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }

    fn get_vault_key(&self, vault_id: &[u8; 16]) -> CoreResult<Option<Envelope>> {
        let body: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT envelope FROM vault_keys WHERE vault_id = ?1",
                params![vault_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)?;
        match body {
            Some(bytes) => Ok(Some(Envelope::from_cbor(&bytes)?)),
            None => Ok(None),
        }
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> CoreResult<()> {
        if key == META_SCHEMA_VERSION {
            return Err(CoreError::StorageFailure);
        }
        self.connection
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value.to_vec()],
            )
            .map_err(|_| CoreError::StorageFailure)?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> CoreResult<Option<Vec<u8>>> {
        self.connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| CoreError::StorageFailure)
    }

    fn delete_vault(&mut self, vault_id: &[u8; 16]) -> CoreResult<()> {
        for table in ["ops", "heads", "vault_keys"] {
            self.connection
                .execute(
                    &format!("DELETE FROM {table} WHERE vault_id = ?1"),
                    params![vault_id.to_vec()],
                )
                .map_err(|_| CoreError::StorageFailure)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{SigningKeyPair, Timestamp};
    use crate::oplog::op::{Op, OpKind};
    use crate::vault::items::{Item, ItemKind, UrlMatch};
    use std::path::PathBuf;

    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "studge-test-{}-{}-{name}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        path
    }

    fn demo_op(device: &SigningKeyPair, vk: &VaultKey) -> StoredOp {
        let mut item =
            Item::new(ITEM, VAULT, ItemKind::Login, at("2026-11-05T09:00:00Z")).expect("item");
        item.set_field("title", "Demo Bank Login", &at("2026-11-05T09:00:00Z"))
            .expect("title");
        item.set_field(
            "password",
            "hunter2-demo-password",
            &at("2026-11-05T09:00:00Z"),
        )
        .expect("password");
        item.add_url(
            "https://demo-bank.example/login",
            UrlMatch::ExactHost,
            &at("2026-11-05T09:00:00Z"),
        )
        .expect("url");
        let payload = item.to_payload_bytes().expect("payload");
        let sealed = Op::seal_payload(vk, &VAULT, &ITEM, OpKind::Create, &payload).expect("seal");
        Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            DEVICE,
            at("2026-11-05T10:00:00Z"),
            OpKind::Create,
            Some(ITEM),
            sealed,
        )
        .expect("op")
        .sign(device)
        .expect("sign")
    }

    #[test]
    fn round_trips_ops_and_heads() {
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let vk = VaultKey::from_bytes([3u8; 32]);
        let mut store = SqliteStore::open_in_memory().expect("store");
        assert_eq!(store.schema_version().expect("schema"), 1);

        let op = demo_op(&device, &vk);
        store.put_op(&op).expect("put");
        assert_eq!(store.count_ops(&VAULT).expect("count"), 1);
        let read = store
            .get_op(&VAULT, &op.hash().expect("hash"))
            .expect("get")
            .expect("present");
        assert_eq!(read.hash().expect("hash"), op.hash().expect("hash"));
        assert_eq!(store.list_ops(&VAULT).expect("list").len(), 1);

        let head = VaultHead::create(
            &device,
            VAULT,
            DEVICE,
            vec![op.hash().expect("hash")],
            1,
            1,
            at("2026-11-05T10:05:00Z"),
        )
        .expect("head");
        store.put_head(&head).expect("head");
        assert_eq!(
            store
                .get_head(&VAULT)
                .expect("get")
                .expect("head")
                .hash()
                .expect("hash"),
            head.hash().expect("hash")
        );
    }

    #[test]
    fn the_database_file_contains_no_plaintext() {
        let path = temp_path("leak");
        {
            let device = SigningKeyPair::from_seed([2u8; 32]);
            let vk = VaultKey::from_bytes([3u8; 32]);
            let mut store = SqliteStore::open(&path).expect("open");
            let op = demo_op(&device, &vk);
            store.put_op(&op).expect("put");
            let head = VaultHead::create(
                &device,
                VAULT,
                DEVICE,
                vec![op.hash().expect("hash")],
                1,
                1,
                at("2026-11-05T10:05:00Z"),
            )
            .expect("head");
            store.put_head(&head).expect("head");
        }
        let bytes = std::fs::read(&path).expect("read db");
        let _ = std::fs::remove_file(&path);
        let haystack = String::from_utf8_lossy(&bytes);
        for needle in [
            "Demo Bank Login",
            "hunter2-demo-password",
            "demo-bank.example",
            "password",
        ] {
            assert!(
                !haystack.contains(needle),
                "the database file leaked {needle:?}"
            );
        }
    }

    #[test]
    fn a_future_schema_is_rejected() {
        let path = temp_path("schema");
        {
            let store = SqliteStore::open(&path).expect("open");
            drop(store);
        }
        // Rewrite the recorded version to v2.
        {
            let connection = Connection::open(&path).expect("reopen");
            connection
                .execute(
                    "UPDATE meta SET value = ?1 WHERE key = ?2",
                    params![2u32.to_be_bytes().to_vec(), META_SCHEMA_VERSION],
                )
                .expect("update");
        }
        let result = SqliteStore::open(&path);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(result, Err(CoreError::UnsupportedSchemaVersion)));
    }

    #[test]
    fn deleting_a_vault_keeps_other_vaults() {
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let vk = VaultKey::from_bytes([3u8; 32]);
        let mut store = SqliteStore::open_in_memory().expect("store");
        let op = demo_op(&device, &vk);
        store.put_op(&op).expect("put");
        store.delete_vault(&[0x99; 16]).expect("noop");
        assert_eq!(store.count_ops(&VAULT).expect("count"), 1);
        store.delete_vault(&VAULT).expect("delete");
        assert_eq!(store.count_ops(&VAULT).expect("count"), 0);
    }
}
