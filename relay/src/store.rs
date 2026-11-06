//! The relay's storage layer: sqlx + SQLite (Postgres optional), SPEC ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§7.9.
//!
//! Every column holds public metadata or ciphertext. Ops are stored **exactly
//! as received** and never updated; the only destructive path is deleting a
//! whole account, which cascades.

use crate::error::ApiError;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;

/// A stored account.
#[derive(Debug, Clone)]
pub struct AccountRow {
    /// The raw account record (JSON bytes, as received).
    pub record: Vec<u8>,
    /// Its `If-Match` version.
    pub record_version: i64,
    /// The OPAQUE password file.
    pub password_file: Vec<u8>,
    /// Tombstone time, when the account is being deleted.
    pub deleted_at: Option<String>,
}

/// A device row.
#[derive(Debug, Clone)]
pub struct DeviceRow {
    /// The device id.
    pub device_id: Vec<u8>,
    /// Its Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Its certificate bytes.
    pub certificate: Vec<u8>,
    /// When it was certified.
    pub created_at: String,
    /// When it was revoked.
    pub revoked_at: Option<String>,
}

/// A vault row.
#[derive(Debug, Clone)]
pub struct VaultRow {
    /// The signed head bytes, if any.
    pub head: Option<Vec<u8>>,
    /// Its hash, the compare-and-swap token.
    pub head_hash: Option<Vec<u8>>,
    /// Number of stored ops.
    pub op_count: i64,
    /// Highest Lamport clock seen.
    pub lamport_max: i64,
    /// Bytes of op bodies.
    pub storage_bytes: i64,
}

/// One stored op.
#[derive(Debug, Clone)]
pub struct OpRow {
    /// The op hash.
    pub op_hash: Vec<u8>,
    /// The op id.
    pub op_id: Vec<u8>,
    /// The Lamport clock.
    pub lamport: i64,
    /// The raw op bytes.
    pub body: Vec<u8>,
    /// The size of `body`.
    pub size: i64,
}

/// The database handle.
#[derive(Debug, Clone)]
pub struct RelayStore {
    pool: SqlitePool,
}

impl RelayStore {
    /// Opens (or creates) the database, applies pragmas and runs migrations.
    pub async fn open(path: &Path) -> Result<Self, ApiError> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .map_err(|_| ApiError::Unavailable)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(Self { pool })
    }

    /// An in-memory database for tests.
    pub async fn open_in_memory() -> Result<Self, ApiError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(|_| ApiError::Unavailable)?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(Self { pool })
    }

    // ------------------------------------------------------------- accounts

    /// Creates an account; `false` when the id already exists.
    pub async fn create_account(
        &self,
        account_id: &[u8],
        record: &[u8],
        password_file: &[u8],
        created_at: &str,
    ) -> Result<bool, ApiError> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO accounts (account_id, record, record_version, password_file, created_at)
             VALUES (?1, ?2, 1, ?3, ?4)",
        )
        .bind(account_id)
        .bind(record)
        .bind(password_file)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reads an account, including tombstoned ones.
    pub async fn account(&self, account_id: &[u8]) -> Result<Option<AccountRow>, ApiError> {
        let row = sqlx::query(
            "SELECT record, record_version, password_file, deleted_at FROM accounts WHERE account_id = ?1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| AccountRow {
            record: row.get("record"),
            record_version: row.get("record_version"),
            password_file: row.get("password_file"),
            deleted_at: row.get("deleted_at"),
        }))
    }

    /// Replaces the account record when `expected_version` still holds.
    pub async fn replace_account_record(
        &self,
        account_id: &[u8],
        record: &[u8],
        expected_version: i64,
    ) -> Result<bool, ApiError> {
        let result = sqlx::query(
            "UPDATE accounts SET record = ?1, record_version = record_version + 1
             WHERE account_id = ?2 AND record_version = ?3 AND deleted_at IS NULL",
        )
        .bind(record)
        .bind(account_id)
        .bind(expected_version)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected() == 1)
    }

    /// Tombstones an account and drops every session at once.
    pub async fn tombstone_account(&self, account_id: &[u8], at: &str) -> Result<(), ApiError> {
        let mut transaction = self.pool.begin().await.map_err(|_| ApiError::Unavailable)?;
        sqlx::query(
            "UPDATE accounts SET deleted_at = ?1 WHERE account_id = ?2 AND deleted_at IS NULL",
        )
        .bind(at)
        .bind(account_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        sqlx::query("DELETE FROM sessions WHERE account_id = ?1")
            .bind(account_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::Unavailable)
    }

    /// Deletes tombstoned accounts whose tombstone is older than `before`.
    pub async fn purge_tombstones_before(&self, before: &str) -> Result<u64, ApiError> {
        let result =
            sqlx::query("DELETE FROM accounts WHERE deleted_at IS NOT NULL AND deleted_at < ?1")
                .bind(before)
                .execute(&self.pool)
                .await
                .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected())
    }

    // -------------------------------------------------------------- devices

    /// Adds a certified device (idempotent for the same bytes).
    pub async fn add_device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
        public_key: &[u8],
        certificate: &[u8],
        created_at: &str,
    ) -> Result<bool, ApiError> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO devices (account_id, device_id, public_key, certificate, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(public_key)
        .bind(certificate)
        .bind(created_at)
        .execute(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected() == 1)
    }

    /// Marks a device revoked and deletes its sessions in one transaction.
    pub async fn revoke_device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
        revoked_at: &str,
    ) -> Result<bool, ApiError> {
        let mut transaction = self.pool.begin().await.map_err(|_| ApiError::Unavailable)?;
        let result = sqlx::query(
            "UPDATE devices SET revoked_at = ?1 WHERE account_id = ?2 AND device_id = ?3 AND revoked_at IS NULL",
        )
        .bind(revoked_at)
        .bind(account_id)
        .bind(device_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        sqlx::query("DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2")
            .bind(account_id)
            .bind(device_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reads one device.
    pub async fn device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
    ) -> Result<Option<DeviceRow>, ApiError> {
        let row = sqlx::query(
            "SELECT device_id, public_key, certificate, created_at, revoked_at
             FROM devices WHERE account_id = ?1 AND device_id = ?2",
        )
        .bind(account_id)
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| DeviceRow {
            device_id: row.get("device_id"),
            public_key: row.get("public_key"),
            certificate: row.get("certificate"),
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
        }))
    }

    // -------------------------------------------------------------- sessions

    /// Stores a session, replacing the previous one for the same device.
    pub async fn create_session(
        &self,
        token_hash: &[u8],
        account_id: &[u8],
        device_id: &[u8],
        created_at: &str,
        expires_at: &str,
    ) -> Result<(), ApiError> {
        let mut transaction = self.pool.begin().await.map_err(|_| ApiError::Unavailable)?;
        sqlx::query("DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2")
            .bind(account_id)
            .bind(device_id)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        sqlx::query(
            "INSERT INTO sessions (token_hash, account_id, device_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(token_hash)
        .bind(account_id)
        .bind(device_id)
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::Unavailable)
    }

    /// Reads a session by token hash.
    pub async fn session(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>, String)>, ApiError> {
        let row = sqlx::query(
            "SELECT account_id, device_id, expires_at FROM sessions WHERE token_hash = ?1",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| {
            (
                row.get::<Vec<u8>, _>("account_id"),
                row.get::<Vec<u8>, _>("device_id"),
                row.get::<String, _>("expires_at"),
            )
        }))
    }

    /// Deletes one session by token hash.
    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<(), ApiError> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(())
    }

    /// Deletes expired sessions (the sweeper in `main`).
    pub async fn delete_expired_sessions(&self, now: &str) -> Result<u64, ApiError> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected())
    }

    // ----------------------------------------------------------------- vaults

    /// Creates the vault row if it does not exist yet.
    pub async fn ensure_vault(&self, account_id: &[u8], vault_id: &[u8]) -> Result<(), ApiError> {
        sqlx::query("INSERT OR IGNORE INTO vaults (account_id, vault_id) VALUES (?1, ?2)")
            .bind(account_id)
            .bind(vault_id)
            .execute(&self.pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(())
    }

    /// Reads a vault that belongs to `account_id`.
    pub async fn vault(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
    ) -> Result<Option<VaultRow>, ApiError> {
        let row = sqlx::query(
            "SELECT head, head_hash, op_count, lamport_max, storage_bytes
             FROM vaults WHERE account_id = ?1 AND vault_id = ?2",
        )
        .bind(account_id)
        .bind(vault_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| VaultRow {
            head: row.get("head"),
            head_hash: row.get("head_hash"),
            op_count: row.get("op_count"),
            lamport_max: row.get("lamport_max"),
            storage_bytes: row.get("storage_bytes"),
        }))
    }

    /// Total vault bytes for an account (the quota counter).
    pub async fn account_storage_bytes(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        let row = sqlx::query(
            "SELECT COALESCE(SUM(storage_bytes), 0) AS total FROM vaults WHERE account_id = ?1",
        )
        .bind(account_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        Ok(row.get::<i64, _>("total"))
    }

    /// Number of vaults an account has.
    pub async fn vault_count(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM vaults WHERE account_id = ?1")
            .bind(account_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(row.get::<i64, _>("n"))
    }

    /// Inserts ops for one vault. Returns the number actually stored.
    ///
    /// `INSERT OR IGNORE` gives idempotency: the same bytes for the same
    /// `(vault_id, op_id)` are accepted silently; the caller checks for a
    /// *different* hash under an existing `op_id` before calling this.
    pub async fn insert_ops(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        ops: &[OpRow],
        kind_max_lamport: i64,
        now: &str,
    ) -> Result<usize, ApiError> {
        let mut transaction = self.pool.begin().await.map_err(|_| ApiError::Unavailable)?;
        let mut inserted = 0usize;
        let mut bytes = 0i64;
        for op in ops {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO ops
                 (op_hash, vault_id, op_id, lamport, kind, item_id, device_id, created_at, body, size)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9)",
            )
            .bind(&op.op_hash)
            .bind(vault_id)
            .bind(&op.op_id)
            .bind(op.lamport)
            .bind("create")
            .bind(account_id)
            .bind(now)
            .bind(&op.body)
            .bind(op.size)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
            if result.rows_affected() == 1 {
                inserted += 1;
                bytes += op.size;
            }
        }
        sqlx::query(
            "UPDATE vaults SET op_count = op_count + ?1,
                               lamport_max = MAX(lamport_max, ?2),
                               storage_bytes = storage_bytes + ?3
             WHERE account_id = ?4 AND vault_id = ?5",
        )
        .bind(inserted as i64)
        .bind(kind_max_lamport)
        .bind(bytes)
        .bind(account_id)
        .bind(vault_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(inserted)
    }

    /// The stored op hash for an `(vault_id, op_id)`, if any.
    pub async fn op_hash_for_id(
        &self,
        vault_id: &[u8],
        op_id: &[u8],
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let row = sqlx::query("SELECT op_hash FROM ops WHERE vault_id = ?1 AND op_id = ?2")
            .bind(vault_id)
            .bind(op_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| row.get::<Vec<u8>, _>("op_hash")))
    }

    /// Ops of a vault after a cursor, in `(lamport, op_hash)` order.
    pub async fn ops_after(
        &self,
        vault_id: &[u8],
        cursor: Option<(i64, Vec<u8>)>,
        limit: i64,
    ) -> Result<Vec<OpRow>, ApiError> {
        let rows = match cursor {
            None => {
                sqlx::query(
                    "SELECT op_hash, op_id, lamport, body, size FROM ops
                     WHERE vault_id = ?1 ORDER BY lamport, op_hash LIMIT ?2",
                )
                .bind(vault_id)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
            Some((lamport, hash)) => {
                sqlx::query(
                    "SELECT op_hash, op_id, lamport, body, size FROM ops
                     WHERE vault_id = ?1
                       AND (lamport > ?2 OR (lamport = ?2 AND op_hash > ?3))
                     ORDER BY lamport, op_hash LIMIT ?4",
                )
                .bind(vault_id)
                .bind(lamport)
                .bind(hash)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|_| ApiError::Unavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| OpRow {
                op_hash: row.get("op_hash"),
                op_id: row.get("op_id"),
                lamport: row.get("lamport"),
                body: row.get("body"),
                size: row.get("size"),
            })
            .collect())
    }

    /// The `(lamport, op_hash)` of one op, for cursor resolution.
    pub async fn op_position(
        &self,
        vault_id: &[u8],
        op_hash: &[u8],
    ) -> Result<Option<(i64, Vec<u8>)>, ApiError> {
        let row =
            sqlx::query("SELECT lamport, op_hash FROM ops WHERE vault_id = ?1 AND op_hash = ?2")
                .bind(vault_id)
                .bind(op_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| ApiError::Unavailable)?;
        Ok(row.map(|row| {
            (
                row.get::<i64, _>("lamport"),
                row.get::<Vec<u8>, _>("op_hash"),
            )
        }))
    }

    /// Compare-and-swap the head: `expected` is the hash being replaced, or
    /// `None` for the first head (`If-Match: *`).
    pub async fn compare_and_swap_head(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        expected: Option<&[u8]>,
        head: &[u8],
        head_hash: &[u8],
    ) -> Result<bool, ApiError> {
        let result = match expected {
            None => {
                sqlx::query(
                    "UPDATE vaults SET head = ?1, head_hash = ?2
                     WHERE account_id = ?3 AND vault_id = ?4 AND head_hash IS NULL",
                )
                .bind(head)
                .bind(head_hash)
                .bind(account_id)
                .bind(vault_id)
                .execute(&self.pool)
                .await
            }
            Some(expected) => {
                sqlx::query(
                    "UPDATE vaults SET head = ?1, head_hash = ?2
                     WHERE account_id = ?3 AND vault_id = ?4 AND head_hash = ?5",
                )
                .bind(head)
                .bind(head_hash)
                .bind(account_id)
                .bind(vault_id)
                .bind(expected)
                .execute(&self.pool)
                .await
            }
        }
        .map_err(|_| ApiError::Unavailable)?;
        Ok(result.rows_affected() == 1)
    }

    // ---------------------------------------------------------------- counters

    /// Increments a fixed-window counter and returns its new value.
    pub async fn bump_counter(
        &self,
        counter_key: &str,
        window_start: &str,
        limit: i64,
    ) -> Result<i64, ApiError> {
        let mut transaction = self.pool.begin().await.map_err(|_| ApiError::Unavailable)?;
        sqlx::query(
            "INSERT INTO audit (counter_key, count, window_start) VALUES (?1, 1, ?2)
             ON CONFLICT(counter_key) DO UPDATE SET count = count + 1",
        )
        .bind(counter_key)
        .bind(window_start)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::Unavailable)?;
        let row = sqlx::query("SELECT count FROM audit WHERE counter_key = ?1")
            .bind(counter_key)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let count: i64 = row.get("count");
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::Unavailable)?;
        let _ = limit;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];

    async fn store() -> RelayStore {
        RelayStore::open_in_memory().await.expect("store")
    }

    #[tokio::test]
    async fn an_account_can_be_created_once() {
        let store = store().await;
        assert!(store
            .create_account(&ACCOUNT, b"record", b"file", "2026-11-06T00:00:00Z")
            .await
            .expect("create"));
        assert!(!store
            .create_account(&ACCOUNT, b"other", b"other", "2026-11-06T00:00:00Z")
            .await
            .expect("duplicate"));
        let row = store
            .account(&ACCOUNT)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(row.record, b"record");
        assert_eq!(row.record_version, 1);
    }

    #[tokio::test]
    async fn the_record_version_drives_compare_and_swap() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r1", b"file", "2026-11-06T00:00:00Z")
            .await
            .expect("create");
        assert!(store
            .replace_account_record(&ACCOUNT, b"r2", 1)
            .await
            .expect("swap"));
        assert!(!store
            .replace_account_record(&ACCOUNT, b"r3", 1)
            .await
            .expect("stale swap"));
        assert_eq!(
            store
                .account(&ACCOUNT)
                .await
                .expect("get")
                .expect("row")
                .record_version,
            2
        );
    }

    #[tokio::test]
    async fn a_tombstoned_account_disappears_after_the_sweep() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r", b"file", "2020-01-01T00:00:00Z")
            .await
            .expect("create");
        store
            .tombstone_account(&ACCOUNT, "2020-01-02T00:00:00Z")
            .await
            .expect("tombstone");
        assert!(store
            .account(&ACCOUNT)
            .await
            .expect("get")
            .expect("still there")
            .deleted_at
            .is_some());
        let purged = store
            .purge_tombstones_before("2020-01-03T00:00:00Z")
            .await
            .expect("purge");
        assert_eq!(purged, 1);
        assert!(store.account(&ACCOUNT).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn ops_are_idempotent_and_paginate() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r", b"file", "2026-11-06T00:00:00Z")
            .await
            .expect("create");
        store.ensure_vault(&ACCOUNT, &VAULT).await.expect("vault");
        let ops = vec![
            OpRow {
                op_hash: vec![1u8; 32],
                op_id: vec![1u8; 16],
                lamport: 1,
                body: vec![9u8; 10],
                size: 10,
            },
            OpRow {
                op_hash: vec![2u8; 32],
                op_id: vec![2u8; 16],
                lamport: 2,
                body: vec![9u8; 20],
                size: 20,
            },
        ];
        assert_eq!(
            store
                .insert_ops(&ACCOUNT, &VAULT, &ops, 2, "2026-11-06T00:00:00Z")
                .await
                .expect("insert"),
            2
        );
        assert_eq!(
            store
                .insert_ops(&ACCOUNT, &VAULT, &ops, 2, "2026-11-06T00:00:00Z")
                .await
                .expect("reinsert"),
            0
        );
        let vault = store
            .vault(&ACCOUNT, &VAULT)
            .await
            .expect("v")
            .expect("row");
        assert_eq!(vault.op_count, 2);
        assert_eq!(vault.storage_bytes, 30);
        assert_eq!(vault.lamport_max, 2);

        let first_page = store.ops_after(&VAULT, None, 1).await.expect("page");
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].lamport, 1);
        let next = store
            .ops_after(
                &VAULT,
                Some((first_page[0].lamport, first_page[0].op_hash.clone())),
                10,
            )
            .await
            .expect("page 2");
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].lamport, 2);
    }

    #[tokio::test]
    async fn head_compare_and_swap_holds() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r", b"file", "2026-11-06T00:00:00Z")
            .await
            .expect("create");
        store.ensure_vault(&ACCOUNT, &VAULT).await.expect("vault");
        assert!(store
            .compare_and_swap_head(&ACCOUNT, &VAULT, None, b"head1", b"h1")
            .await
            .expect("first"));
        assert!(!store
            .compare_and_swap_head(&ACCOUNT, &VAULT, None, b"head2", b"h2")
            .await
            .expect("second first"));
        assert!(store
            .compare_and_swap_head(&ACCOUNT, &VAULT, Some(b"h1"), b"head2", b"h2")
            .await
            .expect("swap"));
        assert!(!store
            .compare_and_swap_head(&ACCOUNT, &VAULT, Some(b"h1"), b"head3", b"h3")
            .await
            .expect("stale swap"));
    }

    #[tokio::test]
    async fn revoking_a_device_drops_its_sessions() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r", b"file", "2026-11-06T00:00:00Z")
            .await
            .expect("create");
        store
            .add_device(&ACCOUNT, &[1u8; 16], b"pk", b"cert", "2026-11-06T00:00:00Z")
            .await
            .expect("device");
        store
            .create_session(
                b"tok",
                &ACCOUNT,
                &[1u8; 16],
                "2026-11-06T00:00:00Z",
                "2099-01-01T00:00:00Z",
            )
            .await
            .expect("session");
        assert!(store.session(b"tok").await.expect("get").is_some());
        store
            .revoke_device(&ACCOUNT, &[1u8; 16], "2026-11-06T01:00:00Z")
            .await
            .expect("revoke");
        assert!(store.session(b"tok").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn counters_increment_per_bucket() {
        let store = store().await;
        for expected in 1..=3 {
            let count = store
                .bump_counter("login:abc:2026110600", "2026-11-06T00:00:00Z", 10)
                .await
                .expect("bump");
            assert_eq!(count, expected);
        }
        let other = store
            .bump_counter("login:abc:2026110601", "2026-11-06T01:00:00Z", 10)
            .await
            .expect("bump");
        assert_eq!(other, 1);
    }
}
