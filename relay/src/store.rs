//! The relay's storage layer: rusqlite (bundled SQLite), SPEC §7.9.
//!
//! Every column holds public metadata or ciphertext. Ops are stored **exactly
//! as received** and never updated; the only destructive path is deleting a
//! whole account, which cascades.
//!
//! A `vault_id` is owned by exactly one account (SPEC §7.4, R-0601). Every op
//! query is scoped to `(account_id, vault_id)` and the `vaults` table carries a
//! global unique index on `vault_id`, so two accounts can never share a stream.
//!
//! All rusqlite calls are synchronous and dispatched via
//! `tokio::task::spawn_blocking` so the async runtime is never blocked.

use crate::error::ApiError;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
#[derive(Debug, Clone, Default)]
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
    /// The device that signed the op.
    pub device_id: Vec<u8>,
    /// The op kind, as its wire name.
    pub kind: String,
    /// The item the op touches, when its kind names one.
    pub item_id: Option<Vec<u8>>,
}

/// The database handle — cheaply `Clone`able.
#[derive(Debug, Clone)]
pub struct RelayStore {
    conn: Arc<Mutex<Connection>>,
}

// ──────────────────────────────────────────────────── migration SQL ──────────

/// Each entry is one migration. Applied in order once, tracked via
/// `schema_version`. The index in the slice is the migration number (0-based).
const MIGRATIONS: &[&str] = &[
    // 0001 — initial schema
    "-- Studge Pass relay schema (SPEC §7.9).
-- Every byte stored here is public metadata or ciphertext (§3.2).

CREATE TABLE IF NOT EXISTS accounts (
    account_id    BLOB PRIMARY KEY,
    record        BLOB NOT NULL,
    record_version INTEGER NOT NULL,
    password_file BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    deleted_at    TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    account_id  BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id   BLOB NOT NULL,
    public_key  BLOB NOT NULL,
    certificate BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    PRIMARY KEY (account_id, device_id)
);

CREATE TABLE IF NOT EXISTS vaults (
    account_id    BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    vault_id      BLOB NOT NULL,
    head          BLOB,
    head_hash     BLOB,
    op_count      INTEGER NOT NULL DEFAULT 0,
    lamport_max   INTEGER NOT NULL DEFAULT 0,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, vault_id)
);

CREATE TABLE IF NOT EXISTS ops (
    op_hash    BLOB PRIMARY KEY,
    vault_id   BLOB NOT NULL,
    op_id      BLOB NOT NULL,
    lamport    INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    item_id    BLOB,
    device_id  BLOB NOT NULL,
    created_at TEXT NOT NULL,
    body       BLOB NOT NULL,
    size       INTEGER NOT NULL,
    UNIQUE (vault_id, op_id)
);

CREATE INDEX IF NOT EXISTS ops_vault_order ON ops (vault_id, lamport, op_hash);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    account_id BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id  BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_device ON sessions (account_id, device_id);

CREATE TABLE IF NOT EXISTS audit (
    counter_key  TEXT PRIMARY KEY,
    count        INTEGER NOT NULL,
    window_start TEXT NOT NULL
);",
    // 0002 — login states
    "CREATE TABLE IF NOT EXISTS login_states (
    account_id BLOB NOT NULL,
    device_id  BLOB NOT NULL,
    state      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (account_id, device_id)
);",
    // 0003 — vault ids are globally owned and ops carry their account (R-0601).
    //
    // Before this migration `ops` was keyed by `vault_id` alone, so an account
    // could push one op to another account's vault id and from then on read —
    // and inject into — that whole op stream. The table is rebuilt with
    // `account_id` in the primary key and in the unique constraint, and with a
    // foreign key to `vaults` that cascades: deleting an account now really
    // deletes its op ciphertext (R-0607). `vaults.vault_id` becomes globally
    // unique, so ownership cannot be split again.
    "CREATE TABLE ops_v3 (
    account_id BLOB NOT NULL,
    vault_id   BLOB NOT NULL,
    op_hash    BLOB NOT NULL,
    op_id      BLOB NOT NULL,
    lamport    INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    item_id    BLOB,
    device_id  BLOB NOT NULL,
    created_at TEXT NOT NULL,
    body       BLOB NOT NULL,
    size       INTEGER NOT NULL,
    PRIMARY KEY (account_id, op_hash),
    UNIQUE (account_id, vault_id, op_id),
    FOREIGN KEY (account_id, vault_id) REFERENCES vaults (account_id, vault_id)
        ON DELETE CASCADE
);

INSERT INTO ops_v3 (account_id, vault_id, op_hash, op_id, lamport, kind, item_id,
                    device_id, created_at, body, size)
SELECT v.account_id, o.vault_id, o.op_hash, o.op_id, o.lamport, o.kind, o.item_id,
       o.device_id, o.created_at, o.body, o.size
FROM ops o
JOIN vaults v ON v.vault_id = o.vault_id;

DROP TABLE ops;
ALTER TABLE ops_v3 RENAME TO ops;

CREATE INDEX IF NOT EXISTS ops_account_vault_order
    ON ops (account_id, vault_id, lamport, op_hash);

CREATE UNIQUE INDEX IF NOT EXISTS vaults_vault_id_global ON vaults (vault_id);",
];

/// Why opening or upgrading the database failed.
#[derive(Debug)]
enum MigrateError {
    /// SQLite refused a statement.
    Db(rusqlite::Error),
    /// A migration refused to run on this data. Refusing beats guessing.
    Refused(&'static str),
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(error) => write!(f, "{error}"),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

impl From<rusqlite::Error> for MigrateError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(error)
    }
}

/// Opens a connection, sets pragmas and applies pending migrations.
fn open_connection(path: Option<&Path>) -> Result<Connection, MigrateError> {
    let conn = match path {
        Some(p) => Connection::open(p)?,
        None => Connection::open_in_memory()?,
    };
    // WAL journal mode: readers don't block writers, writers don't block readers.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// Applies any migration whose number is higher than the current schema version.
fn run_migrations(conn: &Connection) -> Result<(), MigrateError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
             version INTEGER NOT NULL
         );",
    )?;
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    for (i, sql) in MIGRATIONS.iter().enumerate() {
        let version = i as i64 + 1;
        if version > current {
            // 0003 rebuilds `ops` and makes `vault_id` globally unique; it must
            // not run on a database where one vault id already has two owners.
            if version == 3 {
                check_global_vault_ownership(conn)?;
            }
            // The migration and its version row commit together, so an
            // interrupted upgrade leaves the previous version intact instead
            // of a half-rebuilt table.
            let batch = format!(
                "BEGIN;\n{sql}\nINSERT INTO schema_version (version) VALUES ({version});\nCOMMIT;"
            );
            if let Err(error) = conn.execute_batch(&batch) {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(MigrateError::Db(error));
            }
        }
    }
    Ok(())
}

/// Refuses to upgrade a database where one `vault_id` already has two owners.
///
/// That state is either a 2^-128 collision or R-0601 having been exercised.
/// Picking an owner would silently hand one account's ops to another, so the
/// relay refuses to start and leaves the database untouched.
fn check_global_vault_ownership(conn: &Connection) -> Result<(), MigrateError> {
    let duplicates: i64 = conn.query_row(
        "SELECT COUNT(*) FROM (
             SELECT vault_id FROM vaults GROUP BY vault_id HAVING COUNT(*) > 1
         )",
        [],
        |row| row.get(0),
    )?;
    if duplicates == 0 {
        Ok(())
    } else {
        Err(MigrateError::Refused(
            "migration 0003 refused: a vault id is owned by more than one account (R-0601)",
        ))
    }
}

/// Converts a database error into the relay's generic `ApiError::Unavailable`.
fn db_err(e: rusqlite::Error) -> ApiError {
    tracing::error!(error = %e, "database error");
    ApiError::Unavailable
}

/// Converts an open/migrate failure into the generic error, logging the reason.
fn open_err(e: MigrateError) -> ApiError {
    tracing::error!(error = %e, "database could not be opened");
    ApiError::Unavailable
}

impl RelayStore {
    /// Opens (or creates) the database at `path`, applies pragmas and migrations.
    pub async fn open(path: &Path) -> Result<Self, ApiError> {
        let path = path.to_path_buf();
        let conn = tokio::task::spawn_blocking(move || open_connection(Some(&path)))
            .await
            .map_err(|_| ApiError::Unavailable)?
            .map_err(open_err)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// An in-memory database for tests.
    pub async fn open_in_memory() -> Result<Self, ApiError> {
        let conn = tokio::task::spawn_blocking(|| open_connection(None))
            .await
            .map_err(|_| ApiError::Unavailable)?
            .map_err(open_err)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Acquires the lock and runs `f` on the connection inside `spawn_blocking`.
    async fn with_conn<F, T>(&self, f: F) -> Result<T, ApiError>
    where
        F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn
                .lock()
                .map_err(|_| rusqlite::Error::ExecuteReturnedResults)?;
            f(&guard)
        })
        .await
        .map_err(|_| ApiError::Unavailable)?
        .map_err(db_err)
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
        let account_id = account_id.to_vec();
        let record = record.to_vec();
        let password_file = password_file.to_vec();
        let created_at = created_at.to_string();
        self.with_conn(move |conn| {
            let n = conn.execute(
                "INSERT OR IGNORE INTO accounts
                     (account_id, record, record_version, password_file, created_at)
                 VALUES (?1, ?2, 1, ?3, ?4)",
                rusqlite::params![account_id, record, password_file, created_at],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Reads an account, including tombstoned ones.
    pub async fn account(&self, account_id: &[u8]) -> Result<Option<AccountRow>, ApiError> {
        let account_id = account_id.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT record, record_version, password_file, deleted_at
                 FROM accounts WHERE account_id = ?1",
            )?;
            let mut rows = stmt.query([&account_id as &dyn rusqlite::ToSql])?;
            if let Some(row) = rows.next()? {
                Ok(Some(AccountRow {
                    record: row.get(0)?,
                    record_version: row.get(1)?,
                    password_file: row.get(2)?,
                    deleted_at: row.get(3)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Replaces the account record when `expected_version` still holds.
    pub async fn replace_account_record(
        &self,
        account_id: &[u8],
        record: &[u8],
        expected_version: i64,
    ) -> Result<bool, ApiError> {
        let account_id = account_id.to_vec();
        let record = record.to_vec();
        self.with_conn(move |conn| {
            let n = conn.execute(
                "UPDATE accounts SET record = ?1, record_version = record_version + 1
                 WHERE account_id = ?2 AND record_version = ?3 AND deleted_at IS NULL",
                rusqlite::params![record, account_id, expected_version],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Tombstones an account and drops every session at once.
    pub async fn tombstone_account(&self, account_id: &[u8], at: &str) -> Result<(), ApiError> {
        let account_id = account_id.to_vec();
        let at = at.to_string();
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "UPDATE accounts SET deleted_at = ?1
                 WHERE account_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![at, account_id],
            )?;
            tx.execute(
                "DELETE FROM sessions WHERE account_id = ?1",
                [&account_id as &dyn rusqlite::ToSql],
            )?;
            tx.commit()
        })
        .await
    }

    /// Deletes tombstoned accounts whose tombstone is older than `before`.
    pub async fn purge_tombstones_before(&self, before: &str) -> Result<u64, ApiError> {
        let before = before.to_string();
        self.with_conn(move |conn| {
            let n = conn.execute(
                "DELETE FROM accounts WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
                [&before],
            )?;
            Ok(n as u64)
        })
        .await
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
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        let public_key = public_key.to_vec();
        let certificate = certificate.to_vec();
        let created_at = created_at.to_string();
        self.with_conn(move |conn| {
            let n = conn.execute(
                "INSERT OR IGNORE INTO devices
                     (account_id, device_id, public_key, certificate, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![account_id, device_id, public_key, certificate, created_at],
            )?;
            Ok(n == 1)
        })
        .await
    }

    /// Number of devices enrolled for an account (revoked or not).
    pub async fn device_count(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        let account_id = account_id.to_vec();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM devices WHERE account_id = ?1",
                [&account_id as &dyn rusqlite::ToSql],
                |row| row.get::<_, i64>(0),
            )
        })
        .await
    }

    /// Alias for [`device_count`].
    pub async fn count_devices(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        self.device_count(account_id).await
    }

    /// Marks a device revoked and deletes its sessions in one transaction.
    pub async fn revoke_device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
        revoked_at: &str,
    ) -> Result<bool, ApiError> {
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        let revoked_at = revoked_at.to_string();
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let n = tx.execute(
                "UPDATE devices SET revoked_at = ?1
                 WHERE account_id = ?2 AND device_id = ?3 AND revoked_at IS NULL",
                rusqlite::params![revoked_at, account_id, device_id],
            )?;
            tx.execute(
                "DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2",
                rusqlite::params![account_id, device_id],
            )?;
            tx.commit()?;
            Ok(n == 1)
        })
        .await
    }

    /// Reads one device.
    pub async fn device(
        &self,
        account_id: &[u8],
        device_id: &[u8],
    ) -> Result<Option<DeviceRow>, ApiError> {
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT device_id, public_key, certificate, created_at, revoked_at
                 FROM devices WHERE account_id = ?1 AND device_id = ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![account_id, device_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(DeviceRow {
                    device_id: row.get(0)?,
                    public_key: row.get(1)?,
                    certificate: row.get(2)?,
                    created_at: row.get(3)?,
                    revoked_at: row.get(4)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await
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
        let token_hash = token_hash.to_vec();
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        let created_at = created_at.to_string();
        let expires_at = expires_at.to_string();
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "DELETE FROM sessions WHERE account_id = ?1 AND device_id = ?2",
                rusqlite::params![account_id, device_id],
            )?;
            tx.execute(
                "INSERT INTO sessions (token_hash, account_id, device_id, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![token_hash, account_id, device_id, created_at, expires_at],
            )?;
            tx.commit()
        })
        .await
    }

    /// Reads a session by token hash.
    pub async fn session(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<u8>, String)>, ApiError> {
        let token_hash = token_hash.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT account_id, device_id, expires_at
                 FROM sessions WHERE token_hash = ?1",
            )?;
            let mut rows = stmt.query([&token_hash as &dyn rusqlite::ToSql])?;
            if let Some(row) = rows.next()? {
                Ok(Some((row.get(0)?, row.get(1)?, row.get(2)?)))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Deletes one session by token hash.
    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<(), ApiError> {
        let token_hash = token_hash.to_vec();
        self.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?1",
                [&token_hash as &dyn rusqlite::ToSql],
            )?;
            Ok(())
        })
        .await
    }

    /// Deletes expired sessions (the sweeper in `main`).
    pub async fn delete_expired_sessions(&self, now: &str) -> Result<u64, ApiError> {
        let now = now.to_string();
        self.with_conn(move |conn| {
            let n = conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [&now])?;
            Ok(n as u64)
        })
        .await
    }

    // ----------------------------------------------------------------- vaults

    /// The account that owns `vault_id`, if the vault exists at all.
    ///
    /// Vault ids are globally owned (SPEC §7.4, R-0601): the caller uses this
    /// to tell "new vault" from "someone else's vault" before creating rows.
    pub async fn vault_owner(&self, vault_id: &[u8]) -> Result<Option<Vec<u8>>, ApiError> {
        let vault_id = vault_id.to_vec();
        self.with_conn(move |conn| {
            let mut stmt =
                conn.prepare_cached("SELECT account_id FROM vaults WHERE vault_id = ?1")?;
            let mut rows = stmt.query([&vault_id as &dyn rusqlite::ToSql])?;
            match rows.next()? {
                Some(row) => Ok(Some(row.get(0)?)),
                None => Ok(None),
            }
        })
        .await
    }

    /// Claims `vault_id` for `account_id`, creating the row on the first push.
    ///
    /// Returns `false` when the id already belongs to a different account. The
    /// check and the insert are one database call, so a racing push from
    /// another account cannot slip between them, and nothing is written on the
    /// `false` path. The caller answers the same `404` it uses for a missing
    /// vault (SPEC §7.8).
    pub async fn claim_vault(&self, account_id: &[u8], vault_id: &[u8]) -> Result<bool, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        self.with_conn(move |conn| {
            // `vaults.vault_id` is globally unique (migration 0003), so the
            // insert is a no-op when anyone owns the id.
            conn.execute(
                "INSERT OR IGNORE INTO vaults (account_id, vault_id) VALUES (?1, ?2)",
                rusqlite::params![account_id, vault_id],
            )?;
            let owner: Vec<u8> = conn.query_row(
                "SELECT account_id FROM vaults WHERE vault_id = ?1",
                [&vault_id as &dyn rusqlite::ToSql],
                |row| row.get(0),
            )?;
            Ok(owner == account_id)
        })
        .await
    }

    /// Reads a vault that belongs to `account_id`.
    pub async fn vault(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
    ) -> Result<Option<VaultRow>, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT head, head_hash, op_count, lamport_max, storage_bytes
                 FROM vaults WHERE account_id = ?1 AND vault_id = ?2",
            )?;
            let mut rows = stmt.query(rusqlite::params![account_id, vault_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(VaultRow {
                    head: row.get(0)?,
                    head_hash: row.get(1)?,
                    op_count: row.get(2)?,
                    lamport_max: row.get(3)?,
                    storage_bytes: row.get(4)?,
                }))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Total vault bytes for an account (the quota counter).
    pub async fn account_storage_bytes(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        let account_id = account_id.to_vec();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT COALESCE(SUM(storage_bytes), 0) FROM vaults WHERE account_id = ?1",
                [&account_id as &dyn rusqlite::ToSql],
                |row| row.get::<_, i64>(0),
            )
        })
        .await
    }

    /// Number of vaults an account has.
    pub async fn vault_count(&self, account_id: &[u8]) -> Result<i64, ApiError> {
        let account_id = account_id.to_vec();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM vaults WHERE account_id = ?1",
                [&account_id as &dyn rusqlite::ToSql],
                |row| row.get::<_, i64>(0),
            )
        })
        .await
    }

    /// Inserts ops for one vault. Returns the number actually stored.
    ///
    /// `INSERT OR IGNORE` gives idempotency: the same bytes for the same
    /// `(account_id, vault_id, op_id)` are accepted silently; the caller checks
    /// for a *different* hash under an existing `op_id` before calling this.
    pub async fn insert_ops(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        ops: &[OpRow],
        kind_max_lamport: i64,
        now: &str,
    ) -> Result<usize, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        let ops = ops.to_vec();
        let now = now.to_string();
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction()?;
            let mut inserted = 0usize;
            let mut bytes = 0i64;
            for op in &ops {
                let n = tx.execute(
                    "INSERT OR IGNORE INTO ops
                         (account_id, vault_id, op_hash, op_id, lamport, kind, item_id,
                          device_id, created_at, body, size)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        account_id,
                        vault_id,
                        op.op_hash,
                        op.op_id,
                        op.lamport,
                        op.kind,
                        op.item_id,
                        op.device_id,
                        now,
                        op.body,
                        op.size
                    ],
                )?;
                if n == 1 {
                    inserted += 1;
                    bytes += op.size;
                }
            }
            tx.execute(
                "UPDATE vaults
                 SET op_count     = op_count + ?1,
                     lamport_max  = MAX(lamport_max, ?2),
                     storage_bytes = storage_bytes + ?3
                 WHERE account_id = ?4 AND vault_id = ?5",
                rusqlite::params![
                    inserted as i64,
                    kind_max_lamport,
                    bytes,
                    account_id,
                    vault_id
                ],
            )?;
            tx.commit()?;
            Ok(inserted)
        })
        .await
    }

    /// The stored op hash for an `(account_id, vault_id, op_id)`, if any.
    pub async fn op_hash_for_id(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        op_id: &[u8],
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        let op_id = op_id.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT op_hash FROM ops
                 WHERE account_id = ?1 AND vault_id = ?2 AND op_id = ?3",
            )?;
            let mut rows = stmt.query(rusqlite::params![account_id, vault_id, op_id])?;
            if let Some(row) = rows.next()? {
                Ok(Some(row.get(0)?))
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// Ops of an account's vault after a cursor, in `(lamport, op_hash)` order.
    pub async fn ops_after(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        cursor: Option<(i64, Vec<u8>)>,
        limit: i64,
    ) -> Result<Vec<OpRow>, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        self.with_conn(move |conn| {
            let rows: Vec<OpRow> = match cursor {
                None => {
                    let mut stmt = conn.prepare_cached(
                        "SELECT op_hash, op_id, lamport, body, size, device_id, kind, item_id
                         FROM ops WHERE account_id = ?1 AND vault_id = ?2
                         ORDER BY lamport, op_hash LIMIT ?3",
                    )?;
                    let mut rows = stmt.query(rusqlite::params![account_id, vault_id, limit])?;
                    let mut out = Vec::new();
                    while let Some(row) = rows.next()? {
                        out.push(OpRow {
                            op_hash: row.get(0)?,
                            op_id: row.get(1)?,
                            lamport: row.get(2)?,
                            body: row.get(3)?,
                            size: row.get(4)?,
                            device_id: row.get(5)?,
                            kind: row.get(6)?,
                            item_id: row.get(7)?,
                        });
                    }
                    out
                }
                Some((lamport, hash)) => {
                    let mut stmt = conn.prepare_cached(
                        "SELECT op_hash, op_id, lamport, body, size, device_id, kind, item_id
                         FROM ops WHERE account_id = ?1 AND vault_id = ?2
                           AND (lamport > ?3 OR (lamport = ?3 AND op_hash > ?4))
                         ORDER BY lamport, op_hash LIMIT ?5",
                    )?;
                    let mut rows = stmt.query(rusqlite::params![
                        account_id, vault_id, lamport, hash, limit
                    ])?;
                    let mut out = Vec::new();
                    while let Some(row) = rows.next()? {
                        out.push(OpRow {
                            op_hash: row.get(0)?,
                            op_id: row.get(1)?,
                            lamport: row.get(2)?,
                            body: row.get(3)?,
                            size: row.get(4)?,
                            device_id: row.get(5)?,
                            kind: row.get(6)?,
                            item_id: row.get(7)?,
                        });
                    }
                    out
                }
            };
            Ok(rows)
        })
        .await
    }

    /// The `(lamport, op_hash)` of one op, for cursor resolution.
    pub async fn op_position(
        &self,
        account_id: &[u8],
        vault_id: &[u8],
        op_hash: &[u8],
    ) -> Result<Option<(i64, Vec<u8>)>, ApiError> {
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        let op_hash = op_hash.to_vec();
        self.with_conn(move |conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT lamport, op_hash FROM ops
                 WHERE account_id = ?1 AND vault_id = ?2 AND op_hash = ?3",
            )?;
            let mut rows = stmt.query(rusqlite::params![account_id, vault_id, op_hash])?;
            if let Some(row) = rows.next()? {
                Ok(Some((row.get(0)?, row.get(1)?)))
            } else {
                Ok(None)
            }
        })
        .await
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
        let account_id = account_id.to_vec();
        let vault_id = vault_id.to_vec();
        let head = head.to_vec();
        let head_hash = head_hash.to_vec();
        let expected = expected.map(|e| e.to_vec());
        self.with_conn(move |conn| {
            let n = match expected {
                None => conn.execute(
                    "UPDATE vaults SET head = ?1, head_hash = ?2
                     WHERE account_id = ?3 AND vault_id = ?4 AND head_hash IS NULL",
                    rusqlite::params![head, head_hash, account_id, vault_id],
                )?,
                Some(exp) => conn.execute(
                    "UPDATE vaults SET head = ?1, head_hash = ?2
                     WHERE account_id = ?3 AND vault_id = ?4 AND head_hash = ?5",
                    rusqlite::params![head, head_hash, account_id, vault_id, exp],
                )?,
            };
            Ok(n == 1)
        })
        .await
    }

    // ---------------------------------------------------------------- login states

    /// Stores the relay's ServerLogin state between the two login messages.
    pub async fn put_login_state(
        &self,
        account_id: &[u8],
        device_id: &[u8],
        state_bytes: &[u8],
        created_at: &str,
    ) -> Result<(), ApiError> {
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        let state_bytes = state_bytes.to_vec();
        let created_at = created_at.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO login_states
                     (account_id, device_id, state, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![account_id, device_id, state_bytes, created_at],
            )?;
            Ok(())
        })
        .await
    }

    /// Takes (reads and deletes) the login state for one login exchange. A
    /// state can be used exactly once: a replayed finalization finds nothing.
    pub async fn take_login_state(
        &self,
        account_id: &[u8],
        device_id: &[u8],
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let account_id = account_id.to_vec();
        let device_id = device_id.to_vec();
        self.with_conn(move |conn| {
            // Read first, then delete (rusqlite doesn't support RETURNING on DELETE).
            let state: Option<Vec<u8>> = {
                let mut stmt = conn.prepare_cached(
                    "SELECT state FROM login_states
                     WHERE account_id = ?1 AND device_id = ?2",
                )?;
                let mut rows = stmt.query(rusqlite::params![account_id, device_id])?;
                rows.next()?.map(|row| row.get(0)).transpose()?
            };
            if state.is_some() {
                conn.execute(
                    "DELETE FROM login_states WHERE account_id = ?1 AND device_id = ?2",
                    rusqlite::params![account_id, device_id],
                )?;
            }
            Ok(state)
        })
        .await
    }

    // ---------------------------------------------------------------- counters

    /// Increments a fixed-window counter and returns its new value.
    pub async fn bump_counter(
        &self,
        counter_key: &str,
        window_start: &str,
        limit: i64,
    ) -> Result<i64, ApiError> {
        let counter_key = counter_key.to_string();
        let window_start = window_start.to_string();
        let _ = limit;
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO audit (counter_key, count, window_start) VALUES (?1, 1, ?2)
                 ON CONFLICT(counter_key) DO UPDATE SET count = count + 1",
                rusqlite::params![counter_key, window_start],
            )?;
            let count: i64 = tx.query_row(
                "SELECT count FROM audit WHERE counter_key = ?1",
                [&counter_key],
                |row| row.get(0),
            )?;
            tx.commit()?;
            Ok(count)
        })
        .await
    }

    // --------------------------------------------------------------- audit housekeeping

    /// Deletes audit buckets whose `window_start` is strictly before `before`.
    ///
    /// Old buckets are never useful again (their window has closed) and the
    /// audit table must not grow without bound, so callers sweep periodically.
    pub async fn purge_expired_counters(&self, before: &str) -> Result<u64, ApiError> {
        let before = before.to_string();
        self.with_conn(move |conn| {
            let n = conn.execute("DELETE FROM audit WHERE window_start < ?1", [&before])?;
            Ok(n as u64)
        })
        .await
    }

    /// Alias for [`purge_expired_counters`].
    pub async fn delete_expired_counters(&self, before: &str) -> Result<u64, ApiError> {
        self.purge_expired_counters(before).await
    }

    /// Alias for [`purge_expired_counters`].
    pub async fn expire_counters(&self, before: &str) -> Result<u64, ApiError> {
        self.purge_expired_counters(before).await
    }

    /// Alias for [`purge_expired_counters`].
    pub async fn purge_audit_before(&self, before: &str) -> Result<u64, ApiError> {
        self.purge_expired_counters(before).await
    }

    /// Caps the audit table at `cap` rows.
    ///
    /// Expired buckets must be evicted beforehand via
    /// [`Self::purge_expired_counters`]; this method never deletes active
    /// buckets, because doing so would reset an in-flight rate limit.
    /// If the table is still over the cap after expired rows have been
    /// removed, this returns `RateLimited` so the caller refuses new
    /// counters instead of silently resetting limits.
    pub async fn cap_audit_table(&self, cap: i64) -> Result<u64, ApiError> {
        let count: i64 = self
            .with_conn(move |conn| {
                conn.query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            })
            .await?;
        if count <= cap {
            Ok(0)
        } else {
            Err(ApiError::RateLimited)
        }
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
        store.claim_vault(&ACCOUNT, &VAULT).await.expect("vault");
        let ops = vec![
            OpRow {
                op_hash: vec![1u8; 32],
                op_id: vec![1u8; 16],
                lamport: 1,
                body: vec![9u8; 10],
                size: 10,
                ..OpRow::default()
            },
            OpRow {
                op_hash: vec![2u8; 32],
                op_id: vec![2u8; 16],
                lamport: 2,
                body: vec![9u8; 20],
                size: 20,
                ..OpRow::default()
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

        let first_page = store
            .ops_after(&ACCOUNT, &VAULT, None, 1)
            .await
            .expect("page");
        assert_eq!(first_page.len(), 1);
        assert_eq!(first_page[0].lamport, 1);
        let next = store
            .ops_after(
                &ACCOUNT,
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
        store.claim_vault(&ACCOUNT, &VAULT).await.expect("vault");
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
    async fn a_vault_id_is_claimed_by_one_account_only() {
        const OTHER: [u8; 16] = [0xB2; 16];
        let store = store().await;
        for account in [ACCOUNT, OTHER] {
            store
                .create_account(&account, b"r", b"file", "2026-11-06T00:00:00Z")
                .await
                .expect("create");
        }
        assert!(store
            .claim_vault(&ACCOUNT, &VAULT)
            .await
            .expect("first claim"));
        assert!(store
            .claim_vault(&ACCOUNT, &VAULT)
            .await
            .expect("repeat claim"));
        // The second account gets nothing, and no row is written for it.
        assert!(!store
            .claim_vault(&OTHER, &VAULT)
            .await
            .expect("foreign claim"));
        assert_eq!(
            store.vault_owner(&VAULT).await.expect("owner"),
            Some(ACCOUNT.to_vec())
        );
        assert!(
            store.vault(&OTHER, &VAULT).await.expect("vault").is_none(),
            "a refused claim must not create a vault row"
        );
        assert_eq!(store.vault_count(&OTHER).await.expect("count"), 0);
    }

    #[tokio::test]
    async fn deleting_an_account_deletes_its_ops() {
        let store = store().await;
        store
            .create_account(&ACCOUNT, b"r", b"file", "2020-01-01T00:00:00Z")
            .await
            .expect("create");
        assert!(store.claim_vault(&ACCOUNT, &VAULT).await.expect("vault"));
        let ops = vec![OpRow {
            op_hash: vec![7u8; 32],
            op_id: vec![7u8; 16],
            lamport: 1,
            body: vec![9u8; 10],
            size: 10,
            ..OpRow::default()
        }];
        assert_eq!(
            store
                .insert_ops(&ACCOUNT, &VAULT, &ops, 1, "2020-01-01T00:00:00Z")
                .await
                .expect("insert"),
            1
        );
        store
            .tombstone_account(&ACCOUNT, "2020-01-02T00:00:00Z")
            .await
            .expect("tombstone");
        store
            .purge_tombstones_before("2020-01-03T00:00:00Z")
            .await
            .expect("purge");
        // R-0607: the op ciphertext goes with the account, not just the vault row.
        assert!(
            store
                .ops_after(&ACCOUNT, &VAULT, None, 10)
                .await
                .expect("ops")
                .is_empty(),
            "ops must not outlive the account"
        );
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

    #[tokio::test]
    async fn expired_audit_buckets_are_purged() {
        let store = store().await;
        store
            .bump_counter("login:abc:2020010100", "2020-01-01T00:00:00Z", 10)
            .await
            .expect("bump old");
        store
            .bump_counter("login:abc:2026110600", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump new");
        let purged = store
            .purge_expired_counters("2026-01-01T00:00:00Z")
            .await
            .expect("purge");
        assert_eq!(purged, 1, "only the old bucket is removed");
        // The new bucket survives.
        let count = store
            .bump_counter("login:abc:2026110600", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump");
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn cap_audit_table_does_not_delete_active_counters() {
        let store = store().await;
        // Two active buckets.
        store
            .bump_counter("login:a:1", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump a");
        store
            .bump_counter("login:b:2", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump b");
        // Cap of 1 is below the number of active rows.
        let res = store.cap_audit_table(1).await;
        assert!(res.is_err(), "over cap must refuse instead of deleting");
        // Both active counters survive.
        let a = store
            .bump_counter("login:a:1", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump a");
        let b = store
            .bump_counter("login:b:2", "2026-11-06T00:00:00Z", 10)
            .await
            .expect("bump b");
        assert_eq!(a, 2);
        assert_eq!(b, 2);
    }
}
