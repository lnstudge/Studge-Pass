-- Studge Pass relay schema (SPEC §7.9).
-- Every byte stored here is public metadata or ciphertext (§3.2).

CREATE TABLE accounts (
    account_id    BLOB PRIMARY KEY,
    record        BLOB NOT NULL,
    record_version INTEGER NOT NULL,
    password_file BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    deleted_at    TEXT
);

CREATE TABLE devices (
    account_id  BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id   BLOB NOT NULL,
    public_key  BLOB NOT NULL,
    certificate BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    PRIMARY KEY (account_id, device_id)
);

CREATE TABLE vaults (
    account_id    BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    vault_id      BLOB NOT NULL,
    head          BLOB,
    head_hash     BLOB,
    op_count      INTEGER NOT NULL DEFAULT 0,
    lamport_max   INTEGER NOT NULL DEFAULT 0,
    storage_bytes INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, vault_id)
);

CREATE TABLE ops (
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

CREATE INDEX ops_vault_order ON ops (vault_id, lamport, op_hash);

CREATE TABLE sessions (
    token_hash BLOB PRIMARY KEY,
    account_id BLOB NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id  BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX sessions_device ON sessions (account_id, device_id);

-- Rate-limit and abuse counters. The key is a bucket name (for example
-- "login:<account_id>:<hour>") and never contains request content.
CREATE TABLE audit (
    counter_key  TEXT PRIMARY KEY,
    count        INTEGER NOT NULL,
    window_start TEXT NOT NULL
);
