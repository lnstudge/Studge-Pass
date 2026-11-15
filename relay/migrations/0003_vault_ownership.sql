-- 0003 — vault ids are globally owned and ops carry their account (R-0601).
-- Before this migration `ops` was keyed by `vault_id` alone, so an account
-- could push one op to another account's vault id and from then on read —
-- and inject into — that whole op stream. The table is rebuilt with
-- `account_id` in the primary key and in the unique constraint, and with a
-- foreign key to `vaults` that cascades: deleting an account now really
-- deletes its op ciphertext (R-0607). `vaults.vault_id` becomes globally
-- unique, so ownership cannot be split again.

CREATE TABLE ops_v3 (
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

CREATE UNIQUE INDEX IF NOT EXISTS vaults_vault_id_global ON vaults (vault_id);
