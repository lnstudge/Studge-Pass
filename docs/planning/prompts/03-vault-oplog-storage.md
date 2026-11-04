<!-- Phase 3: vault, op log, storage, import/export. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 3: vault data model, operation log, local encrypted storage, import/export, generator and TOTP, all in core.**

1. Item types (core/src/vault/items.rs):
   - Login: title, username, password, urls with a match rule (exact-host default | base-domain | starts-with), totp secret, notes, custom fields and linked passkeys.
   - Passkey: credential_id, rp_id, user_handle, user_name, display_name, P-256 private key (PKCS#8, secret), sign_count, backup flags, created_at.
   - SecureNote, Card, Identity, SshKey (storage only).
   - India templates: Aadhaar, PAN, UPI ID, Netbanking (customer id, login password, MPIN, transaction password), DigiLocker, Passport, Voter ID.
   - Common fields on every item: id, vault_id, created_at, updated_at, favourite, tags, and history (the last 10 values of each secret field).
2. Op log (core/src/oplog): the Op struct, canonical CBOR, op_hash, sign and verify, and materialising the DAG into current item state using the SPEC conflict rule. Also VaultHead sign and verify, and verify_descends(last_trusted_head, new_head, ops) for detecting rollbacks and forks.
3. Storage: a LocalStore trait. Implement it on SQLite (rusqlite, bundled feature), storing only encrypted ops, encrypted key bundles and non-secret metadata. Add an in-memory implementation for tests. Encrypted backups use the .studgevault file format.
4. Account API: create_account(password) -> (AccountBundle, SecretKey, RecoveryKitData). unlock(password, secret_key, bundle) -> UnlockedAccount. lock() zeroizes everything.
5. Importers (each returns ImportReport {imported, skipped_with_reason}, and none may log item contents): Bitwarden JSON and CSV, Chrome/Google CSV, Apple Passwords CSV, 1Password 1PUX, Proton Pass export, Dashlane CSV, KeePass XML, and generic CSV with column mapping.
6. Exporters: encrypted .studgevault, plain JSON and CSV (each requires an explicit `allow_plaintext` flag), and KeePass XML.
7. Generator: passwords (length, character sets, exclude-ambiguous option) and passphrases (bundled EFF large wordlist, separator, capitalisation, number), with an entropy estimate. Use OsRng only.
8. TOTP: RFC 6238 (SHA-1/256/512, 6 or 8 digits, 30 or 60 s) and otpauth:// URI parsing.

Tests:
- Op-log tamper tests: a modified payload, a bad signature, a dropped op, reordered ops, a replayed old head and a forked head must all be detected.
- Conflict-resolution tests.
- Importer tests with fixture files containing FAKE data only.
- RFC 6238 test vectors for TOTP.
- Basic statistics tests for the generator.

Run every check, update PROGRESS.md, and commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Preview for me: `cargo run -p studge-core --example vault_tour` creates a demo vault with fake items (including Aadhaar, PAN and UPI templates), shows the op log as a readable table (op hash, parents, device, kind), demonstrates a conflict being resolved, and imports a fake Bitwarden file with its ImportReport. Add an "Op log" view to the preview page that renders the demo log as a small graph.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
Tools (see "Connected tools" in AGENTS.md): save this exact prompt in Notion Prompts first; log every step in the Notion Execution log; commit and push every step to GitHub; file self-attack findings as GitHub issues and Notion Risks; open the PR with "Closes #<this phase's issue>"; use every skill that helps and record which ones.
