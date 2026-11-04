<!-- Phase 1: protocol spec and threat model. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md first. **Phase 1: protocol specification and threat model.** This phase is documentation only. Do not write code.

Write docs/SPEC.md (8–15 pages) and docs/THREAT_MODEL.md using the decisions below. Where a detail is missing, propose one, mark it **PROPOSED**, and list it in docs/DECISIONS.md for my review.

### 1. Identities and keys
- account_id and device_id: random UUIDv4.
- Secret Key: 128 random bits, generated on the first device. It is shown once in the format `SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X` (Crockford base32, final checksum group). It is stored on devices and in the printable recovery kit, and NEVER sent to the relay.
- Master Unlock Key: MUK = HKDF-SHA256(ikm = Argon2id(NFKC(master_password), salt = account_salt [16 random bytes, stored on relay], m = 64 MiB, t = 3, p = 1) || secret_key, info = "studge/v1/muk", L = 32). The KDF parameters are versioned and upgradable, never downgradable.
- Auth secret = HKDF(MUK, "studge/v1/opaque-password"). It is used as the OPAQUE password, so an attacker who steals relay data cannot brute-force the master password without the Secret Key.
- Account Key (AK): random 256-bit. The relay stores AEAD(MUK, AK, aad = canonical{suite, "ak", account_id}).
- Account identity keys (encrypted under AK): an Ed25519 signing key, plus X25519 and ML-KEM-768 encryption keys for hybrid sharing.
- Device keys: one Ed25519 key per device, certified by an account-identity signature over (account_id, device_id, device_pubkey, created_at). Revocation is a signed record.
- Vault Key (VK): random 256-bit per vault. For the owner it is wrapped by AK; for shared vaults it is wrapped by HPKE to each member.
- Item Key (IK): random 256-bit per item, wrapped by VK.

### 2. Encryption format
- AEAD: XChaCha20-Poly1305 with a random 24-byte nonce. Envelope = {suite: "v1", nonce, ciphertext}.
- AAD = deterministic CBOR of {suite, scope id (account_id or vault_id), item_id, record_type, field_name (if per-field), schema_version}.
- Content hashes: BLAKE3. Use SHA-256 only where an external standard requires it.
- Everything signed or hashed uses deterministic CBOR (RFC 8949 §4.2.1).

### 3. Vault operation log
- Op = {vault_id, op_id, parents: [op_hash], lamport, device_id, created_at, kind (create | update | delete | move | membership | key_rotation), item_id, payload_ciphertext}.
- op_hash = BLAKE3(canonical(Op without signature)). sig = Ed25519(device key, op_hash).
- Vault state is a DAG of ops. For item conflicts, the highest (lamport, device_id) wins, and losing versions are kept in item history.
- VaultHead = {vault_id, heads: [op_hash], op_count, lamport_max}, signed by a device. Clients remember the last verified head for each vault. They reject any relay response that does not descend from it, which detects both rollbacks and forks.

### 4. Relay API (HTTP; JSON for control messages, CBOR for ops)
- OPAQUE registration and login (opaque-ke, ristretto255, Argon2id KSF) produce a session token. The token is 256 random bits; the relay stores only its SHA-256. Tokens expire after 24 h and are bound to a device_id.
- Endpoints: POST /v1/register/start and /finish, POST /v1/login/start and /finish, GET and PUT /v1/account (encrypted key bundle), POST and DELETE /v1/devices, POST /v1/vaults/:id/ops (append-only), GET /v1/vaults/:id/ops?since=cursor, GET and PUT /v1/vaults/:id/head (compare-and-swap), DELETE /v1/account. Phase 11 adds a key-directory API.
- The relay validates only structure, sizes, authentication, quotas and rate limits. It never interprets ciphertext.
- Storage backends sit behind a Transport trait: http relay, folder (files in any synced directory) and memory (for tests).

### 5. Dashboard scoring (details in Phase 10)
score = 100 × Σ(w × p) / Σw
- p = 1.0 for a passkey or security key with no password left
- p = 0.8 for a passkey plus a strong unique fallback password
- p = 0.6 for a password plus TOTP or security-key 2FA
- p = 0.3 for a password plus SMS or email OTP
- p = 0.1 for a strong unique password only
- p = 0.0 for a weak, reused or breached password
- w = 5 for recovery roots (email, phone carrier, Apple/Google/Microsoft accounts)
- w = 3 for money (banks, UPI, cards, brokers, crypto)
- w = 1 for everything else

### 6. Sharing and recovery (summary; full design in Phases 11–12)
- Sharing: HPKE (RFC 9180) with hybrid X25519 + ML-KEM-768, if a maintained crate supports it cleanly. Otherwise use X25519 now and document the upgrade path. Public keys go in an append-only key-transparency log with Merkle consistency proofs. Contacts can be verified with safety codes.
- Recovery: a printable recovery kit. Guardian recovery uses a Recovery Key split by Shamir 2-of-3, with each share HPKE-encrypted to a guardian. The owner's devices can cancel within 72 h. Emergency access has an owner-defined waiting period.

### THREAT_MODEL.md
Write a table for each adversary covering: assets at risk, attacks, mitigations (with SPEC section links) and residual risk.
- A1: fully malicious relay
- A2: network attacker
- A3: malicious sharee or removed member
- A4: malicious web page attacking the extension (phishing look-alikes, DOM clickjacking with opacity 0, iframe tricks, fake WebAuthn requests)
- A5: stolen locked device
- A6: malware on an unlocked device (out of scope; explain why)
- A7: supply-chain attacker
- A8: hostile browser extension

Add two mapping sections:
1. The ETH Zurich 2026 malicious-server attack classes (unauthenticated metadata and field swapping, key substitution during sharing and org joining, legacy-crypto downgrade, rollback) mapped to our mitigations.
2. The DEF CON 33 DOM-based extension clickjacking attack mapped to our mitigation.

### Finish
Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and list the 10 decisions I most need to review, each with your recommendation.

Preview for me: render SPEC.md and THREAT_MODEL.md into the preview page (a "Docs" tab with a table of contents), and add a simple SVG diagram of the key hierarchy (password + Secret Key → MUK → AK → vault keys → item keys) and of the relay trust boundary.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
