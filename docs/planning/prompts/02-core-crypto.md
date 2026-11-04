<!-- Phase 2: core cryptography. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md, docs/SPEC.md, docs/THREAT_MODEL.md and docs/PROGRESS.md. **Phase 2: the cryptography module in core/src/crypto, implemented exactly as SPEC.md says.** No networking and no storage.

Implement:
1. `secret_key`: generate, encode and decode the SP1 format with its checksum. Reject bad checksums and wrong lengths.
2. `kdf`: derive_muk(password, salt, secret_key, params) with NFKC normalisation; derive_subkey(key, label) with HKDF-SHA256. Keep every label as a constant in one file.
3. `aead`: seal and open with XChaCha20-Poly1305 using the Envelope type. open() returns an error on any failure, including an unknown suite or the wrong AAD.
4. `aad`: a typed builder that produces deterministic CBOR. The API must make it impossible to encrypt without AAD.
5. `keys`: newtypes MasterUnlockKey, AccountKey, VaultKey and ItemKey wrapping Zeroizing<[u8; 32]>. Redact Debug, avoid Clone where possible, and provide wrap/unwrap functions.
6. `signing`: Ed25519 device keys, device certificates (create and verify) and revocation records.
7. `hpke`: seal_to and open_from with the `hpke` crate (X25519-HKDF-SHA256 + ChaCha20Poly1305). Add the ML-KEM-768 hybrid only if a maintained crate supports it cleanly. Otherwise create the trait, leave a TODO(security), and record the decision in DECISIONS.md.
8. `random`: one function backed by OsRng. Nothing else may produce randomness.

Tests in core/tests/:
- Round-trip tests for every public function.
- Tamper tests: flipping any byte of the nonce, ciphertext or tag fails. Changing any AAD field (vault_id, item_id, field_name, record_type) fails. A wrong suite fails. Unwrapping with the wrong key fails.
- proptest properties for seal/open and wrap/unwrap.
- Known-answer vectors: use fixed inputs and a deterministic RNG behind a test-only feature, and save them to core/tests/vectors/v1.json so other languages can be checked against them later.
- Use small Argon2 parameters in normal tests, plus one #[ignore] test with the real parameters.

Constraints: #![forbid(unsafe_code)]. No unwrap or expect outside tests. Errors use a thiserror enum, CryptoError, whose messages contain no secret data. Pin crate versions and justify each in DECISIONS.md.
Run fmt, clippy -D warnings, test and cargo deny. Update PROGRESS.md and commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report test counts and any deviations from SPEC.

Preview for me: `cargo run -p studge-core --example crypto_tour`. It walks through creating a demo account with fake data step by step: Secret Key format, KDF timing, encrypting an item, then showing that a flipped byte, a swapped AAD field and a wrong key each fail with a clear message. Add a "Crypto tour" card to the preview page with the command and its expected output.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
Tools (see "Connected tools" in AGENTS.md): save this exact prompt in Notion Prompts first; log every step in the Notion Execution log; commit and push every step to GitHub; file self-attack findings as GitHub issues and Notion Risks; open the PR with "Closes #<this phase's issue>"; use every skill that helps and record which ones.
