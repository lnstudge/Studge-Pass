# Decisions

One entry per decision with the options considered, the choice and the reason.
Status: **Proposed** → **Approved by founder** (by merging the phase pull
request) or **Rejected**. Mirrored in the Notion Decisions database.

## D-0001 — Pin dependency versions via committed lockfiles

- **Options:** exact `=` pins in `Cargo.toml`; caret ranges plus a committed
  `Cargo.lock`; no pinning at all.
- **Choice:** caret ranges in `Cargo.toml`, with `Cargo.lock` and
  `pnpm-lock.yaml` committed; Dependabot opens weekly, reviewable updates.
- **Reason:** the committed lockfile is the exact pin that CI and the founder's
  machine build against, and it keeps security updates small and reviewable.
  AGENTS.md requires committed lockfiles. Exact `=` pins would make every
  transitive update a manual edit.
- **Status:** Approved by founder

## D-0002 — Phase 0 relay scope: axum + tokio only

- **Options:** scaffold the relay with the full Phase 4 stack (axum, tokio,
  sqlx, tracing) immediately; or only what the Phase 0 acceptance criteria need.
- **Choice:** axum + tokio with a single `GET /health` endpoint; sqlx, tracing
  and SQLite arrive in Phase 4 where they have behaviour to justify them.
- **Reason:** Phase 0 must stay minimal. Pulling a database layer and its
  dependency tree in early adds supply-chain surface with zero behaviour behind
  it.
- **Status:** Approved by founder

## D-0003 — Preview dashboard: Vite + TypeScript, no framework, no runtime network

- **Options:** a React (or similar) app; or a single no-framework Vite page.
- **Choice:** one page built from plain TypeScript modules and CSS custom
  properties; data comes only from `docs/preview/status.json` via a Vite JSON
  import; no external fonts and no third-party requests at runtime; the file is
  validated against `tools/preview/status.schema.json` at build time.
- **Reason:** the dashboard is a status page. The smallest dependency surface is
  the easiest to keep secure and fast, and the schema keeps the page honest.
- **Status:** Approved by founder

## D-0004 — CI: pinned actions, read-only permissions, both operating systems

- **Options:** floating action tags (`@v4`); full commit-SHA pins.
- **Choice:** pin `actions/checkout`, `dtolnay/rust-toolchain`,
  `Swatinem/rust-cache`, `EmbarkStudios/cargo-deny-action`, gitleaks and CodeQL
  to full commit SHAs; `permissions: contents: read` on every workflow;
  ubuntu-latest + windows-latest test matrix.
- **Reason:** AGENTS.md supply-chain bar — least privilege, and no mutable
  references in CI that a compromised upstream tag could redirect.
- **Status:** Approved by founder

## D-0005 — CodeQL is gated on public repositories

- **Options:** run CodeQL and let it fail on the private repository; drop CodeQL
  entirely; keep the workflow but skip the job while the repository is private.
- **Choice:** keep `codeql.yml` in the repository, but gate the `analyze` job on
  `!github.event.repository.private`. It starts running automatically if the
  repository becomes public or GitHub Advanced Security is enabled.
- **Reason:** on a private repository without GHAS the SARIF upload is rejected
  ("Resource not accessible by integration"), so the check is permanently red
  and trains reviewers to ignore failures. The analysis itself worked (12 Rust
  files extracted, 0 extraction errors) — only the upload is unavailable. The
  gap is recorded as R-0001 in docs/THREAT_MODEL.md.
- **Status:** Approved by founder

## Phase 1 proposals (D-0101 … D-0116)

These fill details the Phase 1 brief left open. Each one is **PROPOSED**: the
SPEC is written as if it were adopted, and the founder can change any of them
before Phase 2 starts. The ten that matter most are listed at the end of the
Phase 1 PR description.

## D-0101 — The Secret Key is 128 bits with a 27-character display

- **Options:** (a) 128 bits in 26 characters (130 bits, 2 pad bits) with no
  checksum; (b) 128 bits in a 27-character display (26 data + 1 check); (c) 125
  bits in the brief's exact 26-character format (25 data + 1 check).
- **Choice:** **(b)** — a full 128-bit key printed as
  `SP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`: 26 key characters (130 bits, the top
  two fixed to zero) followed by a 5-bit check character.
- **Reason:** the founder chose the full 128 bits. The extra character buys back
  the missing three bits and keeps a real typo check. 125 bits would also have
  been safe, but 128 is what the brief asked for.
- **Affects:** SPEC §4.2, §4.3, `docs/diagrams/key-hierarchy.svg`. **Status:** Approved by founder.

## D-0102 — OPAQUE uses the identity KSF

- **Options:** Argon2id KSF inside OPAQUE with the §4.3 parameters; identity KSF.
- **Choice:** identity KSF.
- **Reason:** the OPAQUE password input is already a uniform 256-bit HKDF output
  (`auth_secret`); stretching it again costs unlock time without adding entropy.
  The one place stretching matters — a human password — is §4.3.
- **Affects:** SPEC §4.4. **Status:** Approved by founder.

## D-0103 — The Account Key is wrapped under a derived key, not the MUK itself

- **Options:** `AEAD(MUK, AK)` literally as the brief writes it; derive
  `k_ak = HKDF(MUK, "studge/v1/ak-wrap")` first.
- **Choice:** derived key.
- **Reason:** AGENTS.md rule 3 requires purpose-specific sub-keys, and using one
  key for both OPAQUE derivation and AEAD is key reuse. The brief's notation
  reads as shorthand.
- **Affects:** SPEC §4.5. **Status:** Approved by founder.

## D-0104 — Head pins are stored in the encrypted key bundle as a hint

- **Options:** pins only on the device that verified them; also in the bundle.
- **Choice:** both; the bundle copy is a hint, never the sole anchor.
- **Reason:** a brand-new device otherwise has no anchor at all. The bundle copy
  narrows the rollback window to the first fetch. It does not remove trust on
  first use (R-0102).
- **Affects:** SPEC §4.5, §6.9. **Status:** Approved by founder.

## D-0105 — Sharing uses X25519-only HPKE in v1; the ML-KEM key is stored now

- **Options:** wait for a maintained hybrid X25519+ML-KEM-768 HPKE crate; ship
  X25519 now with the post-quantum identity key already in the account.
- **Choice:** X25519 now; generate and store the ML-KEM-768 identity key;
  **Phase 11 must re-check for a maintained hybrid HPKE / X-Wing crate and
  switch if one exists.**
- **Reason:** no maintained crate offers the hybrid KEM cleanly today, and
  composing it by hand is forbidden. Storing the PQ key now avoids a key
  directory migration for every account later. The founder approved the X25519
  v1 on the Phase 11 re-check condition.
- **Affects:** SPEC §4.6, §9.2; THREAT_MODEL R-0116. **Status:** Approved by founder.

## D-0106 — Certificates and revocations carry `suite` and `type`

- **Options:** sign exactly the brief's field list; add `suite` and `type`.
- **Choice:** add both fields before signing.
- **Reason:** the same identity key signs certificates, revocations and
  transparency entries; without a type field a signature could be replayed in
  another role.
- **Affects:** SPEC §4.7, §4.8. **Status:** Approved by founder.

## D-0107 — Device enrolment requires a possession proof

- **Options:** certify whatever public key the approving device is shown;
  require the new device to sign a single-use nonce.
- **Choice:** signed nonce proof.
- **Reason:** a swapped QR code or a typo must not be enough to enrol a key the
  new device does not hold — that would create either a dead device or one an
  attacker controls.
- **Affects:** SPEC §4.7. **Status:** Approved by founder.

## D-0108 — Wrapping keys are salted with the object id

- **Options:** one `vk-wrap`/`ik-wrap` key for every object; salt with `vault_id`
  and `item_id`.
- **Choice:** per-object salt.
- **Reason:** every vault and item gets an independent wrapping key, so a nonce
  collision or a leaked key in one object cannot spread. It costs nothing.
- **Affects:** SPEC §4.9, §4.10. **Status:** Approved by founder.

## D-0109 — Vaults and items use random UUIDv4 identifiers

- **Options:** derive ids from content; random UUIDv4.
- **Choice:** random UUIDv4 (`vault_id`, `item_id`, `op_id`).
- **Reason:** the brief fixes account and device ids only. Random ids avoid
  leaking structure (a content hash would reveal equality across vaults) and
  avoid collisions between devices creating items offline.
- **Affects:** SPEC §4.1. **Status:** Approved by founder.

## D-0110 — Concrete size limits and quotas

- **Options:** leave them to each implementation; fix numbers in the spec.
- **Choice:** the table in SPEC §7.7 (1 MiB payload, 100 vaults, 250k ops per
  vault, **100 MiB of vault data per account on the free hosted relay**, 1 GiB
  once attachments ship, self-hosters may raise it, 8 MiB request, rate limits).
- **Reason:** every limit is a DoS and cost control; concrete numbers make Phase
  4 testable and can be raised later without a protocol change, because they are
  server policy, not cryptography.
- **Affects:** SPEC §5.6, §7.7. **Status:** Approved by founder.

## D-0111 — No snapshots or compaction in v1

- **Options:** add a snapshot op kind now; keep every op forever.
- **Choice:** full history; compaction deferred to a later schema version.
- **Reason:** snapshots add a second way to reconstruct state and a second way
  to get it wrong. Quotas bound growth, and clients may cache materialised
  state locally.
- **Affects:** SPEC §6.10. **Status:** Approved by founder.

## D-0112 — Add `DELETE /v1/sessions/current`

- **Options:** rely on 24-hour expiry; add an explicit logout endpoint.
- **Choice:** add the endpoint.
- **Reason:** “log out this device” is a user expectation, and a bearer token is
  otherwise valid until it expires.
- **Affects:** SPEC §7.3, §7.4. **Status:** Approved by founder.

## D-0113 — Dummy OPAQUE flow for unknown accounts

- **Options:** answer early for an unknown `account_id`; run a dummy exchange.
- **Choice:** dummy exchange with a random secret.
- **Reason:** it removes an account-enumeration timing oracle, and it is cheap
  because the KSF is the identity function (D-0102).
- **Affects:** SPEC §7.3. **Status:** Approved by founder.

## D-0114 — Folder transport layout

- **Options:** one file per vault; one file per op.
- **Choice:** one file per op named by hash, plus `account.cbor`, `devices.cbor`,
  `head.cbor` and a lock file; atomic rename on write.
- **Reason:** append-only even on a synced folder, and a truncated write is
  detectable by hash. One file per op avoids whole-vault rewrites and sync
  conflicts between devices.
- **Affects:** SPEC §7.10. **Status:** Approved by founder.

## D-0115 — Recovery uses replicated 2-of-3 XOR sharing, no new crate

- **Options:** `sharks`; `vsss-rs`; a 2-of-3 XOR construction from approved
  primitives.
- **Choice:** **(c)** — replicated XOR sharing. Two random 32-byte pads `R1` and
  `R2`; `R3 = R1 ⊕ R2 ⊕ S`; guardian *i* holds pads *i* and *i+1*; any two
  guardians therefore hold all three pads. Each 64-byte share is HPKE-sealed
  with AAD binding `account_id`, `guardian_id` and `share_index`.
- **Reason:** the founder chose a textbook construction from `OsRng` and XOR. It
  is information-theoretically 2-of-3, needs no third-party crate, and is fully
  specified in SPEC §10.2. Phase 12 writes the test vectors (fixed `S`, `R1`,
  `R2`, the expected shares and all three reconstruction pairs).
- **Affects:** SPEC §10.2. **Status:** Approved by founder.

## D-0116 — Scoring: one class per item, explicit empty-vault state

- **Options:** let an item count in several classes; decide what an empty vault
  scores.
- **Choice:** highest weight wins; an empty vault shows “nothing to score yet”
  with value 100 rather than a bare perfect score.
- **Reason:** deterministic and explainable to a non-expert; a 0 for an empty
  vault would look like a failure and a bare 100 like a claim.
- **Affects:** SPEC §8. **Status:** Approved by founder.

## D-0117 — v1 membership is write-or-nothing

- **Options:** add signed capabilities now so a member can hold read-only
  access; ship sharing where every member can write, and say so; postpone
  sharing entirely.
- **Choice:** write-or-nothing in v1, **and Phase 11 must add owner-signed
  capabilities so view-only sharing can be enforced** (issue #18). The UI must
  not offer “view only” until then.
- **Reason:** the relay cannot enforce roles, and peers accept any op signed by a
  certified member device. Without a capability the owner signs, “read-only” is
  a promise the protocol cannot keep — exactly the kind of unbacked security
  claim AGENTS.md forbids. Approved on the condition that Phase 11 adds the
  capabilities. Recorded as R-0113.
- **Affects:** SPEC §9.1; THREAT_MODEL R-0113; issue #18. **Status:** Approved by founder.

## Phase 2 decisions (D-0201 … D-0207)

Implementation choices made while building `core/src/crypto`. Each is consistent
with the approved SPEC; the founder approved all seven when PR #38 was merged.

## D-0201 — Crate versions for Phase 2

- **Choice:** the pinned set below, with `Cargo.lock` committed. All are on the
  AGENTS.md approved list except `thiserror` (error derive), `proptest` and
  `serde_json` (dev-only); none of those does cryptography.

| Crate | Version | Used for (SPEC) | Why this one |
| --- | --- | --- | --- |
| `argon2` | 0.6.0 | Argon2id for the MUK (§4.3) | RustCrypto, RFC 9106, no `unsafe` in our paths |
| `blake3` | 1.8.7 | op hashes, checksum, safety codes (§5.7) | the reference BLAKE3 implementation |
| `chacha20poly1305` | 0.11.0 | XChaCha20-Poly1305 envelopes (§5.1) | RustCrypto AEAD, 24-byte nonce support |
| `ciborium` | 0.2.2 | canonical CBOR (§5.3) | small serde CBOR; we add a strict re-encode check |
| `ed25519-dalek` | 3.0.0 | device/identity signatures (§4.7) | dalek-cryptography, RFC 8032 |
| `getrandom` | 0.4.3 | the only RNG (§4, rule 3) | OS source, no userspace fallback |
| `hkdf` | 0.13.0 | every sub-key (§5.4) | RustCrypto, RFC 5869 |
| `hpke` | 0.15.1 | sealing vault keys (§9.2) | RFC 9180; X25519 KEM; features pinned to `x25519,chacha,alloc,getrandom` |
| `sha2` | 0.11.1 | HKDF/OPAQUE internals (§5.7) | RustCrypto |
| `subtle` | 2.6.1 | constant-time compares (rule 5) | the standard constant-time primitives |
| `thiserror` | 2.0.21 | `CryptoError` derive | no runtime behaviour of its own |
| `unicode-normalization` | 0.1.26 | NFKC passwords (§4.3) | Unicode reference tables |
| `x25519-dalek` | 3.0.0 | HPKE recipient keys (§4.6) | dalek-cryptography |
| `zeroize` | 1.9.1 | secret wiping (rule 4) | the standard zeroization crate |
| `proptest` | 1.12.0 (dev) | property tests | shrinking + reproducibility |
| `serde_json` | 1.0.154 (dev) | the vector file | test-only |

- **Reason:** pinning plus a committed lockfile gives reproducible builds; every
  entry is either on the approved list or does no crypto at all.
- **Affects:** `core/Cargo.toml`, `Cargo.lock`. **Status:** Approved by founder.

## D-0202 — Timestamps are fixed-width RFC 3339 UTC

- **Options:** Unix seconds as an integer; RFC 3339 text; a date-time crate.
- **Choice:** `YYYY-MM-DDTHH:MM:SSZ`, exactly 20 characters, parsed strictly.
  Comparison is numeric through a small civil-date conversion, so no date crate
  is added.
- **Reason:** §6.1 already uses RFC 3339 for ops, and §4.7–4.8 leave the encoding
  open. Fixed width makes the text sort correctly and keeps the wire readable.
- **Affects:** SPEC §4.7, §4.8 (clarification). **Status:** Approved by founder.

## D-0203 — The `test-vectors` feature exposes fixed-nonce sealing

- **Options:** a deterministic RNG behind a feature; a `seal_with_nonce` helper
  behind a feature; no vectors generated in-tree.
- **Choice:** `test-vectors` exposes `aead::seal_with_nonce`, and only that.
  Nonces stay random everywhere else, and `seal` cannot be talked into taking a
  caller nonce in a normal build.
- **Reason:** the vectors need byte-exact ciphertext; a deterministic RNG would
  be a much larger foot-gun than one fixed-nonce function. The feature is
  documented as test-only and CI runs it as a separate step.
- **Affects:** `core/Cargo.toml`, `core/tests/vectors.rs`. **Status:** Approved by founder.

## D-0204 — KDF minimums live in `derive_muk`; tests use a crate-internal raw path

- **Options:** accept any parameters in the primitive and enforce minimums in the
  account layer; enforce in `derive_muk`; make tests slow.
- **Choice:** `derive_muk` rejects anything below 64 MiB / t=3 / p=1 or an
  unknown version. The unit tests that need speed call `derive_muk_raw`, which is
  `pub(crate)` and unreachable from outside the crate.
- **Reason:** defense in depth — a caller cannot accidentally accept a downgraded
  account — while keeping the suite fast. The real parameters are exercised by
  one `#[ignore]` test that verifies the published MUK vector.
- **Affects:** SPEC §4.3. **Status:** Approved by founder.

## D-0205 — The hybrid KEM is available upstream, but v1 stays X25519

- **Options:** wire X-Wing now because `hpke` 0.15 ships it; keep v1 on X25519
  per D-0105 and leave a typed seam.
- **Choice:** keep X25519. `hpke::KemChoice::XWingMlKem768` exists and returns
  `UnsupportedKem`, with a `TODO(security)` that points at Phase 11.
- **Reason:** D-0105 was approved with exactly this condition, and SPEC §9.2
  says v1 wraps with X25519. The finding that the crate now supports X-Wing
  means the Phase 11 re-check can almost certainly flip it on; that is a
  Phase 11 change, not a Phase 2 surprise.
- **Affects:** SPEC §9.2, R-0116. **Status:** Approved by founder.

## D-0206 — The wasm build uses the browser RNG backend for getrandom

- **Options:** leave wasm builds unsupported; enable getrandom's `wasm_js`
  feature for wasm32 only; implement a custom backend.
- **Choice:** enable `wasm_js` in `core-wasm` under
  `cfg(target_arch = "wasm32")` only.
- **Reason:** getrandom 0.4 has no default backend on `wasm32-unknown-unknown`,
  so after Phase 2 added core's RNG the workspace stopped building for the
  extension target and CI caught it. The documented feature uses the browser's
  `Crypto.getRandomValues` through wasm-bindgen and does not affect native
  builds, which keep the OS backend.
- **Affects:** `core-wasm/Cargo.toml`, `Cargo.lock`. **Status:** Approved by founder.

## D-0207 — Every signature covers a BLAKE3 digest, not the raw body

- **Options:** sign the canonical CBOR directly (as §4.7 read for the enrolment
  proof); sign `BLAKE3(canonical CBOR)` for every signed object.
- **Choice:** the digest, for certificates, revocations and enrolment proofs,
  matching the op hash rule in §6.3. SPEC §4.7 was updated.
- **Reason:** one rule across the whole protocol, a fixed 32-byte signed message,
  and domain separation already lives in the body's `suite`/`type` fields.
  **Note:** the Phase 2 code first signed raw bodies and was corrected during the
  PR #38 review; the vectors were regenerated.
- **Affects:** SPEC §4.7, §4.8, §6.3; `core/src/crypto/signing.rs`; vectors.
  **Status:** Approved by founder.
