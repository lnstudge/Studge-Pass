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

## Phase 3 decisions (D-0301 … D-0306)

Implementation choices made while building the vault model, op log, storage,
import/export, generator and TOTP. Each is consistent with the approved SPEC;
the founder approves them by merging the Phase 3 pull request.

## D-0301 — Crates added in Phase 3, and why each one earns its place

- **Options:** hand-write everything (CSV, XML, TOTP, SQLite); add the smallest
  set of maintained crates; add a general "password manager utilities" bundle.
- **Choice:** the six below, pinned in `core/Cargo.toml` and locked in
  `Cargo.lock`.

| Crate | Version | Used for | Why this one |
| --- | --- | --- | --- |
| `rusqlite` | 0.41.1 | local `LocalStore` (SPEC §6, task item 3) | The brief names it. `bundled` compiles SQLite from source, so there is no system library to trust or version-match. Native targets only (see below). |
| `quick-xml` | 0.42.0 | KeePass XML import/export | Founder's choice (Q1 of the Phase 3 kickoff). No DTD, no entity expansion, no XInclude; `default-features = false` keeps the encoding layer out. |
| `totp-rs` | 6.0.0 | RFC 6238 TOTP (approved crate) | Already on the AGENTS.md list. `otpauth`, `zeroize` and `std` only. |
| `p256` | 0.14.0 | validating a stored passkey private key | Approved crate. Used once, to reject a corrupt PKCS#8 key at import instead of storing a passkey that can never sign. |
| `ml-kem` | 0.3.4 | ML-KEM-768 identity key in the bundle (SPEC §4.6, D-0105) | Approved crate. Generation and 64-byte seed storage only; nothing encapsulates with it in v1. |
| `serde_json` | 1.0.154 | import/export of the JSON formats | Was already a dev-dependency for the vectors. No `serde` derive: the importers read `serde_json::Value` directly, so no proc-macro crate enters the build. |

- **Not added:** a ZIP crate (`zip`, `flate2`) — see D-0304; an XML or CSV
  framework beyond `quick-xml` and the hand-written RFC 4180 reader; a date
  crate (`Timestamp` already exists); `base32` (the Secret Key already has a
  Crockford codec, and TOTP secrets use the standard alphabet through
  `totp-rs`).
- **SQLite is a native-only dependency.** `core-wasm` builds `core` for
  `wasm32-unknown-unknown`, where a C SQLite cannot go, so `rusqlite` lives
  under `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` and the
  SQLite module behind `#[cfg(not(target_arch = "wasm32"))]`. The browser
  extension keeps its vault in the extension's own storage (Phase 8).
- **Cost accepted:** `totp-rs` with `otpauth` pulls in `url` → `idna` → `icu_*`,
  which is a large data payload for a small feature. Kept anyway because
  hand-rolling percent-decoding and query parsing is a worse trade for a
  password manager; trimming it is a Phase 8 size decision, not a v1 one.
- **Affects:** `core/Cargo.toml`, `Cargo.lock`. **Status:** Proposed.

## D-0302 — KeePass XML: quick-xml with every dangerous feature switched off

- **Options:** a hand-written subset parser; `quick-xml`; defer the format.
- **Choice:** `quick-xml` 0.42.0 — the founder's answer at the Phase 3 kickoff.
  The importer rejects any `<!DOCTYPE>`, `<!ENTITY>`, processing instruction,
  unknown **entity reference** (only the five predefined entities and numeric
  character references are resolved), a duplicate key inside one entry and an
  element nested inside an element's text, and caps input at 64 MiB, nesting at
  64 and one element's text at 1 MiB.
- **Correction (PR #41 review):** this decision used to say the importer also
  rejects *unknown elements*. It does not, and should not: every real KeePass
  export carries elements this importer does not model (`Times`, `AutoType`,
  `Binaries`, `CustomData`, …), so rejecting unknown elements would reject every
  real file. Elements outside the modelled set are **ignored**, which is recorded
  as R-0302; unknown entities and malformed values are rejected. The founder's
  review chose correction over rejecting unknown elements.
- **Reason:** `quick-xml` is a tokenizer, not a document engine: it does not
  fetch external entities, expand internal ones, or honour DTDs unless asked.
  Refusing those constructs at the token level, plus size and depth caps, closes
  the XXE and billion-laughs classes without inventing a parser. Values are
  assembled byte-exactly (text pieces plus resolved entity references, committed
  when the element closes) and proven by export→import round-trip tests (R-0305).
- **Affects:** `core/src/import/keepass.rs`, `core/src/export/keepass.rs`;
  THREAT_MODEL R-0302, R-0305. **Status:** Proposed (correction awaiting
  approval with the rest of PR #41).

## D-0303 — In v1 an op carries the whole item; item keys wait for Phase 5

- **Options:** op payload = the full item state under the vault's `op-payload`
  key; or op payload = a diff, with per-field `item-field` envelopes under each
  item's key.
- **Choice:** the full state, sealed under `op-payload` with AAD
  `op/item`. The `ik` and `item-field` record types stay in the crypto layer
  (they are implemented and tested since Phase 2) and are written by the sync
  engine in Phase 5, where per-item records actually travel.
- **Reason:** SPEC §6.10 already says a client may cache materialised state and
  that v1 has no compaction, so a self-contained op is the simplest correct
  history: materialising is "take the winning op per item", with no replay of
  diffs and no second way to reconstruct state. Encrypting the same fields
  twice (once under the item key, once under the op key) would add 40 bytes per
  field and a second failure mode for no confidentiality gain, because the vault
  key protects both.
- **Consequence to revisit:** sharing a single item across vaults (Phase 11)
  re-encrypts it under the destination vault rather than re-wrapping an item
  key. Recorded as a follow-up.
- **Affects:** SPEC §5.5, §6.1; `core/src/vault`, `core/src/oplog`.
  **Status:** Proposed.

## D-0304 — 1PUX import takes the extracted `export.data` JSON

- **Options:** add a ZIP crate and read `.1pux` directly; require the caller to
  extract `export.data`; defer 1Password import.
- **Choice:** the extracted JSON — the founder's answer at the Phase 3 kickoff.
- **Reason:** a `.1pux` is a ZIP whose only interesting member is
  `export.data` (JSON). Reading ZIP means a decompressor in the most
  security-sensitive crate in the project, and core is deliberately I/O-free.
  The CLI and desktop clients (Phases 6–7) open the archive with platform
  tooling and hand core the bytes; the importer documents exactly that contract
  and rejects anything that is not the 1PUX JSON shape.
- **Affects:** `core/src/import/onepassword.rs`. **Status:** Proposed.

## D-0305 — `move` ops are rejected in v1

- **Options:** define `move` as a folder move inside one vault; define it as a
  move between vaults; reject the kind until a later phase defines it.
- **Choice:** reject it — the founder's answer at the Phase 3 kickoff. An op
  whose `kind` is `move` is a hard `UnsupportedOpKind` error, never silently
  ignored, and the item is not materialised from it.
- **Reason:** SPEC §6.1 lists the kind but defines no payload, no folder concept
  and no cross-vault semantics. Guessing would put an invented meaning into the
  signed history that cannot be changed without a schema version bump. Rejecting
  is fail-closed: a vault that contains such an op refuses to materialise rather
  than showing a state nobody agreed on. Phase 5/6 defines folders if the
  design needs them.
- **Affects:** SPEC §6.1 (note), `core/src/oplog/materialise.rs`, THREAT_MODEL
  R-0303. **Status:** Proposed.

## D-0306 — The local SQLite store keeps only ciphertext and public metadata

- **Options:** store plaintext item rows for speed; store ops and let the client
  materialise; store a plaintext cache alongside.
- **Choice:** the store holds exactly three things: op ciphertext (canonical
  bytes, hash-addressed), wrapped key envelopes, and non-secret metadata
  (`vault_id`, `lamport`, `kind`, `device_id`, `received_at`, schema version).
  There is no plaintext table. A test dumps the whole database file and greps it
  for the demo plaintext, the item titles and the passwords.
- **Reason:** AGENTS.md rule 4 and the A5 threat ("stolen locked device"): a
  local database is the most likely thing an attacker images first. Keeping the
  disk copy ciphertext-only means the same reasoning as the relay applies
  locally, and the query path already has to decrypt to show anything.
- **Cost:** materialising a vault decrypts every op it needs; SQLite indexes on
  `vault_id` and `lamport` keep the scan bounded, and Phase 5 adds a decrypted
  in-memory cache that is dropped on lock.
- **Affects:** `core/src/storage`, THREAT_MODEL R-0304. **Status:** Proposed.

## Phase 3 decisions, continued (D-0307 … D-0311)

## D-0307 — `.studgevault` is a container of already-encrypted records

- **Options:** encrypt the backup under a new passphrase-derived key; wrap the
  vault key for the file; ship a container of the records that are already
  ciphertext.
- **Choice:** the container. A backup holds the account record (AK envelope and
  key bundle), each vault's wrapped key, its head and its ops — every one of them
  already sealed by the code that owns it.
- **Reason:** a new file key would need a new HKDF label and a new record type,
  which this phase is not allowed to invent, and it would add a second place
  where a wrong passphrase could produce a silently different file. Because the
  records are individually authenticated, the container needs no MAC of its own:
  a flipped byte inside a record is caught when that record is verified or
  decrypted (tested), and a flipped structural byte is caught by the strict CBOR
  parser. Opening a backup therefore needs exactly what opening the account
  needs: the password and the Secret Key (SPEC §10.1).
- **Consequence:** the header (account id, vault ids, counts, creation time) is
  visible, the same metadata class as R-0101.
- **Affects:** `core/src/export/backup.rs`. **Status:** Proposed.

## D-0308 — The EFF large wordlist is bundled, with attribution

- **Options:** fetch a wordlist at runtime; generate one; bundle the EFF list.
- **Choice:** bundle `core/data/eff_large_wordlist.txt` (7776 words, fetched
  unmodified from eff.org on 2026-11-04) with `include_str!`, and record its
  CC BY 3.0 US licence and attribution in `core/data/README.md`.
- **Reason:** a passphrase generator that needs the network is not a passphrase
  generator. The list is a data file, not code, and its licence permits
  redistribution with attribution. Four of its words contain a hyphen
  (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`), which is why the default `-`
  separator is documented as ambiguous for splitting (not for security).
- **Affects:** `core/data/`, `core/src/generate.rs`. **Status:** Proposed.

## D-0309 — TOTP secrets shorter than 128 bits are accepted, and flagged

- **Options:** refuse a secret under 128 bits; accept it silently; accept it and
  surface the weakness.
- **Choice:** accept it through `totp-rs`'s non-compliant builder path, after our
  own parameter checks, and expose `TotpConfig::is_legacy_strength()` so the UI
  can say that the *service* chose a short secret.
- **Reason:** RFC 4226 recommends 160 bits and `totp-rs` refuses under 128, but
  real services still issue 80-bit secrets. Refusing one means refusing the
  user's account, and silently accepting one would hide a weakness the user
  cannot fix. The flag is the honest middle: the code still yields unguessable
  values (2^80), and the UI can explain where it came from.
- **Affects:** `core/src/totp.rs`. **Status:** Proposed.

## D-0310 — The conflict order is total: hash breaks a (lamport, device) tie

- **Options:** define the winner as SPEC §6.6 does and leave a tie undefined;
  add a final deterministic tiebreak.
- **Choice:** compare `(lamport, device_id)` as SPEC says, then `op_hash` if both
  are equal. Two different ops from one device with the same clock and the same
  parents (a device that forked itself, e.g. a restored backup) are therefore
  still resolved identically on every client.
- **Reason:** SPEC's rule is total between honest devices but not against one
  device that produced two ops for the same item at the same clock. A tie left
  undefined would make two clients disagree about the same history — exactly the
  failure the hash-chained log exists to prevent. The hash is random-looking and
  cannot be steered to pick a winner in advance.
- **Affects:** SPEC §6.6 (clarification), `core/src/oplog/materialise.rs`.
  **Status:** Proposed.

## D-0311 — KDF policy is enforced where the key is derived, not where the file is parsed

- **Options:** reject weak KDF parameters while parsing an account record; reject
  them when deriving the MUK; both.
- **Choice:** at derivation. `AccountBundle::from_cbor` parses any recorded
  parameters, and `derive_muk` refuses anything under the §4.3 floor before it
  runs Argon2.
- **Reason:** a client that cannot even parse the record can only say "corrupt
  file"; one that parses and then refuses says "this account was downgraded",
  which is the message a user needs. The security property is unchanged because
  there is no path to a key without `derive_muk`; the tests use a crate-internal
  raw derivation that is unreachable from outside the crate (D-0204).
- **Affects:** `core/src/account.rs`, `core/src/crypto/kdf.rs`. **Status:** Proposed.
