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
- **Status:** Proposed

## D-0002 — Phase 0 relay scope: axum + tokio only

- **Options:** scaffold the relay with the full Phase 4 stack (axum, tokio,
  sqlx, tracing) immediately; or only what the Phase 0 acceptance criteria need.
- **Choice:** axum + tokio with a single `GET /health` endpoint; sqlx, tracing
  and SQLite arrive in Phase 4 where they have behaviour to justify them.
- **Reason:** Phase 0 must stay minimal. Pulling a database layer and its
  dependency tree in early adds supply-chain surface with zero behaviour behind
  it.
- **Status:** Proposed

## D-0003 — Preview dashboard: Vite + TypeScript, no framework, no runtime network

- **Options:** a React (or similar) app; or a single no-framework Vite page.
- **Choice:** one page built from plain TypeScript modules and CSS custom
  properties; data comes only from `docs/preview/status.json` via a Vite JSON
  import; no external fonts and no third-party requests at runtime; the file is
  validated against `tools/preview/status.schema.json` at build time.
- **Reason:** the dashboard is a status page. The smallest dependency surface is
  the easiest to keep secure and fast, and the schema keeps the page honest.
- **Status:** Proposed

## D-0004 — CI: pinned actions, read-only permissions, both operating systems

- **Options:** floating action tags (`@v4`); full commit-SHA pins.
- **Choice:** pin `actions/checkout`, `dtolnay/rust-toolchain`,
  `Swatinem/rust-cache`, `EmbarkStudios/cargo-deny-action`, gitleaks and CodeQL
  to full commit SHAs; `permissions: contents: read` on every workflow;
  ubuntu-latest + windows-latest test matrix.
- **Reason:** AGENTS.md supply-chain bar — least privilege, and no mutable
  references in CI that a compromised upstream tag could redirect.
- **Status:** Proposed

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
- **Status:** Proposed

## Phase 1 proposals (D-0101 … D-0116)

These fill details the Phase 1 brief left open. Each one is **PROPOSED**: the
SPEC is written as if it were adopted, and the founder can change any of them
before Phase 2 starts. The ten that matter most are listed at the end of the
Phase 1 PR description.

## D-0101 — The Secret Key is 125 bits with a 5-bit checksum

- **Options:** (a) 128 bits in 26 characters (130 bits, 2 pad bits) with no
  checksum; (b) 128 bits in a 27-character display (26 data + 1 check); (c) 125
  bits in the brief's exact 26-character format (25 data + 1 check).
- **Choice:** (c).
- **Reason:** it matches the printed format exactly, 125 bits is still far above
  the 112-bit floor, and a real checksum catches the typing errors people make
  when reading paper. Option (b) is equally sound if 128 bits is a hard
  requirement; only the printed length changes.
- **Affects:** SPEC §4.2. **Status:** Proposed.

## D-0102 — OPAQUE uses the identity KSF

- **Options:** Argon2id KSF inside OPAQUE with the §4.3 parameters; identity KSF.
- **Choice:** identity KSF.
- **Reason:** the OPAQUE password input is already a uniform 256-bit HKDF output
  (`auth_secret`); stretching it again costs unlock time without adding entropy.
  The one place stretching matters — a human password — is §4.3.
- **Affects:** SPEC §4.4. **Status:** Proposed.

## D-0103 — The Account Key is wrapped under a derived key, not the MUK itself

- **Options:** `AEAD(MUK, AK)` literally as the brief writes it; derive
  `k_ak = HKDF(MUK, "studge/v1/ak-wrap")` first.
- **Choice:** derived key.
- **Reason:** AGENTS.md rule 3 requires purpose-specific sub-keys, and using one
  key for both OPAQUE derivation and AEAD is key reuse. The brief's notation
  reads as shorthand.
- **Affects:** SPEC §4.5. **Status:** Proposed.

## D-0104 — Head pins are stored in the encrypted key bundle as a hint

- **Options:** pins only on the device that verified them; also in the bundle.
- **Choice:** both; the bundle copy is a hint, never the sole anchor.
- **Reason:** a brand-new device otherwise has no anchor at all. The bundle copy
  narrows the rollback window to the first fetch. It does not remove trust on
  first use (R-0102).
- **Affects:** SPEC §4.5, §6.9. **Status:** Proposed.

## D-0105 — Sharing uses X25519-only HPKE in v1; the ML-KEM key is stored now

- **Options:** wait for a maintained hybrid X25519+ML-KEM-768 HPKE crate; ship
  X25519 now with the post-quantum identity key already in the account.
- **Choice:** X25519 now; generate and store the ML-KEM-768 identity key; switch
  the wrap to hybrid in a later suite version.
- **Reason:** no maintained crate offers the hybrid KEM cleanly today, and
  composing it by hand is forbidden. Storing the PQ key now avoids a key
  directory migration for every account later.
- **Affects:** SPEC §4.6, §9.2. **Status:** Proposed.

## D-0106 — Certificates and revocations carry `suite` and `type`

- **Options:** sign exactly the brief's field list; add `suite` and `type`.
- **Choice:** add both fields before signing.
- **Reason:** the same identity key signs certificates, revocations and
  transparency entries; without a type field a signature could be replayed in
  another role.
- **Affects:** SPEC §4.7, §4.8. **Status:** Proposed.

## D-0107 — Device enrolment requires a possession proof

- **Options:** certify whatever public key the approving device is shown;
  require the new device to sign a single-use nonce.
- **Choice:** signed nonce proof.
- **Reason:** a swapped QR code or a typo must not be enough to enrol a key the
  new device does not hold — that would create either a dead device or one an
  attacker controls.
- **Affects:** SPEC §4.7. **Status:** Proposed.

## D-0108 — Wrapping keys are salted with the object id

- **Options:** one `vk-wrap`/`ik-wrap` key for every object; salt with `vault_id`
  and `item_id`.
- **Choice:** per-object salt.
- **Reason:** every vault and item gets an independent wrapping key, so a nonce
  collision or a leaked key in one object cannot spread. It costs nothing.
- **Affects:** SPEC §4.9, §4.10. **Status:** Proposed.

## D-0109 — Vaults and items use random UUIDv4 identifiers

- **Options:** derive ids from content; random UUIDv4.
- **Choice:** random UUIDv4 (`vault_id`, `item_id`, `op_id`).
- **Reason:** the brief fixes account and device ids only. Random ids avoid
  leaking structure (a content hash would reveal equality across vaults) and
  avoid collisions between devices creating items offline.
- **Affects:** SPEC §4.1. **Status:** Proposed.

## D-0110 — Concrete size limits and quotas

- **Options:** leave them to each implementation; fix numbers in the spec.
- **Choice:** the table in SPEC §7.7 (1 MiB payload, 100 vaults, 250k ops per
  vault, 10 GiB per account, 8 MiB request, rate limits).
- **Reason:** every limit is a DoS and cost control; concrete numbers make Phase
  4 testable and can be raised later without a protocol change, because they are
  server policy, not cryptography.
- **Affects:** SPEC §5.6, §7.7. **Status:** Proposed.

## D-0111 — No snapshots or compaction in v1

- **Options:** add a snapshot op kind now; keep every op forever.
- **Choice:** full history; compaction deferred to a later schema version.
- **Reason:** snapshots add a second way to reconstruct state and a second way
  to get it wrong. Quotas bound growth, and clients may cache materialised
  state locally.
- **Affects:** SPEC §6.10. **Status:** Proposed.

## D-0112 — Add `DELETE /v1/sessions/current`

- **Options:** rely on 24-hour expiry; add an explicit logout endpoint.
- **Choice:** add the endpoint.
- **Reason:** “log out this device” is a user expectation, and a bearer token is
  otherwise valid until it expires.
- **Affects:** SPEC §7.3, §7.4. **Status:** Proposed.

## D-0113 — Dummy OPAQUE flow for unknown accounts

- **Options:** answer early for an unknown `account_id`; run a dummy exchange.
- **Choice:** dummy exchange with a random secret.
- **Reason:** it removes an account-enumeration timing oracle, and it is cheap
  because the KSF is the identity function (D-0102).
- **Affects:** SPEC §7.3. **Status:** Proposed.

## D-0114 — Folder transport layout

- **Options:** one file per vault; one file per op.
- **Choice:** one file per op named by hash, plus `account.cbor`, `devices.cbor`,
  `head.cbor` and a lock file; atomic rename on write.
- **Reason:** append-only even on a synced folder, and a truncated write is
  detectable by hash. One file per op avoids whole-vault rewrites and sync
  conflicts between devices.
- **Affects:** SPEC §7.10. **Status:** Proposed.

## D-0115 — A Shamir crate is needed for recovery (blocks Phase 12)

- **Options:** `sharks`, `vsss-rs`, another maintained implementation, or a
  2-of-3 XOR construction from approved primitives.
- **Choice:** none yet — this needs the founder's approval before Phase 12.
- **Reason:** AGENTS.md forbids adding a crypto crate without approval, and
  inventing secret sharing would be worse. The spec deliberately does not name a
  crate until it is approved.
- **Affects:** SPEC §10.2. **Status:** Proposed (needs a decision).

## D-0116 — Scoring: one class per item, explicit empty-vault state

- **Options:** let an item count in several classes; decide what an empty vault
  scores.
- **Choice:** highest weight wins; an empty vault shows “nothing to score yet”
  with value 100 rather than a bare perfect score.
- **Reason:** deterministic and explainable to a non-expert; a 0 for an empty
  vault would look like a failure and a bare 100 like a claim.
- **Affects:** SPEC §8. **Status:** Proposed.
