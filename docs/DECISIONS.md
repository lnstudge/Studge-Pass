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
