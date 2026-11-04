# Studge Pass threat model

> **Status: skeleton.** Phase 1 fills this in. Open risks found during Phase 0's
> self-attack review are recorded under "Open risks" at the end of this file.

## Assets and adversaries

## Trust boundaries

## Attacks on the relay

## Attacks on clients

## Attacks on sync

## Attacks on recovery

## Supply-chain attacks

## Phase 0 self-attack review (2026-11-04)

What an attacker would try against what Phase 0 actually ships: the repository,
its CI, the five crates and the local preview dashboard. "Blocked" means a test
or a mechanical control fails the build if the protection is removed; anything
not blocked is recorded under Open risks below.

| # | Attack | Blocked by | Evidence |
| --- | --- | --- | --- |
| 1 | Store HTML/JavaScript in `status.json` (title, summary, caption) so the dashboard executes it when the founder opens it | Rendering only through `textContent`; ESLint bans `innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`; CSP has `script-src 'self'` and no `unsafe-eval` | `src/static-scan.test.ts` (3 tests), `eslint.config.js` rules |
| 2 | Point a screenshot entry at `../../AGENTS.md`, an absolute path or another origin to read local files or beacon out | Schema pattern `^screenshots/[A-Za-z0-9._/-]+$`, `screenshotUrl()` rejects `..`, absolute and cross-origin paths, validator checks the file exists | `src/lib.test.ts` (path-traversal cases), `scripts/validate-status.mjs` |
| 3 | Add a dependency whose install script runs arbitrary code on the maintainer's machine | `.npmrc` sets `ignore-scripts=true`; pnpm also blocks by default; Playwright browsers are installed explicitly | `src/repo-policy.test.ts` (`ignore-scripts`), install log (135 packages, no build scripts) |
| 4 | Move an upstream action tag to attacker code so CI runs it with repository access | Every `uses:` pinned to a 40-character commit SHA; policy test fails on a floating tag | `src/repo-policy.test.ts` (SHA pinning) |
| 5 | Use `pull_request_target` or a write-scoped token to escalate a pull request | No `pull_request_target` anywhere; every workflow starts from `permissions: contents: read` | `src/repo-policy.test.ts` (permissions, no target) |
| 6 | Commit a secret | gitleaks on every push and PR; manual staged-diff secret scan before every commit | Security workflow green on every commit; one false positive (`risk-title` vs the `sk-` pattern) triaged by hand |
| 7 | Introduce a vulnerable or yanked crate | `cargo deny` with `yanked = "deny"` and the advisory database; weekly `cargo audit`; Dependabot PRs reviewed by the founder | `cargo deny check` green; `security.yml` |
| 8 | Pull in a dependency whose licence is incompatible with GPL-3.0/AGPL-3.0 | `[licenses]` allowlist in `deny.toml`; CI deny job | `cargo deny check` — "licenses ok" |
| 9 | Reach the relay or the dashboard from another machine on the LAN | Relay binds a constant `127.0.0.1:8787` with a unit test; Vite binds `127.0.0.1` | `relay/src/main.rs` (`binds_to_loopback_only`), `src/repo-policy.test.ts` |
| 10 | Land `unwrap()`/`expect()`/`panic!` on a future network, file or user input path | Policy test scans production Rust and strips `#[cfg(test)]` modules; clippy `-D warnings` | `src/repo-policy.test.ts`, CI clippy job |
| 11 | Get a phishing or hostile link into the dashboard through `status.json` | Only a reviewed repository file feeds it; every push is reviewed before merge | Not blocked mechanically — R-0002 (accepted, low) |
| 12 | Read files outside `docs/` through the local Vite server | `server.fs.allow` is limited to the repository root, which is already public to the founder; the server is loopback-only | Reviewed in `vite.config.ts` — R-0003 (accepted, low) |
| 13 | Point `pnpm shot` at a hostile page | The helper only renders and screenshots; it holds no credentials and stores nothing but a PNG | Reviewed in `scripts/shot.mjs` — accepted |
| 14 | Slip past gitleaks with a secret format it does not know | Manual staged-diff review before every commit; GitHub secret scanning can be enabled later | Not blocked mechanically — R-0004 (accepted, low) |
| 15 | Ship a high or critical npm advisory in the build tooling | CI runs `pnpm audit --audit-level high`; Dependabot tracks upgrades; moderate dev-only findings are recorded (R-0005) | `security.yml` pnpm-audit job |

## Open risks

### R-0001 — CodeQL code scanning is unavailable while the repository is private

- **Phase:** 0 · **Status:** Open · **Severity:** medium · **Issue:** #23
- **What:** `codeql.yml` skips its analysis job unless the repository is public
  or GitHub Advanced Security is enabled, because the SARIF upload is rejected on
  private repositories without GHAS ("Resource not accessible by integration").
- **Impact:** no automated code-scanning queries run in CI yet. gitleaks (every
  push and PR), `cargo deny` (advisories, licences, bans, sources), `cargo audit`
  (weekly) and clippy still run.
- **Resolution:** make the repository public, or enable GHAS; the workflow then
  runs unchanged on the next push.

### R-0002 — Link targets in `status.json` are trusted from the repository

- **Phase:** 0 · **Status:** Accepted · **Severity:** low
- **What:** the dashboard renders whatever URLs the file contains. A malicious
  pull request could point a "Try it" card or link at a phishing page.
- **Why accepted:** the file is part of the reviewed repository; every pull
  request is read by the founder before merge, and the dashboard is local.
- **Revisit:** if status.json ever becomes writable by anything other than a
  reviewed commit, allowlist the URL hosts.

### R-0003 — The local preview server runs with a relaxed style CSP

- **Phase:** 0 · **Status:** Accepted · **Severity:** low
- **What:** `style-src 'unsafe-inline'` is required for Vite's hot reload; the
  page itself writes no inline styles in markup.
- **Why accepted:** the server is loopback-only, serves a reviewed repository
  and has no authentication, accounts or secrets. The product UI must not copy
  this relaxation (the design-system phases enforce a strict CSP).

### R-0004 — gitleaks can miss novel secret formats

- **Phase:** 0 · **Status:** Accepted · **Severity:** low
- **What:** secret scanners only find what they have patterns for.
- **Why accepted:** a manual staged-diff scan runs before every commit, the
  project stores no secrets in the repository by design, and GitHub secret
  scanning can be enabled later without code changes.

### R-0005 — `minimatch` advisory in the ESLint toolchain (dev-only)

- **Phase:** 0 · **Status:** Accepted · **Severity:** low
- **What:** `pnpm audit` reports GHSA-g3hv-75wg-m249 (moderate: denial of service
  through globpart amplification, `minimatch >=7.0.0 <11.0.1`), reached through
  `eslint -> minimatch` and `typescript-eslint -> minimatch`.
- **Why accepted:** the whole chain is build-time tooling. It is never shipped to
  users and never runs on untrusted input; the dashboard renders through DOM
  text nodes with a CSP in front of it. No patched ESLint release exists yet.
- **Mitigation:** CI runs `pnpm audit --audit-level high`, so a high or critical
  advisory fails the build; Dependabot tracks the upgrade.
- **Revisit:** when ESLint or typescript-eslint move to `minimatch >= 11.0.1`.
