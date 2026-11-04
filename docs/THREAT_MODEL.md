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

## Open risks

### R-0001 — CodeQL code scanning is unavailable while the repository is private

- **Phase:** 0 · **Status:** Open
- **What:** `codeql.yml` skips its analysis job unless the repository is public
  or GitHub Advanced Security is enabled, because the SARIF upload is rejected on
  private repositories without GHAS ("Resource not accessible by integration").
- **Impact:** no automated code-scanning queries run in CI yet. gitleaks (every
  push and PR), `cargo deny` (advisories, licences, bans, sources), `cargo audit`
  (weekly) and clippy still run.
- **Resolution:** make the repository public, or enable GHAS; the workflow then
  runs unchanged on the next push.
