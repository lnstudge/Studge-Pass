<!-- Phase 15: hardening and release. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 15: hardening and release engineering.**

- Fuzzing with cargo-fuzz for the envelope parser, op CBOR decoding, every importer, the CXF parser and relay request parsing. Add a short CI fuzz smoke run.
- Dependency hygiene: cargo audit, cargo deny and cargo vet in CI, plus Dependabot.
- Reproducible builds: pin toolchains and lockfiles, set SOURCE_DATE_EPOCH, and script deterministic builds for the relay (Docker), the CLI and the extension zip. A CI job builds twice and compares hashes.
- Release workflow:
  1. A version tag triggers builds for Windows, macOS and Linux, the extension zips and the Android AAB.
  2. Sign artifacts with Sigstore cosign.
  3. Publish SBOMs (CycloneDX for Rust and JS) and checksums.
- docs/AUDIT_PACK.md: an architecture overview, links to SPEC and THREAT_MODEL, evil-relay test results, the crypto crates with versions, and known limitations, ready to send to an audit firm.
- Update SECURITY.md with a disclosure policy and a bug-bounty placeholder.

Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Preview for me: a "Release readiness" panel on the preview page covering fuzzing hours and crashes found, reproducible-build hash comparison, SBOM link, signature verification command and audit-pack status.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
Tools (see "Connected tools" in AGENTS.md): save this exact prompt in Notion Prompts first; log every step in the Notion Execution log; commit and push every step to GitHub; file self-attack findings as GitHub issues and Notion Risks; open the PR with "Closes #<this phase's issue>"; use every skill that helps and record which ones.
