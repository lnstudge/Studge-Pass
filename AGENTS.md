# Studge Pass: rules for AI coding agents

## What this project is
Studge Pass is a free, fully open-source password and passkey manager. Every feature is free forever, with no paid tiers. Clients and core are GPL-3.0-or-later. The sync server ("relay") is AGPL-3.0-or-later.
Security promise: the relay is treated as an attacker. It stores only ciphertext. It must not be able to read, modify, reorder, roll back or substitute data without clients detecting it.

## Repository layout
- /core: Rust lib `studge-core`. Crypto, vault model, op log, sync engine, import/export, health scoring. No direct I/O; uses injected traits.
- /core-wasm: wasm-bindgen wrapper of core for the browser extension.
- /core-ffi: UniFFI wrapper of core for Android/iOS (added later).
- /relay: Rust bin `studge-relay` (axum, sqlx, SQLite by default).
- /cli: Rust bin `studge`.
- /test-harness: the evil relay and adversarial integration tests.
- /desktop: Tauri 2 + React + TypeScript.
- /extension: MV3 browser extension (TypeScript).
- /android, /ios: native apps (later).
- /docs: SPEC.md, THREAT_MODEL.md, PROGRESS.md, DECISIONS.md.

## Non-negotiable security rules
1. Never invent cryptography. Use only well-known, maintained crates. Pin versions and justify each in docs/DECISIONS.md. Approved list:
   argon2, chacha20poly1305 (XChaCha20Poly1305), hkdf, sha2, blake3, ed25519-dalek, x25519-dalek, p256, hpke, ml-kem, opaque-ke, rand_core/getrandom (OsRng only), zeroize, secrecy, subtle, ciborium, unicode-normalization, totp-rs, zxcvbn.
   Ask before adding any other crypto crate.
2. Every ciphertext is AEAD. Its AAD binds the suite version, account or vault id, item id, record type and field name. Any decryption failure is a hard error. Never skip or "repair" it silently.
3. XChaCha20-Poly1305 nonces are 24 random bytes from OsRng. Derive purpose-specific sub-keys with HKDF using labels "studge/v1/<purpose>", defined as constants in one file.
4. Secrets live in Zeroizing/SecretBox types. Never log, print, Debug-format, serialise into errors, or send secrets or plaintext anywhere. Implement Debug manually with redaction.
5. Compare MACs, tokens and hashes in constant time (subtle).
6. `#![forbid(unsafe_code)]` in core, relay and cli.
7. No legacy or downgrade paths. There is one cipher suite id, "v1". Reject unknown versions.
8. The relay must never receive the master password, a password-equivalent hash, the Secret Key, the account key, vault keys, item keys, plaintext item data or plaintext URLs.
9. Core makes no network calls except through the injected Transport trait. No analytics. No telemetry.
10. No unwrap(), expect() or panic! on any input that comes from the network, files or users. These are allowed in tests only.
11. Browser extension: never render fill or save prompts inside page-controlled DOM. Always take the origin from the browser's sender information, never from page-provided data.

## Security bar (the top priority, above features, speed and looks)
No software is unhackable, so build as if skilled, well-funded attackers are already looking at every line.
- If something cannot be done securely, do not ship it. Stop and ask me.
- Defence in depth: each layer assumes the layer before it has already failed.
- Secure by default: the safest settings are on. Risky options are off, behind a clear warning.
- Least privilege everywhere: extension permissions, Tauri capabilities, Android permissions, token scopes, CI permissions (`permissions: read-all` by default).
- Validate every input at every trust boundary. Enforce strict size limits. Parse strictly and reject unknown fields.
- Follow OWASP ASVS Level 3 for the relay, OWASP MASVS L2 for mobile, and avoid the CWE Top 25.
- No `eval`, no `new Function`, no `innerHTML` or `dangerouslySetInnerHTML` with data. Strict CSP with no `unsafe-inline` and no `unsafe-eval` (`wasm-unsafe-eval` is allowed only where WebAssembly needs it).
- Every authentication path has rate limits, constant-time checks and generic error messages.
- Supply chain: commit lockfiles, pin every version, keep dependencies minimal, block dependency install scripts, pin GitHub Actions to commit SHAs, and run cargo audit, cargo deny and pnpm audit.
- Before every commit, check the staged diff for secrets and private data.
- **End every phase by attacking your own work.** List at least 10 concrete ways an attacker could break what you just built. For each, prove with a test that it is blocked, or record it as an open risk in docs/THREAT_MODEL.md.
- Never claim in the UI, the README or a commit message that something is secure unless a test or an audit backs it.

## Design bar (beauty and ease of use)
The goal is the most beautiful, calm and trustworthy password manager available, and noticeably nicer to use than 1Password, Bitwarden, Proton Pass and Dashlane.
- All UI uses the shared design system in /design (tokens for colour, type, spacing, radius, elevation and motion). Never hard-code colours or sizes in components.
- Clarity over decoration. One primary action per screen. Generous whitespace on an 8-point spacing grid. Strong typographic hierarchy. One consistent icon set.
- Motion of 150–250 ms ease-out that feels quick and calm, and that respects reduced-motion settings. Add small moments of delight: copy confirmation, unlock, the score ring filling.
- Design empty, loading and error states with care. Use skeletons instead of spinners. Error messages say what happened and what to do next.
- Design light and dark themes separately, not as inversions of each other. Meet WCAG 2.2 AA (aim for AAA on body text). Support full keyboard and screen-reader use. Touch targets are at least 44 px.
- Indian scripts must render beautifully (pair the UI font with Noto Sans Devanagari and other Noto families). Layouts must not break with long Hindi or Tamil strings.
- Privacy in the UI: never fetch site favicons from third parties by default. Use locally generated monogram avatars.
- Security UX: never trade safety for looks. No dark patterns. Warnings are calm, clear and specific.
- Every UI phase ends with screenshots in docs/screenshots/ (light and dark, desktop and narrow widths) and a short self-critique against this design bar.

## Git workflow: commit and push after every step
1. At the start of a phase: `git switch main`, `git pull`, then `git switch -c phase-NN-short-name`.
2. After EVERY logical step:
   1. Run the fast checks for what you touched.
   2. Stage specific files with `git add <paths>` (never blindly `git add -A`).
   3. Check `git status` and `git diff --cached` for secrets.
   4. `git commit -s -m "<type>(<scope>): <summary>"`, using Conventional Commits.
   5. `git push -u origin phase-NN-short-name`.
3. Never push to main directly. Never force-push. Never rewrite history that has already been pushed.
4. At the end of a phase: run the full checks, do the self-attack review, make the final push, then open a pull request:
   `gh pr create --base main --title "Phase NN: <name>" --body "<summary, test results, self-attack findings, screenshots if UI>"`.
   Do NOT merge it. I review and merge.
5. If a push or `gh` command fails (authentication or network), stop and tell me. Do not work around it.

## Working rules
- Before starting, read AGENTS.md, docs/SPEC.md, docs/THREAT_MODEL.md and docs/PROGRESS.md.
- Do only the phase or task you were asked for. Write anything outside scope under "Follow-ups" in PROGRESS.md.
- Write tests alongside code: unit tests, property tests (proptest) for crypto and parsing, tamper tests and integration tests.
- Before you finish, all of these must pass:
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all
  cargo deny check
  pnpm -r lint and pnpm -r test, if TypeScript packages changed
- Commit and push after every logical step, following the Git workflow above. Use `git commit -s` (DCO sign-off). Never commit secrets, .env files or real vault data.
- At the end of every task, add an entry to docs/PROGRESS.md covering: what changed, how to run or try it, test results, known gaps and open questions.
- If a security decision is unclear, stop and ask. Do not guess.
- The development machine is Windows 11. Scripts must work in PowerShell, and paths must be cross-platform.
- Keep dependencies few. Prefer the standard library and the approved crates.
