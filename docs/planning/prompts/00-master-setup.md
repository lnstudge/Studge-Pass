<!-- Phase 0: repository setup, rules and preview dashboard (master prompt). Copy everything below this line into a new AutoClaw task. -->

You are the lead engineer for **Studge Pass**, a free, fully open-source password and passkey manager. I am the founder and the only human on the project. I work on Windows 11 and will review everything you do. This task sets up the repository and the rules that every later task will follow. Do NOT write application logic yet.

## Product context (remember it for all future work)
Studge Pass is a password + passkey manager in which every feature is free forever.
Its five differentiators:
1. Free forever, by charter. The code cannot be relicensed (DCO, no CLA).
2. Safe even if our own sync server is hacked. Every byte is authenticated, vault history is a signed hash chain, and there is no legacy crypto.
3. A passkey-aware security dashboard with a phishing-resistance score and a "blast radius" view of the accounts that can reset other accounts.
4. Recovery without the vendor: 2-of-3 guardians plus emergency access.
5. Bring-your-own storage: a hosted relay, a self-hosted relay, or any synced folder.
First market: India. That means low-end Android, Indian languages later, and item templates for Aadhaar, PAN, UPI and netbanking.

## Fixed tech stack (do not change without asking me)
- Rust stable (edition 2021), Cargo workspace.
- Relay: axum + tokio + sqlx (SQLite default, Postgres optional) + tracing.
- Desktop: Tauri 2 + React + TypeScript + Vite.
- Browser extension: Manifest V3 + TypeScript + Vite, with core compiled to WebAssembly.
- Android (later): Kotlin + Jetpack Compose via UniFFI. iOS (later): SwiftUI via UniFFI.
- JavaScript tooling: pnpm workspaces.

## Create this repository layout
The repository already exists and is cloned (GitHub: lnstudge/Studge-Pass). It contains only README.md and .gitattributes from GitHub; replace or extend both. The repository root IS the `studge-pass/` folder shown below.
```
studge-pass/
  AGENTS.md                 (exact content below)
  README.md                 (what Studge Pass is, status "pre-alpha, do not store real passwords", how to build)
  LICENSE                   (full GPL-3.0-or-later text)
  relay/LICENSE             (full AGPL-3.0-or-later text)
  SECURITY.md               (report vulnerabilities via GitHub private security advisories)
  CONTRIBUTING.md           (DCO sign-off required with `git commit -s`; no CLA)
  Cargo.toml                (workspace members: core, core-wasm, relay, cli, test-harness)
  rust-toolchain.toml       (channel = "stable", components rustfmt + clippy, target wasm32-unknown-unknown)
  rustfmt.toml, deny.toml   (cargo-deny: GPL/AGPL-compatible licence allowlist, deny yanked crates, ban openssl)
  .gitignore                (target/, node_modules/, dist/, .env*, *.studgevault, *.log)
  .gitattributes            (* text=auto eol=lf)
  .editorconfig
  core/        lib crate `studge-core`; src/lib.rs has #![forbid(unsafe_code)] and empty modules: crypto, vault, oplog, sync, import, health, error
  core-wasm/   cdylib crate `studge-core-wasm`; exports `version()` via wasm-bindgen
  relay/       bin crate `studge-relay`; GET /health returns {"status":"ok","version":"<crate version>"} on 127.0.0.1:8787
  cli/         bin crate `studge`; `studge --version` (clap)
  test-harness/ lib crate, empty for now
  desktop/  extension/  android/  ios/   (README.md placeholders saying which phase builds them)
  docs/SPEC.md, docs/THREAT_MODEL.md   (headings only; Phase 1 fills them)
  docs/PROGRESS.md, docs/DECISIONS.md
  .github/workflows/ci.yml
```

## Write AGENTS.md with exactly this content
-----BEGIN AGENTS.md-----
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

## Show your work: live preview (the founder wants to see everything)
The founder watches the build as it happens. Never work silently.
1. **Plan first.** At the start of a phase, post the plan in chat as a numbered checklist of steps. Write the same checklist into `docs/preview/status.json` (see below).
2. **Narrate each step.** Before each step, say in 1–2 plain sentences what you are about to do and why. After each step, post a short "Step N done" report in chat:
   - what changed (files, plus a 3–5 line summary of the diff)
   - the command you ran and the key lines of its output (test summary, server response, build result)
   - **how I can see it myself right now**: a URL, a command or a screenshot
3. **Visual work.** Whenever you build or change anything visible (Storybook, desktop app, extension, Android, dashboard):
   - start or keep running its dev server and give me the local URL
   - after each UI step, take Playwright screenshots (light and dark) into `docs/screenshots/phase-NN/step-NN-<name>-<theme>.png`
   - show the screenshot in chat if AutoClaw can display images; otherwise give the file path
4. **Non-visual work** (crypto, storage, relay, sync): give me a runnable demo with FAKE data that prints what is happening in plain language, for example `cargo run -p studge-core --example crypto_tour`. Never print real secrets; demo keys are labelled "DEMO ONLY".
5. **The preview page.** Keep the local dev-preview dashboard up to date (built in Phase 0, opened with `pnpm preview`, served at http://localhost:4400). After every step, update `docs/preview/status.json`, then rebuild the page. It shows:
   - the current phase and its checklist with done, in-progress and next steps
   - the latest check results (fmt, clippy, tests passed/failed, cargo deny)
   - a timeline of commits pushed in this phase, with links to GitHub
   - a screenshot gallery for the phase
   - the demo commands and dev-server URLs to try
   - the self-attack findings table and open risks
   - links to Storybook, the PR and the docs
6. **When a phase ends,** post a final "Preview summary": what I can try, exactly how, and what it should look like.

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
- At the end of every task, add an entry to docs/PROGRESS.md covering: what changed, how to run or try it, test results, known gaps and open questions. Keep docs/preview/status.json current after every step, not only at the end.
- If a security decision is unclear, stop and ask. Do not guess.
- The development machine is Windows 11. Scripts must work in PowerShell, and paths must be cross-platform.
- Keep dependencies few. Prefer the standard library and the approved crates.
-----END AGENTS.md-----

## Dev preview dashboard (build it in this phase)
Create a tiny pnpm workspace package `tools/preview` (Vite + TypeScript, no UI framework needed, no external network requests):
- Data source: `docs/preview/status.json`. Define its JSON schema in `tools/preview/status.schema.json` and validate the file on build. Fields:
  - phase {id, name, branch, pr_url}
  - steps [{n, title, state: done|doing|next, summary, commit_sha}]
  - checks {fmt, clippy, tests {passed, failed, ignored}, deny, updated_at}
  - commits [{sha, message, url}]
  - screenshots [{path, caption}]
  - try_it [{label, command_or_url}]
  - risks [{title, severity, status}]
  - links [{label, url}]
- Page: a clean, readable single page in the Studge Pass style (deep teal accent, light and dark themes, IBM Plex Sans or a system font). It has a progress bar, a step checklist, a check-results panel with pass/fail chips, a commit timeline, a screenshot gallery with a click-to-enlarge lightbox, "Try it" cards with copy buttons, and a risks table.
- Commands:
  - `pnpm preview` builds the page and serves it at http://localhost:4400, rebuilding automatically when status.json or screenshots change.
  - `pnpm preview:update` runs the fast checks and git log, then writes their results into status.json.
- Root `package.json` with pnpm workspaces and `"packageManager"` pinned. Add `docs/preview/status.json` for Phase 0 itself and keep it updated after every step of this phase.
- Screenshot helper: `pnpm shot <url> <out.png>` uses Playwright to capture light and dark screenshots. Install Chromium only for Playwright.

## CI (.github/workflows/ci.yml)
Run on push and pull_request, on ubuntu-latest and windows-latest:
- cargo fmt --all -- --check
- cargo clippy --all-targets --all-features -- -D warnings
- cargo test --all
- cargo deny check (ubuntu only)
- cargo build -p studge-core-wasm --target wasm32-unknown-unknown
Use dtolnay/rust-toolchain and Swatinem/rust-cache, pinned to full commit SHAs. Set `permissions: contents: read` at the top of every workflow.
Also add:
- .github/workflows/security.yml: gitleaks secret scanning on every push and PR, plus `cargo audit` on a weekly schedule.
- .github/dependabot.yml for cargo, npm and github-actions (weekly).
- CodeQL analysis for JavaScript/TypeScript, and for Rust if GitHub supports it at that time.

## Acceptance criteria
- `cargo build --all` and `cargo test --all` succeed on my Windows machine.
- `cargo run -p studge-relay` answers GET http://127.0.0.1:8787/health.
- `cargo run -p studge -- --version` prints the version.
- `cargo build -p studge-core-wasm --target wasm32-unknown-unknown` succeeds.
- `pnpm install` then `pnpm preview` opens the dev-preview dashboard at http://localhost:4400, showing Phase 0's steps, checks and commits.
- docs/PROGRESS.md has a "Phase 0" entry.
- Follow the Git workflow in AGENTS.md: work on branch `phase-00-setup`, commit and push after every step, and finish by opening a pull request with `gh pr create`. Do not merge it.

Follow "Show your work" in AGENTS.md from the very first step: post your plan, narrate each step, and keep the preview page updated.

When you finish, stop and give me:
1. the file tree
2. the exact commands I should run to verify
3. anything that failed or needs my decision
