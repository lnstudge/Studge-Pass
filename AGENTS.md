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

## Development environment: Windows + WSL (read before running any command)
The founder's PC runs Windows 11 with **Smart App Control on**. It blocks the unsigned helper programs that Rust compiles on Windows ("An Application Control policy has blocked this file", os error 4551). So:
- **Never run cargo, rustc, rustup, pnpm, npm, npx, node or playwright directly in PowerShell.** Run them through the wrapper in the repo root:
  `.\x.ps1 cargo build --all`
  `.\x.ps1 cargo test -p studge-core`
  `.\x.ps1 "pnpm install && pnpm preview"`
  The wrapper runs the command inside WSL Ubuntu in /mnt/c/dev/Studge-Pass, with Rust build output on the Linux disk (~/.cache/studge-pass/target). Wherever a prompt or this file says `cargo …` or `pnpm …`, it means `.\x.ps1 cargo …` or `.\x.ps1 pnpm …`.
- **Git and gh run on Windows directly** (already signed in). Never run git inside WSL.
- WSL Ubuntu already has: Rust stable with rustfmt, clippy and the wasm32 target; cargo-deny; wasm-bindgen-cli; Node 24; pnpm; gh; build-essential; Playwright's Chromium system libraries; and Noto fonts for Indian scripts. Install project-level tools (crates, npm packages, Playwright browsers) through the wrapper as normal.
- **Never use sudo** and never change the system. If a Linux system package is missing, stop and give me the exact `wsl -u root apt-get install …` command to run.
- **Dev servers** started through the wrapper are reachable from Windows at http://localhost:<port>. Bind to localhost. Edits made from Windows do not raise Linux file events on /mnt/c, so Vite, Storybook and other watchers must use polling when `STUDGE_WSL=1` (for example Vite `server.watch.usePolling: true`). The wrapper also sets `CHOKIDAR_USEPOLLING=1`.
- Long-running servers (preview, Storybook, relay) block the terminal. Start them in a separate terminal or as a background process, and tell me the URL.
- Keep `x.ps1`, `scripts/wsl-run.sh` and the `.gitattributes` rule `*.sh text eol=lf`. Shell scripts must use LF line endings.
- Windows-only steps (the Windows desktop installer, the Android emulator) are handled in their phases. GitHub's CI runs on both ubuntu-latest and windows-latest, and Smart App Control does not affect CI.

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

## Connected tools: Notion, GitHub and skills
AutoClaw has the Notion and GitHub connectors and a set of skills. Use them on every task.

### Notion: document everything, from prompt to execution
The Notion home is a page called **"Studge Pass: Build Log"**. Phase 0 creates it and stores its page and database IDs in `docs/notion.json`. These IDs are not secret.
It contains these databases:
- **Prompts:** every prompt given to AutoClaw, saved word for word. Fields: title, phase, date, full prompt text, and a link to the task's execution log.
- **Phases:** one row per phase. Fields: phase number and name, status (Not started / In progress / In review / Merged), branch, PR link, GitHub issue link, start and end dates, summary, and the preview-dashboard checks.
- **Execution log:** one row per step. Fields: phase, step number, what and why, commands run, key output, result (pass/fail), commit SHA and GitHub link, screenshots (uploaded images or repo paths), and skills used.
- **Decisions:** mirrors docs/DECISIONS.md. Fields: decision, options considered, choice, reason, status (Proposed / Approved by founder / Rejected).
- **Risks and findings:** self-attack, review and red-team findings. Fields: title, severity, phase, status (Open / Fixed / Accepted), test name and GitHub issue link.
- **Test runs:** per phase, the counts of passed, failed and ignored tests, plus cargo deny and audit results.

Rules:
1. At the very start of every task, create a Prompts entry containing the exact prompt you received. Then create or update the phase row with status In progress.
2. After every step, add an Execution log row in the same moment you commit and push, and link it to the commit.
3. At the end of the phase, write the phase summary (what was built, how to try it, test results, risks, PR link) and set the status to In review.
4. Keep Notion and the repo in sync. The repo (docs/*.md) is the source of truth for specs. Notion is the readable log and dashboard.
5. **Never put secrets in Notion.** Notion is not end-to-end encrypted. No keys, tokens, passwords (not even test ones), vault files or private data. Mask any token-like value as `****`.
6. If a Notion call fails, keep working. Log the step locally in docs/PROGRESS.md, tell me in chat, and back-fill Notion when it works again.

### GitHub: everything goes to GitHub
- Use the git CLI for commits and pushes, following the Git workflow below.
- Use the GitHub connector (fall back to the `gh` CLI if it fails) for:
  - **Issues:** one tracking issue per phase (label `phase`). Every self-attack, review or red-team finding becomes an issue with the `security` label and a severity label. Every follow-up becomes an issue with the `follow-up` label.
  - **Milestones:** one milestone per phase. Phase issues and PRs are attached to it.
  - **Pull requests:** open the PR at the end of the phase with "Closes #<phase issue>" in the body and the Notion phase page link. Request review from @lnstudge. Never merge it yourself.
  - **Labels:** phase, security, severity:critical/high/medium/low, follow-up, design, docs, ci.
  - Comment progress on the phase issue at the end of the phase, linking the Notion summary.
- Do not change repository settings, branch protection, secrets or collaborators.

### Skills: use every skill that helps
- At the start of each task, list the skills available to you and state which ones you will use for this phase and why. Use them wherever they improve the result, for example:
  - frontend, design or UI skills for Phases 6b, 7, 8, 10 and 13
  - testing and code-review skills for every phase
  - documentation skills for the docs and Notion pages
  - security or audit skills for the self-attack review
- Record the skills used in each Execution log row.
- Ask me before using any skill that sends code or data to a third-party service other than GitHub and Notion.

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
   - links to Storybook, the PR, the docs, the GitHub phase issue and the Notion phase page
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
   **Authorship:** the founder is the sole author of every commit and pull request. Never add
   `Co-authored-by:`, `Signed-off-by:` for any name other than the founder's (`git commit -s` adds
   the founder's own sign-off), "Generated with …" lines, or any other agent or tool attribution
   to commit messages, pull request titles or bodies.
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
- The development machine is Windows 11 with builds running in WSL through `.\x.ps1` (see "Development environment"). Repo scripts must work through the wrapper, and paths must be cross-platform.
- Keep dependencies few. Prefer the standard library and the approved crates.
