<!-- Phase 7: desktop app. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 7: the desktop app** in /desktop, built with Tauri 2 + React + TypeScript + Vite. Call studge-core from Rust commands. Secrets reach JavaScript only when the user reveals or copies a field, and are cleared from React state on lock.

Screens:
- Onboarding: create account → show the Secret Key and save or print the recovery kit → choose sync (Studge relay URL, self-hosted URL or local folder). Import from another manager.
- Unlock: master password. Leave a hook for Windows Hello quick unlock in a later phase.
- Vault list: search, filters (type, vault, favourites, tags) and keyboard navigation.
- Item detail: copy buttons (clipboard clears after 30 s), reveal toggles, TOTP with a countdown.
- Item editor for every item type, including the India templates.
- Password and passphrase generator, an import/export wizard and a devices list.
- Settings: auto-lock (default 10 min, plus lock on OS sleep or screen lock), clipboard timer, theme, language. Use i18next with English and Hindi string files to start.

Design:
- Build every screen from the @studge/design components (Phase 6b). The desktop app is the flagship: it should look and feel more polished than 1Password.
- Signature moments: a satisfying unlock animation, an elegant vault list with monogram avatars, and a copy button with a visible 30 s clipboard countdown.

Security:
- Use Tauri's isolation pattern. Strict CSP: `default-src 'self'`, with no unsafe-inline and no unsafe-eval.
- No remote content.
- Capability allowlist with only the commands the app needs.
- Devtools disabled in release builds.

Tests: Rust tests for the commands, Vitest for UI logic, and a Playwright smoke test if it is practical. Write `pnpm tauri dev` instructions for Windows in PROGRESS.md. Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and tell me exactly how to run it.

Design: use the @studge/design tokens and components from Phase 6b and follow the Design bar in AGENTS.md. Finish with light and dark screenshots in docs/screenshots/phase-07/ and a self-critique of where it falls short of the bar, then fix the top 3 issues before opening the PR.

Preview for me: keep `pnpm tauri dev` running so I can click around while you build, and tell me which screen to look at after each step. Add before/after screenshots of each screen to the preview gallery.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
