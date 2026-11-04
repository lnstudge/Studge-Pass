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
- The name is "Studge Pass", with its own identity: a deep teal accent and calm neutrals. Avoid purple and anything that looks like Proton Pass.
- WCAG AA contrast, visible focus states, light and dark themes.

Security:
- Strict Tauri CSP and no remote content.
- Capability allowlist with only the commands the app needs.
- Devtools disabled in release builds.

Tests: Rust tests for the commands, Vitest for UI logic, and a Playwright smoke test if it is practical. Write `pnpm tauri dev` instructions for Windows in PROGRESS.md. Commit with -s. Stop and tell me exactly how to run it.
