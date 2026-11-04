<!-- Phase 8: browser extension, passwords. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 8: the browser extension for passwords** (Chrome, Edge, Brave and Firefox; MV3, TypeScript, Vite, webextension-polyfill). Use studge-core through core-wasm.

Architecture:
- Background service worker: holds the unlocked session (core-wasm) and locks on a timer and on browser idle. Keys never go to content scripts.
- Content script (isolated world): detects login, signup, password-change and multi-step (email first, then password) forms using autocomplete attributes and heuristics. Origin matching runs in Rust core using the public suffix list. The default rule is exact host.
- Anti-clickjacking (DEF CON 33):
  - NEVER render interactive fill or save UI in page-controlled DOM.
  - Fill happens from the toolbar popup, the keyboard shortcut or the context menu.
  - An optional inline menu may be shown only inside an extension-origin iframe. It accepts clicks only when IntersectionObserver v2 (trackVisibility) reports it fully visible for at least 500 ms. It is off by default on Firefox.
  - Never auto-fill on page load.
  - Filling a cross-origin iframe requires a confirmation that names the iframe's origin.
- Save and update prompts appear in extension UI after form submission.
- Messaging: validate sender.id, sender.tab, sender.frameId and sender.origin on every message. A frame can only ever receive secrets for its own origin.
- Popup (React): unlock, matches for the current site first, search, fill/copy, generator and TOTP.
- Minimal permissions, no remote code, and the extension page CSP `script-src 'self' 'wasm-unsafe-eval'; object-src 'none'`. No third-party scripts, fonts or analytics.

Tests:
- Unit tests for form detection on fixture HTML pages: login, signup, multi-step, iframes, shadow DOM.
- Playwright E2E with the extension loaded against local fixture pages, including a clickjacking fixture (opacity 0 overlay). That test must prove that no fill happens.

Build to dist/chrome and dist/firefox, and document loading the unpacked extension. Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Design: use the @studge/design tokens and components from Phase 6b and follow the Design bar in AGENTS.md. Finish with light and dark screenshots in docs/screenshots/phase-08/ and a self-critique of where it falls short of the bar, then fix the top 3 issues before opening the PR.
