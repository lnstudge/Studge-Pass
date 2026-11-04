<!-- Phase 10: passkey-aware security dashboard. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 10: the passkey-aware security dashboard.** The logic lives in Rust core. The UI goes in the desktop app and in a "Health" tab of the extension popup.

Core (core/src/health):
- Findings for each account:
  - weak (zxcvbn score ≤ 2)
  - reused (compare local hashes)
  - breached: use the HIBP Pwned Passwords range API with k-anonymity. Send only the first 5 hex characters of the SHA-1 and set the `Add-Padding: true` header. Call it from the client and cache results encrypted.
  - old (unchanged for more than 2 years)
  - 2FA available but not used
  - passkey-capable site but password only
  - has a passkey but the password still works ("fallback")
  - passkey only stored in another manager (from import metadata)
- Site capability dataset: write tools/build-sites, which compiles a compact JSON list (domain → passkey support, 2FA methods, change-password URL) from the public 2factorauth/twofactorauth data. Check its licence and schema first and record them in DECISIONS.md. Sign the list with a project key, ship it inside the app and verify it on load. Make no per-site network lookups.
- Recovery roots: group accounts by the email or phone number they use, and detect major email providers and carriers. The user can override the result.
- Score: implement exactly the SPEC §5 formula and expose its breakdown per account.
- Next-best-action queue, ranked by w × (1 − p).

UI:
- Score ring with the trend.
- Tiles: passkeys, fallback passwords, upgradeable sites, breached, missing 2FA.
- An action list with Fix, Upgrade and Retire buttons that open the item editor and the site's change-password or passkey page.
- A blast-radius panel and a passkey portability bar.
- Everything is computed on the device.

Tests: scoring fixtures, an HIBP client tested against a mock server, and dataset signature verification. Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Design: use the @studge/design tokens and components from Phase 6b and follow the Design bar in AGENTS.md. Finish with light and dark screenshots in docs/screenshots/phase-10/ and a self-critique of where it falls short of the bar, then fix the top 3 issues before opening the PR.
