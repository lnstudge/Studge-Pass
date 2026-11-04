<!-- Phase 9: passkeys in the extension + CXF. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 9: passkeys in the extension, plus FIDO CXF import/export.**

1. Authenticator in Rust core:
   - ES256 (p256) keys and 32-byte random credential IDs.
   - authenticatorData: rpIdHash, flags UP, UV, BE, BS and AT, signCount 0 for synced keys, and an AAGUID constant documented in DECISIONS.md.
   - COSE public-key encoding and a "none" attestationObject (CBOR).
   - Assertions sign authenticatorData || SHA-256(clientDataJSON).
2. Interception:
   - A MAIN-world script wraps navigator.credentials.create and .get for publicKey requests and forwards them through the isolated content script to the background.
   - The background builds clientDataJSON ITSELF, using the origin from the browser's sender information, never from the page.
   - Validate that rpId equals the origin's host or a registrable suffix of it (public suffix list). Reject http: except localhost.
   - Honour allowCredentials, excludeCredentials, residentKey and userVerification. Always require the vault to be unlocked plus user approval.
   - Support conditional mediation (passkey autofill) where feasible.
3. UX: an extension-owned popup window lists matching passkeys. "Use another device" falls back to the browser's native implementation by calling the original function.
4. Store passkeys as encrypted vault items, linked to the Login item for the same site.
5. PRF / hmac-secret: support sites that request the PRF extension, using a per-credential secret. Document the design.
6. CXF: import and export passkeys, logins, TOTP and notes in the FIDO CXF v1.0 format (read the spec at fidoalliance.org/specs/cx/). Encrypt the exported file with HPKE as an interim measure, because CXP is still a draft.

Tests:
- Unit tests for authenticatorData, attestation and assertion encoding against known vectors.
- Playwright E2E against a local test relying party built with @simplewebauthn/server: register and sign in work; a wrong origin and a mismatched rpId are rejected.
- Add a manual checklist for webauthn.io and passkeys.io to PROGRESS.md.

Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Preview for me: run the local test relying party at a localhost URL with a page that shows each WebAuthn request and response in readable form (decoded clientDataJSON, authenticatorData flags, rpIdHash). Add a "Passkeys" section to the preview page with that decoded view and screenshots of the passkey picker.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
