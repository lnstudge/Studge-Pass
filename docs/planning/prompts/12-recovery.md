<!-- Phase 12: recovery and emergency access. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 12: recovery and emergency access.**

- Recovery kit: generated locally as a printable HTML (and PDF if practical). It contains the account id, Secret Key, a QR code, the relay URL and plain instructions.
- Guardians (social recovery):
  - The user picks 3 Studge Pass contacts, preferably verified with safety codes.
  - Generate a Recovery Key that wraps the AK; the relay stores this as a separate envelope.
  - Split the Recovery Key with Shamir 2-of-3 using a maintained crate such as vsss-rs (record the choice), and HPKE-encrypt each share to a guardian.
  - Recovery flow:
    1. A new device creates a recovery request.
    2. Guardians approve in their app and re-encrypt their share to the new device's key.
    3. The requester combines 2 shares, unwraps the AK, and sets a new master password and a new Secret Key.
    4. The owner's existing devices are notified and can cancel within 72 h (configurable).
- Emergency access: a trusted contact requests access to chosen vaults. If the owner does not reject the request within the waiting period (1–30 days), the vault keys are released. Document the trade-offs of pre-wrapping.
- Lockout guard: warn when an account has only one way to unlock.

Tests:
- the happy path works
- 1 approval is not enough
- the owner cancels
- the relay replays an old approval
- the relay swaps a guardian's key

Commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report.

Preview for me: a guided demo of the recovery flow with 4 fake accounts (owner and 3 guardians), with screenshots of each screen and a timeline on the preview page showing request → approvals → waiting period → recovered.
Follow "Show your work" in AGENTS.md: post your plan, narrate every step, and update docs/preview/status.json after each one.
