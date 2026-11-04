<!-- Phase 11: sharing and families. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 11: sharing and families.**

- Shared vaults: the owner HPKE-wraps the VK to each member's encryption key. Roles are owner, editor and viewer. Membership lives as signed ops in the vault log, and clients reject ops from non-members or from viewers.
- Removing a member rotates the VK (re-wrapping item keys) and records a key_rotation op.
- Key directory with transparency on the relay:
  - an append-only Merkle log (RFC 6962 style) of account identity keys, device certificates and revocations
  - endpoints for inclusion proofs and consistency proofs
  - clients store the last signed tree head and verify consistency on every lookup
  - a user's own devices cross-check tree heads
- Safety codes: a 60-digit (or 12-word) code derived from both identity keys, shown for in-person verification. Contacts can be marked verified.
- Invites: a link plus a one-time code exchanged out of band.
- A "Family caretaker" vault template with short guidance in the UI.

Evil-relay tests:
- key substitution during lookup is detected
- a removed member cannot decrypt new items
- the relay cannot add a member
- a forked key log is detected

Commit with -s. Stop and report.
