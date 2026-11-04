<!-- Phase 5: sync engine and evil-relay harness. Copy everything below this line into a new AutoClaw task. -->

Read AGENTS.md and the docs. **Phase 5: the sync engine and the evil-relay test harness.** This harness is a public selling point, so make it thorough and readable.

1. core/src/sync: an async Transport trait with three implementations:
   - HttpRelayTransport (reqwest, rustls only)
   - FolderTransport: writes each op to a file named by its op_hash, plus a head file, into any folder (Google Drive, Dropbox, OneDrive, Syncthing, WebDAV mount). It must tolerate duplicate files and the "conflicted copy" files that sync tools create.
   - MemoryTransport
2. SyncEngine:
   1. Pull.
   2. Verify every op: signature, device certificate, AAD binding, parents present.
   3. Merge.
   4. Check that the new head descends from the last trusted head.
   5. Push local ops.
   6. Update the signed head, retrying the compare-and-swap if needed.
   It works offline-first: local changes queue and sync later.
3. test-harness: an EvilRelay wrapper around any Transport. Each test can configure it to:
   - drop ops, reorder ops or replay old ops
   - return an old head (rollback)
   - show different histories to two devices (fork)
   - swap ciphertext between items or between vaults
   - flip bytes or strip signatures
   - substitute a device certificate or public key
   - serve another account's key bundle
   - downgrade the suite id
4. For each attack, write a test proving that the client detects it, returns a specific SyncError variant, and leaves local data unchanged. Use test names like `evil_relay_rollback_is_detected`.
5. Two-device and three-device simulations: concurrent edits converge, deletes follow the rule, and an offline device catches up.
6. Add a table to THREAT_MODEL.md mapping every evil-relay test to the threat it covers.

Run every check, update PROGRESS.md, and commit and push following AGENTS.md, run the self-attack review, and open the pull request. Stop and report the attack list with pass/fail for each.
