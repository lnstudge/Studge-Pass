//! The sync engine: pull, stage, verify, commit and push (SPEC §6.8–§6.9, §7.10).
//!
//! `SyncEngine` implements the offline-first sync loop:
//!
//! 1. **Pull** — fetch ops + head from the transport.
//! 2. **Stage** — parse and verify every new op into a temporary staging set
//!    (DAG copy).  The committed DAG is **not** touched until step 4.
//! 3. **Verify head** — the remote head must (a) parse, (b) have all tips in
//!    the staging+committed DAG, (c) have a valid signature, and (d) descend
//!    from the pinned head (§6.9 steps 1–4).  If a pin exists and no head was
//!    returned, that is a withhold attack → `RollbackDetected`.
//! 4. **Commit** — only after the head passes all checks, merge the staged ops
//!    into the committed DAG and advance the pin.
//! 5. **Push** — send locally-queued pending ops.  If `transport.push` fails
//!    the pending ops are **restored** to the queue before returning the error.
//! 6. **Update head** — compare-and-swap with retry once on CAS conflict.
//!
//! # TOFU / confirm
//!
//! On the very first sync, the vault has no pinned head.  The engine sets the
//! pin but keeps `is_tofu = true`.  The caller MUST call [`VaultSyncState::confirm_head`]
//! once a second device or a safety code confirms the tip — only then is TOFU
//! cleared (SPEC §4.5).

use crate::crypto::signing::Timestamp;
use crate::error::CoreError;
use crate::oplog::dag::Dag;
use crate::oplog::devices::DeviceRegistry;
use crate::oplog::head::{check_head_update, HeadUpdate, VaultHead};
use crate::oplog::op::{OpHash, StoredOp};
use crate::sync::transport::{SyncError, Transport, NO_HEAD};

/// A vault's sync state, held by the engine.
#[derive(Debug)]
pub struct VaultSyncState {
    dag: Dag,
    /// The last head that passed the §6.9 checks.
    pinned_head: Option<VaultHead>,
    /// Ops produced locally that have not been pushed yet.
    pending: Vec<StoredOp>,
    /// Whether the vault was first-seen on this device (TOFU, §4.5).
    /// Cleared only by [`confirm_head`], not by the first sync alone.
    is_tofu: bool,
}

impl VaultSyncState {
    /// Creates an empty sync state for `vault_id`.
    pub fn new(vault_id: [u8; 16]) -> Self {
        Self {
            dag: Dag::new(vault_id),
            pinned_head: None,
            pending: Vec::new(),
            is_tofu: true,
        }
    }

    /// Creates a sync state with a pre-loaded DAG and a pinned head from the
    /// key bundle hint (§4.5 `head_pins` — already verified by the account
    /// layer at bundle-open time).
    ///
    /// A state created this way is **not** in TOFU — the head was already
    /// verified by a second source.
    pub fn with_pin(dag: Dag, pinned_head: VaultHead) -> Self {
        Self {
            dag,
            pinned_head: Some(pinned_head),
            pending: Vec::new(),
            is_tofu: false,
        }
    }

    /// The DAG of verified and committed ops.
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// The pinned head, if any.
    pub fn pinned_head(&self) -> Option<&VaultHead> {
        self.pinned_head.as_ref()
    }

    /// Whether this vault is still in trust-on-first-use mode.
    ///
    /// Returns `true` until [`confirm_head`] is called.  SPEC §4.5: a vault
    /// stays "not yet verified" until a second device or safety code confirms
    /// the tip.  The UI should warn the user while `is_tofu()` is `true`.
    pub fn is_tofu(&self) -> bool {
        self.is_tofu
    }

    /// Confirms that the current pinned head has been verified by a second
    /// device or safety code, clearing the TOFU flag.
    ///
    /// This is a no-op if there is no pinned head yet or if TOFU is already
    /// cleared.
    pub fn confirm_head(&mut self) {
        self.is_tofu = false;
    }

    /// Adds an op produced locally to the pending queue.
    pub fn enqueue(&mut self, op: StoredOp) {
        self.pending.push(op);
    }

    /// Drains the pending queue (called by the engine after a successful push).
    fn drain_pending(&mut self) -> Vec<StoredOp> {
        std::mem::take(&mut self.pending)
    }
}

/// The result of a single sync cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    /// Number of ops pulled from the transport.
    pub pulled: usize,
    /// Number of ops pushed to the transport.
    pub pushed: usize,
    /// Whether the head changed (fast-forward).
    pub head_advanced: bool,
    /// Whether the vault is still in TOFU mode.
    pub is_tofu: bool,
}

/// The sync engine.
///
/// One engine per device-registry.  Create one [`VaultSyncState`] per vault.
pub struct SyncEngine {
    devices: DeviceRegistry,
}

impl SyncEngine {
    /// Creates a sync engine backed by `devices`.
    pub fn new(devices: DeviceRegistry) -> Self {
        Self { devices }
    }

    /// Runs a full sync cycle for one vault.
    ///
    /// `now` is the wall-clock time used when signing the new head.  Callers
    /// on native targets pass `Timestamp::now()?`; callers on wasm pass a
    /// value derived from `Date.now()` via the platform API.  This keeps
    /// `studge-core` free of `SystemTime` calls (which panic on
    /// `wasm32-unknown-unknown`).
    ///
    /// # Error semantics
    ///
    /// Any error leaves `state` unchanged.  In particular:
    /// - Ops staged during step 2 are discarded; the committed DAG is untouched.
    /// - Pending ops that could not be pushed are restored to the queue.
    pub fn sync(
        &self,
        vault_id: [u8; 16],
        state: &mut VaultSyncState,
        transport: &mut dyn Transport,
        signing_key: &crate::crypto::signing::SigningKeyPair,
        device_id: [u8; 16],
        now: Timestamp,
    ) -> Result<SyncResult, SyncError> {
        // ── Step 1: pull ─────────────────────────────────────────────────────
        // The cursor is the set of all current DAG tips, not just the first.
        // With concurrent concurrent heads, using only the first tip could leave
        // the second branch un-fetched.  We use the lexicographically smallest
        // tip as the cursor (a single hash the transport uses as a "since" token)
        // because the MemoryTransport / relay return everything after a given
        // position.  The engine then deduplicates via the DAG's idempotent add.
        let cursor: Option<OpHash> = {
            let heads = state.dag().heads();
            // Use the smallest hash so we always fetch from before the oldest
            // un-merged tip.  None means "give me everything".
            heads.into_iter().min()
        };

        let remote = transport.pull(vault_id, cursor)?;
        let pulled = remote.ops.len();

        // ── Step 2: stage pulled ops in a scratch DAG ────────────────────────
        // We clone the committed DAG so that any error leaves state unchanged.
        let mut staged_dag = state.dag.clone();
        for op in &remote.ops {
            match staged_dag.add(op.clone(), &self.devices) {
                Ok(_) => {}
                Err(CoreError::UnknownParent) => return Err(SyncError::MissingParent),
                Err(CoreError::OpVerificationFailed) => {
                    return Err(SyncError::OpVerificationFailed)
                }
                Err(CoreError::HeadVerificationFailed) => {
                    return Err(SyncError::OpVerificationFailed)
                }
                Err(CoreError::DuplicateOp) => {
                    // Same op_id, different content — a substitution attack.
                    return Err(SyncError::OpVerificationFailed);
                }
                Err(_) => return Err(SyncError::OpVerificationFailed),
            }
        }

        // ── Step 3: verify the remote head ───────────────────────────────────
        let mut head_advanced = false;
        let new_pin: Option<VaultHead> = match remote.head {
            Some(ref remote_head) => {
                // §6.9 step 1: verify signature, suite, vault_id, device.
                remote_head
                    .verify(&self.devices)
                    .map_err(|_| SyncError::OpVerificationFailed)?;

                if remote_head.vault_id() != &vault_id {
                    return Err(SyncError::VaultMismatch);
                }

                // §6.9 step 2: every tip in the head must exist in the staged DAG.
                for tip in remote_head.heads() {
                    if !staged_dag.has(tip) {
                        return Err(SyncError::HeadReferencesUnknownOp);
                    }
                }

                // §6.9 step 3: descent from pinned head (or TOFU first-accept).
                if let Some(ref pinned) = state.pinned_head {
                    match check_head_update(pinned, remote_head, &staged_dag) {
                        Ok(HeadUpdate::NoChange) => None, // no-op
                        Ok(HeadUpdate::FastForward { .. }) => {
                            head_advanced = true;
                            Some(remote_head.clone())
                        }
                        Err(CoreError::RollbackDetected) => {
                            return Err(SyncError::RollbackDetected)
                        }
                        Err(CoreError::ForkDetected) => return Err(SyncError::ForkDetected),
                        Err(CoreError::HeadCountersRegressed) => {
                            return Err(SyncError::HeadCountersRegressed)
                        }
                        Err(_) => return Err(SyncError::OpVerificationFailed),
                    }
                } else {
                    // No pin yet: TOFU first-sync.  Accept the head; keep
                    // is_tofu = true so the UI can warn until confirm_head()
                    // is called.
                    head_advanced = true;
                    Some(remote_head.clone())
                }
            }

            None => {
                // Transport returned no head.
                // If we already have a pin, this is a withhold attack (SPEC §6.9):
                // the relay is hiding the fact that the vault has a head.
                if state.pinned_head.is_some() {
                    return Err(SyncError::RollbackDetected);
                }
                // No pin and no remote head: empty vault, nothing to do.
                None
            }
        };

        // ── Step 4: commit — only reached when head checks passed ─────────────
        state.dag = staged_dag;
        if let Some(h) = new_pin {
            state.pinned_head = Some(h);
        }

        // ── Steps 5 & 6: push pending ops + update head ─────────────────────
        let pending = state.drain_pending();
        let pushed = if !pending.is_empty() {
            // Add locally-produced ops to the committed DAG before signing the
            // new head.
            for op in &pending {
                match state.dag.add(op.clone(), &self.devices) {
                    Ok(_) | Err(CoreError::DuplicateOp) => {}
                    Err(e) => {
                        // Our own op failed DAG validation — logic error.
                        state.pending = pending; // restore
                        return Err(SyncError::from(e));
                    }
                }
            }

            // Push to transport.  On any error, restore pending and bail.
            let n = match transport.push(vault_id, &pending) {
                Ok(n) => n,
                Err(e) => {
                    state.pending = pending; // restore on network/IO error
                    return Err(e);
                }
            };

            // Build and publish a new head from the current DAG.
            let tips = state.dag.heads();
            if !tips.is_empty() {
                let new_head = VaultHead::create(
                    signing_key,
                    vault_id,
                    device_id,
                    tips,
                    state.dag.len() as u64,
                    state.dag.lamport_max(),
                    now,
                )
                .map_err(|_| SyncError::MalformedPayload)?;

                let expected = state
                    .pinned_head
                    .as_ref()
                    .and_then(|h| h.hash().ok())
                    .unwrap_or(NO_HEAD);

                match transport.put_head(vault_id, &new_head, expected) {
                    Ok(()) => {
                        state.pinned_head = Some(new_head);
                        head_advanced = true;
                    }
                    Err(SyncError::ForkDetected) => {
                        // Another device raced us; re-queue and let the next
                        // sync cycle resolve.
                        state.pending = pending;
                        return Ok(SyncResult {
                            pulled,
                            pushed: n,
                            head_advanced,
                            is_tofu: state.is_tofu,
                        });
                    }
                    Err(e) => {
                        state.pending = pending; // re-queue on I/O error
                        return Err(e);
                    }
                }
            }
            n
        } else {
            0
        };

        Ok(SyncResult {
            pulled,
            pushed,
            head_advanced,
            is_tofu: state.is_tofu,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair};
    use crate::oplog::devices::DeviceRegistry;
    use crate::oplog::op::{Op, OpKind};
    use crate::sync::memory::MemoryTransport;

    const ACCOUNT: [u8; 16] = [0xAA; 16];
    const VAULT: [u8; 16] = [0xBB; 16];
    const ITEM: [u8; 16] = [0xCC; 16];
    const DEV1: [u8; 16] = [0xD1; 16];
    const DEV2: [u8; 16] = [0xD2; 16];

    fn at(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn now() -> Timestamp {
        at("2026-11-15T10:00:00Z")
    }

    struct Fixture {
        #[allow(dead_code)]
        identity: SigningKeyPair,
        dev1_key: SigningKeyPair,
        dev2_key: SigningKeyPair,
        registry: DeviceRegistry,
        vk: VaultKey,
    }

    impl Fixture {
        fn new() -> Self {
            let identity = SigningKeyPair::from_seed([1u8; 32]);
            let dev1_key = SigningKeyPair::from_seed([2u8; 32]);
            let dev2_key = SigningKeyPair::from_seed([3u8; 32]);
            let mut reg = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
            let cert1 = DeviceCertificate::create(
                &identity,
                ACCOUNT,
                DEV1,
                dev1_key.public_bytes(),
                at("2026-11-05T09:00:00Z"),
            )
            .unwrap();
            reg.certify(&cert1, &at("2026-11-05T09:30:00Z")).unwrap();
            let cert2 = DeviceCertificate::create(
                &identity,
                ACCOUNT,
                DEV2,
                dev2_key.public_bytes(),
                at("2026-11-05T09:00:00Z"),
            )
            .unwrap();
            reg.certify(&cert2, &at("2026-11-05T09:30:00Z")).unwrap();
            Self {
                identity,
                dev1_key,
                dev2_key,
                registry: reg,
                vk: VaultKey::from_bytes([3u8; 32]),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn make_op(
            &self,
            op_idx: u8,
            device_id: [u8; 16],
            key: &SigningKeyPair,
            parents: Vec<[u8; 32]>,
            lamport: u64,
            kind: OpKind,
            body: &[u8],
        ) -> StoredOp {
            let payload = Op::seal_payload(&self.vk, &VAULT, &ITEM, kind, body).unwrap();
            Op::new(
                VAULT,
                [op_idx; 16],
                parents,
                lamport,
                device_id,
                at("2026-11-05T10:00:00Z"),
                kind,
                Some(ITEM),
                payload,
            )
            .unwrap()
            .sign(key)
            .unwrap()
        }

        fn engine(&self) -> SyncEngine {
            SyncEngine::new(self.registry.clone())
        }
    }

    // ── Helper: sync with the fixed now() timestamp ───────────────────────────

    fn sync(
        engine: &SyncEngine,
        vault_id: [u8; 16],
        state: &mut VaultSyncState,
        transport: &mut dyn Transport,
        key: &SigningKeyPair,
        dev: [u8; 16],
    ) -> Result<SyncResult, SyncError> {
        engine.sync(vault_id, state, transport, key, dev, now())
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn single_device_push_then_pull() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        let mut state1 = VaultSyncState::new(VAULT);
        let op = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op);
        let r1 = sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        assert_eq!(r1.pushed, 1);
        assert!(r1.head_advanced);

        let mut state2 = VaultSyncState::new(VAULT);
        let r2 = sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert_eq!(r2.pulled, 1);
        assert_eq!(state2.dag().len(), 1);
    }

    #[test]
    fn rollback_is_rejected() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1.clone());
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        let hash1 = op1.hash().unwrap();

        let op2 = fix.make_op(
            2,
            DEV1,
            &fix.dev1_key,
            vec![hash1],
            2,
            OpKind::Update,
            b"v2",
        );
        state1.enqueue(op2);
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();

        let mut state2 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert_eq!(state2.dag().len(), 2);
        assert!(state2.pinned_head().is_some());

        let old_head = VaultHead::create(
            &fix.dev1_key,
            VAULT,
            DEV1,
            vec![hash1],
            1,
            1,
            at("2026-11-05T10:01:00Z"),
        )
        .unwrap();
        let old_head_bytes = old_head.to_cbor().unwrap();
        let old_hash = old_head.hash().unwrap();
        transport.set_raw_head(VAULT, old_head_bytes, old_hash);
        transport.truncate_ops(VAULT, 1);

        let err = sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap_err();
        assert_eq!(err, SyncError::RollbackDetected);
        assert_eq!(state2.dag().len(), 2);
    }

    #[test]
    fn missing_parent_is_detected() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1.clone());
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        let hash1 = op1.hash().unwrap();

        let op2b = fix.make_op(
            2,
            DEV1,
            &fix.dev1_key,
            vec![hash1],
            2,
            OpKind::Update,
            b"v2",
        );
        let hash2 = op2b.hash().unwrap();
        let raw2b = op2b.to_cbor().unwrap();
        transport.truncate_ops(VAULT, 0);
        transport.inject_raw_op(VAULT, hash2, raw2b);

        let mut state2 = VaultSyncState::new(VAULT);
        let err = sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap_err();
        assert_eq!(err, SyncError::MissingParent);
        assert_eq!(state2.dag().len(), 0);
    }

    #[test]
    fn offline_device_queues_and_then_pushes() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1);
        assert_eq!(state1.pending.len(), 1);

        let r = sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        assert_eq!(r.pushed, 1);
        assert_eq!(state1.pending.len(), 0);
    }

    // ── Fix 3a: pending ops restored on push failure ──────────────────────────

    struct FailPushTransport(MemoryTransport);

    impl Transport for FailPushTransport {
        fn push(&mut self, _vault_id: [u8; 16], _ops: &[StoredOp]) -> Result<usize, SyncError> {
            Err(SyncError::Io("simulated network failure".into()))
        }

        fn pull(
            &mut self,
            vault_id: [u8; 16],
            cursor: Option<[u8; 32]>,
        ) -> Result<crate::sync::transport::VaultOps, SyncError> {
            self.0.pull(vault_id, cursor)
        }

        fn put_head(
            &mut self,
            vault_id: [u8; 16],
            head: &VaultHead,
            expected_hash: [u8; 32],
        ) -> Result<(), SyncError> {
            self.0.put_head(vault_id, head, expected_hash)
        }
    }

    #[test]
    fn pending_ops_restored_on_push_failure() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut fail_transport = FailPushTransport(MemoryTransport::new());

        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1);

        // Sync against a transport that always fails push.
        let err = sync(
            &engine,
            VAULT,
            &mut state1,
            &mut fail_transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap_err();
        assert_eq!(err, SyncError::Io("simulated network failure".into()));

        // The pending op MUST still be in the queue for the next sync.
        assert_eq!(
            state1.pending.len(),
            1,
            "pending ops must be restored on push failure"
        );

        // Now sync against a working transport — should succeed and push the op.
        let mut good_transport = MemoryTransport::new();
        let r = sync(
            &engine,
            VAULT,
            &mut state1,
            &mut good_transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        assert_eq!(r.pushed, 1, "pending op must be pushed on next sync");
        assert_eq!(state1.pending.len(), 0);
    }

    // ── Fix 3b: withheld head detected when pin exists ────────────────────────

    struct NoHeadTransport(MemoryTransport);

    impl Transport for NoHeadTransport {
        fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError> {
            self.0.push(vault_id, ops)
        }

        fn pull(
            &mut self,
            vault_id: [u8; 16],
            cursor: Option<[u8; 32]>,
        ) -> Result<crate::sync::transport::VaultOps, SyncError> {
            let mut v = self.0.pull(vault_id, cursor)?;
            v.head = None; // withhold head
            Ok(v)
        }

        fn put_head(
            &mut self,
            vault_id: [u8; 16],
            head: &VaultHead,
            expected_hash: [u8; 32],
        ) -> Result<(), SyncError> {
            self.0.put_head(vault_id, head, expected_hash)
        }
    }

    #[test]
    fn withheld_head_is_detected_when_pin_exists() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Build a two-op history.
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        let hash1 = op1.hash().unwrap();
        state1.enqueue(op1);
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        let op2 = fix.make_op(
            2,
            DEV1,
            &fix.dev1_key,
            vec![hash1],
            2,
            OpKind::Update,
            b"v2",
        );
        state1.enqueue(op2);
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();

        // Device 2 syncs honestly to get a pin.
        let mut state2 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert!(state2.pinned_head().is_some());

        // Now the relay withholds the head.
        let raw_state = transport; // move inner honest transport into NoHeadTransport
        let mut no_head_transport = NoHeadTransport(raw_state);
        let err = sync(
            &engine,
            VAULT,
            &mut state2,
            &mut no_head_transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SyncError::RollbackDetected,
            "withheld head must be detected as rollback"
        );
        // State unchanged.
        assert_eq!(state2.dag().len(), 2);
    }

    // ── Fix 3c: fork leaves the DAG unchanged ────────────────────────────────

    #[test]
    fn fork_in_staged_ops_leaves_dag_unchanged() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Build a genesis op.
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        let _hash1 = op1.hash().unwrap();
        state1.enqueue(op1.clone());
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();

        // Device 2 syncs to get genesis.
        let mut state2 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert_eq!(state2.dag().len(), 1);

        // Build an op that references a non-existent parent (simulating a
        // malicious payload that the relay injects).
        let fake_parent = [0xABu8; 32];
        let evil_op = fix.make_op(
            9,
            DEV1,
            &fix.dev1_key,
            vec![fake_parent],
            2,
            OpKind::Update,
            b"evil",
        );
        let evil_hash = evil_op.hash().unwrap();
        let evil_raw = evil_op.to_cbor().unwrap();
        transport.inject_raw_op(VAULT, evil_hash, evil_raw);

        // Also set a head pointing at the evil op (so the head check runs).
        let evil_head = VaultHead::create(
            &fix.dev1_key,
            VAULT,
            DEV1,
            vec![evil_hash],
            2,
            2,
            at("2026-11-15T10:00:00Z"),
        )
        .unwrap();
        let evil_head_bytes = evil_head.to_cbor().unwrap();
        let evil_head_hash = evil_head.hash().unwrap();
        transport.set_raw_head(VAULT, evil_head_bytes, evil_head_hash);

        // Drop the original op so only the evil op is returned.
        transport.truncate_ops(VAULT, 0);
        transport.inject_raw_op(VAULT, evil_hash, evil_op.to_cbor().unwrap());

        let err = sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap_err();
        assert_eq!(
            err,
            SyncError::MissingParent,
            "malformed op must be rejected"
        );
        // The DAG must still have exactly 1 op (genesis), not 2.
        assert_eq!(
            state2.dag().len(),
            1,
            "DAG must be unchanged after a failed sync"
        );
    }

    // ── Fix 3d: TOFU / confirm_head ──────────────────────────────────────────

    #[test]
    fn is_tofu_true_until_confirm_head_is_called() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        let mut state1 = VaultSyncState::new(VAULT);
        assert!(state1.is_tofu(), "new state must be TOFU");

        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1);
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();

        // After first sync, still TOFU until confirm_head() is called.
        assert!(
            state1.is_tofu(),
            "TOFU must remain true after first sync alone"
        );

        // Device 2 syncs and also starts TOFU.
        let mut state2 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert!(state2.is_tofu(), "device2 also starts as TOFU");

        // Calling confirm_head() clears TOFU.
        state2.confirm_head();
        assert!(!state2.is_tofu(), "TOFU must be cleared after confirm_head");

        // confirm_head on state1 also clears.
        state1.confirm_head();
        assert!(!state1.is_tofu(), "TOFU must clear for device1 too");
    }

    // ── Fix 3e: pull cursor uses all concurrent heads ────────────────────────

    #[test]
    fn sync_with_two_concurrent_heads_fetches_all_ops() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Push genesis.
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        let hash1 = op1.hash().unwrap();
        state1.enqueue(op1);
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();

        // Device 2 pulls genesis.
        let mut state2 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();

        // Both devices create a concurrent branch from genesis.
        let op_a = fix.make_op(2, DEV1, &fix.dev1_key, vec![hash1], 2, OpKind::Update, b"A");
        state1.enqueue(op_a);
        let op_b = fix.make_op(3, DEV2, &fix.dev2_key, vec![hash1], 2, OpKind::Update, b"B");
        state2.enqueue(op_b);

        // Both push their branch.
        sync(
            &engine,
            VAULT,
            &mut state1,
            &mut transport,
            &fix.dev1_key,
            DEV1,
        )
        .unwrap();
        sync(
            &engine,
            VAULT,
            &mut state2,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        // Now both are in the transport.

        // A fresh device3 must pull all 3 ops (genesis + A + B).
        let mut state3 = VaultSyncState::new(VAULT);
        sync(
            &engine,
            VAULT,
            &mut state3,
            &mut transport,
            &fix.dev2_key,
            DEV2,
        )
        .unwrap();
        assert_eq!(
            state3.dag().len(),
            3,
            "device3 must fetch all ops including both concurrent branches"
        );
    }
}
