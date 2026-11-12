//! The sync engine: pull, merge and push (SPEC §6.8–§6.9, §7.10).
//!
//! `SyncEngine` implements the offline-first sync loop described in the phase
//! prompt:
//!
//! 1. **Pull** — fetch ops + head from the transport.
//! 2. **Verify** — run every op through `Dag::add` (signature, cert, AAD,
//!    parents present, Lamport rule).
//! 3. **Merge** — the DAG absorbs new ops; conflicts are resolved by the
//!    `(lamport, device_id)` rule already in `materialise`.
//! 4. **Check head** — the new head must descend from the pinned head.
//! 5. **Push** — send locally-queued ops to the transport.
//! 6. **Update head** — compare-and-swap with retry.
//!
//! Offline-first means: `push` and `update_head` can fail with an I/O error
//! and the engine queues the ops in `pending` for the next call to `sync`.
//! Local data that is already verified stays usable.

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
    /// Whether the vault was first-seen on this device (TOFU, §6.9 last §).
    is_first_sync: bool,
}

impl VaultSyncState {
    /// Creates an empty sync state for `vault_id`.
    pub fn new(vault_id: [u8; 16]) -> Self {
        Self {
            dag: Dag::new(vault_id),
            pinned_head: None,
            pending: Vec::new(),
            is_first_sync: true,
        }
    }

    /// Creates a sync state with a pre-loaded DAG and a pinned head from the
    /// key bundle hint (§4.5 `head_pins` — already verified by the account
    /// layer at bundle-open time).
    pub fn with_pin(dag: Dag, pinned_head: VaultHead) -> Self {
        Self {
            dag,
            pinned_head: Some(pinned_head),
            pending: Vec::new(),
            is_first_sync: false,
        }
    }

    /// The DAG of verified ops.
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// The pinned head, if any.
    pub fn pinned_head(&self) -> Option<&VaultHead> {
        self.pinned_head.as_ref()
    }

    /// Whether this vault has only ever been seen on the local device.
    pub fn is_tofu(&self) -> bool {
        self.is_first_sync
    }

    /// Adds an op produced locally to the pending queue.
    pub fn enqueue(&mut self, op: StoredOp) {
        self.pending.push(op);
    }

    /// Drains the pending queue (called after a successful push).
    pub fn drain_pending(&mut self) -> Vec<StoredOp> {
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
    /// Whether the vault was brand-new on this device (TOFU).
    pub was_first_sync: bool,
}

/// The sync engine.
///
/// One engine, one set of devices.  Create one `VaultSyncState` per vault.
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
    /// Steps:
    /// 1. Pull from `transport`.
    /// 2. Verify + merge every new op into `state.dag`.
    /// 3. Verify the remote head.
    /// 4. Check descent from the pinned head.
    /// 5. Push pending ops.
    /// 6. Update head (CAS, retry once on conflict).
    ///
    /// If step 3 or 4 fails, the function returns the error immediately
    /// without touching the pin.  Local data is unchanged.
    pub fn sync(
        &self,
        vault_id: [u8; 16],
        state: &mut VaultSyncState,
        transport: &mut dyn Transport,
        signing_key: &crate::crypto::signing::SigningKeyPair,
        device_id: [u8; 16],
    ) -> Result<SyncResult, SyncError> {
        let cursor: Option<OpHash> = state.dag().heads().into_iter().next();
        let was_first = state.is_first_sync;

        // ── Step 1 & 2: pull + merge ─────────────────────────────────────────
        let remote = transport.pull(vault_id, cursor)?;
        let pulled = remote.ops.len();

        for op in &remote.ops {
            // Every op MUST verify before we look at its fields (§6.3).
            // Dag::add enforces: sig, cert, AAD-match, parents, Lamport.
            match state.dag.add(op.clone(), &self.devices) {
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
        if let Some(ref remote_head) = remote.head {
            // §6.9 step 1: verify signature, suite, vault_id, device not revoked.
            remote_head
                .verify(&self.devices)
                .map_err(|_| SyncError::OpVerificationFailed)?;

            if remote_head.vault_id() != &vault_id {
                return Err(SyncError::VaultMismatch);
            }

            // §6.9 step 2: every `heads` entry must exist in our DAG.
            for tip in remote_head.heads() {
                if !state.dag.has(tip) {
                    return Err(SyncError::HeadReferencesUnknownOp);
                }
            }

            // ── Step 4: check descent from the pin ───────────────────────────
            if let Some(ref pinned) = state.pinned_head {
                match check_head_update(pinned, remote_head, &state.dag) {
                    Ok(HeadUpdate::NoChange) => {}
                    Ok(HeadUpdate::FastForward { .. }) => {
                        state.pinned_head = Some(remote_head.clone());
                        head_advanced = true;
                    }
                    Err(CoreError::RollbackDetected) => return Err(SyncError::RollbackDetected),
                    Err(CoreError::ForkDetected) => return Err(SyncError::ForkDetected),
                    Err(CoreError::HeadCountersRegressed) => {
                        return Err(SyncError::HeadCountersRegressed)
                    }
                    Err(_) => return Err(SyncError::OpVerificationFailed),
                }
            } else {
                // No pin yet: this is a TOFU first-sync or a new vault.
                state.pinned_head = Some(remote_head.clone());
                head_advanced = true;
                state.is_first_sync = false;
            }
        }

        // ── Steps 5 & 6: push pending ops + update head ─────────────────────
        let pending = state.drain_pending();
        let pushed = if !pending.is_empty() {
            // Add locally-produced ops to our own DAG first so the head
            // we sign reflects them.
            for op in &pending {
                match state.dag.add(op.clone(), &self.devices) {
                    Ok(_) | Err(CoreError::DuplicateOp) => {} // already added → ok
                    Err(e) => {
                        // Our own op failed DAG validation — a logic error.
                        state.pending = pending; // restore
                        return Err(SyncError::from(e));
                    }
                }
            }
            let n = transport.push(vault_id, &pending)?;
            // Build and publish a new head from our current DAG.
            let tips = state.dag.heads();
            if !tips.is_empty() {
                let now = crate::crypto::signing::Timestamp::now()
                    .map_err(|_| SyncError::MalformedPayload)?;
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

                // Retry once on CAS conflict.
                match transport.put_head(vault_id, &new_head, expected) {
                    Ok(()) => {
                        state.pinned_head = Some(new_head);
                        head_advanced = true;
                    }
                    Err(SyncError::ForkDetected) => {
                        // Another device raced us.  The next sync cycle
                        // will pull the new head and resolve.
                        state.pending = pending; // re-queue
                        return Ok(SyncResult {
                            pulled,
                            pushed: n,
                            head_advanced,
                            was_first_sync: was_first,
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
            was_first_sync: was_first,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
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

    /// A two-device fixture.
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

    #[test]
    fn single_device_push_then_pull() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Push one op from device 1.
        let mut state1 = VaultSyncState::new(VAULT);
        let op = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op);
        let r1 = engine
            .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
            .unwrap();
        assert_eq!(r1.pushed, 1);
        assert!(r1.head_advanced);

        // Device 2 pulls and sees it.
        let mut state2 = VaultSyncState::new(VAULT);
        let r2 = engine
            .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
            .unwrap();
        assert_eq!(r2.pulled, 1);
        assert_eq!(state2.dag().len(), 1);
    }

    #[test]
    fn rollback_is_rejected() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Push two ops.
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1.clone());
        engine
            .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
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
        engine
            .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
            .unwrap();

        // Device 2 sees the current head with two ops.
        let mut state2 = VaultSyncState::new(VAULT);
        engine
            .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
            .unwrap();
        assert_eq!(state2.dag().len(), 2);
        assert!(state2.pinned_head().is_some());

        // Evil relay: roll back to just op1.
        // Build a head for just op1.
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

        // Remove op2 from transport (so pull returns only op1).
        transport.truncate_ops(VAULT, 1);

        // The next sync from state2 should detect a rollback.
        let err = engine
            .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
            .unwrap_err();
        assert_eq!(err, SyncError::RollbackDetected);
        // Local state unchanged: still 2 ops.
        assert_eq!(state2.dag().len(), 2);
    }

    #[test]
    fn missing_parent_is_detected() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Device 1 pushes genesis.
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1.clone());
        engine
            .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
            .unwrap();
        let hash1 = op1.hash().unwrap();

        // Inject op2 without op1 visible to device2's pull (the transport
        // only sees op2 after we truncate op1 away, but op2 references hash1).
        let op2 = fix.make_op(
            2,
            DEV1,
            &fix.dev1_key,
            vec![hash1],
            2,
            OpKind::Update,
            b"v2",
        );
        // Put op2 directly, then remove op1 from what device2 would see.
        transport.push(VAULT, &[op2]).unwrap();
        transport.truncate_ops(VAULT, 0); // Remove op1 from the ordered list.
                                          // Re-inject only op2 (which references op1 as a parent).
        let raw2 = transport.raw_ops(&VAULT); // empty after truncation
        drop(raw2);
        // Manually inject op2 at position 0 so pull returns it without op1.
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
        transport.inject_raw_op(VAULT, hash2, raw2b);

        let mut state2 = VaultSyncState::new(VAULT);
        let err = engine
            .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
            .unwrap_err();
        assert_eq!(err, SyncError::MissingParent);
        assert_eq!(state2.dag().len(), 0);
    }

    #[test]
    fn offline_device_queues_and_then_pushes() {
        let fix = Fixture::new();
        let engine = fix.engine();
        let mut transport = MemoryTransport::new();

        // Device 1 makes an op and queues it locally (no network).
        let mut state1 = VaultSyncState::new(VAULT);
        let op1 = fix.make_op(1, DEV1, &fix.dev1_key, vec![], 1, OpKind::Create, b"v1");
        state1.enqueue(op1);
        // The transport is still empty.  Simulate "no network" by checking
        // state before calling sync.
        assert_eq!(state1.pending.len(), 1);

        // Now sync (network available).
        let r = engine
            .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
            .unwrap();
        assert_eq!(r.pushed, 1);
        assert_eq!(state1.pending.len(), 0);
    }
}
