//! Shared test fixture for evil-relay integration tests.
//!
//! One `Fixture` has two certified devices, a vault key, and helpers to make
//! signed ops.  It is the same setup used by the engine unit tests, pulled up
//! to the harness crate so every test file can reuse it.

use studge_core::crypto::keys::VaultKey;
use studge_core::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
use studge_core::oplog::dag::Dag;
use studge_core::oplog::devices::DeviceRegistry;
use studge_core::oplog::op::{Op, OpHash, OpKind, StoredOp};
use studge_core::sync::engine::{SyncEngine, SyncResult, VaultSyncState};
use studge_core::sync::transport::{SyncError, Transport};

pub const ACCOUNT: [u8; 16] = [0xAA; 16];
pub const VAULT: [u8; 16] = [0xBB; 16];
pub const ITEM: [u8; 16] = [0xCC; 16];
pub const DEV1: [u8; 16] = [0xD1; 16];
pub const DEV2: [u8; 16] = [0xD2; 16];

pub fn at(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap()
}

/// Fixed "now" timestamp for all test syncs.
pub fn now() -> Timestamp {
    at("2026-11-15T10:00:00Z")
}

/// Convenience wrapper: sync with the fixed test timestamp.
pub fn sync(
    engine: &SyncEngine,
    vault_id: [u8; 16],
    state: &mut VaultSyncState,
    transport: &mut dyn Transport,
    key: &SigningKeyPair,
    dev: [u8; 16],
) -> Result<SyncResult, SyncError> {
    engine.sync(vault_id, state, transport, key, dev, now())
}

/// Two-device test fixture.
pub struct Fixture {
    pub identity: SigningKeyPair,
    pub dev1_key: SigningKeyPair,
    pub dev2_key: SigningKeyPair,
    pub registry: DeviceRegistry,
    pub vk: VaultKey,
}

impl Fixture {
    pub fn new() -> Self {
        let identity = SigningKeyPair::from_seed([1u8; 32]);
        let dev1_key = SigningKeyPair::from_seed([2u8; 32]);
        let dev2_key = SigningKeyPair::from_seed([3u8; 32]);
        let mut registry = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
        let cert1 = DeviceCertificate::create(
            &identity,
            ACCOUNT,
            DEV1,
            dev1_key.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .unwrap();
        registry
            .certify(&cert1, &at("2026-11-05T09:30:00Z"))
            .unwrap();
        let cert2 = DeviceCertificate::create(
            &identity,
            ACCOUNT,
            DEV2,
            dev2_key.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .unwrap();
        registry
            .certify(&cert2, &at("2026-11-05T09:30:00Z"))
            .unwrap();
        Self {
            identity,
            dev1_key,
            dev2_key,
            registry,
            vk: VaultKey::from_bytes([3u8; 32]),
        }
    }

    /// Creates a signed op.
    #[allow(clippy::too_many_arguments)]
    pub fn make_op(
        &self,
        op_idx: u8,
        device_id: [u8; 16],
        key: &SigningKeyPair,
        parents: Vec<OpHash>,
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

    /// Genesis op for device 1.
    pub fn genesis(&self) -> StoredOp {
        self.make_op(1, DEV1, &self.dev1_key, vec![], 1, OpKind::Create, b"v1")
    }

    /// Returns the engine backed by this fixture's device registry.
    pub fn engine(&self) -> SyncEngine {
        SyncEngine::new(self.registry.clone())
    }

    /// Returns a fresh empty sync state for VAULT.
    pub fn state1() -> VaultSyncState {
        VaultSyncState::new(VAULT)
    }

    pub fn state2() -> VaultSyncState {
        VaultSyncState::new(VAULT)
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a two-op linear history on `transport`, leaves device1's state
/// pinned at the second op.  Returns `(hash1, hash2, state1)`.
pub fn two_op_history(
    fix: &Fixture,
    transport: &mut dyn Transport,
) -> (OpHash, OpHash, VaultSyncState) {
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    sync(&engine, VAULT, &mut state1, transport, &fix.dev1_key, DEV1).unwrap();

    let op2 = fix.make_op(
        2,
        DEV1,
        &fix.dev1_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"v2",
    );
    let hash2 = op2.hash().unwrap();
    state1.enqueue(op2);
    sync(&engine, VAULT, &mut state1, transport, &fix.dev1_key, DEV1).unwrap();

    (hash1, hash2, state1)
}

/// Builds a pre-loaded `Dag` with two ops (for use in `VaultSyncState::with_pin`).
pub fn loaded_dag(fix: &Fixture, op1: &StoredOp, op2: &StoredOp) -> Dag {
    let mut dag = Dag::new(VAULT);
    dag.add(op1.clone(), &fix.registry).unwrap();
    dag.add(op2.clone(), &fix.registry).unwrap();
    dag
}
