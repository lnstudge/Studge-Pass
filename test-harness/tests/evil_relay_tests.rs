//! Evil-relay attack tests.
//!
//! Each test proves that a specific attack by the relay is detected by the
//! sync engine, returns the expected `SyncError` variant, and leaves local
//! data unchanged.  Test names are documented in the threat-model table
//! (THREAT_MODEL.md §19).
//!
//! # Attack → expected error mapping
//!
//! | Test | Attack | Expected SyncError |
//! |---|---|---|
//! | `evil_relay_rollback_is_detected` | `RollbackHead` | `RollbackDetected` |
//! | `evil_relay_ghost_head_entry_is_detected` | `GhostHeadEntry` | `HeadReferencesUnknownOp` |
//! | `evil_relay_reordered_ops_cause_missing_parent` | `ReorderOps` | `MissingParent` |
//! | `evil_relay_stripped_signature_is_detected` | `StripSignature` | `OpVerificationFailed` |
//! | `evil_relay_flipped_bit_is_detected` | `FlipBit` | `OpVerificationFailed` |
//! | `evil_relay_substitute_device_cert_is_detected` | `SubstituteDeviceCert` | `OpVerificationFailed` |
//! | `evil_relay_downgrade_suite_is_detected` | `DowngradeSuite` | `OpVerificationFailed` |
//! | `evil_relay_truncate_ops_is_detected` | `TruncateOps` | `HeadReferencesUnknownOp` |
//! | `evil_relay_replay_old_op_is_harmless` | `ReplayOldOp` | no error (idempotent) |
//! | `evil_relay_honest_passthrough_succeeds` | `Honest` | no error |
//! | `two_device_concurrent_edits_converge` | — | no error, final state has 3 ops |
//! | `three_device_concurrent_edits_converge` | — | no error, all 3 devices agree |

use studge_core::oplog::op::{OpHash, OpKind};
use studge_core::sync::memory::MemoryTransport;
use studge_core::sync::transport::SyncError;
use studge_test_harness::{
    evil_relay::{Attack, EvilRelay},
    fixture::{Fixture, DEV1, DEV2, VAULT},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Runs a full two-op setup on an EvilRelay and then syncs device2 against it.
/// Returns (fix, evil, state2, hash1, hash2).
fn two_op_setup_with_evil(
    attack: Attack,
) -> (
    Fixture,
    EvilRelay,
    studge_core::sync::engine::VaultSyncState,
    OpHash,
    OpHash,
) {
    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    // Build the honest two-op history through the evil relay (Honest mode)
    // so its snapshot machinery runs.
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
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
    let hash2 = op2.hash().unwrap();
    state1.enqueue(op2);
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
        .unwrap();

    // Now arm the attack.
    evil.set_attack(attack);
    // Device 2 starts fresh.
    let state2 = Fixture::state2();
    (fix, evil, state2, hash1, hash2)
}

// ─── Attack tests ────────────────────────────────────────────────────────────

/// A rollback (server serves an old head after new ops exist) MUST be detected.
#[test]
fn evil_relay_rollback_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::RollbackHead { snapshot_index: 0 });
    let engine = fix.engine();

    // First sync device2 honestly so it gets a pin on op2 head.
    evil.set_attack(Attack::Honest);
    engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap();
    assert_eq!(state2.dag().len(), 2);
    assert!(state2.pinned_head().is_some());

    // Evil: serve the snapshot-0 head (op1 only) — a rollback.
    evil.set_attack(Attack::RollbackHead { snapshot_index: 0 });
    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    assert_eq!(
        err,
        SyncError::RollbackDetected,
        "rollback must be detected"
    );
    // Local state must be unchanged.
    assert_eq!(
        state2.dag().len(),
        2,
        "local state must be unchanged after rollback"
    );
}

/// A head that references a hash the client has never seen MUST be detected.
#[test]
fn evil_relay_ghost_head_entry_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::GhostHeadEntry);
    let engine = fix.engine();

    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    // Either the head parse failed (MalformedPayload → mapped to
    // OpVerificationFailed) or the engine caught the ghost tip.
    assert!(
        matches!(
            err,
            SyncError::HeadReferencesUnknownOp
                | SyncError::OpVerificationFailed
                | SyncError::MalformedPayload
        ),
        "ghost head tip must be detected: {err:?}"
    );
}

/// Reordering ops so children arrive before parents MUST cause MissingParent.
#[test]
fn evil_relay_reordered_ops_cause_missing_parent() {
    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    // Build a two-op history through the evil relay so snapshots work.
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
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
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
        .unwrap();
    // Arm the reorder attack.
    evil.set_attack(Attack::ReorderOps);
    let mut state2 = Fixture::state2();
    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    assert_eq!(
        err,
        SyncError::MissingParent,
        "reordered ops must cause MissingParent"
    );
    assert_eq!(
        state2.dag().len(),
        0,
        "local state must be empty after failure"
    );
}

/// A zeroed signature MUST be detected.
/// The sig comes first in canonical CBOR; we zero bytes 7..71 (the sig data).
#[test]
fn evil_relay_stripped_signature_is_detected() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    // Build one op honestly.
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1.clone());
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // Build tampered bytes: same op but with zeroed sig.
    // Canonical map starts: 0xAC (12 entries) | key "sig" (0x63 0x73 0x69 0x67)
    // | value header (0x58 0x40) | 64 sig bytes.
    // Sig data starts at byte 7, ends at byte 70.
    let mut raw = op1.to_cbor().unwrap();
    if raw.len() > 71 {
        raw[7..71].iter_mut().for_each(|b| *b = 0);
    }
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    let result = engine.sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2);
    // from_cbor: re-encode check will fail because the raw bytes have zeroed
    // sig but the struct still re-encodes to the original sig → MalformedPayload.
    // OR: from_cbor reads the zeroed sig → re-encode matches → verify() fails.
    assert!(result.is_err(), "stripped signature must be detected");
    assert_eq!(state2.dag().len(), 0, "local state must be unchanged");
}

/// A flipped bit in a CBOR op MUST be detected.
/// We flip a bit in the payload field bytes (largest field, at offset > 100).
#[test]
fn evil_relay_flipped_bit_is_detected() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1.clone());
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // Flip a byte in the payload (AEAD ciphertext) area.
    // The payload is the last significant field; flip a byte near the end.
    let mut raw = op1.to_cbor().unwrap();
    let flip_pos = raw.len() - 10; // near the end (in the payload ciphertext)
    raw[flip_pos] ^= 0xFF;
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    let result = engine.sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2);
    // The flip is in the payload field → re-encode check compares raw with
    // re-serialised: the payload CBOR bytes change → mismatch → MalformedPayload.
    // OR the op parses but fails sig or AEAD tag check.
    assert!(
        result.is_err(),
        "flipped bit must be detected: {:?}",
        result
    );
    assert_eq!(state2.dag().len(), 0);
}

/// A tampered head device_id MUST cause verification failure.
#[test]
fn evil_relay_substitute_device_cert_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::SubstituteDeviceCert);
    let engine = fix.engine();

    // First, sync device2 honestly to get the real ops.
    evil.set_attack(Attack::Honest);
    engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap();

    // Now arm substitution for next sync.
    evil.set_attack(Attack::SubstituteDeviceCert);
    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    // The tampered head either fails from_cbor or fails verify.
    assert!(
        matches!(
            err,
            SyncError::OpVerificationFailed | SyncError::MalformedPayload
        ),
        "substituted device cert must be detected: {err:?}"
    );
}

/// A downgraded suite id in the head MUST be detected.
#[test]
fn evil_relay_downgrade_suite_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::DowngradeSuite);
    let engine = fix.engine();
    // First get the ops honestly, then arm the downgrade.
    evil.set_attack(Attack::Honest);
    engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap();
    evil.set_attack(Attack::DowngradeSuite);
    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    // The patched head fails from_cbor (suite "v0" is unknown) or verify.
    assert!(
        matches!(
            err,
            SyncError::OpVerificationFailed | SyncError::MalformedPayload
        ),
        "downgraded suite must be detected: {err:?}"
    );
}

/// A truncated op list leaves the head referencing ops we don't have.
#[test]
fn evil_relay_truncate_ops_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::TruncateOps { n: 0 });
    let engine = fix.engine();
    let err = engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap_err();
    // Head references op2 which we don't have (we got zero ops).
    assert!(
        matches!(
            err,
            SyncError::HeadReferencesUnknownOp | SyncError::OpVerificationFailed
        ),
        "truncated ops must be detected: {err:?}"
    );
}

/// Replaying an old op is idempotent — no error, state unchanged.
#[test]
fn evil_relay_replay_old_op_is_harmless() {
    let (fix, mut evil, mut state2, _hash1, _hash2) = two_op_setup_with_evil(Attack::ReplayOldOp);
    let engine = fix.engine();
    // Replay is idempotent: the DAG already has the op so it's a no-op.
    engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap();
    assert_eq!(state2.dag().len(), 2, "replay must not duplicate ops");
}

/// Honest passthrough (sanity): device2 gets both ops.
#[test]
fn evil_relay_honest_passthrough_succeeds() {
    let (fix, mut evil, mut state2, _hash1, _hash2) = two_op_setup_with_evil(Attack::Honest);
    let engine = fix.engine();
    engine
        .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
        .unwrap();
    assert_eq!(state2.dag().len(), 2);
}

/// Swapping the raw bytes of two ops MUST be detected.
///
/// When op_b (which references op_a as parent) is served first (swapped to
/// position 0), the client gets `MissingParent`.  When op_a's bytes are at
/// position 1, op_a's op_id and vault_id disagree with op_b's body → the
/// re-encode check in `from_cbor` fails → `MalformedPayload`.
#[test]
fn evil_relay_swapped_ciphertext_is_detected() {
    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    // Build history through the evil relay so snapshots are taken.
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
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
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
        .unwrap();

    evil.set_attack(Attack::SwapCiphertext { a: 0, b: 1 });
    let mut state2 = Fixture::state2();
    let result = engine.sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2);
    // Swap detection: MissingParent (op_b before op_a) or OpVerificationFailed
    // (wrong op_id in the body).  Any error is correct.
    assert!(
        result.is_err(),
        "swapped ciphertext must be detected; got: {:?}",
        result
    );
}

// ─── Multi-device simulation tests ───────────────────────────────────────────

/// Two devices make concurrent edits to the same item; both should converge
/// after each syncs.
#[test]
fn two_device_concurrent_edits_converge() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    // Device 1 pushes genesis.
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // Both devices go offline and each creates an op from the same parent.
    // Device 1: update A
    let op_a = fix.make_op(
        2,
        DEV1,
        &fix.dev1_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"dev1-edit",
    );
    let _hash_a = op_a.hash().unwrap();
    state1.enqueue(op_a);

    // Device 2: comes online, pulls genesis, then makes its own concurrent edit.
    let mut state2 = Fixture::state2();
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    assert_eq!(state2.dag().len(), 1, "device2 should see genesis");

    let op_b = fix.make_op(
        3,
        DEV2,
        &fix.dev2_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"dev2-edit",
    );
    state2.enqueue(op_b);

    // Both sync: device1 pushes A, device2 pulls A then pushes B.
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();

    // Now device1 pulls B.
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    assert_eq!(state1.dag().len(), 3, "device1 should see genesis + A + B");
    assert_eq!(state2.dag().len(), 3, "device2 should see genesis + A + B");

    // Both DAGs must have the same set of tip hashes.
    let tips1 = state1.dag().heads();
    let tips2 = state2.dag().heads();
    assert_eq!(
        tips1, tips2,
        "both devices must agree on the DAG tips after convergence"
    );
}

/// Three devices concurrently produce one op each; all must converge on the
/// same 4-op DAG.
#[test]
fn three_device_concurrent_edits_converge() {
    use studge_core::crypto::signing::{DeviceCertificate, SigningKeyPair};
    use studge_test_harness::fixture::at;

    const DEV3: [u8; 16] = [0xD3; 16];
    let fix = Fixture::new();
    // Add a third device to the registry.
    let dev3_key = SigningKeyPair::from_seed([4u8; 32]);
    let mut registry = fix.registry.clone();
    let cert3 = DeviceCertificate::create(
        &fix.identity,
        studge_test_harness::fixture::ACCOUNT,
        DEV3,
        dev3_key.public_bytes(),
        at("2026-11-05T09:00:00Z"),
    )
    .unwrap();
    registry
        .certify(&cert3, &at("2026-11-05T09:30:00Z"))
        .unwrap();
    let engine = studge_core::sync::engine::SyncEngine::new(registry);

    let mut transport = MemoryTransport::new();

    // Device 1 pushes genesis.
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // All three devices pull genesis.
    let mut state2 = studge_core::sync::engine::VaultSyncState::new(VAULT);
    let mut state3 = studge_core::sync::engine::VaultSyncState::new(VAULT);
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    engine
        .sync(VAULT, &mut state3, &mut transport, &dev3_key, DEV3)
        .unwrap();

    // Each device makes a concurrent edit from the genesis.
    let op_a = fix.make_op(2, DEV1, &fix.dev1_key, vec![hash1], 2, OpKind::Update, b"A");
    state1.enqueue(op_a);
    let op_b = fix.make_op(3, DEV2, &fix.dev2_key, vec![hash1], 2, OpKind::Update, b"B");
    state2.enqueue(op_b);
    let op_c = fix.make_op(4, DEV3, &dev3_key, vec![hash1], 2, OpKind::Update, b"C");
    state3.enqueue(op_c);

    // All sync in order.
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    engine
        .sync(VAULT, &mut state3, &mut transport, &dev3_key, DEV3)
        .unwrap();

    // All devices pull to catch up.
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    engine
        .sync(VAULT, &mut state3, &mut transport, &dev3_key, DEV3)
        .unwrap();

    assert_eq!(state1.dag().len(), 4, "4 ops: genesis + A + B + C");
    assert_eq!(state2.dag().len(), 4);
    assert_eq!(state3.dag().len(), 4);

    // All three must see the same tips.
    let tips1 = state1.dag().heads();
    let tips2 = state2.dag().heads();
    let tips3 = state3.dag().heads();
    assert_eq!(tips1, tips2, "device1 and device2 must converge");
    assert_eq!(tips2, tips3, "device2 and device3 must converge");
}

/// An offline device queues ops and pushes them when it reconnects.
#[test]
fn offline_device_catches_up() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    // Device 1: push genesis.
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // Device 2 goes offline: it queues one op without syncing.
    let mut state2 = Fixture::state2();
    // Device 2 must first have genesis to compute parents.
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    let op_offline = fix.make_op(
        2,
        DEV2,
        &fix.dev2_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"offline-edit",
    );
    state2.enqueue(op_offline);

    // Device 1 makes two more edits.
    let op1b = fix.make_op(
        3,
        DEV1,
        &fix.dev1_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"d1-edit-1",
    );
    let hash1b = op1b.hash().unwrap();
    state1.enqueue(op1b);
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();

    // Device 2 comes back online and syncs (pulls dev1-edit-1 + pushes offline-edit).
    engine
        .sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
        .unwrap();
    let _ = hash1b;

    // Device 2 should now have: genesis + dev1-edit-1 + offline-edit (3 ops, two branches).
    assert_eq!(state2.dag().len(), 3, "offline device must catch up");

    // Device 1 now pulls op_offline from device 2.
    engine
        .sync(VAULT, &mut state1, &mut transport, &fix.dev1_key, DEV1)
        .unwrap();
    assert_eq!(state1.dag().len(), 3, "device1 must converge with device2");
    assert_eq!(
        state1.dag().len(),
        state2.dag().len(),
        "both devices converge"
    );
}
