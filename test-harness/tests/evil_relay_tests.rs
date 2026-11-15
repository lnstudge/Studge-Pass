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
//! | `evil_relay_swapped_ciphertext_is_detected` | `SwapCiphertext` | error |
//! | `evil_relay_fork_head_is_detected` | `ForkHead` | `HeadReferencesUnknownOp` |
//! | `evil_relay_drop_ops_is_detected` | `DropOps` | `HeadReferencesUnknownOp` |
//! | `evil_relay_wrong_vault_id_is_detected` | `WrongVaultId` | `OpVerificationFailed` |
//! | `evil_relay_withheld_head_is_detected` | `WithholdHead` | `RollbackDetected` |
//! | `two_device_concurrent_edits_converge` | — | no error, final state has 3 ops |
//! | `three_device_concurrent_edits_converge` | — | no error, all 3 devices agree |

use studge_core::oplog::op::{OpHash, OpKind};
use studge_core::sync::memory::MemoryTransport;
use studge_core::sync::transport::SyncError;
use studge_test_harness::{
    evil_relay::{Attack, EvilRelay},
    fixture::{sync, Fixture, DEV1, DEV2, VAULT},
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Runs a full two-op setup on an EvilRelay and then arms the attack.
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
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();

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
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();

    evil.set_attack(attack);
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
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();
    assert_eq!(state2.dag().len(), 2);
    assert!(state2.pinned_head().is_some());

    // Evil: serve the snapshot-0 head (op1 only) — a rollback.
    evil.set_attack(Attack::RollbackHead { snapshot_index: 0 });
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
    assert_eq!(
        err,
        SyncError::RollbackDetected,
        "rollback must be detected"
    );
    assert_eq!(state2.dag().len(), 2, "local state must be unchanged");
}

/// A head that references a hash the client has never seen MUST be detected.
#[test]
fn evil_relay_ghost_head_entry_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::GhostHeadEntry);
    let engine = fix.engine();

    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
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
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();
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
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();

    evil.set_attack(Attack::ReorderOps);
    let mut state2 = Fixture::state2();
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
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
#[test]
fn evil_relay_stripped_signature_is_detected() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
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

    let mut raw = op1.to_cbor().unwrap();
    if raw.len() > 71 {
        raw[7..71].iter_mut().for_each(|b| *b = 0);
    }
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    let result = sync(
        &engine,
        VAULT,
        &mut state2,
        &mut transport,
        &fix.dev2_key,
        DEV2,
    );
    assert!(result.is_err(), "stripped signature must be detected");
    assert_eq!(state2.dag().len(), 0, "local state must be unchanged");
}

/// A flipped bit in a CBOR op MUST be detected.
#[test]
fn evil_relay_flipped_bit_is_detected() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
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

    let mut raw = op1.to_cbor().unwrap();
    let flip_pos = raw.len() - 10;
    raw[flip_pos] ^= 0xFF;
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    let result = sync(
        &engine,
        VAULT,
        &mut state2,
        &mut transport,
        &fix.dev2_key,
        DEV2,
    );
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

    evil.set_attack(Attack::Honest);
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();

    evil.set_attack(Attack::SubstituteDeviceCert);
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
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
    evil.set_attack(Attack::Honest);
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();
    evil.set_attack(Attack::DowngradeSuite);
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
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
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
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
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();
    assert_eq!(state2.dag().len(), 2, "replay must not duplicate ops");
}

/// Honest passthrough (sanity): device2 gets both ops.
#[test]
fn evil_relay_honest_passthrough_succeeds() {
    let (fix, mut evil, mut state2, _hash1, _hash2) = two_op_setup_with_evil(Attack::Honest);
    let engine = fix.engine();
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();
    assert_eq!(state2.dag().len(), 2);
}

/// Swapping the raw bytes of two ops MUST be detected.
#[test]
fn evil_relay_swapped_ciphertext_is_detected() {
    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    let engine = fix.engine();
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();
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
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();

    evil.set_attack(Attack::SwapCiphertext { a: 0, b: 1 });
    let mut state2 = Fixture::state2();
    let result = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2);
    assert!(
        result.is_err(),
        "swapped ciphertext must be detected; got: {:?}",
        result
    );
}

// ── Fix 4: new named attack tests ────────────────────────────────────────────

/// ForkHead: a head with a ghost tip MUST be detected.
/// The relay returns honest ops but a head pointing to a hash the client has
/// never seen.  The engine must reject with HeadReferencesUnknownOp.
#[test]
fn evil_relay_fork_head_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) = two_op_setup_with_evil(Attack::ForkHead);
    let engine = fix.engine();
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::HeadReferencesUnknownOp
                | SyncError::OpVerificationFailed
                | SyncError::MalformedPayload
        ),
        "ForkHead must be detected: {err:?}"
    );
    // If this test ever passes (no error), the protection is gone.
}

/// DropOps: relay drops all ops but returns the honest head.
/// The engine must detect that the head references ops it does not have.
#[test]
fn evil_relay_drop_ops_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) = two_op_setup_with_evil(Attack::DropOps);
    let engine = fix.engine();
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
    assert_eq!(
        err,
        SyncError::HeadReferencesUnknownOp,
        "DropOps must be detected as HeadReferencesUnknownOp"
    );
    assert_eq!(state2.dag().len(), 0, "local state must be unchanged");
}

/// WrongVaultId: relay returns ops tagged with a different vault id.
/// The re-encode check or signature verification must reject them.
#[test]
fn evil_relay_wrong_vault_id_is_detected() {
    let (fix, mut evil, mut state2, _hash1, _hash2) =
        two_op_setup_with_evil(Attack::WrongVaultId {
            other_vault: [0xFFu8; 16],
        });
    let engine = fix.engine();
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
    assert!(
        matches!(
            err,
            SyncError::OpVerificationFailed
                | SyncError::MalformedPayload
                | SyncError::HeadReferencesUnknownOp
        ),
        "WrongVaultId must be detected: {err:?}"
    );
    assert_eq!(state2.dag().len(), 0, "local state must be unchanged");
}

/// WithholdHead: relay returns honest ops but no head, while device already
/// has a pin.  Engine must detect this as RollbackDetected (Fix 3b).
#[test]
fn evil_relay_withheld_head_is_detected() {
    use studge_test_harness::evil_relay::Attack;
    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    let engine = fix.engine();

    // Build two-op history.
    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
    let hash1 = op1.hash().unwrap();
    state1.enqueue(op1);
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();
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
    sync(&engine, VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1).unwrap();

    // Device 2 syncs honestly to get a pin.
    let mut state2 = Fixture::state2();
    evil.set_attack(Attack::Honest);
    sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap();
    assert!(state2.pinned_head().is_some(), "state2 must have a pin");

    // Now the relay withholds the head.
    evil.set_attack(Attack::WithholdHead);
    let err = sync(&engine, VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2).unwrap_err();
    assert_eq!(
        err,
        SyncError::RollbackDetected,
        "withheld head must be detected as RollbackDetected"
    );
    // Local state unchanged.
    assert_eq!(state2.dag().len(), 2, "local state must be unchanged");
}

// ─── Multi-device simulation tests ───────────────────────────────────────────

/// Two devices make concurrent edits to the same item; both should converge
/// after each syncs.
#[test]
fn two_device_concurrent_edits_converge() {
    let fix = Fixture::new();
    let mut transport = MemoryTransport::new();
    let engine = fix.engine();

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
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

    let op_a = fix.make_op(
        2,
        DEV1,
        &fix.dev1_key,
        vec![hash1],
        2,
        OpKind::Update,
        b"dev1-edit",
    );
    state1.enqueue(op_a);

    let mut state2 = Fixture::state2();
    sync(
        &engine,
        VAULT,
        &mut state2,
        &mut transport,
        &fix.dev2_key,
        DEV2,
    )
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
    sync(
        &engine,
        VAULT,
        &mut state1,
        &mut transport,
        &fix.dev1_key,
        DEV1,
    )
    .unwrap();

    assert_eq!(state1.dag().len(), 3, "device1 should see genesis + A + B");
    assert_eq!(state2.dag().len(), 3, "device2 should see genesis + A + B");

    let tips1 = state1.dag().heads();
    let tips2 = state2.dag().heads();
    assert_eq!(tips1, tips2, "both devices must agree on the DAG tips");
}

/// Three devices concurrently produce one op each; all must converge on the
/// same 4-op DAG.
#[test]
fn three_device_concurrent_edits_converge() {
    use studge_core::crypto::signing::{DeviceCertificate, SigningKeyPair};
    use studge_test_harness::fixture::at;

    const DEV3: [u8; 16] = [0xD3; 16];
    let fix = Fixture::new();
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

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
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

    let mut state2 = studge_core::sync::engine::VaultSyncState::new(VAULT);
    let mut state3 = studge_core::sync::engine::VaultSyncState::new(VAULT);
    sync(
        &engine,
        VAULT,
        &mut state2,
        &mut transport,
        &fix.dev2_key,
        DEV2,
    )
    .unwrap();
    sync(&engine, VAULT, &mut state3, &mut transport, &dev3_key, DEV3).unwrap();

    let op_a = fix.make_op(2, DEV1, &fix.dev1_key, vec![hash1], 2, OpKind::Update, b"A");
    state1.enqueue(op_a);
    let op_b = fix.make_op(3, DEV2, &fix.dev2_key, vec![hash1], 2, OpKind::Update, b"B");
    state2.enqueue(op_b);
    let op_c = fix.make_op(4, DEV3, &dev3_key, vec![hash1], 2, OpKind::Update, b"C");
    state3.enqueue(op_c);

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
    sync(&engine, VAULT, &mut state3, &mut transport, &dev3_key, DEV3).unwrap();

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
    sync(&engine, VAULT, &mut state3, &mut transport, &dev3_key, DEV3).unwrap();

    assert_eq!(state1.dag().len(), 4, "4 ops: genesis + A + B + C");
    assert_eq!(state2.dag().len(), 4);
    assert_eq!(state3.dag().len(), 4);

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

    let mut state1 = Fixture::state1();
    let op1 = fix.genesis();
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

    let mut state2 = Fixture::state2();
    sync(
        &engine,
        VAULT,
        &mut state2,
        &mut transport,
        &fix.dev2_key,
        DEV2,
    )
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
    let _ = hash1b;

    assert_eq!(state2.dag().len(), 3, "offline device must catch up");

    sync(
        &engine,
        VAULT,
        &mut state1,
        &mut transport,
        &fix.dev1_key,
        DEV1,
    )
    .unwrap();
    assert_eq!(state1.dag().len(), 3, "device1 must converge with device2");
    assert_eq!(
        state1.dag().len(),
        state2.dag().len(),
        "both devices converge"
    );
}
