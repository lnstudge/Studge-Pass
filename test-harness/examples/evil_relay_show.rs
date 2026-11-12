//! `evil_relay_show` — demonstrates every evil-relay attack and prints a result table.
//!
//! This is a pure DEMO with fabricated device keys and vault payloads labelled
//! **"DEMO ONLY"**.  No real vault data is involved.
//!
//! Run with:
//! ```
//! cargo run -p studge-test-harness --example evil_relay_show
//! ```

use studge_core::{
    oplog::op::OpKind,
    sync::{
        engine::{SyncResult, VaultSyncState},
        memory::MemoryTransport,
        transport::SyncError,
    },
};
use studge_test_harness::{
    evil_relay::{Attack, EvilRelay},
    fixture::{DEV1, DEV2, VAULT},
};

// ─── Terminal colour helpers (no extra deps) ──────────────────────────────────

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn ok(s: &str) -> String {
    format!("{GREEN}✓ {s}{RESET}")
}
fn fail(s: &str) -> String {
    format!("{RED}✗ {s}{RESET}")
}
fn note(s: &str) -> String {
    format!("{YELLOW}~ {s}{RESET}")
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("{BOLD}{CYAN}══════════════════════════════════════════════════════{RESET}");
    println!("{BOLD}{CYAN}  Studge Pass — Evil-Relay Attack Table  [DEMO ONLY]  {RESET}");
    println!("{BOLD}{CYAN}══════════════════════════════════════════════════════{RESET}");
    println!();
    println!("  Each row arms one attack and syncs a fresh device2.");
    println!("  {GREEN}✓{RESET}  = attack detected (sync returned an error)");
    println!("  {YELLOW}~{RESET}  = attack was idempotent / harmless by design");
    println!();

    // Each row: (label, expected_err?, run_fn)
    // expected_err = None means "any error is acceptable"
    // expected_err = Some(e) means "exactly this error"
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        &str,
        Option<SyncError>,
        fn() -> Result<SyncResult, SyncError>,
    )> = vec![
        ("Honest passthrough (sanity)", None, || {
            run_one(Attack::Honest, false)
        }),
        (
            "RollbackHead — old head after new ops",
            Some(SyncError::RollbackDetected),
            || run_one(Attack::RollbackHead { snapshot_index: 0 }, true),
        ),
        ("GhostHeadEntry — head refs unknown op", None, || {
            run_one(Attack::GhostHeadEntry, false)
        }),
        ("TruncateOps — withhold all ops", None, || {
            run_one(Attack::TruncateOps { n: 0 }, false)
        }),
        (
            "ReorderOps — children before parents",
            Some(SyncError::MissingParent),
            || run_one(Attack::ReorderOps, false),
        ),
        ("DropOps — empty op list, honest head", None, || {
            run_one(Attack::DropOps, false)
        }),
        ("SwapCiphertext — swap ops[0] and ops[1]", None, || {
            run_one(Attack::SwapCiphertext { a: 0, b: 1 }, false)
        }),
        (
            "FlipBit — flip bit in sig bytes (raw inject)",
            None,
            run_flipped_bit,
        ),
        (
            "StripSignature — zero sig bytes (raw inject)",
            None,
            run_stripped_sig,
        ),
        ("SubstituteDeviceCert — flip head sig byte", None, || {
            run_one(Attack::SubstituteDeviceCert, true)
        }),
        ("WrongVaultId — replace vault_id in ops", None, || {
            run_one(
                Attack::WrongVaultId {
                    other_vault: [0xFFu8; 16],
                },
                false,
            )
        }),
        ("DowngradeSuite — replace 'v1' with 'v0'", None, || {
            run_one(Attack::DowngradeSuite, true)
        }),
        ("ReplayOldOp — append first op again", None, || {
            // Expected to succeed (idempotent)
            run_one(Attack::ReplayOldOp, false)
        }),
    ];

    let col_w = 50usize;
    println!(
        "  {BOLD}{:<col_w$}  {:<22}  Result{RESET}",
        "Attack", "Expected error"
    );
    println!("  {}", "─".repeat(col_w + 2 + 22 + 2 + 20));

    let mut passed = 0usize;
    let mut failed_list: Vec<String> = Vec::new();

    for (label, expected, run_fn) in &rows {
        let result = run_fn();
        let is_honest = *label == "Honest passthrough (sanity)";
        let is_replay = label.starts_with("ReplayOldOp");

        let expected_str = expected
            .as_ref()
            .map(|e| format!("{e:?}"))
            .unwrap_or_else(|| {
                if is_honest || is_replay {
                    "—".to_string()
                } else {
                    "any error".to_string()
                }
            });

        let verdict = match (&result, expected) {
            // Honest passthrough — expect success.
            (Ok(_), None) if is_honest => {
                passed += 1;
                ok("passed — no attack")
            }
            // ReplayOldOp — idempotent.
            (Ok(_), None) if is_replay => {
                passed += 1;
                note("harmless (idempotent)")
            }
            // Any error is fine when expected == None (we just need is_err).
            (Err(_), None) => {
                passed += 1;
                ok(&format!("blocked ({:?})", result.as_ref().unwrap_err()))
            }
            // Specific error matched.
            (Err(e), Some(exp)) if e == exp => {
                passed += 1;
                ok(&format!("blocked ({e:?})"))
            }
            // Specific error — different variant (still blocked, warn).
            (Err(e), Some(_)) => {
                passed += 1;
                note(&format!("blocked (got {e:?})"))
            }
            // No error but we expected one.
            (Ok(_), Some(exp)) => {
                failed_list.push(format!("  FAIL — {label}: expected {exp:?}, got Ok"));
                fail(&format!("NOT blocked (expected {exp:?})"))
            }
            // Unexpected success (attack expected to be detected).
            (Ok(_), None) => {
                failed_list.push(format!("  FAIL — {label}: unexpected Ok"));
                fail("NOT blocked")
            }
        };

        println!("  {:<col_w$}  {:<22}  {}", label, expected_str, verdict);
    }

    println!();
    println!(
        "  {BOLD}Result: {passed}/{} attacks handled correctly.{RESET}",
        rows.len()
    );

    if !failed_list.is_empty() {
        println!();
        println!("{RED}Failures:{RESET}");
        for f in &failed_list {
            println!("{RED}{f}{RESET}");
        }
        std::process::exit(1);
    } else {
        println!();
        println!("{GREEN}All attacks are detected.{RESET}");
    }
    println!();
}

// ─── Run one attack against a fresh two-op history ───────────────────────────

/// Builds a two-op history, arms the attack, then syncs a fresh device2.
///
/// `pre_sync_d2` — if true, device2 syncs honestly first (needed for attacks
/// that require a pinned head before the evil pull: rollback, downgrade,
/// substitute-cert).
fn run_one(attack: Attack, pre_sync_d2: bool) -> Result<SyncResult, SyncError> {
    use studge_test_harness::fixture::Fixture;

    let fix = Fixture::new();
    let mut evil = EvilRelay::new(MemoryTransport::new());
    let engine = fix.engine();

    // ── Device 1 builds a two-op history through the evil relay (Honest). ──
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
        b"DEMO ONLY v2",
    );
    state1.enqueue(op2);
    engine
        .sync(VAULT, &mut state1, &mut evil, &fix.dev1_key, DEV1)
        .unwrap();

    // ── Device 2: optionally pre-sync, then arm the attack. ──
    let mut state2 = VaultSyncState::new(VAULT);
    if pre_sync_d2 {
        engine
            .sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
            .unwrap();
    }
    evil.set_attack(attack);
    engine.sync(VAULT, &mut state2, &mut evil, &fix.dev2_key, DEV2)
}

// ─── Direct-inject variants (bypass EvilRelay wrapper) ───────────────────────

/// Flip a byte in the sig bytes of an op and inject it directly via
/// `inject_raw_op` (bypassing CBOR re-encode check).  The unit tests use
/// this approach.
fn run_flipped_bit() -> Result<SyncResult, SyncError> {
    use studge_test_harness::fixture::Fixture;

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

    // Flip a byte near the end of the raw CBOR (payload / AEAD tag area).
    let mut raw = op1.to_cbor().unwrap();
    let flip_pos = raw.len() - 10;
    raw[flip_pos] ^= 0xFF;
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    engine.sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
}

/// Zero the Ed25519 signature bytes in an op and inject it directly.
fn run_stripped_sig() -> Result<SyncResult, SyncError> {
    use studge_test_harness::fixture::Fixture;

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

    // Canonical CBOR map starts: header | key "sig" | value header | 64 sig bytes.
    // Sig data is at bytes 7..71.
    let mut raw = op1.to_cbor().unwrap();
    if raw.len() > 71 {
        raw[7..71].iter_mut().for_each(|b| *b = 0);
    }
    transport.inject_raw_op(VAULT, hash1, raw);

    let mut state2 = Fixture::state2();
    engine.sync(VAULT, &mut state2, &mut transport, &fix.dev2_key, DEV2)
}
