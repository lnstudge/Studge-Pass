//! Evil relay and adversarial integration tests (SPEC §7.12, AGENTS.md §Security bar).
//!
//! This crate is deliberately hostile.  It implements a relay that lies,
//! reorders, replays and drops, so the sync engine's checks are exercised
//! against an attacker, not a friend.
//!
//! # Using `EvilRelay`
//!
//! ```rust,ignore
//! let mut evil = EvilRelay::new(MemoryTransport::new());
//! evil.set_attack(Attack::RollbackHead);
//! // Run the sync engine against it:
//! let err = engine.sync(..., &mut evil, ...).unwrap_err();
//! assert_eq!(err, SyncError::RollbackDetected);
//! ```

#![forbid(unsafe_code)]

pub mod evil_relay;
pub mod fixture;
