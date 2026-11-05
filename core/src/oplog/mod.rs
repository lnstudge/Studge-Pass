//! The vault operation log: SPEC §6.
//!
//! An op is a signed, content-addressed change to one vault; the ops form a
//! DAG whose tips are summarised by a signed head. Together they give the
//! "relay is an attacker" promise its teeth:
//!
//! - every op is signed by a certified device, so the relay cannot edit one;
//! - every op names its parents, so the relay cannot drop or reorder one
//!   without producing a missing-parent error;
//! - every head carries counters and must descend from the pinned head, so the
//!   relay cannot serve an old state or a second history.
//!
//! Nothing here does I/O. A caller adds verified ops to a [`Dag`], materialises
//! state with a vault key, and compares heads against the one it pinned.

pub mod dag;
pub mod devices;
pub mod head;
pub mod materialise;
pub mod op;

pub use dag::Dag;
pub use devices::DeviceRegistry;
pub use head::{check_head_update, verify_descends, HeadUpdate, VaultHead};
pub use materialise::{materialise, materialise_at, VaultState};
pub use op::{hash_eq, Op, OpHash, OpId, OpKind, StoredOp};
