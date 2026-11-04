#![forbid(unsafe_code)]

//! Studge Pass core.
//!
//! Crypto, vault model, operation log, sync engine, import/export and health
//! scoring. No direct I/O: everything that touches the outside world arrives
//! through injected traits. The crate is filled in phase by phase; Phase 0 only
//! fixes the module layout.

pub mod crypto;
pub mod error;
pub mod health;
pub mod import;
pub mod oplog;
pub mod sync;
pub mod vault;
