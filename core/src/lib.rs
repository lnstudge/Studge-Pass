#![forbid(unsafe_code)]

//! Studge Pass core.
//!
//! Crypto, vault model, operation log, sync engine, import/export and health
//! scoring. No direct I/O: everything that touches the outside world arrives
//! through injected traits, so the crate builds for native targets and for
//! `wasm32-unknown-unknown` alike.

pub mod cbor;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod health;
pub mod import;
pub mod oplog;
pub mod sync;
pub mod vault;

pub use error::{CoreError, CoreResult};
