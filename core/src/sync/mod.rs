//! The sync engine and transport layer (SPEC §7.10).
//!
//! Core talks to every storage backend through the [`Transport`] trait.  The
//! same sync logic runs against the relay server, a synced folder, or an
//! in-memory store used by tests and the evil-relay harness.
//!
//! # Architecture
//!
//! ```text
//!   SyncEngine ──► Transport (http | folder | memory)
//!        │
//!        ├── pull: fetch ops + head from the backend
//!        ├── verify: signature, device cert, AAD, parents present, Lamport
//!        ├── stage: collect ops in a temporary set
//!        ├── check_head_update: descends from pinned head?
//!        ├── commit: merge staged ops into the DAG (only after head verified)
//!        ├── push: send locally-queued ops
//!        └── update head: CAS
//! ```
//!
//! # Wasm compatibility
//!
//! `studge-core` builds for `wasm32-unknown-unknown` (the browser extension).
//! There is therefore **no** I/O dependency in this module.
//! `FolderTransport` and `HttpRelayTransport` live in the
//! `studge-sync-transports` crate (native-only).

pub mod engine;
pub mod memory;
pub mod transport;

pub use engine::SyncEngine;
pub use memory::MemoryTransport;
pub use transport::{SyncError, Transport, VaultOps};
