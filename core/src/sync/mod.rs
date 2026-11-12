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
//!        ├── merge: DAG::add for each new op
//!        ├── check_head_update: descends from pinned head?
//!        ├── push: send locally-queued ops
//!        └── update head: CAS
//! ```
//!
//! # Wasm compatibility
//!
//! `studge-core` builds for `wasm32-unknown-unknown` (the browser extension).
//! There is therefore **no** async runtime dependency in this module; every
//! method is synchronous/blocking.  Callers that need async (Tauri, CLI) wrap
//! the engine in `tokio::task::spawn_blocking` or an equivalent.
//!
//! `HttpRelayTransport` is the one exception: it uses `reqwest` and is gated
//! behind `cfg(not(target_arch = "wasm32"))` so the wasm build never sees it.

pub mod engine;
pub mod folder;
pub mod memory;
pub mod transport;

#[cfg(not(target_arch = "wasm32"))]
pub mod http;

pub use engine::SyncEngine;
pub use folder::FolderTransport;
pub use memory::MemoryTransport;
pub use transport::{SyncError, Transport, VaultOps};

#[cfg(not(target_arch = "wasm32"))]
pub use http::HttpRelayTransport;
