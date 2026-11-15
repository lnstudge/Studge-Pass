//! Concrete `Transport` implementations for Studge Pass.
//!
//! This crate provides two native (non-wasm) transports:
//! - [`FolderTransport`]: syncs a vault through a local directory (e.g. a
//!   Dropbox / iCloud folder).
//! - [`HttpRelayTransport`]: talks to a `studge-relay` instance over HTTPS.
//!
//! The `studge-core` crate only contains the `Transport` trait and the engine.
//! These implementations are kept here so that `studge-core` builds for
//! `wasm32-unknown-unknown` without dragging in `reqwest` or `std::fs`.
//!
//! # Design
//!
//! Both types implement `studge_core::sync::transport::Transport`.  Callers
//! hold them as `Box<dyn Transport>` or as concrete types when they know which
//! backend they need.

#![forbid(unsafe_code)]

pub mod folder;
pub mod http;

pub use folder::FolderTransport;
pub use http::HttpRelayTransport;
