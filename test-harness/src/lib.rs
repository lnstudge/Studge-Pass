#![forbid(unsafe_code)]

//! The evil relay and adversarial integration tests (Phase 5+).
//!
//! This crate is deliberately hostile: it implements relays that lie, reorder,
//! replay and truncate, so the sync engine's checks are exercised against an
//! attacker, not a friend.
