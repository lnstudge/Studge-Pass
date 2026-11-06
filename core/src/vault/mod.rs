//! The vault data model: items, their templates and their invariants.
//!
//! An item is plaintext only while the vault is unlocked. On disk and on the
//! relay it exists solely as an authenticated op payload (SPEC §5.5, §6.1).
//! Nothing in this module does I/O or encryption; it is a pure data model with
//! strict constructors, so the op log can treat "an Item" as a trusted value.

pub mod items;
pub mod templates;

pub use items::{CustomField, HistoryEntry, Item, ItemId, ItemKind, UrlEntry, UrlMatch, VaultId};
pub use templates::{field_spec, template, FieldSpec, Template};
