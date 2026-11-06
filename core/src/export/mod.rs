//! Export: the encrypted `.studgevault` backup and the plaintext formats.
//!
//! Two rules hold across every exporter here:
//!
//! - the encrypted backup never decrypts anything, so it adds no attack surface;
//! - every plaintext format requires `allow_plaintext: true`, and refuses with
//!   [`crate::error::CoreError::PlaintextNotAllowed`] otherwise. A caller cannot
//!   leak a vault by forgetting a warning: they have to name the choice.

pub mod backup;
pub mod csv;
pub mod json;
pub mod keepass;

pub use backup::{BackupFile, VaultArchive, BACKUP_VERSION, MAGIC};
pub use csv::{export_csv, HEADER as CSV_HEADER};
pub use json::{export_json, FORMAT as JSON_FORMAT};
pub use keepass::export_keepass;
