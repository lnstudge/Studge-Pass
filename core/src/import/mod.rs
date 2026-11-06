//! Import from other password managers (task item 5).
//!
//! Every importer parses bytes into [`ParsedItem`]s and returns an
//! [`ImportReport`] that counts what was imported and why anything was skipped.
//! Two rules hold throughout:
//!
//! - **No item content ever leaves this module.** Skip reasons are an enum, never
//!   a message built from the file, and nothing here logs, prints or formats a
//!   title, a password or a URL.
//! - **Nothing is guessed.** A value that does not map onto an item template
//!   field is skipped with a reason, not invented into a field name (R-0114).
//!
//! Fixtures in `core/tests/fixtures/import/` are entirely fake.

pub mod apple;
pub mod bitwarden;
pub mod chrome;
pub mod csv_reader;
pub mod dashlane;
pub mod generic;
pub mod keepass;
pub mod onepassword;
pub mod proton;

use crate::crypto::signing::Timestamp;
use crate::error::{CoreError, CoreResult};
use crate::vault::items::{Item, ItemId, ItemKind, UrlMatch, VaultId};

/// Refuse an import file larger than this.
pub const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;
/// Refuse an import with more items than this.
pub const MAX_IMPORT_ITEMS: usize = 100_000;

/// Why one entry was not imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The source type has no Studge Pass equivalent.
    UnsupportedType,
    /// No title, and an untitled item is not worth creating.
    MissingTitle,
    /// A value that cannot be mapped safely.
    InvalidValue,
    /// The entry exceeded a size or count limit.
    TooLarge,
    /// The entry was empty.
    Empty,
}

/// One skipped entry: where it was, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Skipped {
    /// The 0-based position in the source file (row or array index).
    pub index: usize,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// The result of an import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// How many items were produced.
    pub imported: usize,
    /// How many were skipped, and why.
    pub skipped: Vec<Skipped>,
}

impl ImportReport {
    /// Records one skip.
    pub fn skip(&mut self, index: usize, reason: SkipReason) {
        self.skipped.push(Skipped { index, reason });
    }

    /// Number of skipped entries.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// A one-line, content-free summary (safe to log).
    pub fn summary(&self) -> String {
        format!("imported {}, skipped {}", self.imported, self.skipped.len())
    }
}

/// An item parsed from a foreign file, before it is bound to a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedItem {
    /// The Studge Pass kind it maps to.
    pub kind: ItemKind,
    /// Scalar template fields, already validated against the template.
    pub fields: Vec<(String, String)>,
    /// URLs and their match rules.
    pub urls: Vec<(String, UrlMatch)>,
    /// User-labelled custom fields (login only).
    pub custom: Vec<(String, String, bool)>,
    /// Tags.
    pub tags: Vec<String>,
    /// Favourite flag.
    pub favourite: bool,
}

impl ParsedItem {
    /// An empty login with a title.
    pub fn login(title: &str) -> Self {
        Self {
            kind: ItemKind::Login,
            fields: vec![("title".to_string(), title.to_string())],
            urls: Vec::new(),
            custom: Vec::new(),
            tags: Vec::new(),
            favourite: false,
        }
    }

    /// Sets a scalar field; later calls replace earlier ones.
    pub fn set(&mut self, name: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        if let Some(entry) = self.fields.iter_mut().find(|(key, _)| key == name) {
            entry.1 = value.to_string();
        } else {
            self.fields.push((name.to_string(), value.to_string()));
        }
    }

    /// Builds a real [`Item`] bound to a vault and id.
    pub fn into_item(self, vault_id: VaultId, id: ItemId, now: &Timestamp) -> CoreResult<Item> {
        let mut item = Item::new(id, vault_id, self.kind, now.clone())?;
        for (name, value) in &self.fields {
            if name == "title" {
                item.set_field("title", value, now)?;
            }
        }
        for (name, value) in &self.fields {
            if name == "title" {
                continue;
            }
            item.set_field(name, value, now)?;
        }
        for (url, rule) in &self.urls {
            item.add_url(url, *rule, now)?;
        }
        for (label, value, hidden) in &self.custom {
            item.add_custom(label, value, *hidden, now)?;
        }
        if !self.tags.is_empty() {
            item.set_tags(self.tags.clone(), now)?;
        }
        if self.favourite {
            item.set_favourite(true, now);
        }
        Ok(item)
    }

    /// A field value, if set.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Whether the parsed item has a title worth keeping.
    pub fn has_title(&self) -> bool {
        self.fields
            .iter()
            .any(|(name, value)| name == "title" && !value.trim().is_empty())
    }
}

/// Result of an importer: the items and the report.
#[derive(Debug, Clone, Default)]
pub struct ImportOutcome {
    /// The parsed items, in source order.
    pub items: Vec<ParsedItem>,
    /// Counts and skip reasons.
    pub report: ImportReport,
}

impl ImportOutcome {
    /// Records a successfully parsed item.
    pub fn push(&mut self, item: ParsedItem) {
        self.items.push(item);
        self.report.imported = self.items.len();
    }

    /// Records a skip.
    pub fn skip(&mut self, index: usize, reason: SkipReason) {
        self.report.skip(index, reason);
    }
}

/// Rejects an input before parsing (size guard).
pub fn check_input_size(bytes: &[u8]) -> CoreResult<()> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(CoreError::TooManyEntries);
    }
    Ok(())
}

/// Maps a common URL or leaves it out. A URL without a scheme gets `https://`
/// only when it looks like a host; anything else is dropped rather than guessed.
pub fn normalise_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains("://") {
        // Some other scheme (otpauth, ftp, javascript…) is not a login URL.
        return None;
    } else if trimmed.contains('.') && !trimmed.contains(' ') {
        format!("https://{trimmed}")
    } else {
        return None;
    };
    if candidate.len() > crate::vault::items::MAX_URL_CHARS {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> Timestamp {
        Timestamp::parse("2026-11-05T10:00:00Z").expect("timestamp")
    }

    #[test]
    fn parsed_items_become_real_items() {
        let mut parsed = ParsedItem::login("Demo Only");
        parsed.set("username", "demo");
        parsed.set("password", "demo-password");
        parsed.set("notes", "line one");
        parsed
            .urls
            .push(("https://demo.example".into(), UrlMatch::ExactHost));
        parsed.custom.push(("PIN".into(), "1234".into(), true));
        parsed.tags.push("demo".into());
        parsed.favourite = true;

        let item = parsed
            .into_item([0x22; 16], [0x33; 16], &at())
            .expect("item");
        assert_eq!(item.field("title"), Some("Demo Only"));
        assert_eq!(item.field("password"), Some("demo-password"));
        assert_eq!(item.urls().len(), 1);
        assert_eq!(item.custom().len(), 1);
        assert!(item.favourite());
    }

    #[test]
    fn an_unknown_field_is_an_error_not_a_silent_drop() {
        let mut parsed = ParsedItem::login("Demo Only");
        parsed.set("passwort", "typo");
        assert_eq!(
            parsed
                .into_item([0x22; 16], [0x33; 16], &at())
                .expect_err("unknown field"),
            CoreError::UnknownField
        );
    }

    #[test]
    fn urls_are_normalised_conservatively() {
        assert_eq!(
            normalise_url("demo.example").as_deref(),
            Some("https://demo.example")
        );
        assert_eq!(
            normalise_url("http://demo.example/x").as_deref(),
            Some("http://demo.example/x")
        );
        for bad in [
            "",
            "   ",
            "javascript:alert(1)",
            "ftp://x.test",
            "not a url",
        ] {
            assert_eq!(normalise_url(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_report_never_carries_content() {
        let mut report = ImportReport::default();
        report.skip(3, SkipReason::UnsupportedType);
        assert_eq!(report.summary(), "imported 0, skipped 1");
        assert_eq!(report.skipped[0].index, 3);
    }
}
