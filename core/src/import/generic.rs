//! Generic CSV import with an explicit column mapping.
//!
//! For files that have no standard shape. The caller says which column is which
//! (by index, or by name through [`ColumnMapping::from_header`]) and every other
//! column is ignored — nothing is guessed from the data.

use crate::error::{CoreError, CoreResult};
use crate::import::csv_reader;
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::UrlMatch;

/// Which column holds what. `None` means "this file has no such column".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ColumnMapping {
    /// Title column.
    pub title: Option<usize>,
    /// Username column.
    pub username: Option<usize>,
    /// Password column.
    pub password: Option<usize>,
    /// URL column.
    pub url: Option<usize>,
    /// Notes column.
    pub notes: Option<usize>,
    /// TOTP column (base32 secret or `otpauth://` URI).
    pub totp: Option<usize>,
}

impl ColumnMapping {
    /// Guesses the mapping from a header row, matching the usual names.
    pub fn from_header(header: &[String]) -> Self {
        let find = |names: &[&str]| -> Option<usize> {
            header.iter().position(|cell| {
                let cell = cell.trim();
                names.iter().any(|name| cell.eq_ignore_ascii_case(name))
            })
        };
        Self {
            title: find(&["title", "name", "account"]),
            username: find(&["username", "user", "login", "email"]),
            password: find(&["password", "pass", "secret"]),
            url: find(&["url", "urls", "website", "site", "uri"]),
            notes: find(&["notes", "note", "comment"]),
            totp: find(&["totp", "otp", "otpauth", "otpsecret"]),
        }
    }
}

/// Imports a CSV with an explicit column mapping. Row 0 is the header and is
/// skipped; the mapping refers to absolute column indexes.
pub fn import(text: &str, mapping: &ColumnMapping) -> CoreResult<ImportOutcome> {
    check_input_size(text.as_bytes())?;
    if mapping.title.is_none() {
        return Err(CoreError::InvalidImport);
    }
    let rows = csv_reader::parse(text)?;
    if rows.is_empty() {
        return Err(CoreError::InvalidImport);
    }
    if rows.len().saturating_sub(1) > MAX_IMPORT_ITEMS {
        return Err(CoreError::TooManyEntries);
    }

    let mut outcome = ImportOutcome::default();
    for (offset, row) in rows.iter().skip(1).enumerate() {
        let index = offset + 1;
        let title = cell(row, mapping.title);
        if title.is_empty() {
            outcome.skip(index, SkipReason::MissingTitle);
            continue;
        }
        let mut parsed = ParsedItem::login(title);
        parsed.set("username", cell(row, mapping.username));
        parsed.set("password", cell(row, mapping.password));
        parsed.set("notes", cell(row, mapping.notes));
        if let Some(url) = crate::import::normalise_url(cell(row, mapping.url)) {
            parsed.urls.push((url, UrlMatch::ExactHost));
        }
        let totp = cell(row, mapping.totp);
        if !totp.is_empty() {
            if crate::totp::TotpConfig::from_field(totp).is_ok() {
                parsed.set("totp", totp);
            } else {
                outcome.skip(index, SkipReason::InvalidValue);
                continue;
            }
        }
        outcome.push(parsed);
    }
    Ok(outcome)
}

fn cell(row: &[String], index: Option<usize>) -> &str {
    index
        .and_then(|index| row.get(index))
        .map(|value| value.trim())
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSV: &str = "Site Login,Account,Note,Secret\nDemo One,demo@example.test,first,demo-password\nDemo Two,demo2@example.test,second,demo-password-2\n";

    #[test]
    fn imports_with_an_explicit_mapping() {
        let mapping = ColumnMapping {
            title: Some(0),
            username: Some(1),
            notes: Some(2),
            password: Some(3),
            ..ColumnMapping::default()
        };
        let outcome = import(CSV, &mapping).expect("import");
        assert_eq!(outcome.report.imported, 2);
        assert_eq!(outcome.items[0].fields[0].1, "Demo One");
        assert_eq!(outcome.items[0].fields.len(), 4);
    }

    #[test]
    fn header_detection_finds_the_usual_names() {
        let header: Vec<String> = ["Title", "Username", "Password", "URL", "Notes", "TOTP"]
            .iter()
            .map(|value| value.to_string())
            .collect();
        let mapping = ColumnMapping::from_header(&header);
        assert_eq!(mapping.title, Some(0));
        assert_eq!(mapping.username, Some(1));
        assert_eq!(mapping.password, Some(2));
        assert_eq!(mapping.url, Some(3));
        assert_eq!(mapping.notes, Some(4));
        assert_eq!(mapping.totp, Some(5));
    }

    #[test]
    fn a_mapping_without_a_title_is_rejected() {
        let mapping = ColumnMapping {
            password: Some(1),
            ..ColumnMapping::default()
        };
        assert_eq!(
            import(CSV, &mapping).expect_err("no title"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn columns_beyond_the_row_are_empty_not_a_panic() {
        let mapping = ColumnMapping {
            title: Some(0),
            password: Some(9),
            ..ColumnMapping::default()
        };
        let outcome = import(CSV, &mapping).expect("import");
        assert_eq!(outcome.report.imported, 2);
    }
}
