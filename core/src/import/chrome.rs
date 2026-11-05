//! Chrome / Google Password Manager CSV import.
//!
//! Header: `name,url,username,password[,note]`. Chrome has no match rule, so
//! every URL becomes an exact-host rule and the user can widen it later.

use crate::error::{CoreError, CoreResult};
use crate::import::csv_reader;
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::UrlMatch;

/// Imports a Chrome password CSV.
pub fn import(text: &str) -> CoreResult<ImportOutcome> {
    check_input_size(text.as_bytes())?;
    let rows = csv_reader::parse(text)?;
    let header = rows.first().ok_or(CoreError::InvalidImport)?;
    let find = |names: &[&str]| -> Option<usize> {
        header.iter().position(|cell| {
            let cell = cell.trim();
            names.iter().any(|name| cell.eq_ignore_ascii_case(name))
        })
    };
    let name = find(&["name"]).ok_or(CoreError::InvalidImport)?;
    let url = find(&["url"]).ok_or(CoreError::InvalidImport)?;
    let username = find(&["username"]).ok_or(CoreError::InvalidImport)?;
    let password = find(&["password"]).ok_or(CoreError::InvalidImport)?;
    let note = find(&["note", "notes"]);
    if rows.len().saturating_sub(1) > MAX_IMPORT_ITEMS {
        return Err(CoreError::TooManyEntries);
    }

    let mut outcome = ImportOutcome::default();
    for (offset, row) in rows.iter().skip(1).enumerate() {
        let index = offset + 1;
        let title = cell(row, Some(name));
        if title.is_empty() {
            outcome.skip(index, SkipReason::MissingTitle);
            continue;
        }
        let mut parsed = ParsedItem::login(title);
        parsed.set("username", cell(row, Some(username)));
        parsed.set("password", cell(row, Some(password)));
        if let Some(url) = crate::import::normalise_url(cell(row, Some(url))) {
            parsed.urls.push((url, UrlMatch::ExactHost));
        }
        if let Some(note) = note {
            parsed.set("notes", cell(row, Some(note)));
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

    const CSV: &str = include_str!("../../tests/fixtures/import/chrome.csv");

    #[test]
    fn imports_chrome_rows() {
        let outcome = import(CSV).expect("import");
        assert_eq!(outcome.report.imported, 2);
        assert_eq!(outcome.items[0].fields[0].1, "demo.example");
        assert_eq!(outcome.items[0].urls[0].0, "https://demo.example/login");
        assert_eq!(outcome.items[1].fields[0].1, "Demo Mail");
    }

    #[test]
    fn a_missing_column_is_rejected() {
        assert!(import("name,url\nA,https://a.test\n").is_err());
    }

    #[test]
    fn an_untitled_row_is_skipped() {
        let outcome = import("name,url,username,password\n,https://a.test,u,p\n").expect("import");
        assert_eq!(outcome.report.imported, 0);
        assert_eq!(outcome.report.skipped[0].reason, SkipReason::MissingTitle);
    }
}
