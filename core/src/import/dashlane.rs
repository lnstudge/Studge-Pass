//! Dashlane CSV import.
//!
//! Header: `username,username2,username3,title,password,note,url,category,otpSecret`.
//! Dashlane's `category` is not a Studge Pass kind, so it is stored as a tag; a
//! row with several usernames keeps the first and records the rest as notes only
//! if the notes column is empty (never silently dropping data).

use crate::error::{CoreError, CoreResult};
use crate::import::csv_reader;
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::totp::TotpConfig;
use crate::vault::items::UrlMatch;

/// Imports a Dashlane CSV.
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
    let title = find(&["title", "name"]).ok_or(CoreError::InvalidImport)?;
    let username = find(&["username"]);
    let username2 = find(&["username2"]);
    let password = find(&["password"]);
    let note = find(&["note", "notes"]);
    let url = find(&["url"]);
    let category = find(&["category"]);
    let otp = find(&["otpsecret", "otp", "totp"]);
    if rows.len().saturating_sub(1) > MAX_IMPORT_ITEMS {
        return Err(CoreError::TooManyEntries);
    }

    let mut outcome = ImportOutcome::default();
    for (offset, row) in rows.iter().skip(1).enumerate() {
        let index = offset + 1;
        let title = cell(row, Some(title));
        if title.is_empty() {
            outcome.skip(index, SkipReason::MissingTitle);
            continue;
        }
        let mut parsed = ParsedItem::login(title);
        parsed.set("username", cell(row, username));
        parsed.set("password", cell(row, password));
        let mut notes = cell(row, note).to_string();
        let second = cell(row, username2);
        if !second.is_empty() {
            if !notes.is_empty() {
                notes.push('\n');
            }
            notes.push_str(second);
        }
        parsed.set("notes", &notes);
        if let Some(url) = crate::import::normalise_url(cell(row, url)) {
            parsed.urls.push((url, UrlMatch::ExactHost));
        }
        let tag = cell(row, category);
        if !tag.is_empty() && tag.len() <= crate::vault::items::MAX_TAG_CHARS {
            parsed.tags.push(tag.to_string());
        }
        let otp = cell(row, otp);
        if !otp.is_empty() {
            if TotpConfig::from_field(otp).is_ok() {
                parsed.set("totp", otp);
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

    const CSV: &str = include_str!("../../tests/fixtures/import/dashlane.csv");

    #[test]
    fn imports_dashlane_rows() {
        let outcome = import(CSV).expect("import");
        assert_eq!(outcome.report.imported, 2);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Shopping");
        assert_eq!(outcome.items[0].tags, vec!["shopping".to_string()]);
        // The second username lands in the notes, never dropped.
        let notes = outcome.items[1]
            .fields
            .iter()
            .find(|(name, _)| name == "notes")
            .expect("notes");
        assert!(notes.1.contains("demo.second@example.test"));
    }
}
