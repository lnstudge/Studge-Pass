//! Apple Passwords CSV import.
//!
//! Header: `Title,URL,Username,Password,Notes[,OTPAuth]`. The TOTP column holds
//! an `otpauth://` URI, which is stored as-is in the login's `totp` field after
//! a parse check — a broken URI is skipped rather than stored.

use crate::error::{CoreError, CoreResult};
use crate::import::csv_reader;
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::totp::TotpConfig;
use crate::vault::items::UrlMatch;

/// Imports an Apple Passwords CSV.
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
    let url = find(&["url"]);
    let username = find(&["username"]);
    let password = find(&["password"]);
    let notes = find(&["notes", "note"]);
    let totp = find(&["otpauth", "otp", "totp"]);
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
        parsed.set("notes", cell(row, notes));
        if let Some(url) = crate::import::normalise_url(cell(row, url)) {
            parsed.urls.push((url, UrlMatch::ExactHost));
        }
        let otp = cell(row, totp);
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

    const CSV: &str = include_str!("../../tests/fixtures/import/apple.csv");

    #[test]
    fn imports_apple_rows_with_otp() {
        let outcome = import(CSV).expect("import");
        assert_eq!(outcome.report.imported, 2);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Bank");
        assert_eq!(outcome.items[0].fields[1].0, "username");
        let totp = outcome.items[0]
            .fields
            .iter()
            .find(|(name, _)| name == "totp")
            .expect("totp");
        assert!(totp.1.starts_with("otpauth://totp/"));
    }

    #[test]
    fn a_broken_otp_skips_the_row_instead_of_storing_it() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\nDemo,https://a.test,u,p,,otpauth://totp/x?secret=!!!!\n";
        let outcome = import(csv).expect("import");
        assert_eq!(outcome.report.imported, 0);
        assert_eq!(outcome.report.skipped[0].reason, SkipReason::InvalidValue);
    }

    #[test]
    fn a_missing_title_column_is_rejected() {
        assert!(import("URL,Username\nhttps://a.test,u\n").is_err());
    }
}
