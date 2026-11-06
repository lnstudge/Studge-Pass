//! 1Password import from the `export.data` JSON inside a `.1pux` archive
//! (D-0304).
//!
//! A `.1pux` file is a ZIP whose only interesting member is `export.data`. Core
//! has no ZIP reader on purpose, so the CLI and the desktop app open the archive
//! with platform tooling and hand this module the member's bytes; a direct
//! `.1pux` upload is rejected with a clear error.
//!
//! Categories recognised: login, password, secure note, credit card, identity.
//! Anything else is skipped with a reason, never mapped to a guess.

use crate::error::{CoreError, CoreResult};
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::{ItemKind, UrlMatch};
use serde_json::Value;

/// Imports the `export.data` member of a 1PUX archive.
pub fn import(bytes: &[u8]) -> CoreResult<ImportOutcome> {
    check_input_size(bytes)?;
    // A raw ZIP starts with "PK\x03\x04"; say so instead of failing on JSON.
    if bytes.starts_with(b"PK\x03\x04") {
        return Err(CoreError::InvalidImport);
    }
    let document: Value = serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidImport)?;
    let accounts = document
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or(CoreError::InvalidImport)?;

    let mut outcome = ImportOutcome::default();
    let mut index = 0usize;
    for account in accounts {
        let Some(items) = account.get("items").and_then(Value::as_array) else {
            continue;
        };
        if items.len() > MAX_IMPORT_ITEMS {
            return Err(CoreError::TooManyEntries);
        }
        for item in items {
            index += 1;
            match parse_item(item) {
                Ok(Some(parsed)) => outcome.push(parsed),
                Ok(None) => outcome.skip(index, SkipReason::Empty),
                Err(reason) => outcome.skip(index, reason),
            }
        }
    }
    Ok(outcome)
}

fn parse_item(item: &Value) -> Result<Option<ParsedItem>, SkipReason> {
    let title = item
        .get("overview")
        .and_then(|overview| overview.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if title.is_empty() {
        return Err(SkipReason::MissingTitle);
    }
    let category = text_of(item.get("categoryUuid")).unwrap_or_default();
    let details = item.get("details");

    let mut parsed = match category {
        // 001 login, 005 password
        "001" | "005" => {
            let mut parsed = ParsedItem::login(&title);
            if let Some(details) = details {
                for field in login_fields(details) {
                    let designation = text_of(field.get("designation")).unwrap_or_default();
                    let value = text_of(field.get("value")).unwrap_or_default();
                    match designation {
                        "username" => parsed.set("username", value),
                        "password" => parsed.set("password", value),
                        "totp" => parsed.set("totp", value),
                        _ => {}
                    }
                }
                parsed.set(
                    "notes",
                    text_of(details.get("notesPlain")).unwrap_or_default(),
                );
            }
            if let Some(urls) = item
                .get("overview")
                .and_then(|overview| overview.get("urls"))
                .and_then(Value::as_array)
            {
                for entry in urls {
                    if let Some(url) =
                        crate::import::normalise_url(text_of(entry.get("url")).unwrap_or_default())
                    {
                        parsed.urls.push((url, UrlMatch::ExactHost));
                    }
                }
            }
            parsed
        }
        // 003 secure note
        "003" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::SecureNote,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(details) = details {
                parsed.set(
                    "notes",
                    text_of(details.get("notesPlain")).unwrap_or_default(),
                );
            }
            parsed
        }
        // 002 credit card
        "002" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Card,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(details) = details {
                for section in sections(details) {
                    for field in section_fields(section) {
                        let name = text_of(field.get("name")).unwrap_or_default();
                        let value = text_of(field.get("value")).unwrap_or_default();
                        let target = match name.to_ascii_lowercase().as_str() {
                            "cardholder name" | "cardholder" => "cardholder",
                            "number" | "card number" => "number",
                            "expiry date" | "expiry" => "expiry_month",
                            "verification number" | "cvv" | "cvc" => "cvv",
                            _ => continue,
                        };
                        parsed.set(target, value);
                    }
                }
            }
            parsed
        }
        // 004 identity
        "004" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Identity,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(details) = details {
                for section in sections(details) {
                    for field in section_fields(section) {
                        let name = text_of(field.get("name")).unwrap_or_default();
                        let value = text_of(field.get("value")).unwrap_or_default();
                        let target = match name.to_ascii_lowercase().as_str() {
                            "first name" => "first_name",
                            "last name" => "last_name",
                            "email" => "email",
                            "phone" => "phone",
                            "address" => "address",
                            "birth date" | "date of birth" => "dob",
                            _ => continue,
                        };
                        parsed.set(target, value);
                    }
                }
            }
            parsed
        }
        _ => return Err(SkipReason::UnsupportedType),
    };

    if let Some(tags) = item
        .get("overview")
        .and_then(|overview| overview.get("tags"))
        .and_then(Value::as_array)
    {
        for tag in tags {
            if let Some(tag) = tag.as_str() {
                if !tag.is_empty() && tag.len() <= crate::vault::items::MAX_TAG_CHARS {
                    parsed.tags.push(tag.to_string());
                }
            }
        }
    }
    Ok(Some(parsed))
}

fn login_fields(details: &Value) -> Vec<&Value> {
    details
        .get("loginFields")
        .and_then(Value::as_array)
        .map(|fields| fields.iter().collect())
        .unwrap_or_default()
}

fn sections(details: &Value) -> Vec<&Value> {
    details
        .get("sections")
        .and_then(Value::as_array)
        .map(|sections| sections.iter().collect())
        .unwrap_or_default()
}

fn section_fields(section: &Value) -> Vec<&Value> {
    section
        .get("fields")
        .and_then(Value::as_array)
        .map(|fields| fields.iter().collect())
        .unwrap_or_default()
}

fn text_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = include_str!("../../tests/fixtures/import/onepassword.data.json");

    #[test]
    fn imports_the_recognised_categories() {
        let outcome = import(DATA.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 3);
        assert_eq!(outcome.items[0].kind, ItemKind::Login);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Login");
        assert_eq!(outcome.items[1].kind, ItemKind::SecureNote);
        assert_eq!(outcome.items[2].kind, ItemKind::Card);
    }

    #[test]
    fn a_zip_archive_gets_a_clear_error() {
        assert_eq!(
            import(b"PK\x03\x04rest").expect_err("zip"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn an_unsupported_category_is_skipped() {
        let data =
            br#"{"accounts":[{"items":[{"categoryUuid":"999","overview":{"title":"Demo"}}]}]}"#;
        let outcome = import(data).expect("import");
        assert_eq!(outcome.report.imported, 0);
        assert_eq!(
            outcome.report.skipped[0].reason,
            SkipReason::UnsupportedType
        );
    }

    #[test]
    fn a_missing_title_is_skipped() {
        let data = br#"{"accounts":[{"items":[{"categoryUuid":"001","overview":{}}]}]}"#;
        let outcome = import(data).expect("import");
        assert_eq!(outcome.report.skipped[0].reason, SkipReason::MissingTitle);
    }
}
