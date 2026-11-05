//! Bitwarden import: the JSON vault export and the CSV export.
//!
//! Bitwarden's export carries enough structure to map cleanly onto Studge Pass
//! items: `type` selects the kind, `login.uris[].match` maps onto our three URL
//! rules, and `fields` become custom fields on a login (the only kind that has
//! them). Anything else is skipped with a reason.

use crate::error::{CoreError, CoreResult};
use crate::import::csv_reader;
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::{ItemKind, UrlMatch};
use serde_json::Value;

/// Imports a Bitwarden JSON export (`/data/export` or the desktop export).
pub fn import_json(bytes: &[u8]) -> CoreResult<ImportOutcome> {
    check_input_size(bytes)?;
    let document: Value = serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidImport)?;
    let items = document
        .get("items")
        .and_then(Value::as_array)
        .ok_or(CoreError::InvalidImport)?;
    if items.len() > MAX_IMPORT_ITEMS {
        return Err(CoreError::TooManyEntries);
    }

    let mut outcome = ImportOutcome::default();
    for (index, item) in items.iter().enumerate() {
        match parse_json_item(item) {
            Ok(Some(parsed)) => outcome.push(parsed),
            Ok(None) => outcome.skip(index, SkipReason::Empty),
            Err(reason) => outcome.skip(index, reason),
        }
    }
    Ok(outcome)
}

fn parse_json_item(item: &Value) -> Result<Option<ParsedItem>, SkipReason> {
    let kind = item.get("type").and_then(Value::as_u64);
    let name = text_of(item.get("name")).unwrap_or_default();
    if name.trim().is_empty() {
        return Err(SkipReason::MissingTitle);
    }
    let favourite = item
        .get("favorite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let notes = text_of(item.get("notes")).unwrap_or_default();

    let mut parsed = match kind {
        Some(1) => {
            let mut parsed = ParsedItem::login(name);
            if let Some(login) = item.get("login") {
                parsed.set(
                    "username",
                    text_of(login.get("username")).unwrap_or_default(),
                );
                parsed.set(
                    "password",
                    text_of(login.get("password")).unwrap_or_default(),
                );
                parsed.set("totp", text_of(login.get("totp")).unwrap_or_default());
                if let Some(uris) = login.get("uris").and_then(Value::as_array) {
                    for entry in uris {
                        let raw = text_of(entry.get("uri")).unwrap_or_default();
                        let rule = match entry.get("match").and_then(Value::as_u64) {
                            Some(0) => UrlMatch::BaseDomain,
                            Some(2) => UrlMatch::StartsWith,
                            // 1 = host, 3 = exact, 4 = regex (unsupported: we
                            // fall back to the exact host, never to a pattern).
                            _ => UrlMatch::ExactHost,
                        };
                        if let Some(url) = crate::import::normalise_url(raw) {
                            parsed.urls.push((url, rule));
                        }
                    }
                }
                // Older exports only have a single `uri`.
                if parsed.urls.is_empty() {
                    if let Some(url) =
                        crate::import::normalise_url(text_of(login.get("uri")).unwrap_or_default())
                    {
                        parsed.urls.push((url, UrlMatch::ExactHost));
                    }
                }
            }
            parsed
        }
        Some(2) => {
            let mut parsed = ParsedItem {
                kind: ItemKind::SecureNote,
                fields: vec![("title".to_string(), name.to_string())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite,
            };
            parsed.set("notes", notes);
            parsed
        }
        Some(3) => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Card,
                fields: vec![("title".to_string(), name.to_string())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite,
            };
            if let Some(card) = item.get("card") {
                parsed.set(
                    "cardholder",
                    text_of(card.get("cardholderName")).unwrap_or_default(),
                );
                parsed.set("number", text_of(card.get("number")).unwrap_or_default());
                parsed.set(
                    "expiry_month",
                    text_of(card.get("expMonth")).unwrap_or_default(),
                );
                parsed.set(
                    "expiry_year",
                    text_of(card.get("expYear")).unwrap_or_default(),
                );
                parsed.set("cvv", text_of(card.get("code")).unwrap_or_default());
            }
            parsed.set("notes", notes);
            parsed
        }
        Some(4) => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Identity,
                fields: vec![("title".to_string(), name.to_string())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite,
            };
            if let Some(identity) = item.get("identity") {
                let first = text_of(identity.get("firstName")).unwrap_or_default();
                let last = text_of(identity.get("lastName")).unwrap_or_default();
                parsed.set("first_name", first);
                parsed.set("last_name", last);
                parsed.set("full_name", format!("{first} {last}").trim());
                parsed.set("email", text_of(identity.get("email")).unwrap_or_default());
                parsed.set("phone", text_of(identity.get("phone")).unwrap_or_default());
                parsed.set(
                    "address",
                    text_of(identity.get("address1")).unwrap_or_default(),
                );
            }
            parsed.set("notes", notes);
            parsed
        }
        _ => return Err(SkipReason::UnsupportedType),
    };

    if parsed.kind == ItemKind::Login {
        parsed.set("notes", notes);
        if let Some(fields) = item.get("fields").and_then(Value::as_array) {
            for field in fields {
                let label = text_of(field.get("name")).unwrap_or_default();
                let value = text_of(field.get("value")).unwrap_or_default();
                if label.is_empty() || value.is_empty() {
                    continue;
                }
                if parsed.custom.len() >= crate::vault::items::MAX_CUSTOM_FIELDS {
                    return Err(SkipReason::TooLarge);
                }
                // Bitwarden type 1 is "hidden".
                let hidden = field.get("type").and_then(Value::as_u64) == Some(1);
                parsed
                    .custom
                    .push((label.to_string(), value.to_string(), hidden));
            }
        }
    }
    if parsed.fields.len() <= 1
        && parsed.custom.is_empty()
        && parsed.urls.is_empty()
        && notes.is_empty()
    {
        // A title-only entry is legal (an empty login), so keep it: the user
        // asked for everything to come across.
        return Ok(Some(parsed));
    }
    Ok(Some(parsed))
}

/// Imports a Bitwarden CSV export.
pub fn import_csv(text: &str) -> CoreResult<ImportOutcome> {
    check_input_size(text.as_bytes())?;
    let rows = csv_reader::parse(text)?;
    let header = rows.first().ok_or(CoreError::InvalidImport)?;
    let columns = Columns::detect(header)?;
    if rows.len().saturating_sub(1) > MAX_IMPORT_ITEMS {
        return Err(CoreError::TooManyEntries);
    }

    let mut outcome = ImportOutcome::default();
    for (offset, row) in rows.iter().skip(1).enumerate() {
        let index = offset + 1;
        let title = columns.get(row, Some(columns.title)).unwrap_or_default();
        if title.trim().is_empty() {
            outcome.skip(index, SkipReason::MissingTitle);
            continue;
        }
        let kind = match columns.get(row, columns.kind) {
            Some("login") | Some("1") | None => ItemKind::Login,
            Some("secureNote") | Some("secure_note") | Some("2") => ItemKind::SecureNote,
            Some("card") | Some("3") => ItemKind::Card,
            Some("identity") | Some("4") => ItemKind::Identity,
            Some(_) => {
                outcome.skip(index, SkipReason::UnsupportedType);
                continue;
            }
        };

        let mut parsed = match kind {
            ItemKind::Login => {
                let mut parsed = ParsedItem::login(title);
                parsed.set(
                    "username",
                    columns.get(row, columns.username).unwrap_or_default(),
                );
                parsed.set(
                    "password",
                    columns.get(row, columns.password).unwrap_or_default(),
                );
                parsed.set("totp", columns.get(row, columns.totp).unwrap_or_default());
                if let Some(url) =
                    crate::import::normalise_url(columns.get(row, columns.url).unwrap_or_default())
                {
                    parsed.urls.push((url, UrlMatch::ExactHost));
                }
                parsed
            }
            other => ParsedItem {
                kind: other,
                fields: vec![("title".to_string(), title.to_string())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            },
        };
        parsed.set("notes", columns.get(row, columns.notes).unwrap_or_default());
        outcome.push(parsed);
    }
    Ok(outcome)
}

struct Columns {
    kind: Option<usize>,
    title: usize,
    username: Option<usize>,
    password: Option<usize>,
    url: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
}

impl Columns {
    fn detect(header: &[String]) -> CoreResult<Self> {
        let find = |name: &str| -> Option<usize> {
            header
                .iter()
                .position(|cell| cell.trim().eq_ignore_ascii_case(name))
        };
        let title = find("name")
            .or_else(|| find("title"))
            .ok_or(CoreError::InvalidImport)?;
        Ok(Self {
            kind: find("type"),
            title,
            username: find("login_username").or_else(|| find("username")),
            password: find("login_password").or_else(|| find("password")),
            url: find("login_uri").or_else(|| find("url")),
            notes: find("notes").or_else(|| find("note")),
            totp: find("login_totp").or_else(|| find("totp")),
        })
    }

    fn get<'a>(&self, row: &'a [String], column: Option<usize>) -> Option<&'a str> {
        column
            .and_then(|index| row.get(index))
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    }
}

fn text_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JSON: &str = include_str!("../../tests/fixtures/import/bitwarden.json");
    const CSV: &str = include_str!("../../tests/fixtures/import/bitwarden.csv");

    #[test]
    fn imports_every_bitwarden_kind() {
        let outcome = import_json(JSON.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 4);
        assert_eq!(outcome.report.skipped_count(), 1);
        assert_eq!(outcome.items[0].kind, ItemKind::Login);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Bank");
        assert_eq!(outcome.items[1].kind, ItemKind::SecureNote);
        assert_eq!(outcome.items[2].kind, ItemKind::Card);
        assert_eq!(outcome.items[3].kind, ItemKind::Identity);
        // The fifth entry has an unknown type.
        assert_eq!(
            outcome.report.skipped[0],
            crate::import::Skipped {
                index: 4,
                reason: SkipReason::UnsupportedType
            }
        );
    }

    #[test]
    fn maps_url_match_rules_and_custom_fields() {
        let outcome = import_json(JSON.as_bytes()).expect("import");
        let login = &outcome.items[0];
        assert_eq!(login.urls[0].0, "https://demo-bank.example/login");
        assert_eq!(login.urls[0].1, UrlMatch::ExactHost);
        assert_eq!(login.urls[1].1, UrlMatch::BaseDomain);
        assert_eq!(login.urls[2].1, UrlMatch::StartsWith);
        assert_eq!(login.custom.len(), 1);
        assert_eq!(login.custom[0].0, "Support PIN");
        assert!(login.custom[0].2);
    }

    #[test]
    fn imports_the_csv_export() {
        let outcome = import_csv(CSV).expect("import");
        assert_eq!(outcome.report.imported, 3);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Mail");
        assert_eq!(outcome.items[0].urls[0].0, "https://mail.example");
        assert_eq!(outcome.items[1].kind, ItemKind::SecureNote);
    }

    #[test]
    fn a_malformed_file_is_rejected() {
        assert!(import_json(b"not json").is_err());
        assert!(import_json(b"{\"items\": 5}").is_err());
        // No column this importer recognises.
        assert!(import_csv("a,b,c\n1,2,3\n").is_err());
    }

    #[test]
    fn an_entry_without_a_title_is_skipped_with_a_reason() {
        let outcome =
            import_json(br#"{"items":[{"type":1,"name":"  ","login":{}}]}"#).expect("import");
        assert_eq!(outcome.report.imported, 0);
        assert_eq!(outcome.report.skipped[0].reason, SkipReason::MissingTitle);
    }
}
