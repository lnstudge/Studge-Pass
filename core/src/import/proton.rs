//! Proton Pass export import.
//!
//! Proton's export is a JSON document with one or more vaults, each holding
//! items shaped `{ type, data: { metadata, content, extraFields } }`. Types
//! recognised: `login`, `note`, `creditCard`, `identity`, `sshKey`. Aliases,
//! Wi-Fi entries and custom types are skipped with a reason.

use crate::error::{CoreError, CoreResult};
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::{ItemKind, UrlMatch};
use serde_json::Value;

/// Imports a Proton Pass JSON export.
pub fn import(bytes: &[u8]) -> CoreResult<ImportOutcome> {
    check_input_size(bytes)?;
    let document: Value = serde_json::from_slice(bytes).map_err(|_| CoreError::InvalidImport)?;
    let vaults = document
        .get("vaults")
        .and_then(Value::as_array)
        .ok_or(CoreError::InvalidImport)?;

    let mut outcome = ImportOutcome::default();
    let mut index = 0usize;
    for vault in vaults {
        let Some(items) = vault.get("items").and_then(Value::as_array) else {
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
    let kind = text_of(item.get("type")).unwrap_or_default();
    let data = item.get("data");
    let title = data
        .and_then(|data| data.get("metadata"))
        .and_then(|metadata| metadata.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if title.is_empty() {
        return Err(SkipReason::MissingTitle);
    }
    let notes = data
        .and_then(|data| data.get("metadata"))
        .and_then(|metadata| metadata.get("note"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let mut parsed = match kind {
        "login" => {
            let mut parsed = ParsedItem::login(&title);
            if let Some(content) = data.and_then(|data| data.get("content")) {
                parsed.set(
                    "username",
                    text_of(content.get("username")).unwrap_or_default(),
                );
                parsed.set(
                    "password",
                    text_of(content.get("password")).unwrap_or_default(),
                );
                let totp = text_of(content.get("totpUri")).unwrap_or_default();
                if !totp.is_empty() && crate::totp::TotpConfig::from_field(totp).is_ok() {
                    parsed.set("totp", totp);
                }
                if let Some(urls) = content.get("urls").and_then(Value::as_array) {
                    for entry in urls {
                        if let Some(url) = crate::import::normalise_url(
                            text_of(entry.get("url")).unwrap_or_default(),
                        ) {
                            parsed.urls.push((url, UrlMatch::ExactHost));
                        }
                    }
                }
            }
            parsed.set("notes", &notes);
            parsed
        }
        "note" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::SecureNote,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            parsed.set("notes", &notes);
            parsed
        }
        "creditCard" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Card,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(content) = data.and_then(|data| data.get("content")) {
                parsed.set(
                    "cardholder",
                    text_of(content.get("cardholderName")).unwrap_or_default(),
                );
                parsed.set("number", text_of(content.get("number")).unwrap_or_default());
                parsed.set(
                    "expiry_month",
                    text_of(content.get("expirationDate")).unwrap_or_default(),
                );
                parsed.set(
                    "cvv",
                    text_of(content.get("verificationNumber")).unwrap_or_default(),
                );
            }
            parsed.set("notes", &notes);
            parsed
        }
        "identity" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::Identity,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(content) = data.and_then(|data| data.get("content")) {
                let first = text_of(content.get("firstName")).unwrap_or_default();
                let last = text_of(content.get("lastName")).unwrap_or_default();
                parsed.set("first_name", first);
                parsed.set("last_name", last);
                parsed.set("full_name", format!("{first} {last}").trim());
                parsed.set("email", text_of(content.get("email")).unwrap_or_default());
                parsed.set(
                    "phone",
                    text_of(content.get("phoneNumber")).unwrap_or_default(),
                );
            }
            parsed.set("notes", &notes);
            parsed
        }
        "sshKey" => {
            let mut parsed = ParsedItem {
                kind: ItemKind::SshKey,
                fields: vec![("title".to_string(), title.clone())],
                urls: Vec::new(),
                custom: Vec::new(),
                tags: Vec::new(),
                favourite: false,
            };
            if let Some(content) = data.and_then(|data| data.get("content")) {
                parsed.set(
                    "private_key",
                    text_of(content.get("privateKey")).unwrap_or_default(),
                );
                parsed.set(
                    "public_key",
                    text_of(content.get("publicKey")).unwrap_or_default(),
                );
            }
            parsed.set("notes", &notes);
            parsed
        }
        _ => return Err(SkipReason::UnsupportedType),
    };

    if let Some(extra) = data
        .and_then(|data| data.get("extraFields"))
        .and_then(Value::as_array)
    {
        for field in extra {
            let label = text_of(field.get("name")).unwrap_or_default();
            let value = text_of(field.get("data")).unwrap_or_default();
            if label.is_empty() || value.is_empty() || parsed.kind != ItemKind::Login {
                continue;
            }
            if parsed.custom.len() >= crate::vault::items::MAX_CUSTOM_FIELDS {
                return Err(SkipReason::TooLarge);
            }
            let hidden = text_of(field.get("type")) == Some("hidden");
            parsed
                .custom
                .push((label.to_string(), value.to_string(), hidden));
        }
    }
    Ok(Some(parsed))
}

fn text_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = include_str!("../../tests/fixtures/import/proton.json");

    #[test]
    fn imports_proton_items() {
        let outcome = import(EXPORT.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 3);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Login");
        assert_eq!(outcome.items[1].kind, ItemKind::SecureNote);
        assert_eq!(outcome.items[2].kind, ItemKind::SshKey);
        assert_eq!(
            outcome.report.skipped[0].reason,
            SkipReason::UnsupportedType
        );
    }

    #[test]
    fn a_missing_vaults_array_is_rejected() {
        assert_eq!(
            import(b"{\"items\":[]}").expect_err("shape"),
            CoreError::InvalidImport
        );
    }
}
