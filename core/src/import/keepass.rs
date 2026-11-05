//! KeePass 2.x XML import (D-0302).
//!
//! `quick-xml` is a tokenizer, not a document engine: it has no DTD processing,
//! no entity expansion and no external fetches unless asked. On top of that this
//! parser refuses `<!DOCTYPE>`, `<!ENTITY>` and processing instructions, caps
//! nesting at 64, caps a value at 1 MiB, and ignores any element outside the
//! KeePass set it understands. That closes XXE and billion-laughs without
//! writing an XML parser.
//!
//! `<History>` subtrees are skipped: they are old versions of an entry, not
//! entries, and importing them would invent items the user never had.

use crate::codec::base64_decode;
use crate::error::{CoreError, CoreResult};
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::UrlMatch;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Most nested elements accepted.
pub const MAX_DEPTH: usize = 64;
/// Longest single text value accepted.
pub const MAX_VALUE_CHARS: usize = 1024 * 1024;

/// Imports a KeePass 2.x XML export.
pub fn import(bytes: &[u8]) -> CoreResult<ImportOutcome> {
    check_input_size(bytes)?;
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::InvalidImport)?;
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err(CoreError::InvalidImport);
    }

    let mut reader = Reader::from_str(text);
    let mut outcome = ImportOutcome::default();
    let mut stack: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut entry = EntryBuilder::default();
    let mut in_entry = false;
    let mut in_history = false;
    let mut current_key = String::new();
    let mut seen_keepass_file = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = element_name(element.name().as_ref())?;
                if stack.len() >= MAX_DEPTH {
                    return Err(CoreError::TooManyEntries);
                }
                if name == "KeePassFile" {
                    seen_keepass_file = true;
                }
                if name == "History" {
                    in_history = true;
                }
                if name == "Group" {
                    groups.push(String::new());
                }
                if name == "Entry" && !in_history {
                    in_entry = true;
                    entry = EntryBuilder::default();
                    entry.group = groups.last().cloned().unwrap_or_default();
                }
                if name == "Value" && in_entry && !in_history {
                    let protected = element.attributes().flatten().any(|attribute| {
                        attribute.key.as_ref().eq_ignore_ascii_case("Protected")
                            && attribute.value.eq_ignore_ascii_case("True")
                    });
                    entry.next_is_protected = protected;
                }
                stack.push(name);
            }
            Ok(Event::Text(value)) => {
                if in_history {
                    continue;
                }
                // The 0.42 reader hands out text with entities already
                // resolved (its events never contain `&` or `<`).
                let text = value.to_string();
                if text.chars().count() > MAX_VALUE_CHARS {
                    return Err(CoreError::TooManyEntries);
                }
                match stack.last().map(String::as_str) {
                    // A group name arrives outside any entry.
                    Some("Name") if stack.len() >= 2 && stack[stack.len() - 2] == "Group" => {
                        if let Some(group) = groups.last_mut() {
                            *group = text;
                        }
                    }
                    Some("Key") if in_entry => current_key = text,
                    Some("Value") if in_entry => {
                        let decoded = if entry.next_is_protected {
                            let bytes = base64_decode(&text)?;
                            String::from_utf8(bytes).map_err(|_| CoreError::InvalidImport)?
                        } else {
                            text
                        };
                        entry.fields.insert(current_key.clone(), decoded);
                        entry.next_is_protected = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::End(element)) => {
                let name = element_name(element.name().as_ref())?;
                if name == "Entry" && in_entry && !in_history {
                    in_entry = false;
                    let finished = std::mem::take(&mut entry);
                    match finished.into_parsed() {
                        Ok(Some(parsed)) => {
                            if outcome.items.len() >= MAX_IMPORT_ITEMS {
                                return Err(CoreError::TooManyEntries);
                            }
                            outcome.push(parsed);
                        }
                        Ok(None) => outcome.skip(outcome.items.len(), SkipReason::Empty),
                        Err(reason) => outcome.skip(outcome.items.len(), reason),
                    }
                }
                if name == "History" {
                    in_history = false;
                }
                if name == "Group" {
                    groups.pop();
                }
                stack.pop();
            }
            Ok(Event::DocType(_)) | Ok(Event::PI(_)) => return Err(CoreError::InvalidImport),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return Err(CoreError::InvalidImport),
        }
    }

    if !seen_keepass_file {
        return Err(CoreError::InvalidImport);
    }
    Ok(outcome)
}

fn element_name(raw: &str) -> CoreResult<String> {
    if raw.len() > 64 {
        return Err(CoreError::InvalidImport);
    }
    Ok(raw.to_string())
}

#[derive(Default)]
struct EntryBuilder {
    fields: std::collections::BTreeMap<String, String>,
    group: String,
    next_is_protected: bool,
}

impl EntryBuilder {
    fn into_parsed(self) -> Result<Option<ParsedItem>, SkipReason> {
        let title = self
            .fields
            .get("Title")
            .map(|value| value.trim())
            .unwrap_or("");
        if title.is_empty() {
            return Ok(None);
        }
        let mut parsed = ParsedItem::login(title);
        parsed.set(
            "username",
            self.fields
                .get("UserName")
                .map(String::as_str)
                .unwrap_or(""),
        );
        parsed.set(
            "password",
            self.fields
                .get("Password")
                .map(String::as_str)
                .unwrap_or(""),
        );
        parsed.set(
            "notes",
            self.fields.get("Notes").map(String::as_str).unwrap_or(""),
        );
        if let Some(url) =
            crate::import::normalise_url(self.fields.get("URL").map(String::as_str).unwrap_or(""))
        {
            parsed.urls.push((url, UrlMatch::ExactHost));
        }
        let otp = self
            .fields
            .get("otp")
            .or_else(|| self.fields.get("TOTP Seed"))
            .or_else(|| self.fields.get("TOTP Settings"))
            .map(String::as_str)
            .unwrap_or("");
        if !otp.is_empty() && crate::totp::TotpConfig::from_field(otp).is_ok() {
            parsed.set("totp", otp);
        }
        // Everything else KeePass stores becomes a custom field, which is the
        // only place a user-defined label may live (R-0114).
        for (key, value) in &self.fields {
            if matches!(
                key.as_str(),
                "Title"
                    | "UserName"
                    | "Password"
                    | "Notes"
                    | "URL"
                    | "otp"
                    | "TOTP Seed"
                    | "TOTP Settings"
            ) || value.trim().is_empty()
            {
                continue;
            }
            if parsed.custom.len() >= crate::vault::items::MAX_CUSTOM_FIELDS {
                return Err(SkipReason::TooLarge);
            }
            parsed.custom.push((key.clone(), value.clone(), false));
        }
        if !self.group.is_empty() && self.group.len() <= crate::vault::items::MAX_TAG_CHARS {
            parsed.tags.push(self.group);
        }
        Ok(Some(parsed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = include_str!("../../tests/fixtures/import/keepass.xml");

    #[test]
    fn imports_entries_including_nested_groups() {
        let outcome = import(XML.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 3);
        assert_eq!(outcome.items[0].fields[0].1, "Demo Bank");
        assert_eq!(outcome.items[1].fields[0].1, "Demo Nested");
        assert_eq!(outcome.items[1].tags, vec!["Sub Group".to_string()]);
    }

    #[test]
    fn skips_history_entries() {
        let outcome = import(XML.as_bytes()).expect("import");
        // The fixture has an old version inside <History>; it must not appear.
        assert!(outcome
            .items
            .iter()
            .all(|item| item.fields[0].1 != "Demo Bank (old)"));
    }

    #[test]
    fn decodes_protected_values() {
        let outcome = import(XML.as_bytes()).expect("import");
        let password = outcome.items[2]
            .fields
            .iter()
            .find(|(name, _)| name == "password")
            .expect("password");
        assert_eq!(password.1, "demo-protected-password");
    }

    #[test]
    fn rejects_doctype_and_entities() {
        let evil = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">]><KeePassFile/>";
        assert_eq!(
            import(evil.as_bytes()).expect_err("doctype"),
            CoreError::InvalidImport
        );
        let entity = "<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value>&lol;</Value></String></Entry></Group></Root></KeePassFile>";
        // quick-xml does not expand entities. Either the file is refused, or
        // the value stays literal; it is never turned into the expansion.
        if let Ok(outcome) = import(entity.as_bytes()) {
            for item in &outcome.items {
                for (_, value) in &item.fields {
                    assert!(!value.contains("lollol"), "entity was expanded");
                }
            }
        }
    }

    #[test]
    fn rejects_a_non_keepass_document() {
        assert_eq!(
            import(b"<html><body>nope</body></html>").expect_err("not keepass"),
            CoreError::InvalidImport
        );
        assert!(import(b"\xff\xfe\x00not utf8").is_err());
    }

    #[test]
    fn refuses_deep_nesting() {
        let mut xml = String::from("<KeePassFile>");
        for _ in 0..80 {
            xml.push_str("<Group>");
        }
        for _ in 0..80 {
            xml.push_str("</Group>");
        }
        xml.push_str("</KeePassFile>");
        assert_eq!(
            import(xml.as_bytes()).expect_err("depth"),
            CoreError::TooManyEntries
        );
    }
}
