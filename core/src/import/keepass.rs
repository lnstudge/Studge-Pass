//! KeePass 2.x XML import (D-0302).
//!
//! `quick-xml` is a tokenizer, not a document engine: it has no DTD processing,
//! no entity expansion and no external fetches unless asked. On top of that this
//! parser refuses `<!DOCTYPE>`, `<!ENTITY>` and processing instructions, caps
//! nesting at 64, caps a value at 1 MiB, and ignores elements outside the KeePass
//! set it models (KeePass's own `Times`, `AutoType`, `Binaries`, …). That closes
//! XXE and billion-laughs without writing an XML parser.
//!
//! Values are assembled **byte-exactly**: quick-xml hands an entity reference to
//! us as its own `Event::GeneralRef`, so every `Text` and `GeneralRef` piece of
//! an element is accumulated into one buffer and committed when the element
//! closes — never per piece. Only the five predefined entities and numeric
//! character references are resolved; anything else is rejected rather than
//! guessed. `<History>` subtrees are skipped: they are old versions of an entry,
//! not entries.

use crate::codec::base64_decode;
use crate::error::{CoreError, CoreResult};
use crate::import::{check_input_size, ImportOutcome, ParsedItem, SkipReason, MAX_IMPORT_ITEMS};
use crate::vault::items::{ItemKind, UrlMatch};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Most nested elements accepted.
pub const MAX_DEPTH: usize = 64;
/// Most characters one element's text may hold.
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
    // The element whose text is being accumulated, and the text so far. Text
    // and entity references arrive as separate events and must join into one
    // value (R-0305).
    let mut pending: Option<(String, String)> = None;
    let mut seen_keepass_file = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = element_name(element.name().as_ref())?;
                if stack.len() >= MAX_DEPTH {
                    return Err(CoreError::TooManyEntries);
                }
                if pending.is_some() {
                    // An element inside the text of another: KeePass never
                    // writes this, and silently flattening it would lose data.
                    return Err(CoreError::InvalidImport);
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
                let parent = stack.last().map(String::as_str);
                let capturing = match name.as_str() {
                    "Key" | "Value" => in_entry && !in_history && parent == Some("String"),
                    "Name" => !in_history && parent == Some("Group"),
                    _ => false,
                };
                if capturing {
                    pending = Some((name.clone(), String::new()));
                }
                if name == "Value" && in_entry && !in_history && parent == Some("String") {
                    let protected = element.attributes().flatten().any(|attribute| {
                        attribute.key.as_ref().eq_ignore_ascii_case("Protected")
                            && attribute.value.eq_ignore_ascii_case("True")
                    });
                    entry.next_is_protected = protected;
                }
                stack.push(name);
            }
            Ok(Event::Text(value)) => {
                if let Some((_, buffer)) = pending.as_mut() {
                    append_capped(buffer, value.as_ref())?;
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                // `&amp;` arrives here as the reference name `amp`. Resolve the
                // five predefined entities and numeric references ourselves;
                // everything else is refused, never guessed.
                if let Some((_, buffer)) = pending.as_mut() {
                    let character = resolve_reference(reference.as_ref())?;
                    buffer.push(character);
                }
            }
            Ok(Event::CData(value)) => {
                // CDATA is literal: no entity resolution, no escaping.
                if let Some((_, buffer)) = pending.as_mut() {
                    append_capped(buffer, value.as_ref())?;
                }
            }
            Ok(Event::End(element)) => {
                let name = element_name(element.name().as_ref())?;
                if let Some((captured, buffer)) = pending.as_ref() {
                    if captured == &name {
                        match captured.as_str() {
                            "Key" => entry.set_key(buffer.clone()),
                            "Name" => {
                                if let Some(group) = groups.last_mut() {
                                    *group = buffer.clone();
                                }
                            }
                            "Value" => entry.set_value(buffer.clone())?,
                            _ => {}
                        }
                        pending = None;
                    }
                }
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
            Ok(Event::Empty(element)) => {
                // `<Value/>` is an empty value, not a missing one: commit an
                // empty string so downstream duplicate detection sees it.
                let name = element_name(element.name().as_ref())?;
                let parent = stack.last().map(String::as_str);
                if in_entry && !in_history && parent == Some("String") {
                    match name.as_str() {
                        "Key" => entry.set_key(String::new()),
                        "Value" => entry.set_value(String::new())?,
                        _ => {}
                    }
                }
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

/// Appends a text piece, capping the accumulated element value.
fn append_capped(buffer: &mut String, piece: &str) -> CoreResult<()> {
    if buffer.chars().count() + piece.chars().count() > MAX_VALUE_CHARS {
        return Err(CoreError::TooManyEntries);
    }
    buffer.push_str(piece);
    Ok(())
}

/// Resolves one XML entity reference (without the delimiters).
///
/// Only the five predefined entities and numeric character references are
/// accepted, and a numeric reference must denote a character that XML 1.0
/// allows: a surrogate, a control character, a value above U+10FFFF or an
/// unknown name is a hard error.
fn resolve_reference(reference: &str) -> CoreResult<char> {
    match reference {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "quot" => Ok('"'),
        "apos" => Ok('\''),
        _ => {
            let code = if let Some(hex) = reference
                .strip_prefix("#x")
                .or_else(|| reference.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16)
            } else if let Some(decimal) = reference.strip_prefix('#') {
                decimal.parse::<u32>()
            } else {
                return Err(CoreError::InvalidImport);
            };
            let code = code.map_err(|_| CoreError::InvalidImport)?;
            if !is_xml_char(code) {
                return Err(CoreError::InvalidImport);
            }
            char::from_u32(code).ok_or(CoreError::InvalidImport)
        }
    }
}

/// The characters XML 1.0 permits a character reference to produce.
fn is_xml_char(code: u32) -> bool {
    matches!(code, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn element_name(raw: &str) -> CoreResult<String> {
    if raw.len() > 64 {
        return Err(CoreError::InvalidImport);
    }
    Ok(raw.to_string())
}

/// The `<String>` elements of one entry, accumulated as they close.
#[derive(Default)]
struct EntryBuilder {
    fields: std::collections::BTreeMap<String, String>,
    group: String,
    next_is_protected: bool,
    current_key: String,
}

impl EntryBuilder {
    /// Stores the text of the `<Key>` element that just closed.
    fn set_key(&mut self, key: String) {
        self.current_key = key;
    }

    /// Stores the text of the `<Value>` element that just closed.
    ///
    /// A protected value is base64 in the file and decoded here; an empty value
    /// is stored as an empty string, not dropped, so a duplicated key is still
    /// detectable.
    fn set_value(&mut self, value: String) -> CoreResult<()> {
        let decoded = if self.next_is_protected {
            let bytes = base64_decode(&value)?;
            String::from_utf8(bytes).map_err(|_| CoreError::InvalidImport)?
        } else {
            value
        };
        if self.fields.contains_key(&self.current_key) {
            // Two values for one key cannot both be true; the file is malformed
            // or hostile, and picking one would be a silent data loss.
            return Err(CoreError::InvalidImport);
        }
        self.fields.insert(self.current_key.clone(), decoded);
        self.next_is_protected = false;
        Ok(())
    }

    /// Builds a parsed item, or a skip reason. The item's kind comes from the
    /// exporter's `StudgeKind` marker (defaulting to a login), and a key that
    /// names a template field of that kind maps back onto the field instead of
    /// becoming a custom field.
    fn into_parsed(self) -> Result<Option<ParsedItem>, SkipReason> {
        let kind = match self.fields.get("StudgeKind") {
            Some(value) => ItemKind::parse(value).map_err(|_| SkipReason::InvalidValue)?,
            None => ItemKind::Login,
        };
        let title = self
            .fields
            .get("Title")
            .map(|value| value.trim())
            .unwrap_or("");
        if title.is_empty() {
            return Ok(None);
        }
        let mut parsed = ParsedItem {
            kind,
            fields: vec![("title".to_string(), title.to_string())],
            urls: Vec::new(),
            custom: Vec::new(),
            tags: Vec::new(),
            favourite: false,
        };
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
        // Everything else maps onto the kind's template if the name matches,
        // and becomes a custom field otherwise: a user-defined label may only
        // live in the custom area (R-0114).
        for (key, value) in &self.fields {
            if matches!(
                key.as_str(),
                "Title"
                    | "UserName"
                    | "Password"
                    | "URL"
                    | "Notes"
                    | "otp"
                    | "TOTP Seed"
                    | "TOTP Settings"
                    | "StudgeKind"
            ) || value.trim().is_empty()
            {
                continue;
            }
            if crate::vault::field_spec(kind, key).is_some() {
                parsed.set(key, value);
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
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
    use crate::export::keepass::export_keepass;
    use crate::oplog::devices::DeviceRegistry;
    use crate::oplog::materialise::{materialise, VaultState};
    use crate::oplog::op::{Op, OpKind};
    use crate::oplog::Dag;
    use crate::vault::items::{Item, ItemKind, UrlMatch};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    const XML: &str = include_str!("../../tests/fixtures/import/keepass.xml");

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn entry(fields: &[(&str, &str)]) -> String {
        let mut xml = String::from("<KeePassFile><Root><Group><Entry>");
        for (key, value) in fields {
            xml.push_str(&format!(
                "<String><Key>{key}</Key><Value>{value}</Value></String>"
            ));
        }
        xml.push_str("</Entry></Group></Root></KeePassFile>");
        xml
    }

    fn first_title_value(xml: &str, key: &str) -> Option<String> {
        let outcome = import(xml.as_bytes()).expect("import");
        outcome
            .items
            .first()
            .and_then(|item| item.fields.iter().find(|(name, _)| name == key))
            .map(|(_, value)| value.clone())
    }

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
    fn entity_references_no_longer_truncate_values() {
        // The founder's reproduction: every piece of the value must arrive,
        // not just the text after the last entity reference.
        let xml = entry(&[
            ("Title", "Bank &amp; Co"),
            ("Password", "p&lt;a&amp;s&gt;s&quot;1"),
        ]);
        assert_eq!(
            first_title_value(&xml, "title"),
            Some("Bank & Co".to_string())
        );
        assert_eq!(
            first_title_value(&xml, "password"),
            Some("p<a&s>s\"1".to_string())
        );
    }

    #[test]
    fn every_special_character_survives_in_every_field() {
        // The literal value we want back, and the same text as it must appear
        // in XML (a bare `&` is malformed XML, not a special character).
        let plain = "& < > \" ' ends & fine";
        let escaped = "&amp; &lt; &gt; &quot; &apos; ends &amp; fine";
        let xml = entry(&[
            ("Title", &format!("Title {escaped}")),
            ("UserName", &format!("user {escaped}")),
            ("Password", &format!("pass {escaped}")),
            ("URL", &format!("https://demo.example/?a=1{escaped}")),
            ("Notes", &format!("note {escaped}")),
            ("Support PIN", &format!("pin {escaped}")),
        ]);
        let outcome = import(xml.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 1);
        let item = &outcome.items[0];
        for name in ["title", "username", "password", "notes"] {
            let value = item
                .fields
                .iter()
                .find(|(field, _)| field == name)
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            assert!(value.ends_with(plain), "{name} lost characters: {value:?}");
        }
        assert!(
            item.urls[0].0.ends_with(plain),
            "url lost characters: {:?}",
            item.urls[0].0
        );
        assert_eq!(item.custom[0].0, "Support PIN");
        assert!(
            item.custom[0].1.ends_with(plain),
            "custom field lost characters: {:?}",
            item.custom[0].1
        );
    }

    #[test]
    fn numeric_character_references_resolve() {
        let xml = entry(&[
            ("Title", "N&#78; hex &#x3C;ok&#x3E;"),
            ("Password", "a&#65;b"),
        ]);
        assert_eq!(
            first_title_value(&xml, "title"),
            Some("NN hex <ok>".to_string())
        );
        assert_eq!(first_title_value(&xml, "password"), Some("aAb".to_string()));
    }

    #[test]
    fn invalid_numeric_references_are_rejected() {
        for bad in ["&#0;", "&#xD800;", "&#x110000;", "&#;"] {
            let xml = entry(&[("Title", &format!("bad {bad}"))]);
            assert_eq!(
                import(xml.as_bytes()).expect_err(bad),
                CoreError::InvalidImport,
                "{bad}"
            );
        }
    }

    #[test]
    fn unknown_entities_are_rejected() {
        for bad in ["&nbsp;", "&lol;", "&ampx;"] {
            let xml = entry(&[("Title", &format!("bad {bad}"))]);
            assert_eq!(
                import(xml.as_bytes()).expect_err(bad),
                CoreError::InvalidImport,
                "{bad}"
            );
        }
    }

    #[test]
    fn cdata_is_literal_text() {
        let xml = "<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value><![CDATA[<b>&raw]]></Value></String></Entry></Group></Root></KeePassFile>";
        assert_eq!(first_title_value(xml, "title"), Some("<b>&raw".to_string()));
    }

    #[test]
    fn an_empty_value_element_is_a_value_not_a_gap() {
        // Two values under one key: the first is empty. If the empty element
        // were treated as "nothing was here", the duplicate check would not
        // fire and one of the two values would silently win.
        let xml = "<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value/></String><String><Key>Title</Key><Value>second</Value></String></Entry></Group></Root></KeePassFile>";
        assert_eq!(
            import(xml.as_bytes()).expect_err("duplicate"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn an_element_inside_text_is_rejected() {
        let xml = "<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value>a<b>nested</b></Value></String></Entry></Group></Root></KeePassFile>";
        assert_eq!(
            import(xml.as_bytes()).expect_err("nested"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn rejects_doctype_and_entities() {
        let evil = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">]><KeePassFile/>";
        assert_eq!(
            import(evil.as_bytes()).expect_err("doctype"),
            CoreError::InvalidImport
        );
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

    #[test]
    fn a_duplicate_key_in_one_entry_is_rejected() {
        let xml = entry(&[
            ("Title", "Demo"),
            ("Password", "first"),
            ("Password", "second"),
        ]);
        assert_eq!(
            import(xml.as_bytes()).expect_err("duplicate"),
            CoreError::InvalidImport
        );
    }

    #[test]
    fn the_kind_marker_selects_the_template() {
        let xml = entry(&[
            ("Title", "Demo Aadhaar"),
            ("StudgeKind", "aadhaar"),
            ("aadhaar_number", "0000 0000 0000"),
        ]);
        let outcome = import(xml.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 1);
        let item = &outcome.items[0];
        assert_eq!(item.kind, ItemKind::Aadhaar);
        assert_eq!(
            item.fields
                .iter()
                .find(|(name, _)| name == "aadhaar_number")
                .map(|(_, value)| value.clone()),
            Some("0000 0000 0000".to_string())
        );
    }

    #[test]
    fn an_unreadable_kind_marker_skips_the_entry() {
        let xml = entry(&[("Title", "Demo"), ("StudgeKind", "not-a-kind")]);
        let outcome = import(xml.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 0);
        assert_eq!(outcome.report.skipped[0].reason, SkipReason::InvalidValue);
    }

    // ------------------------------------------------------- export/import

    fn state_with(fields: &[(&str, &str)], custom: &[(&str, &str)]) -> VaultState {
        let identity = SigningKeyPair::from_seed([1u8; 32]);
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let vk = VaultKey::from_bytes([3u8; 32]);
        let mut registry = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
        let cert = DeviceCertificate::create(
            &identity,
            ACCOUNT,
            DEVICE,
            device.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .expect("cert");
        registry
            .certify(&cert, &at("2026-11-05T09:30:00Z"))
            .expect("certify");
        let mut dag = Dag::new(VAULT);
        let mut item =
            Item::new(ITEM, VAULT, ItemKind::Login, at("2026-11-05T09:00:00Z")).expect("item");
        for (name, value) in fields {
            item.set_field(name, value, &at("2026-11-05T09:00:00Z"))
                .expect("field");
        }
        for (label, value) in custom {
            item.add_custom(label, value, false, &at("2026-11-05T09:00:00Z"))
                .expect("custom");
        }
        item.add_url(
            "https://demo.example/?a=1&b=<two>",
            UrlMatch::ExactHost,
            &at("2026-11-05T09:00:00Z"),
        )
        .expect("url");
        let payload = item.to_payload_bytes().expect("payload");
        let sealed = Op::seal_payload(&vk, &VAULT, &ITEM, OpKind::Create, &payload).expect("seal");
        let op = Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            DEVICE,
            at("2026-11-05T10:00:00Z"),
            OpKind::Create,
            Some(ITEM),
            sealed,
        )
        .expect("op")
        .sign(&device)
        .expect("sign");
        dag.add(op, &registry).expect("add");
        materialise(&dag, &vk).expect("materialise")
    }

    fn tricky_state() -> (VaultState, Item) {
        let tricky = "& < > \" ' ends &";
        let state = state_with(
            &[
                ("title", &format!("Title {tricky}")),
                ("username", &format!("user {tricky}")),
                ("password", &format!("pass {tricky}")),
                ("totp", "JBSWY3DPEHPK3PXP"),
                ("notes", &format!("note\n{tricky}")),
            ],
            &[("Support PIN", &format!("pin {tricky}"))],
        );
        let item = state.item(&ITEM).expect("item").clone();
        (state, item)
    }

    #[test]
    fn keepass_export_import_round_trip_is_byte_exact() {
        let (state, original) = tricky_state();
        let xml = export_keepass(&state, true).expect("export");
        let outcome = import(xml.as_bytes()).expect("import");
        assert_eq!(outcome.report.imported, 1, "report: {:?}", outcome.report);
        let parsed = &outcome.items[0];

        for name in ["title", "username", "password", "notes", "totp"] {
            assert_eq!(
                parsed.field(name),
                original.field(name),
                "{name} did not survive the round trip"
            );
        }
        assert_eq!(
            parsed.urls[0].0,
            original.urls()[0].url(),
            "the url did not survive"
        );
        assert_eq!(parsed.custom.len(), original.custom().len());
        assert_eq!(parsed.custom[0].0, original.custom()[0].label());
        assert_eq!(parsed.custom[0].1, original.custom()[0].value());
    }

    #[test]
    fn keepass_export_rejects_control_characters_by_name() {
        // Item::set_field already refuses control characters, so a VaultState
        // built through the public API cannot hold one; the exporter's own
        // check is defence in depth and is pinned in the exporter's tests
        // (`control_characters_are_an_error_naming_the_field`).
        assert!(Item::new(ITEM, VAULT, ItemKind::Login, at("2026-11-05T09:00:00Z")).is_ok());
    }

    #[test]
    fn keepass_export_rejects_a_custom_label_that_is_reserved() {
        let state = state_with(
            &[("title", "Demo")],
            &[("UserName", "would collide with the real one")],
        );
        assert_eq!(
            export_keepass(&state, true).expect_err("reserved label"),
            CoreError::FieldNotExportable {
                field: "UserName".to_string(),
                reason: "its label is reserved by the KeePass export format",
            }
        );
    }
}
