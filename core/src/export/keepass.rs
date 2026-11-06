//! KeePass 2.x XML export (task item 6).
//!
//! The importer (Phase 3, `import::keepass`) reads this back, and KeePass itself
//! opens the file. Every value is written byte-exactly: the only transformation
//! is XML escaping of the five predefined entities, and a value that XML 1.0
//! cannot represent (a control character) is an error naming the field, never a
//! silent rewrite (R-0305). This is a plaintext exporter and takes the same
//! `allow_plaintext` opt-in as JSON and CSV.
//!
//! Each template field and each custom field becomes its own `<String>` element
//! whose key is the field name or the user's label; the kind travels in a
//! `StudgeKind` marker so the import can map keys back onto the right template.

use crate::error::{CoreError, CoreResult};
use crate::oplog::materialise::VaultState;
use crate::vault::items::Item;

/// The `Generator` string KeePass shows in its metadata pane.
pub const GENERATOR: &str = "Studge Pass";

/// `<String>` keys the importer treats specially; a custom field may not use
/// them, because the import maps keys back onto fields and a collision would
/// silently pick one value.
const RESERVED_KEYS: [&str; 9] = [
    "Title",
    "UserName",
    "Password",
    "URL",
    "Notes",
    "otp",
    "StudgeKind",
    "TOTP Seed",
    "TOTP Settings",
];

/// Template fields written under their own reserved keys.
const OWN_KEYS: [&str; 5] = ["title", "username", "password", "notes", "totp"];

/// Exports a materialised vault as KeePass 2.x XML.
pub fn export_keepass(state: &VaultState, allow_plaintext: bool) -> CoreResult<String> {
    if !allow_plaintext {
        return Err(CoreError::PlaintextNotAllowed);
    }
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    out.push_str("<KeePassFile>\n  <Meta>\n");
    out.push_str("    <Generator>");
    out.push_str(&escape(GENERATOR));
    out.push_str("</Generator>\n");
    out.push_str("    <DatabaseName>Studge Pass export</DatabaseName>\n");
    out.push_str("  </Meta>\n  <Root>\n    <Group>\n      <Name>Studge Pass</Name>\n");
    for item in state.items() {
        write_entry(&mut out, item)?;
    }
    out.push_str("    </Group>\n  </Root>\n</KeePassFile>\n");
    Ok(out)
}

fn write_entry(out: &mut String, item: &Item) -> CoreResult<()> {
    out.push_str("      <Entry>\n");
    write_string(out, "Title", item.field("title").unwrap_or(""))?;
    write_string(out, "UserName", item.field("username").unwrap_or(""))?;
    write_string(out, "Password", item.field("password").unwrap_or(""))?;
    let url = item.urls().first().map(|entry| entry.url()).unwrap_or("");
    write_string(out, "URL", url)?;
    write_string(out, "Notes", item.field("notes").unwrap_or(""))?;
    if let Some(totp) = item.field("totp") {
        write_string(out, "otp", totp)?;
    }
    write_string(out, "StudgeKind", item.kind().as_str())?;
    // Every other template field travels under its own name so the import can
    // map it back onto the template of the recorded kind.
    for spec in crate::vault::template(item.kind()).fields {
        if OWN_KEYS.contains(&spec.name) {
            continue;
        }
        if let Some(value) = item.field(spec.name) {
            write_string(out, spec.name, value)?;
        }
    }
    for entry in item.custom() {
        if RESERVED_KEYS
            .iter()
            .any(|reserved| reserved.eq_ignore_ascii_case(entry.label()))
        {
            return Err(CoreError::FieldNotExportable {
                field: entry.label().to_string(),
                reason: "its label is reserved by the KeePass export format",
            });
        }
        write_string(out, entry.label(), entry.value())?;
    }
    out.push_str("      </Entry>\n");
    Ok(())
}

fn write_string(out: &mut String, key: &str, value: &str) -> CoreResult<()> {
    validate_exportable(key, key)?;
    validate_exportable(key, value)?;
    out.push_str("        <String><Key>");
    out.push_str(&escape(key));
    out.push_str("</Key><Value>");
    out.push_str(&escape(value));
    out.push_str("</Value></String>\n");
    Ok(())
}

/// Rejects what XML 1.0 cannot represent. Control characters other than tab and
/// newline are not expressible in a well-formed document; rewriting them (to a
/// space, say) would hand the user a different password than the one stored.
fn validate_exportable(field: &str, value: &str) -> CoreResult<()> {
    let control = value
        .chars()
        .any(|c| (c.is_control() && c != '\n' && c != '\t') || c == '\u{7F}');
    if control {
        return Err(CoreError::FieldNotExportable {
            field: field.to_string(),
            reason: "contains a control character that XML 1.0 cannot represent",
        });
    }
    Ok(())
}

/// XML text escaping: the five predefined entities, nothing else.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
    use crate::oplog::devices::DeviceRegistry;
    use crate::oplog::materialise::materialise;
    use crate::oplog::op::{Op, OpKind};
    use crate::oplog::Dag;
    use crate::vault::items::{Item, ItemKind};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn state_with(fields: &[(&str, &str)]) -> VaultState {
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

    #[test]
    fn refuses_without_the_opt_in() {
        let state = state_with(&[("title", "Demo")]);
        assert_eq!(
            export_keepass(&state, false).expect_err("no flag"),
            CoreError::PlaintextNotAllowed
        );
    }

    #[test]
    fn escapes_every_value() {
        let state = state_with(&[
            ("title", "A & B <script>"),
            ("password", "\"quoted\" & 'single'"),
        ]);
        let xml = export_keepass(&state, true).expect("export");
        assert!(xml.contains("A &amp; B &lt;script&gt;"));
        assert!(!xml.contains("<script>"));
        assert!(xml.contains("&quot;quoted&quot; &amp; &apos;single&apos;"));
    }

    #[test]
    fn writes_the_keepass_skeleton_and_per_field_strings() {
        let state = state_with(&[
            ("title", "Demo Only"),
            ("username", "demo"),
            ("totp", "JBSWY3DPEHPK3PXP"),
        ]);
        let xml = export_keepass(&state, true).expect("export");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(xml.contains("<Key>Title</Key><Value>Demo Only</Value>"));
        assert!(xml.contains("<Key>UserName</Key><Value>demo</Value>"));
        assert!(xml.contains("<Key>otp</Key><Value>JBSWY3DPEHPK3PXP</Value>"));
        assert!(xml.contains("<Key>StudgeKind</Key><Value>login</Value>"));
        assert!(xml.trim_end().ends_with("</KeePassFile>"));
    }

    #[test]
    fn notes_are_written_untouched() {
        let state = state_with(&[("title", "Demo"), ("notes", "line one\nline two")]);
        let xml = export_keepass(&state, true).expect("export");
        // No "Kind:" suffix, no custom-field stuffing: the value is the value.
        assert!(xml.contains("<Key>Notes</Key><Value>line one\nline two</Value>"));
        assert!(!xml.contains("Kind:"));
    }

    #[test]
    fn control_characters_are_an_error_naming_the_field() {
        // Item::set_field already refuses control characters, so the exporter
        // cannot normally see one; the check exists because a VaultState is a
        // public type and future phases can build one another way. The test
        // pins the behaviour at the exporter's own boundary.
        for (field, value) in [
            ("Title", "bad \u{0007} here"),
            ("Notes", "bad \u{001B} here"),
            ("Password", "bad \u{007F} here"),
            ("Support PIN", "bad \r here"),
        ] {
            assert_eq!(
                validate_exportable(field, value).expect_err("control character"),
                CoreError::FieldNotExportable {
                    field: field.to_string(),
                    reason: "contains a control character that XML 1.0 cannot represent",
                },
                "{field}"
            );
        }
        // Tab and newline are the two control characters XML 1.0 represents.
        assert!(validate_exportable("Notes", "line one\nline two\tend").is_ok());
    }
}
