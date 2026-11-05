//! KeePass 2.x XML export (task item 6).
//!
//! The importer (Phase 3, `import::keepass`) reads this back, and KeePass itself
//! opens the file. Values are written unencrypted unless the caller protects
//! them; this is a plaintext exporter and takes the same `allow_plaintext`
//! opt-in as JSON and CSV.
//!
//! Writing XML by hand is safe here because every value goes through one
//! escaper and the element structure is fixed — nothing user-controlled ever
//! becomes markup.

use crate::error::{CoreError, CoreResult};
use crate::oplog::materialise::VaultState;
use crate::vault::items::Item;

/// The `Generator` string KeePass shows in its metadata pane.
pub const GENERATOR: &str = "Studge Pass";

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
        write_entry(&mut out, item);
    }
    out.push_str("    </Group>\n  </Root>\n</KeePassFile>\n");
    Ok(out)
}

fn write_entry(out: &mut String, item: &Item) {
    out.push_str("      <Entry>\n");
    let title = item.field("title").unwrap_or("");
    write_string(out, "Title", title);
    write_string(out, "UserName", item.field("username").unwrap_or(""));
    write_string(out, "Password", item.field("password").unwrap_or(""));
    let url = item.urls().first().map(|entry| entry.url()).unwrap_or("");
    write_string(out, "URL", url);
    let mut notes = item.field("notes").unwrap_or("").to_string();
    if !notes.is_empty() {
        notes.push('\n');
    }
    notes.push_str(&format!("Kind: {}", item.kind().as_str()));
    for spec in crate::vault::template(item.kind()).fields {
        if matches!(spec.name, "title" | "username" | "password" | "notes") {
            continue;
        }
        if let Some(value) = item.field(spec.name) {
            notes.push_str(&format!("\n{}: {value}", spec.name));
        }
    }
    for entry in item.custom() {
        notes.push_str(&format!("\n{}: {}", entry.label(), entry.value()));
    }
    write_string(out, "Notes", &notes);
    out.push_str("        <String><Key>StudgeKind</Key><Value>");
    out.push_str(&escape(item.kind().as_str()));
    out.push_str("</Value></String>\n");
    out.push_str("      </Entry>\n");
}

fn write_string(out: &mut String, key: &str, value: &str) {
    out.push_str("        <String><Key>");
    out.push_str(&escape(key));
    out.push_str("</Key><Value>");
    out.push_str(&escape(value));
    out.push_str("</Value></String>\n");
}

/// XML text escaping: the five predefined entities, and control characters that
/// XML 1.0 forbids are replaced so a weird note can never break the document.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => out.push(' '),
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
    use crate::vault::items::ItemKind;

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
    fn writes_the_keepass_skeleton() {
        let state = state_with(&[("title", "Demo Only"), ("username", "demo")]);
        let xml = export_keepass(&state, true).expect("export");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(xml.contains("<KeePassFile>"));
        assert!(xml.contains("<Group>"));
        assert!(xml.contains("<Key>Title</Key><Value>Demo Only</Value>"));
        assert!(xml.contains("<Key>StudgeKind</Key><Value>login</Value>"));
        assert!(xml.trim_end().ends_with("</KeePassFile>"));
    }
}
