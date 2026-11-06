//! Plain CSV export (task item 6).
//!
//! One row per item, RFC 4180 quoting, and the same `allow_plaintext` opt-in as
//! the JSON exporter. The column set is fixed so a generic importer can map it
//! back: `kind,title,username,password,urls,totp,notes,fields`.

use crate::error::{CoreError, CoreResult};
use crate::oplog::materialise::VaultState;
use crate::vault::items::Item;

/// The header row, in order.
pub const HEADER: [&str; 8] = [
    "kind", "title", "username", "password", "urls", "totp", "notes", "fields",
];

/// Columns that have their own place in the row.
const OWN_COLUMNS: [&str; 5] = ["title", "username", "password", "totp", "notes"];

/// Exports a materialised vault as CSV.
pub fn export_csv(state: &VaultState, allow_plaintext: bool) -> CoreResult<String> {
    if !allow_plaintext {
        return Err(CoreError::PlaintextNotAllowed);
    }
    let mut out = String::new();
    out.push_str(&HEADER.join(","));
    out.push('\n');
    for item in state.items() {
        let urls: Vec<&str> = item.urls().iter().map(|entry| entry.url()).collect();
        let fields = remaining_fields(item);
        let row = [
            item.kind().as_str().to_string(),
            item.field("title").unwrap_or("").to_string(),
            item.field("username").unwrap_or("").to_string(),
            item.field("password").unwrap_or("").to_string(),
            urls.join(" "),
            item.field("totp").unwrap_or("").to_string(),
            item.field("notes").unwrap_or("").to_string(),
            fields,
        ];
        let escaped: Vec<String> = row.iter().map(|cell| escape(cell)).collect();
        out.push_str(&escaped.join(","));
        out.push('\n');
    }
    Ok(out)
}

/// Every scalar field that is not one of the five dedicated columns, as
/// `name=value` lines (a value may itself contain a newline; CSV quoting keeps
/// the cell intact).
fn remaining_fields(item: &Item) -> String {
    let mut lines = Vec::new();
    for spec in crate::vault::template(item.kind()).fields {
        if OWN_COLUMNS.contains(&spec.name) {
            continue;
        }
        if let Some(value) = item.field(spec.name) {
            lines.push(format!("{}={value}", spec.name));
        }
    }
    for entry in item.custom() {
        lines.push(format!("custom:{}={}", entry.label(), entry.value()));
    }
    lines.join("\n")
}

fn escape(cell: &str) -> String {
    if cell.contains(',') || cell.contains('"') || cell.contains('\n') || cell.contains('\r') {
        let mut out = String::with_capacity(cell.len() + 2);
        out.push('"');
        for character in cell.chars() {
            if character == '"' {
                out.push('"');
            }
            out.push(character);
        }
        out.push('"');
        out
    } else {
        cell.to_string()
    }
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
    use crate::vault::items::{ItemKind, UrlMatch};

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
        item.add_url(
            "https://demo.example",
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

    #[test]
    fn refuses_without_the_opt_in() {
        let state = state_with(&[("title", "Demo")]);
        assert_eq!(
            export_csv(&state, false).expect_err("no flag"),
            CoreError::PlaintextNotAllowed
        );
    }

    #[test]
    fn writes_the_header_and_one_row_per_item() {
        let state = state_with(&[
            ("title", "Demo Only"),
            ("username", "demo@example.test"),
            ("password", "demo-password"),
        ]);
        let text = export_csv(&state, true).expect("export");
        let mut lines = text.lines();
        assert_eq!(lines.next().expect("header"), HEADER.join(","));
        let row = lines.next().expect("row");
        assert!(row.starts_with("login,Demo Only,demo@example.test,demo-password,"));
        assert!(row.contains("https://demo.example"));
        assert_eq!(lines.count(), 0);
    }

    #[test]
    fn quotes_commas_quotes_and_newlines() {
        let state = state_with(&[
            ("title", "Demo, \"quoted\" title"),
            ("notes", "line one\nline two"),
        ]);
        let text = export_csv(&state, true).expect("export");
        assert!(text.contains("\"Demo, \"\"quoted\"\" title\""));
        assert!(text.contains("\"line one\nline two\""));
    }

    #[test]
    fn remaining_fields_travel_in_the_last_column() {
        let state = state_with(&[("title", "Demo"), ("totp", "JBSWY3DPEHPK3PXP")]);
        let text = export_csv(&state, true).expect("export");
        // `totp` has its own column, so the fields cell is empty here.
        let row = text.lines().nth(1).expect("row");
        assert!(row.contains("JBSWY3DPEHPK3PXP"));
        assert!(row.ends_with(','));
    }

    #[test]
    fn csv_round_trip_preserves_special_characters() {
        let tricky = "& < > \" ' , ;\nnewline";
        let state = state_with(&[
            ("title", &format!("Title {tricky}")),
            ("username", &format!("user {tricky}")),
            ("password", &format!("pass {tricky}")),
            ("totp", "JBSWY3DPEHPK3PXP"),
            ("notes", &format!("note {tricky}")),
        ]);
        let csv = export_csv(&state, true).expect("export");
        let mapping = crate::import::generic::ColumnMapping::from_header(
            csv.lines()
                .next()
                .expect("header")
                .split(',')
                .map(|cell| cell.to_string())
                .collect::<Vec<String>>()
                .as_slice(),
        );
        let outcome = crate::import::generic::import(&csv, &mapping).expect("import");
        assert_eq!(outcome.report.imported, 1, "report: {:?}", outcome.report);
        let parsed = &outcome.items[0];
        for name in ["title", "username", "password", "totp", "notes"] {
            assert_eq!(
                parsed.field(name),
                state.item(&ITEM).and_then(|item| item.field(name)),
                "{name} did not survive the round trip"
            );
        }
        assert_eq!(
            parsed.urls[0].0,
            state.item(&ITEM).expect("item").urls()[0].url()
        );
    }
}
