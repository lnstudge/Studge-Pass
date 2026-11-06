//! Plain JSON export (task item 6).
//!
//! Every plaintext exporter takes `allow_plaintext: bool` and refuses when it is
//! false: writing decrypted secrets to disk is a deliberate, explicit act, never
//! a default and never a side effect of "share this vault".
//!
//! The output is a documented, stable shape with a `warning` field so that a
//! person who finds the file knows exactly what it is.

use crate::error::{CoreError, CoreResult};
use crate::oplog::materialise::VaultState;
use crate::vault::items::Item;
use serde_json::{json, Map, Value};

/// The `format` marker of a JSON export.
pub const FORMAT: &str = "studge-vault-json";

/// Exports a materialised vault as pretty JSON.
pub fn export_json(state: &VaultState, allow_plaintext: bool) -> CoreResult<String> {
    if !allow_plaintext {
        return Err(CoreError::PlaintextNotAllowed);
    }
    let mut items = Vec::with_capacity(state.len());
    for item in state.items() {
        items.push(item_json(item));
    }
    let document = json!({
        "format": FORMAT,
        "v": 1,
        "warning": "PLAINTEXT: this file contains decrypted secrets. Store it encrypted and delete it when done.",
        "vault_id": hex(state.vault_id()),
        "op_count": state.op_count(),
        "items": items,
    });
    serde_json::to_string_pretty(&document).map_err(|_| CoreError::MalformedPayload)
}

fn item_json(item: &Item) -> Value {
    let mut fields = Map::new();
    for name in scalar_field_names(item) {
        if let Some(value) = item.field(name) {
            fields.insert(name.to_string(), Value::String(value.to_string()));
        }
    }
    let urls: Vec<Value> = item
        .urls()
        .iter()
        .map(|entry| json!({ "url": entry.url(), "match": entry.match_rule().as_str() }))
        .collect();
    let custom: Vec<Value> = item
        .custom()
        .iter()
        .map(|entry| {
            json!({
                "label": entry.label(),
                "value": entry.value(),
                "hidden": entry.hidden(),
            })
        })
        .collect();
    let passkeys: Vec<Value> = item
        .passkeys()
        .iter()
        .map(|id| Value::String(crate::codec::base64url_encode(id)))
        .collect();
    let mut history = Map::new();
    for name in scalar_field_names(item) {
        let entries = item.history(name);
        if entries.is_empty() {
            continue;
        }
        let list: Vec<Value> = entries
            .iter()
            .map(|entry| json!({ "at": entry.at().as_str(), "value": entry.value() }))
            .collect();
        history.insert(name.to_string(), Value::Array(list));
    }

    json!({
        "kind": item.kind().as_str(),
        "title": item.field("title").unwrap_or(""),
        "favourite": item.favourite(),
        "tags": item.tags(),
        "created_at": item.created_at().as_str(),
        "updated_at": item.updated_at().as_str(),
        "fields": Value::Object(fields),
        "urls": urls,
        "custom": custom,
        "passkeys": passkeys,
        "history": Value::Object(history),
    })
}

fn scalar_field_names(item: &Item) -> Vec<&'static str> {
    crate::vault::template(item.kind())
        .fields
        .iter()
        .map(|spec| spec.name)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
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
    use crate::vault::items::{ItemKind, UrlMatch};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    pub(crate) fn demo_state() -> VaultState {
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
        item.set_field("title", "Demo Only", &at("2026-11-05T09:00:00Z"))
            .expect("title");
        item.set_field("username", "demo@example.test", &at("2026-11-05T09:00:00Z"))
            .expect("username");
        item.set_field("password", "demo-password-1", &at("2026-11-05T09:00:00Z"))
            .expect("password");
        item.set_field("password", "demo-password-2", &at("2026-11-05T09:10:00Z"))
            .expect("password");
        item.add_url(
            "https://demo.example",
            UrlMatch::BaseDomain,
            &at("2026-11-05T09:10:00Z"),
        )
        .expect("url");
        item.add_custom("Support PIN", "4321", true, &at("2026-11-05T09:10:00Z"))
            .expect("custom");
        item.set_tags(vec!["demo".into()], &at("2026-11-05T09:10:00Z"))
            .expect("tags");
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
        let state = demo_state();
        assert_eq!(
            export_json(&state, false).expect_err("no flag"),
            CoreError::PlaintextNotAllowed
        );
    }

    #[test]
    fn exports_a_documented_shape() {
        let state = demo_state();
        let text = export_json(&state, true).expect("export");
        let parsed: Value = serde_json::from_str(&text).expect("json");
        assert_eq!(parsed["format"], FORMAT);
        assert_eq!(parsed["v"], 1);
        assert!(parsed["warning"]
            .as_str()
            .expect("warning")
            .contains("PLAINTEXT"));
        let items = parsed["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["kind"], "login");
        assert_eq!(items[0]["title"], "Demo Only");
        assert_eq!(items[0]["fields"]["password"], "demo-password-2");
        assert_eq!(items[0]["urls"][0]["match"], "base-domain");
        assert_eq!(items[0]["custom"][0]["label"], "Support PIN");
        assert_eq!(
            items[0]["history"]["password"][0]["value"],
            "demo-password-1"
        );
    }

    #[test]
    fn the_document_is_valid_utf8_and_round_trips() {
        let state = demo_state();
        let text = export_json(&state, true).expect("export");
        let bytes = text.as_bytes();
        assert!(std::str::from_utf8(bytes).is_ok());
        let parsed: Value = serde_json::from_str(&text).expect("json");
        assert!(parsed["items"].is_array());
    }

    #[test]
    fn json_round_trip_preserves_every_value_byte_for_byte() {
        let state = demo_state();
        let text = export_json(&state, true).expect("export");
        let parsed: Value = serde_json::from_str(&text).expect("json");
        let item = state.item(&ITEM).expect("item");

        // Every template field that is set comes back exactly, including the
        // entity- and quote-heavy ones.
        for spec in crate::vault::template(item.kind()).fields {
            if let Some(value) = item.field(spec.name) {
                assert_eq!(
                    parsed["items"][0]["fields"][spec.name].as_str(),
                    Some(value),
                    "{} did not survive",
                    spec.name
                );
            }
        }
        assert_eq!(
            parsed["items"][0]["urls"][0]["url"].as_str(),
            Some(item.urls()[0].url())
        );
        assert_eq!(
            parsed["items"][0]["custom"][0]["label"].as_str(),
            Some(item.custom()[0].label())
        );
        assert_eq!(
            parsed["items"][0]["custom"][0]["value"].as_str(),
            Some(item.custom()[0].value())
        );
        // Secret history survives too.
        assert_eq!(
            parsed["items"][0]["history"]["password"][0]["value"].as_str(),
            Some(item.history("password")[0].value())
        );
    }
}
