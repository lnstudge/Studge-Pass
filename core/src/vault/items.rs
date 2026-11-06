//! The vault item: the plaintext object an op payload carries.
//!
//! An item is what a user sees — a login, a passkey, an Aadhaar record — with
//! every value held in a zeroizing buffer and a `Debug` that prints counts, not
//! content. Field names are fixed by the item's template
//! ([`crate::vault::templates`]); an unknown name is rejected on construction
//! and on parse, which is the R-0114 defence against look-alike labels.
//!
//! The item's payload encoding is canonical CBOR (SPEC §6.2) so that two
//! clients holding the same item produce identical bytes.

use crate::cbor::{
    as_array, as_bool, as_bytes, as_text, as_u64, bytes as cbor_bytes, map_pairs, parse_map,
    text as cbor_text,
};
use crate::codec::{base64url_decode, base64url_encode};
use crate::crypto::aad::{canonical_bytes, canonical_map};
use crate::crypto::signing::Timestamp;
use crate::error::{CoreError, CoreResult};
use crate::vault::templates::{field_spec, template};
use ciborium::value::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// An item identifier (SPEC §4.1).
pub type ItemId = [u8; 16];
/// A vault identifier (SPEC §4.1).
pub type VaultId = [u8; 16];

/// At most 1 MiB per field value (SPEC §5.6).
pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
/// At most 1 MiB for the whole op payload (SPEC §6.11).
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// At most 256 fields on an item (SPEC §5.6).
pub const MAX_FIELDS: usize = 256;
/// Tags per item.
pub const MAX_TAGS: usize = 64;
/// Characters per tag.
pub const MAX_TAG_CHARS: usize = 64;
/// Characters in a title.
pub const MAX_TITLE_CHARS: usize = 512;
/// URLs per login.
pub const MAX_URLS: usize = 32;
/// Characters in a URL.
pub const MAX_URL_CHARS: usize = 2048;
/// Custom fields per login.
pub const MAX_CUSTOM_FIELDS: usize = 64;
/// Characters in a custom-field label.
pub const MAX_LABEL_CHARS: usize = 128;
/// Passkeys linked to one login.
pub const MAX_LINKED_PASSKEYS: usize = 32;
/// Bytes of a credential id.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
/// Values kept per secret field (task item 1).
pub const MAX_HISTORY: usize = 10;

/// The kinds of item a vault can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    /// Username, password, URLs, TOTP, custom fields, linked passkeys.
    Login,
    /// A WebAuthn credential.
    Passkey,
    /// Free-form secret text.
    SecureNote,
    /// Payment card.
    Card,
    /// Personal identity record.
    Identity,
    /// SSH private key.
    SshKey,
    /// India: Aadhaar.
    Aadhaar,
    /// India: PAN.
    Pan,
    /// India: UPI ID and PIN.
    Upi,
    /// India: netbanking credentials.
    Netbanking,
    /// India: DigiLocker.
    DigiLocker,
    /// India: passport.
    Passport,
    /// India: voter ID.
    VoterId,
}

impl ItemKind {
    /// Every kind, in the order the UI shows them.
    pub const ALL: [ItemKind; 13] = [
        ItemKind::Login,
        ItemKind::Passkey,
        ItemKind::SecureNote,
        ItemKind::Card,
        ItemKind::Identity,
        ItemKind::SshKey,
        ItemKind::Aadhaar,
        ItemKind::Pan,
        ItemKind::Upi,
        ItemKind::Netbanking,
        ItemKind::DigiLocker,
        ItemKind::Passport,
        ItemKind::VoterId,
    ];

    /// The wire name used inside the payload.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Passkey => "passkey",
            Self::SecureNote => "secure_note",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::SshKey => "ssh_key",
            Self::Aadhaar => "aadhaar",
            Self::Pan => "pan",
            Self::Upi => "upi",
            Self::Netbanking => "netbanking",
            Self::DigiLocker => "digilocker",
            Self::Passport => "passport",
            Self::VoterId => "voter_id",
        }
    }

    /// Parses the wire name; unknown names are an error, never a default.
    pub fn parse(value: &str) -> CoreResult<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or(CoreError::UnknownKind)
    }
}

/// How a stored URL matches a page origin (task item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlMatch {
    /// The host must match exactly (the default).
    ExactHost,
    /// The registrable domain may differ in subdomain.
    BaseDomain,
    /// The URL must start with the stored text.
    StartsWith,
}

impl UrlMatch {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactHost => "exact-host",
            Self::BaseDomain => "base-domain",
            Self::StartsWith => "starts-with",
        }
    }

    /// Parses the wire name.
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "exact-host" => Ok(Self::ExactHost),
            "base-domain" => Ok(Self::BaseDomain),
            "starts-with" => Ok(Self::StartsWith),
            _ => Err(CoreError::UnknownKind),
        }
    }
}

/// One URL and its match rule.
#[derive(Clone, PartialEq, Eq)]
pub struct UrlEntry {
    url: Zeroizing<String>,
    match_rule: UrlMatch,
}

impl UrlEntry {
    /// The URL text.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The match rule.
    pub fn match_rule(&self) -> UrlMatch {
        self.match_rule
    }
}

impl fmt::Debug for UrlEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlEntry")
            .field("len", &self.url.len())
            .field("match_rule", &self.match_rule)
            .finish()
    }
}

/// A user-labelled extra field. The label is untrusted text and is rendered
/// quoted in the UI (SPEC §5.6, R-0114).
#[derive(Clone, PartialEq, Eq)]
pub struct CustomField {
    label: Zeroizing<String>,
    value: Zeroizing<String>,
    hidden: bool,
}

impl CustomField {
    /// The user's label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Whether the UI masks the value until revealed.
    pub fn hidden(&self) -> bool {
        self.hidden
    }
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("label_len", &self.label.len())
            .field("hidden", &self.hidden)
            .finish()
    }
}

/// One previous value of a secret field.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    at: Timestamp,
    value: Zeroizing<String>,
}

impl HistoryEntry {
    /// When this value stopped being current.
    pub fn at(&self) -> &Timestamp {
        &self.at
    }

    /// The old value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for HistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HistoryEntry")
            .field("at", &self.at)
            .field("len", &self.value.len())
            .finish()
    }
}

/// A vault item. Cloning duplicates secret material, so it is deliberate.
#[derive(Clone)]
pub struct Item {
    id: ItemId,
    vault_id: VaultId,
    kind: ItemKind,
    favourite: bool,
    tags: Vec<String>,
    created_at: Timestamp,
    updated_at: Timestamp,
    fields: BTreeMap<String, Zeroizing<String>>,
    history: BTreeMap<String, Vec<HistoryEntry>>,
    urls: Vec<UrlEntry>,
    custom: Vec<CustomField>,
    passkeys: Vec<Vec<u8>>,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("kind", &self.kind)
            .field("fields", &self.fields.len())
            .field("history", &self.history.len())
            .field("urls", &self.urls.len())
            .field("custom", &self.custom.len())
            .field("passkeys", &self.passkeys.len())
            .finish()
    }
}

impl Item {
    /// Creates an empty item of `kind`.
    pub fn new(
        id: ItemId,
        vault_id: VaultId,
        kind: ItemKind,
        created_at: Timestamp,
    ) -> CoreResult<Self> {
        // Touch the template so a future kind without one fails here rather
        // than at the first field write.
        let _ = template(kind);
        Ok(Self {
            id,
            vault_id,
            kind,
            favourite: false,
            tags: Vec::new(),
            created_at: created_at.clone(),
            updated_at: created_at,
            fields: BTreeMap::new(),
            history: BTreeMap::new(),
            urls: Vec::new(),
            custom: Vec::new(),
            passkeys: Vec::new(),
        })
    }

    /// The item id.
    pub fn id(&self) -> &ItemId {
        &self.id
    }

    /// The vault this item belongs to.
    pub fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The item kind.
    pub fn kind(&self) -> ItemKind {
        self.kind
    }

    /// Creation time (never changes).
    pub fn created_at(&self) -> &Timestamp {
        &self.created_at
    }

    /// Last modification time.
    pub fn updated_at(&self) -> &Timestamp {
        &self.updated_at
    }

    /// Whether the item is a favourite.
    pub fn favourite(&self) -> bool {
        self.favourite
    }

    /// The tags.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// A field value, if set.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|value| value.as_str())
    }

    /// The URLs (login only).
    pub fn urls(&self) -> &[UrlEntry] {
        &self.urls
    }

    /// The custom fields (login only).
    pub fn custom(&self) -> &[CustomField] {
        &self.custom
    }

    /// Linked passkey credential ids (login only).
    pub fn passkeys(&self) -> &[Vec<u8>] {
        &self.passkeys
    }

    /// The last values of a secret field, newest first.
    pub fn history(&self, name: &str) -> &[HistoryEntry] {
        self.history
            .get(name)
            .map(|entries| entries.as_slice())
            .unwrap_or(&[])
    }

    /// Sets a scalar field, recording the previous value if it was a secret.
    pub fn set_field(&mut self, name: &str, value: &str, now: &Timestamp) -> CoreResult<()> {
        let spec = field_spec(self.kind, name).ok_or(CoreError::UnknownField)?;
        let cap = if name == "title" {
            MAX_TITLE_CHARS
        } else {
            MAX_FIELD_BYTES
        };
        validate_text(name, value, cap)?;
        validate_field_value(self.kind, name, value)?;

        if spec.secret {
            let previous = self
                .fields
                .get(name)
                .map(|old| Zeroizing::new(old.to_string()))
                .filter(|old| !old.is_empty() && old.as_str() != value);
            if let Some(previous) = previous {
                self.push_history(name, &previous);
            }
        }
        self.fields
            .insert(name.to_string(), Zeroizing::new(value.to_string()));
        self.updated_at = now.clone();
        Ok(())
    }

    /// Removes a scalar field, recording its value if it was a secret.
    pub fn clear_field(&mut self, name: &str, now: &Timestamp) -> CoreResult<()> {
        let spec = field_spec(self.kind, name).ok_or(CoreError::UnknownField)?;
        if let Some(previous) = self.fields.remove(name) {
            if spec.secret && !previous.is_empty() {
                self.push_history(name, &previous);
            }
        }
        self.updated_at = now.clone();
        Ok(())
    }

    /// Adds a URL and its match rule (login only).
    pub fn add_url(&mut self, url: &str, match_rule: UrlMatch, now: &Timestamp) -> CoreResult<()> {
        if !template(self.kind).urls {
            return Err(CoreError::UnknownField);
        }
        if self.urls.len() >= MAX_URLS {
            return Err(CoreError::TooManyEntries);
        }
        validate_url(url)?;
        self.urls.push(UrlEntry {
            url: Zeroizing::new(url.to_string()),
            match_rule,
        });
        self.updated_at = now.clone();
        Ok(())
    }

    /// Replaces the whole URL list (imports and edits).
    pub fn set_urls(&mut self, urls: Vec<(String, UrlMatch)>, now: &Timestamp) -> CoreResult<()> {
        if !template(self.kind).urls && !urls.is_empty() {
            return Err(CoreError::UnknownField);
        }
        if urls.len() > MAX_URLS {
            return Err(CoreError::TooManyEntries);
        }
        let mut entries = Vec::with_capacity(urls.len());
        for (url, match_rule) in urls {
            validate_url(&url)?;
            entries.push(UrlEntry {
                url: Zeroizing::new(url),
                match_rule,
            });
        }
        self.urls = entries;
        self.updated_at = now.clone();
        Ok(())
    }

    /// Adds a user-labelled custom field (login only).
    pub fn add_custom(
        &mut self,
        label: &str,
        value: &str,
        hidden: bool,
        now: &Timestamp,
    ) -> CoreResult<()> {
        if !template(self.kind).custom {
            return Err(CoreError::UnknownField);
        }
        if self.custom.len() >= MAX_CUSTOM_FIELDS {
            return Err(CoreError::TooManyEntries);
        }
        validate_text("label", label, MAX_LABEL_CHARS)?;
        validate_text("value", value, MAX_FIELD_BYTES)?;
        self.custom.push(CustomField {
            label: Zeroizing::new(label.to_string()),
            value: Zeroizing::new(value.to_string()),
            hidden,
        });
        self.updated_at = now.clone();
        Ok(())
    }

    /// Links a passkey credential id (login only).
    pub fn add_passkey(&mut self, credential_id: &[u8], now: &Timestamp) -> CoreResult<()> {
        if !template(self.kind).passkeys {
            return Err(CoreError::UnknownField);
        }
        if self.passkeys.len() >= MAX_LINKED_PASSKEYS {
            return Err(CoreError::TooManyEntries);
        }
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(CoreError::InvalidLength {
                expected: MAX_CREDENTIAL_ID_BYTES,
                actual: credential_id.len(),
            });
        }
        if self.passkeys.iter().any(|id| id == credential_id) {
            return Err(CoreError::TooManyEntries);
        }
        self.passkeys.push(credential_id.to_vec());
        self.updated_at = now.clone();
        Ok(())
    }

    /// Replaces the tag list.
    pub fn set_tags(&mut self, tags: Vec<String>, now: &Timestamp) -> CoreResult<()> {
        if tags.len() > MAX_TAGS {
            return Err(CoreError::TooManyEntries);
        }
        let mut sorted: Vec<String> = Vec::with_capacity(tags.len());
        for tag in tags {
            validate_text("tag", &tag, MAX_TAG_CHARS)?;
            if sorted.iter().any(|existing| existing == &tag) {
                return Err(CoreError::InvalidText);
            }
            sorted.push(tag);
        }
        sorted.sort();
        self.tags = sorted;
        self.updated_at = now.clone();
        Ok(())
    }

    /// Sets or clears the favourite flag.
    pub fn set_favourite(&mut self, favourite: bool, now: &Timestamp) {
        self.favourite = favourite;
        self.updated_at = now.clone();
    }

    fn push_history(&mut self, name: &str, value: &str) {
        let entry = HistoryEntry {
            at: self.updated_at.clone(),
            value: Zeroizing::new(value.to_string()),
        };
        let list = self.history.entry(name.to_string()).or_default();
        list.insert(0, entry);
        list.truncate(MAX_HISTORY);
    }

    /// Canonical CBOR of the payload (SPEC §6.2), capped at 1 MiB.
    pub fn to_payload_bytes(&self) -> CoreResult<Vec<u8>> {
        let fields = Value::Map(
            self.fields
                .iter()
                .map(|(name, value)| (cbor_text(name), cbor_text(value.as_str())))
                .collect(),
        );
        let history = Value::Map(
            self.history
                .iter()
                .map(|(name, entries)| {
                    let items = entries
                        .iter()
                        .map(|entry| {
                            canonical_map(vec![
                                ("at", cbor_text(entry.at.as_str())),
                                ("value", cbor_text(entry.value.as_str())),
                            ])
                        })
                        .collect();
                    (cbor_text(name), Value::Array(items))
                })
                .collect(),
        );
        let urls = Value::Array(
            self.urls
                .iter()
                .map(|entry| {
                    canonical_map(vec![
                        ("url", cbor_text(entry.url.as_str())),
                        ("match", cbor_text(entry.match_rule.as_str())),
                    ])
                })
                .collect(),
        );
        let custom = Value::Array(
            self.custom
                .iter()
                .map(|entry| {
                    canonical_map(vec![
                        ("label", cbor_text(entry.label.as_str())),
                        ("value", cbor_text(entry.value.as_str())),
                        ("hidden", Value::Bool(entry.hidden)),
                    ])
                })
                .collect(),
        );
        let passkeys = Value::Array(
            self.passkeys
                .iter()
                .map(|id| cbor_bytes(id))
                .collect::<Vec<Value>>(),
        );

        let map = canonical_map(vec![
            ("v", Value::Integer(1i64.into())),
            ("kind", cbor_text(self.kind.as_str())),
            ("created_at", cbor_text(self.created_at.as_str())),
            ("updated_at", cbor_text(self.updated_at.as_str())),
            ("favourite", Value::Bool(self.favourite)),
            (
                "tags",
                Value::Array(self.tags.iter().map(|tag| cbor_text(tag)).collect()),
            ),
            ("fields", fields),
            ("history", history),
            ("urls", urls),
            ("custom", custom),
            ("passkeys", passkeys),
        ]);
        let encoded = canonical_bytes(&map)?;
        if encoded.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::PayloadTooLarge);
        }
        Ok(encoded)
    }

    /// Parses a payload produced by [`Item::to_payload_bytes`], binding it to
    /// the vault and item ids the envelope authenticated.
    pub fn from_payload_bytes(vault_id: VaultId, id: ItemId, payload: &[u8]) -> CoreResult<Self> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::PayloadTooLarge);
        }
        let entries = parse_map(payload)?;
        let expected = [
            "v",
            "kind",
            "created_at",
            "updated_at",
            "favourite",
            "tags",
            "fields",
            "history",
            "urls",
            "custom",
            "passkeys",
        ];
        if entries.len() != expected.len() {
            return Err(CoreError::MalformedPayload);
        }
        let find = |name: &str| -> CoreResult<&Value> {
            entries
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
                .ok_or(CoreError::MalformedPayload)
        };
        for (key, _) in &entries {
            if !expected.contains(&key.as_str()) {
                return Err(CoreError::MalformedPayload);
            }
        }

        if as_u64(find("v")?)? != 1 {
            return Err(CoreError::UnsupportedSchemaVersion);
        }
        let kind = ItemKind::parse(as_text(find("kind")?)?)?;
        let created_at = Timestamp::parse(as_text(find("created_at")?)?)?;
        let updated_at = Timestamp::parse(as_text(find("updated_at")?)?)?;
        if updated_at.unix_seconds() < created_at.unix_seconds() {
            return Err(CoreError::MalformedPayload);
        }
        let favourite = as_bool(find("favourite")?)?;

        let mut tags = Vec::new();
        for tag in as_array(find("tags")?)? {
            tags.push(as_text(tag)?.to_string());
        }

        let mut fields: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        for (name, value) in map_pairs(find("fields")?)? {
            if field_spec(kind, &name).is_none() {
                return Err(CoreError::UnknownField);
            }
            if fields.len() >= MAX_FIELDS {
                return Err(CoreError::TooManyEntries);
            }
            let text = as_text(value)?;
            validate_text(&name, text, MAX_FIELD_BYTES)?;
            validate_field_value(kind, &name, text)?;
            fields.insert(name, Zeroizing::new(text.to_string()));
        }

        let mut history: BTreeMap<String, Vec<HistoryEntry>> = BTreeMap::new();
        for (name, value) in map_pairs(find("history")?)? {
            let spec = field_spec(kind, &name).ok_or(CoreError::UnknownField)?;
            if !spec.secret {
                return Err(CoreError::MalformedPayload);
            }
            let entries_for_field = as_array(value)?;
            if entries_for_field.len() > MAX_HISTORY {
                return Err(CoreError::TooManyEntries);
            }
            let mut list = Vec::with_capacity(entries_for_field.len());
            for entry in entries_for_field {
                let pairs = map_pairs(entry)?;
                if pairs.len() != 2 {
                    return Err(CoreError::MalformedPayload);
                }
                let mut at = None;
                let mut text = None;
                for (key, value) in pairs {
                    match key.as_str() {
                        "at" => at = Some(Timestamp::parse(as_text(value)?)?),
                        "value" => text = Some(as_text(value)?.to_string()),
                        _ => return Err(CoreError::MalformedPayload),
                    }
                }
                let at = at.ok_or(CoreError::MalformedPayload)?;
                let value = text.ok_or(CoreError::MalformedPayload)?;
                validate_text("history", &value, MAX_FIELD_BYTES)?;
                list.push(HistoryEntry {
                    at,
                    value: Zeroizing::new(value),
                });
            }
            history.insert(name, list);
        }

        let mut urls = Vec::new();
        for entry in as_array(find("urls")?)? {
            if !template(kind).urls {
                return Err(CoreError::MalformedPayload);
            }
            if urls.len() >= MAX_URLS {
                return Err(CoreError::TooManyEntries);
            }
            let pairs = map_pairs(entry)?;
            if pairs.len() != 2 {
                return Err(CoreError::MalformedPayload);
            }
            let mut url = None;
            let mut rule = None;
            for (key, value) in pairs {
                match key.as_str() {
                    "url" => url = Some(as_text(value)?.to_string()),
                    "match" => rule = Some(UrlMatch::parse(as_text(value)?)?),
                    _ => return Err(CoreError::MalformedPayload),
                }
            }
            let url = url.ok_or(CoreError::MalformedPayload)?;
            validate_url(&url)?;
            urls.push(UrlEntry {
                url: Zeroizing::new(url),
                match_rule: rule.ok_or(CoreError::MalformedPayload)?,
            });
        }

        let mut custom = Vec::new();
        for entry in as_array(find("custom")?)? {
            if !template(kind).custom {
                return Err(CoreError::MalformedPayload);
            }
            if custom.len() >= MAX_CUSTOM_FIELDS {
                return Err(CoreError::TooManyEntries);
            }
            let pairs = map_pairs(entry)?;
            if pairs.len() != 3 {
                return Err(CoreError::MalformedPayload);
            }
            let mut label = None;
            let mut value = None;
            let mut hidden = None;
            for (key, entry_value) in pairs {
                match key.as_str() {
                    "label" => label = Some(as_text(entry_value)?.to_string()),
                    "value" => value = Some(as_text(entry_value)?.to_string()),
                    "hidden" => hidden = Some(as_bool(entry_value)?),
                    _ => return Err(CoreError::MalformedPayload),
                }
            }
            let label = label.ok_or(CoreError::MalformedPayload)?;
            validate_text("label", &label, MAX_LABEL_CHARS)?;
            let value = value.ok_or(CoreError::MalformedPayload)?;
            validate_text("value", &value, MAX_FIELD_BYTES)?;
            custom.push(CustomField {
                label: Zeroizing::new(label),
                value: Zeroizing::new(value),
                hidden: hidden.ok_or(CoreError::MalformedPayload)?,
            });
        }

        let mut passkeys = Vec::new();
        for entry in as_array(find("passkeys")?)? {
            if !template(kind).passkeys {
                return Err(CoreError::MalformedPayload);
            }
            if passkeys.len() >= MAX_LINKED_PASSKEYS {
                return Err(CoreError::TooManyEntries);
            }
            let id = as_bytes(entry)?;
            if id.is_empty() || id.len() > MAX_CREDENTIAL_ID_BYTES {
                return Err(CoreError::MalformedPayload);
            }
            passkeys.push(id.to_vec());
        }

        Ok(Self {
            id,
            vault_id,
            kind,
            favourite,
            tags,
            created_at,
            updated_at,
            fields,
            history,
            urls,
            custom,
            passkeys,
        })
    }

    /// The base64url credential id of a linked passkey, for display.
    pub fn passkey_id_text(id: &[u8]) -> String {
        base64url_encode(id)
    }
}

fn validate_text(name: &str, value: &str, max_chars: usize) -> CoreResult<()> {
    if value.chars().count() > max_chars || name.is_empty() {
        return Err(CoreError::InvalidText);
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(CoreError::InvalidText);
    }
    Ok(())
}

fn validate_url(url: &str) -> CoreResult<()> {
    if url.is_empty() || url.chars().count() > MAX_URL_CHARS {
        return Err(CoreError::InvalidText);
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CoreError::InvalidText);
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(CoreError::InvalidText);
    }
    Ok(())
}

/// Kind-specific value checks. A passkey must hold a key that can actually
/// sign, so a corrupt PKCS#8 blob never reaches the vault.
fn validate_field_value(kind: ItemKind, name: &str, value: &str) -> CoreResult<()> {
    match (kind, name) {
        (ItemKind::Passkey, "private_key_pkcs8") => {
            let der = base64url_decode(value)?;
            p256::SecretKey::from_pkcs8_der(&der).map_err(|_| CoreError::InvalidParameter)?;
        }
        (ItemKind::Passkey, "credential_id") => {
            if base64url_decode(value)?.is_empty() {
                return Err(CoreError::InvalidParameter);
            }
        }
        (ItemKind::Passkey, "sign_count") => {
            value
                .parse::<u32>()
                .map_err(|_| CoreError::InvalidParameter)?;
        }
        (ItemKind::Passkey, "backup_eligible") | (ItemKind::Passkey, "backup_state") => {
            if value != "true" && value != "false" {
                return Err(CoreError::InvalidParameter);
            }
        }
        (ItemKind::Passkey, "created_at") => {
            Timestamp::parse(value)?;
        }
        _ => {}
    }
    Ok(())
}

use p256::pkcs8::DecodePrivateKey;

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: VaultId = [0x22; 16];
    const ITEM: ItemId = [0x33; 16];

    fn now() -> Timestamp {
        Timestamp::parse("2026-11-05T09:30:00Z").expect("timestamp")
    }

    fn later() -> Timestamp {
        Timestamp::parse("2026-11-05T10:45:00Z").expect("timestamp")
    }

    fn login() -> Item {
        let mut item = Item::new(ITEM, VAULT, ItemKind::Login, now()).expect("item");
        item.set_field("title", "Demo bank", &now()).expect("title");
        item.set_field("username", "demo.user", &now())
            .expect("user");
        item.set_field("password", "first-password", &now())
            .expect("password");
        item
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let mut item = login();
        item.add_url("https://demo.example/login", UrlMatch::ExactHost, &now())
            .expect("url");
        item.add_custom("Customer ID", "1234", false, &now())
            .expect("custom");
        item.add_passkey(&[1u8, 2, 3, 4], &now()).expect("passkey");
        item.set_tags(vec!["bank".into(), "india".into()], &now())
            .expect("tags");

        let bytes = item.to_payload_bytes().expect("encode");
        let parsed = Item::from_payload_bytes(VAULT, ITEM, &bytes).expect("parse");
        assert_eq!(parsed.to_payload_bytes().expect("re-encode"), bytes);
        assert_eq!(parsed.field("password"), Some("first-password"));
        assert_eq!(parsed.urls().len(), 1);
        assert_eq!(parsed.urls()[0].match_rule(), UrlMatch::ExactHost);
        assert_eq!(parsed.custom()[0].label(), "Customer ID");
        assert_eq!(parsed.passkeys()[0], vec![1u8, 2, 3, 4]);
        assert_eq!(parsed.tags(), &["bank".to_string(), "india".to_string()]);
    }

    #[test]
    fn secret_history_keeps_the_last_ten_values() {
        let mut item = login();
        for index in 0..15 {
            item.set_field("password", &format!("password-{index}"), &later())
                .expect("set");
        }
        let history = item.history("password");
        assert_eq!(history.len(), MAX_HISTORY);
        assert_eq!(history[0].value(), "password-13");
        assert_eq!(history[MAX_HISTORY - 1].value(), "password-4");
        // A non-secret field never grows history.
        item.set_field("username", "other", &later()).expect("set");
        assert!(item.history("username").is_empty());
    }

    #[test]
    fn rejects_unknown_and_look_alike_field_names() {
        let mut item = login();
        for name in ["Password", "pass\u{043e}rd", "custom", "urls"] {
            assert_eq!(
                item.set_field(name, "x", &now()).expect_err("reject"),
                CoreError::UnknownField,
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_urls_without_a_scheme_and_control_characters() {
        let mut item = login();
        for bad in ["demo.example", "javascript:alert(1)", "https://a b", ""] {
            assert!(
                item.add_url(bad, UrlMatch::ExactHost, &now()).is_err(),
                "{bad}"
            );
        }
        assert!(item
            .add_url("https://demo.example", UrlMatch::BaseDomain, &now())
            .is_ok());
    }

    #[test]
    fn a_card_cannot_carry_a_url() {
        let mut card = Item::new(ITEM, VAULT, ItemKind::Card, now()).expect("card");
        assert_eq!(
            card.add_url("https://x.example", UrlMatch::ExactHost, &now())
                .expect_err("card"),
            CoreError::UnknownField
        );
    }

    #[test]
    fn passkey_keys_are_validated() {
        let mut passkey = Item::new(ITEM, VAULT, ItemKind::Passkey, now()).expect("passkey");
        assert_eq!(
            passkey
                .set_field("private_key_pkcs8", &base64url_encode(b"not a key"), &now())
                .expect_err("garbage"),
            CoreError::InvalidParameter
        );

        // A fixed scalar keeps the test deterministic and needs no RNG.
        let key = p256::SecretKey::from_slice(&[7u8; 32]).expect("scalar is in range");
        let der = p256::pkcs8::EncodePrivateKey::to_pkcs8_der(&key).expect("der");
        passkey
            .set_field(
                "private_key_pkcs8",
                &base64url_encode(der.as_bytes()),
                &now(),
            )
            .expect("valid key");
    }

    #[test]
    fn payload_is_tamper_evident_at_the_shape_level() {
        let item = login();
        let mut bytes = item.to_payload_bytes().expect("encode");
        // Append a byte: no longer canonical, so the parser refuses it.
        bytes.push(0);
        assert!(Item::from_payload_bytes(VAULT, ITEM, &bytes).is_err());
    }

    #[test]
    fn unknown_keys_are_rejected_even_in_canonical_form() {
        let bytes = login().to_payload_bytes().expect("encode");
        let mut cursor = std::io::Cursor::new(bytes);
        let mut value: Value = ciborium::de::from_reader(&mut cursor).expect("decode");
        let Value::Map(ref mut entries) = value else {
            panic!("map");
        };
        entries.push((cbor_text("extra"), Value::Bool(true)));
        let bytes = canonical_bytes(&value).expect("encode");
        assert_eq!(
            Item::from_payload_bytes(VAULT, ITEM, &bytes).expect_err("extra"),
            CoreError::MalformedPayload
        );
    }

    #[test]
    fn debug_never_prints_a_field_value() {
        let item = login();
        let printed = format!("{item:?}");
        assert!(!printed.contains("first-password"));
        assert!(!printed.contains("demo.user"));
        assert!(printed.contains("fields"));
    }

    #[test]
    fn india_templates_round_trip() {
        for (kind, name, value) in [
            (ItemKind::Aadhaar, "aadhaar_number", "1234 5678 9012"),
            (ItemKind::Pan, "pan_number", "ABCDE1234F"),
            (ItemKind::Upi, "upi_id", "demo@okbank"),
            (ItemKind::Passport, "passport_number", "P1234567"),
            (ItemKind::VoterId, "epic_number", "ABC1234567"),
        ] {
            let mut item = Item::new(ITEM, VAULT, kind, now()).expect("item");
            item.set_field("title", "Demo", &now()).expect("title");
            item.set_field(name, value, &now()).expect("field");
            let bytes = item.to_payload_bytes().expect("encode");
            let parsed = Item::from_payload_bytes(VAULT, ITEM, &bytes).expect("parse");
            assert_eq!(parsed.field(name), Some(value));
            assert_eq!(parsed.kind(), kind);
        }
    }

    #[test]
    fn history_of_a_secret_survives_a_round_trip() {
        let mut item = login();
        item.set_field("password", "second-password", &later())
            .expect("set");
        let bytes = item.to_payload_bytes().expect("encode");
        let parsed = Item::from_payload_bytes(VAULT, ITEM, &bytes).expect("parse");
        assert_eq!(parsed.history("password").len(), 1);
        assert_eq!(parsed.history("password")[0].value(), "first-password");
    }
}
