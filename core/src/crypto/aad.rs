//! Typed AAD builder and deterministic CBOR (SPEC §5.3).
//!
//! The AAD binds a ciphertext to exactly one place in the data model. Two
//! properties matter and are enforced here:
//!
//! - **Typed.** A caller names a [`RecordType`] and the builder checks that the
//!   scope, item id and field name are exactly what that type allows. You
//!   cannot forget the AAD: [`crate::crypto::aead::seal`] takes an [`Aad`].
//! - **Deterministic.** The map is encoded with RFC 8949 §4.2.1 key ordering
//!   (shorter keys first, then bytewise), so every client produces the same
//!   bytes for the same context.

use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::labels::SUITE_V1;
use ciborium::value::Value;

/// The entry name inside an account key bundle (SPEC §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleEntry {
    /// Ed25519 identity signing key.
    IdentitySigning,
    /// X25519 identity encryption key.
    IdentityEncryption,
    /// ML-KEM-768 identity key.
    IdentityKem,
    /// Last verified heads per vault.
    HeadPins,
    /// Certified devices and revocations.
    DeviceList,
    /// Bundle format version.
    BundleVersion,
}

impl BundleEntry {
    /// The wire name used inside `record_type`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentitySigning => "identity_signing",
            Self::IdentityEncryption => "identity_encryption",
            Self::IdentityKem => "identity_kem",
            Self::HeadPins => "head_pins",
            Self::DeviceList => "device_list",
            Self::BundleVersion => "bundle_version",
        }
    }
}

/// The closed set of record types from SPEC §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// The wrapped Account Key.
    Ak,
    /// One entry of the account key bundle.
    Bundle(BundleEntry),
    /// A vault key wrapped for its owner.
    VkOwner,
    /// A vault key wrapped for a member (Phase 11).
    VkShare,
    /// A wrapped item key.
    Ik,
    /// One encrypted item field.
    ItemField,
    /// An op payload for create/update.
    OpItem,
    /// An op payload for delete.
    OpItemDelete,
    /// An op payload for move.
    OpItemMove,
    /// An op payload for a membership change.
    OpMembership,
    /// An op payload for a key rotation.
    OpKeyRotation,
    /// A guardian's recovery share (Phase 12).
    RecoveryShare,
    /// An emergency-access grant (Phase 12).
    EmergencyGrant,
    /// A key-transparency leaf (Phase 11).
    KtEntry,
}

impl RecordType {
    /// The exact `record_type` string that goes into the AAD.
    pub fn as_str(self) -> String {
        match self {
            Self::Ak => "ak".to_string(),
            Self::Bundle(entry) => format!("bundle/{}", entry.as_str()),
            Self::VkOwner => "vk-owner".to_string(),
            Self::VkShare => "vk-share".to_string(),
            Self::Ik => "ik".to_string(),
            Self::ItemField => "item-field".to_string(),
            Self::OpItem => "op/item".to_string(),
            Self::OpItemDelete => "op/item-delete".to_string(),
            Self::OpItemMove => "op/item-move".to_string(),
            Self::OpMembership => "op/membership".to_string(),
            Self::OpKeyRotation => "op/key-rotation".to_string(),
            Self::RecoveryShare => "recovery-share".to_string(),
            Self::EmergencyGrant => "emergency-grant".to_string(),
            Self::KtEntry => "kt-entry".to_string(),
        }
    }

    /// Whether the scope is an account id or a vault id.
    fn account_scoped(self) -> bool {
        matches!(
            self,
            Self::Ak | Self::Bundle(_) | Self::RecoveryShare | Self::EmergencyGrant | Self::KtEntry
        )
    }

    /// Whether an `item_id` is required.
    fn needs_item(self) -> bool {
        matches!(
            self,
            Self::Ik | Self::ItemField | Self::OpItem | Self::OpItemDelete | Self::OpItemMove
        )
    }

    /// Whether a `field_name` is required.
    fn needs_field(self) -> bool {
        matches!(self, Self::ItemField)
    }
}

/// Which identifier the scope carries.
#[derive(Debug, Clone, Copy)]
enum Scope {
    Account([u8; 16]),
    Vault([u8; 16]),
}

/// A validated AAD, already in canonical CBOR.
#[derive(Clone, PartialEq, Eq)]
pub struct Aad(Vec<u8>);

impl Aad {
    /// Starts a builder for `record_type`.
    pub fn builder(record_type: RecordType) -> AadBuilder {
        AadBuilder {
            record_type,
            scope: None,
            item_id: None,
            field_name: None,
            schema_version: 1,
        }
    }

    /// The canonical CBOR bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Aad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aad").field("bytes", &self.0.len()).finish()
    }
}

/// Builder for [`Aad`]. `build()` enforces the per-record-type rules.
#[derive(Debug, Clone)]
pub struct AadBuilder {
    record_type: RecordType,
    scope: Option<Scope>,
    item_id: Option<[u8; 16]>,
    field_name: Option<String>,
    schema_version: u8,
}

impl AadBuilder {
    /// Account-scoped records (`ak`, key bundle, recovery, transparency).
    pub fn account(mut self, account_id: [u8; 16]) -> Self {
        self.scope = Some(Scope::Account(account_id));
        self
    }

    /// Vault-scoped records (vault key, item key, item fields, op payloads).
    pub fn vault(mut self, vault_id: [u8; 16]) -> Self {
        self.scope = Some(Scope::Vault(vault_id));
        self
    }

    /// The item this record belongs to.
    pub fn item(mut self, item_id: [u8; 16]) -> Self {
        self.item_id = Some(item_id);
        self
    }

    /// The field name (only for `item-field`).
    pub fn field(mut self, name: &str) -> Self {
        self.field_name = Some(name.to_string());
        self
    }

    /// Overrides the schema version (v1 only; anything else is rejected).
    pub fn schema_version(mut self, version: u8) -> Self {
        self.schema_version = version;
        self
    }

    /// Validates the combination and produces canonical CBOR.
    pub fn build(self) -> CryptoResult<Aad> {
        if self.schema_version != 1 {
            return Err(CryptoError::UnsupportedSchemaVersion);
        }

        let scope_bytes = match (self.scope, self.record_type.account_scoped()) {
            (Some(Scope::Account(id)), true) => id,
            (Some(Scope::Vault(id)), false) => id,
            (Some(_), _) => return Err(CryptoError::MissingAadField),
            (None, _) => return Err(CryptoError::MissingAadField),
        };

        match (self.record_type.needs_item(), self.item_id) {
            (true, Some(_)) => {}
            (true, None) => return Err(CryptoError::MissingAadField),
            (false, Some(_)) => return Err(CryptoError::UnexpectedAadField),
            (false, None) => {}
        }

        let field_name = match (self.record_type.needs_field(), self.field_name) {
            (true, Some(name)) => {
                validate_field_name(&name)?;
                Some(name)
            }
            (true, None) => return Err(CryptoError::MissingAadField),
            (false, Some(_)) => return Err(CryptoError::UnexpectedAadField),
            (false, None) => None,
        };

        let item_value = match self.item_id {
            Some(id) => Value::Bytes(id.to_vec()),
            None => Value::Null,
        };
        let field_value = match field_name {
            Some(name) => Value::Text(name),
            None => Value::Null,
        };

        let map = canonical_map(vec![
            ("suite", Value::Text(SUITE_V1.to_string())),
            ("scope", Value::Bytes(scope_bytes.to_vec())),
            ("item_id", item_value),
            ("record_type", Value::Text(self.record_type.as_str())),
            ("field_name", field_value),
            ("schema_version", Value::Integer(1i64.into())),
        ]);
        Ok(Aad(canonical_bytes(&map)?))
    }
}

/// Field names come from item templates (SPEC §5.6): a short ASCII identifier,
/// never free text. This blocks look-alike labels at the crypto layer (R-0114).
fn validate_field_name(name: &str) -> CryptoResult<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(CryptoError::InvalidEncoding)
    }
}

/// Builds a CBOR map whose keys are ordered per RFC 8949 §4.2.1.
pub fn canonical_map(entries: Vec<(&str, Value)>) -> Value {
    let mut keyed: Vec<(Vec<u8>, Value, Value)> = entries
        .into_iter()
        .map(|(key, value)| {
            let encoded = encode_text_key(key);
            (encoded, Value::Text(key.to_string()), value)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    Value::Map(
        keyed
            .into_iter()
            .map(|(_, key, value)| (key, value))
            .collect(),
    )
}

fn encode_text_key(key: &str) -> Vec<u8> {
    let len = key.len();
    let mut out = Vec::with_capacity(len + 9);
    if len < 24 {
        out.push(0x60 | len as u8);
    } else if len < 256 {
        out.push(0x78);
        out.push(len as u8);
    } else {
        out.push(0x79);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
    out.extend_from_slice(key.as_bytes());
    out
}

/// Recursively sorts map entries into canonical order.
fn canonicalise(value: &Value) -> CryptoResult<Value> {
    match value {
        Value::Map(entries) => {
            let mut keyed: Vec<(Vec<u8>, Value, Value)> = Vec::with_capacity(entries.len());
            for (key, entry) in entries {
                let mut encoded = Vec::new();
                ciborium::ser::into_writer(key, &mut encoded)
                    .map_err(|_| CryptoError::MalformedCbor)?;
                keyed.push((encoded, canonicalise(key)?, canonicalise(entry)?));
            }
            keyed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            Ok(Value::Map(
                keyed
                    .into_iter()
                    .map(|(_, key, value)| (key, value))
                    .collect(),
            ))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalise(item)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

/// Encodes any value as canonical CBOR.
pub fn canonical_bytes(value: &Value) -> CryptoResult<Vec<u8>> {
    let canonical = canonicalise(value)?;
    let mut out = Vec::new();
    ciborium::ser::into_writer(&canonical, &mut out).map_err(|_| CryptoError::MalformedCbor)?;
    Ok(out)
}

/// Parses CBOR and rejects anything not already in canonical form.
pub fn parse_strict(bytes: &[u8]) -> CryptoResult<Value> {
    let value: Value = ciborium::de::from_reader(bytes).map_err(|_| CryptoError::MalformedCbor)?;
    let reencoded = canonical_bytes(&value)?;
    if reencoded != bytes {
        return Err(CryptoError::NonCanonicalCbor);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    const ACCOUNT: [u8; 16] = [0x11; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];

    fn field_aad() -> Aad {
        Aad::builder(RecordType::ItemField)
            .vault(VAULT)
            .item(ITEM)
            .field("password")
            .build()
            .expect("valid")
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(field_aad().as_bytes(), field_aad().as_bytes());
    }

    #[test]
    fn every_field_changes_the_bytes() {
        let base = field_aad();
        let other_field = Aad::builder(RecordType::ItemField)
            .vault(VAULT)
            .item(ITEM)
            .field("username")
            .build()
            .expect("valid");
        let other_item = Aad::builder(RecordType::ItemField)
            .vault(VAULT)
            .item([0x44; 16])
            .field("password")
            .build()
            .expect("valid");
        let other_vault = Aad::builder(RecordType::ItemField)
            .vault([0x55; 16])
            .item(ITEM)
            .field("password")
            .build()
            .expect("valid");
        assert_ne!(base.as_bytes(), other_field.as_bytes());
        assert_ne!(base.as_bytes(), other_item.as_bytes());
        assert_ne!(base.as_bytes(), other_vault.as_bytes());
    }

    #[test]
    fn keys_are_in_canonical_order() {
        let value = parse_strict(field_aad().as_bytes()).expect("canonical");
        let Value::Map(entries) = value else {
            panic!("AAD must be a map");
        };
        let keys: Vec<String> = entries
            .iter()
            .map(|(k, _)| match k {
                Value::Text(t) => t.clone(),
                other => panic!("unexpected key {other:?}"),
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                "scope",
                "suite",
                "item_id",
                "field_name",
                "record_type",
                "schema_version"
            ]
        );
    }

    #[test]
    fn rejects_missing_scope_item_and_field() {
        assert_eq!(
            Aad::builder(RecordType::ItemField)
                .vault(VAULT)
                .field("password")
                .build()
                .expect_err("item missing"),
            CryptoError::MissingAadField
        );
        assert_eq!(
            Aad::builder(RecordType::ItemField)
                .vault(VAULT)
                .item(ITEM)
                .build()
                .expect_err("field missing"),
            CryptoError::MissingAadField
        );
        assert!(!Aad::builder(RecordType::Ak)
            .account(ACCOUNT)
            .build()
            .expect("account + no item is right for ak")
            .as_bytes()
            .is_empty());
        assert_eq!(
            Aad::builder(RecordType::Ak)
                .vault(VAULT)
                .build()
                .expect_err("wrong scope kind"),
            CryptoError::MissingAadField
        );
    }

    #[test]
    fn rejects_item_or_field_where_not_allowed() {
        assert_eq!(
            Aad::builder(RecordType::Ak)
                .account(ACCOUNT)
                .item(ITEM)
                .build()
                .expect_err("item not allowed"),
            CryptoError::UnexpectedAadField
        );
        assert_eq!(
            Aad::builder(RecordType::Ik)
                .vault(VAULT)
                .item(ITEM)
                .field("password")
                .build()
                .expect_err("field not allowed"),
            CryptoError::UnexpectedAadField
        );
    }

    #[test]
    fn rejects_look_alike_field_names() {
        for name in [
            "Passwort",
            "pass wort",
            "pass\u{043e}rd",
            "",
            &"a".repeat(65),
        ] {
            let result = Aad::builder(RecordType::ItemField)
                .vault(VAULT)
                .item(ITEM)
                .field(name)
                .build();
            assert_eq!(
                result.expect_err("must reject"),
                CryptoError::InvalidEncoding,
                "name: {name:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_schema_version() {
        assert_eq!(
            Aad::builder(RecordType::Ak)
                .account(ACCOUNT)
                .schema_version(2)
                .build()
                .expect_err("v2 unknown"),
            CryptoError::UnsupportedSchemaVersion
        );
    }

    #[test]
    fn strict_parser_rejects_non_canonical_maps() {
        // A map with the keys in the wrong order must be rejected.
        let shuffled = Value::Map(vec![
            (Value::Text("suite".into()), Value::Text("v1".into())),
            (Value::Text("scope".into()), Value::Bytes(vec![0u8; 16])),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&shuffled, &mut bytes).expect("encode");
        assert_eq!(
            parse_strict(&bytes).expect_err("must reject"),
            CryptoError::NonCanonicalCbor
        );
    }
}
