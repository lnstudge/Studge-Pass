//! The operation: SPEC §6.1–§6.3.
//!
//! An op is a signed statement that changes one vault. Its identity is
//! `BLAKE3(canonical bytes without sig)`; its signature covers that hash, not
//! the bytes, so verification always recomputes the message from local fields
//! (D-0207). A parser that trusted the transmitted bytes would let an attacker
//! choose what was signed.
//!
//! `move`, `membership` and `key_rotation` parse to a `kind` but are rejected
//! with [`CoreError::UnsupportedOpKind`] until the phase that defines their
//! payloads (D-0305): an op nobody can interpret must stop a client, not be
//! skipped.

use crate::cbor::{
    as_array, as_id16, as_text, as_u64, bytes as cbor_bytes, parse_map, text as cbor_text,
};
use crate::crypto::aad::{canonical_bytes, canonical_map, Aad, RecordType};
use crate::crypto::aead::{self, AeadKey, Envelope};
use crate::crypto::error::CryptoError;
use crate::crypto::signing::{verify, SigningKeyPair, Timestamp, SIGNATURE_BYTES};
use crate::error::{CoreError, CoreResult};
use crate::oplog::devices::DeviceRegistry;
use ciborium::value::Value;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// An operation identifier (SPEC §4.1).
pub type OpId = [u8; 16];
/// A BLAKE3 operation hash.
pub type OpHash = [u8; 32];

/// At most 16 parents per op (SPEC §6.11).
pub const MAX_PARENTS: usize = 16;

/// The closed set of op kinds (SPEC §6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    /// First write of an item.
    Create,
    /// Later write of an item.
    Update,
    /// Removal of an item.
    Delete,
    /// Reserved; rejected in v1 (D-0305).
    Move,
    /// Reserved for sharing (Phase 11).
    Membership,
    /// Reserved for vault-key rotation (Phase 11).
    KeyRotation,
}

impl OpKind {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Move => "move",
            Self::Membership => "membership",
            Self::KeyRotation => "key_rotation",
        }
    }

    /// Parses a wire name.
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "delete" => Ok(Self::Delete),
            "move" => Ok(Self::Move),
            "membership" => Ok(Self::Membership),
            "key_rotation" => Ok(Self::KeyRotation),
            _ => Err(CoreError::UnknownKind),
        }
    }

    /// The payload record type this kind must carry (SPEC §6.1).
    pub fn record_type(self) -> RecordType {
        match self {
            Self::Create | Self::Update => RecordType::OpItem,
            Self::Delete => RecordType::OpItemDelete,
            Self::Move => RecordType::OpItemMove,
            Self::Membership => RecordType::OpMembership,
            Self::KeyRotation => RecordType::OpKeyRotation,
        }
    }

    /// Whether the op names an item.
    pub fn touches_item(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Update | Self::Delete | Self::Move
        )
    }

    /// Whether this build can produce and materialise the kind (D-0305).
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Create | Self::Update | Self::Delete)
    }
}

/// An op without its signature.
#[derive(Clone)]
pub struct Op {
    vault_id: [u8; 16],
    op_id: OpId,
    parents: Vec<OpHash>,
    lamport: u64,
    device_id: [u8; 16],
    created_at: Timestamp,
    kind: OpKind,
    item_id: Option<[u8; 16]>,
    payload: Envelope,
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Op")
            .field("vault_id", &self.vault_id)
            .field("op_id", &self.op_id)
            .field("parents", &self.parents.len())
            .field("lamport", &self.lamport)
            .field("device_id", &self.device_id)
            .field("kind", &self.kind)
            .field("item", &self.item_id.is_some())
            .field("payload_len", &self.payload.ciphertext().len())
            .finish()
    }
}

impl Op {
    /// Builds an op, rejecting an unsupported kind and normalising `parents`.
    ///
    /// The argument list mirrors the wire format field by field. Grouping it
    /// behind a builder would only move the same number of values one level
    /// down, so the lint is allowed here rather than hidden elsewhere.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: [u8; 16],
        op_id: OpId,
        mut parents: Vec<OpHash>,
        lamport: u64,
        device_id: [u8; 16],
        created_at: Timestamp,
        kind: OpKind,
        item_id: Option<[u8; 16]>,
        payload: Envelope,
    ) -> CoreResult<Self> {
        if !kind.is_supported() {
            return Err(CoreError::UnsupportedOpKind);
        }
        if parents.len() > MAX_PARENTS {
            return Err(CoreError::TooManyEntries);
        }
        parents.sort_unstable();
        if parents.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CoreError::InvalidOp);
        }
        if lamport == 0 {
            return Err(CoreError::InvalidOp);
        }
        // Genesis is exactly "no parents, lamport 1"; everything else needs
        // parents, and the Lamport value is checked against them on insert.
        if parents.is_empty() && lamport != 1 {
            return Err(CoreError::InvalidOp);
        }
        match (kind.touches_item(), item_id) {
            (true, Some(_)) => {}
            (true, None) => return Err(CoreError::InvalidOp),
            (false, Some(_)) => return Err(CoreError::InvalidOp),
            (false, None) => {}
        }
        Ok(Self {
            vault_id,
            op_id,
            parents,
            lamport,
            device_id,
            created_at,
            kind,
            item_id,
            payload,
        })
    }

    /// The vault this op belongs to.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// The op id.
    pub fn op_id(&self) -> &OpId {
        &self.op_id
    }

    /// Parent hashes, sorted ascending.
    pub fn parents(&self) -> &[OpHash] {
        &self.parents
    }

    /// The Lamport clock.
    pub fn lamport(&self) -> u64 {
        self.lamport
    }

    /// The device that signed it.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// The advisory creation time (never used for ordering).
    pub fn created_at(&self) -> &Timestamp {
        &self.created_at
    }

    /// The kind.
    pub fn kind(&self) -> OpKind {
        self.kind
    }

    /// The item the op changes, when the kind touches one.
    pub fn item_id(&self) -> Option<&[u8; 16]> {
        self.item_id.as_ref()
    }

    /// The sealed payload.
    pub fn payload(&self) -> &Envelope {
        &self.payload
    }

    /// The canonical CBOR of the op **without** the signature (§6.2).
    pub fn canonical_bytes(&self) -> CoreResult<Vec<u8>> {
        let parents = Value::Array(self.parents.iter().map(|hash| cbor_bytes(hash)).collect());
        let item = match self.item_id {
            Some(id) => cbor_bytes(&id),
            None => Value::Null,
        };
        let payload = Value::Bytes(self.payload.to_cbor()?);
        let map = canonical_map(vec![
            ("suite", cbor_text(crate::crypto::labels::SUITE_V1)),
            ("vault_id", cbor_bytes(&self.vault_id)),
            ("op_id", cbor_bytes(&self.op_id)),
            ("parents", parents),
            ("lamport", Value::Integer(self.lamport.into())),
            ("device_id", cbor_bytes(&self.device_id)),
            ("created_at", cbor_text(self.created_at.as_str())),
            ("kind", cbor_text(self.kind.as_str())),
            ("item_id", item),
            ("schema_version", Value::Integer(1i64.into())),
            ("payload", payload),
        ]);
        Ok(canonical_bytes(&map)?)
    }

    /// `BLAKE3(canonical bytes without sig)` (SPEC §6.2).
    pub fn hash(&self) -> CoreResult<OpHash> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }

    /// Signs the hash with a device key (SPEC §6.3).
    pub fn sign(self, device: &SigningKeyPair) -> CoreResult<StoredOp> {
        let hash = self.hash()?;
        let signature = device.sign(&hash);
        Ok(StoredOp {
            op: self,
            signature,
        })
    }

    /// Seals an item payload for this op's kind and ids (SPEC §5.2, §5.3).
    pub fn seal_payload(
        vk: &crate::crypto::keys::VaultKey,
        vault_id: &[u8; 16],
        item_id: &[u8; 16],
        kind: OpKind,
        plaintext: &[u8],
    ) -> CoreResult<Envelope> {
        if !kind.touches_item() || !kind.is_supported() {
            return Err(CoreError::UnsupportedOpKind);
        }
        let key = op_key(vk, vault_id)?;
        let aad = Aad::builder(kind.record_type())
            .vault(*vault_id)
            .item(*item_id)
            .build()?;
        Ok(aead::seal(&key, &aad, plaintext)?)
    }

    /// Opens this op's payload under the vault key. A tag failure is final.
    pub fn open_payload(
        &self,
        vk: &crate::crypto::keys::VaultKey,
        expected_vault: &[u8; 16],
    ) -> CoreResult<Zeroizing<Vec<u8>>> {
        if &self.vault_id != expected_vault {
            return Err(CoreError::OpVerificationFailed);
        }
        let item_id = self.item_id.ok_or(CoreError::InvalidOp)?;
        let key = op_key(vk, expected_vault)?;
        let aad = Aad::builder(self.kind.record_type())
            .vault(*expected_vault)
            .item(item_id)
            .build()?;
        Ok(aead::open(&key, &aad, &self.payload)?)
    }
}

fn op_key(vk: &crate::crypto::keys::VaultKey, vault_id: &[u8; 16]) -> CoreResult<AeadKey> {
    Ok(crate::crypto::keys::op_payload_key(vk, vault_id)?)
}

/// An op plus its signature — what is stored and transmitted (SPEC §6.1).
#[derive(Clone)]
pub struct StoredOp {
    op: Op,
    signature: [u8; SIGNATURE_BYTES],
}

impl std::fmt::Debug for StoredOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredOp")
            .field("op", &self.op)
            .field("signed", &true)
            .finish()
    }
}

impl StoredOp {
    /// The unsigned part.
    pub fn op(&self) -> &Op {
        &self.op
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// The op hash.
    pub fn hash(&self) -> CoreResult<OpHash> {
        self.op.hash()
    }

    /// The stored form: the op's canonical map plus `sig` (§6.1).
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let mut entries: Vec<(String, Value)> = parse_map(&self.op.canonical_bytes()?)?;
        entries.push(("sig".to_string(), cbor_bytes(&self.signature)));
        // canonical_map takes &str keys; rebuild through the canonicaliser.
        let map = Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (cbor_text(&key), value))
                .collect(),
        );
        Ok(canonical_bytes(&map)?)
    }

    /// Parses a stored op, rejecting any key set other than the SPEC's.
    pub fn from_cbor(bytes: &[u8]) -> CoreResult<Self> {
        let entries = parse_map(bytes)?;
        let expected = [
            "suite",
            "vault_id",
            "op_id",
            "parents",
            "lamport",
            "device_id",
            "created_at",
            "kind",
            "item_id",
            "schema_version",
            "payload",
            "sig",
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
        if as_text(find("suite")?)? != crate::crypto::labels::SUITE_V1 {
            return Err(CoreError::Crypto(CryptoError::UnknownSuite));
        }
        if as_u64(find("schema_version")?)? != 1 {
            return Err(CoreError::UnsupportedSchemaVersion);
        }

        let vault_id = as_id16(find("vault_id")?)?.ok_or(CoreError::MalformedPayload)?;
        let op_id = as_id16(find("op_id")?)?.ok_or(CoreError::MalformedPayload)?;
        let device_id = as_id16(find("device_id")?)?.ok_or(CoreError::MalformedPayload)?;

        let mut parents = Vec::new();
        for parent in as_array(find("parents")?)? {
            let bytes = crate::cbor::as_bytes(parent)?;
            if bytes.len() != 32 {
                return Err(CoreError::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                });
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            parents.push(hash);
        }

        let lamport = as_u64(find("lamport")?)?;
        let created_at = Timestamp::parse(as_text(find("created_at")?)?)?;
        let kind = OpKind::parse(as_text(find("kind")?)?)?;
        let item_id = as_id16(find("item_id")?)?;
        let payload = Envelope::from_cbor(crate::cbor::as_bytes(find("payload")?)?)
            .map_err(CoreError::Crypto)?;
        let signature_bytes = crate::cbor::as_bytes(find("sig")?)?;
        if signature_bytes.len() != SIGNATURE_BYTES {
            return Err(CoreError::InvalidLength {
                expected: SIGNATURE_BYTES,
                actual: signature_bytes.len(),
            });
        }
        let mut signature = [0u8; SIGNATURE_BYTES];
        signature.copy_from_slice(signature_bytes);

        let op = Op::new(
            vault_id, op_id, parents, lamport, device_id, created_at, kind, item_id, payload,
        )?;

        // The signature must cover the hash of the fields we just parsed, not
        // the bytes that arrived. Re-encoding proves the two agree.
        let reencoded = {
            let mut entries: Vec<(String, Value)> = parse_map(&op.canonical_bytes()?)?;
            entries.push(("sig".to_string(), cbor_bytes(&signature)));
            let map = Value::Map(
                entries
                    .into_iter()
                    .map(|(key, value)| (cbor_text(&key), value))
                    .collect(),
            );
            canonical_bytes(&map)?
        };
        if reencoded != bytes {
            return Err(CoreError::MalformedPayload);
        }

        Ok(Self { op, signature })
    }

    /// Verifies the signature against the device key the registry holds, and
    /// the revocation cut-off at `created_at` (SPEC §6.3, §4.8).
    pub fn verify(&self, devices: &DeviceRegistry) -> CoreResult<()> {
        let hash = self.op.hash()?;
        let device_key = devices.key_at(&self.op.device_id, &self.op.created_at)?;
        verify(&device_key, &hash, &self.signature).map_err(|_| CoreError::OpVerificationFailed)
    }
}

/// Constant-time hash equality (AGENTS.md rule 5). Hashes are public, but the
/// habit is what keeps a future secret comparison honest.
pub fn hash_eq(left: &OpHash, right: &OpHash) -> bool {
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::SigningKeyPair;

    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];

    fn now() -> Timestamp {
        Timestamp::parse("2026-11-05T09:30:00Z").expect("timestamp")
    }

    fn vk() -> VaultKey {
        VaultKey::from_bytes([3u8; 32])
    }

    fn payload() -> Envelope {
        Op::seal_payload(&vk(), &VAULT, &ITEM, OpKind::Create, b"item bytes").expect("seal")
    }

    fn op() -> Op {
        Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            [9u8; 16],
            now(),
            OpKind::Create,
            Some(ITEM),
            payload(),
        )
        .expect("op")
    }

    #[test]
    fn hash_is_stable_and_covers_every_header_field() {
        let base = op();
        let hash = base.hash().expect("hash");
        assert_eq!(hash, base.hash().expect("again"));

        let other_kind = Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            [9u8; 16],
            now(),
            OpKind::Update,
            Some(ITEM),
            payload(),
        )
        .expect("op");
        assert!(!hash_eq(&hash, &other_kind.hash().expect("hash")));

        let other_device = Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            [8u8; 16],
            now(),
            OpKind::Create,
            Some(ITEM),
            payload(),
        )
        .expect("op");
        assert!(!hash_eq(&hash, &other_device.hash().expect("hash")));
    }

    #[test]
    fn signature_covers_the_hash_not_the_bytes() {
        let device = SigningKeyPair::from_seed([0x44; 32]);
        let stored = op().sign(&device).expect("sign");
        let hash = stored.hash().expect("hash");
        // Signing something else must not verify.
        let wrong = device.sign(b"not the hash");
        assert!(verify(&device.public_bytes(), &hash, &wrong).is_err());
        assert!(verify(&device.public_bytes(), &hash, stored.signature()).is_ok());
    }

    #[test]
    fn stored_form_round_trips_byte_for_byte() {
        let device = SigningKeyPair::from_seed([0x44; 32]);
        let stored = op().sign(&device).expect("sign");
        let bytes = stored.to_cbor().expect("encode");
        let parsed = StoredOp::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed.hash().expect("hash"), stored.hash().expect("hash"));
        assert_eq!(parsed.to_cbor().expect("re-encode"), bytes);
    }

    #[test]
    fn rejects_non_canonical_or_unknown_keys() {
        let device = SigningKeyPair::from_seed([0x44; 32]);
        let stored = op().sign(&device).expect("sign");
        let bytes = stored.to_cbor().expect("encode");

        let mut cursor = std::io::Cursor::new(bytes.clone());
        let mut value: Value = ciborium::de::from_reader(&mut cursor).expect("decode");
        let Value::Map(ref mut entries) = value else {
            panic!("map");
        };
        entries.push((cbor_text("extra"), Value::Bool(true)));
        let tampered = canonical_bytes(&value).expect("encode");
        assert!(StoredOp::from_cbor(&tampered).is_err());

        let mut truncated = bytes.clone();
        truncated.truncate(bytes.len() - 1);
        assert!(StoredOp::from_cbor(&truncated).is_err());
    }

    #[test]
    fn rejects_unsupported_kinds_and_bad_item_ids() {
        assert_eq!(
            Op::new(
                VAULT,
                [1u8; 16],
                vec![],
                1,
                [9u8; 16],
                now(),
                OpKind::Move,
                Some(ITEM),
                payload(),
            )
            .expect_err("move"),
            CoreError::UnsupportedOpKind
        );
        assert_eq!(
            Op::new(
                VAULT,
                [1u8; 16],
                vec![],
                1,
                [9u8; 16],
                now(),
                OpKind::Create,
                None,
                payload(),
            )
            .expect_err("no item"),
            CoreError::InvalidOp
        );
        assert_eq!(
            Op::new(
                VAULT,
                [1u8; 16],
                vec![],
                1,
                [9u8; 16],
                now(),
                OpKind::Membership,
                Some(ITEM),
                payload(),
            )
            .expect_err("membership"),
            CoreError::UnsupportedOpKind
        );
    }

    #[test]
    fn genesis_rules_and_parent_normalisation() {
        assert_eq!(
            Op::new(
                VAULT,
                [1u8; 16],
                vec![],
                2,
                [9u8; 16],
                now(),
                OpKind::Create,
                Some(ITEM),
                payload(),
            )
            .expect_err("genesis lamport"),
            CoreError::InvalidOp
        );
        let mut parents = vec![[2u8; 32], [1u8; 32]];
        let op = Op::new(
            VAULT,
            [1u8; 16],
            parents.clone(),
            2,
            [9u8; 16],
            now(),
            OpKind::Create,
            Some(ITEM),
            payload(),
        )
        .expect("op");
        parents.sort_unstable();
        assert_eq!(op.parents(), parents.as_slice());

        let duplicated = vec![[1u8; 32], [1u8; 32]];
        assert_eq!(
            Op::new(
                VAULT,
                [1u8; 16],
                duplicated,
                2,
                [9u8; 16],
                now(),
                OpKind::Create,
                Some(ITEM),
                payload(),
            )
            .expect_err("duplicate parents"),
            CoreError::InvalidOp
        );
    }

    #[test]
    fn payload_is_bound_to_the_item_and_kind() {
        let op = op();
        let opened = op.open_payload(&vk(), &VAULT).expect("open");
        assert_eq!(&opened[..], b"item bytes");
        // Another vault id is a different AAD scope.
        assert_eq!(
            op.open_payload(&vk(), &[0x77; 16]).expect_err("vault"),
            CoreError::OpVerificationFailed
        );
        // A different payload key fails the tag.
        let other = VaultKey::from_bytes([4u8; 32]);
        assert!(op.open_payload(&other, &VAULT).is_err());
    }
}
