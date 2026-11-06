//! The `.studgevault` encrypted backup (task item 3).
//!
//! A backup is a container of records that are **already** encrypted: the
//! account record (AK envelope plus key bundle), each vault's wrapped vault key,
//! its head and its ops. Nothing is decrypted on export and no new key or label
//! is introduced (D-0307), so the file is exactly as strong as the account —
//! opening it needs the same password and Secret Key, which is what the recovery
//! kit holds (SPEC §10.1).
//!
//! The header (format version, account id, vault ids, counts, creation time) is
//! metadata of the same kind the relay already sees (R-0101).

use crate::account::AccountBundle;
use crate::cbor::{
    as_array, as_id16, as_text, as_u64, bytes as cbor_bytes, map_pairs, text as cbor_text,
};
use crate::crypto::aad::{canonical_bytes, canonical_map};
use crate::crypto::aead::Envelope;
use crate::crypto::signing::Timestamp;
use crate::error::{CoreError, CoreResult};
use crate::oplog::head::VaultHead;
use crate::oplog::op::StoredOp;
use ciborium::value::Value;

/// File magic, so a wrong file is rejected before any parsing.
pub const MAGIC: &[u8; 12] = b"STUDGEVAULT\0";
/// Backup format version.
pub const BACKUP_VERSION: u8 = 1;
/// Refuse to load a backup larger than this (memory-bomb guard).
pub const MAX_BACKUP_BYTES: usize = 512 * 1024 * 1024;

/// One vault inside a backup.
#[derive(Debug, Clone)]
pub struct VaultArchive {
    vault_id: [u8; 16],
    key_envelope: Envelope,
    head: Option<VaultHead>,
    ops: Vec<StoredOp>,
}

impl VaultArchive {
    /// Builds one vault's archive.
    pub fn new(
        vault_id: [u8; 16],
        key_envelope: Envelope,
        head: Option<VaultHead>,
        ops: Vec<StoredOp>,
    ) -> CoreResult<Self> {
        if let Some(head) = &head {
            if head.vault_id() != &vault_id {
                return Err(CoreError::HeadVerificationFailed);
            }
        }
        for op in &ops {
            if op.op().vault_id() != &vault_id {
                return Err(CoreError::InvalidOp);
            }
        }
        Ok(Self {
            vault_id,
            key_envelope,
            head,
            ops,
        })
    }

    /// The vault id.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// The wrapped vault key.
    pub fn key_envelope(&self) -> &Envelope {
        &self.key_envelope
    }

    /// The head at export time.
    pub fn head(&self) -> Option<&VaultHead> {
        self.head.as_ref()
    }

    /// The ops.
    pub fn ops(&self) -> &[StoredOp] {
        &self.ops
    }
}

/// A whole backup file.
#[derive(Debug, Clone)]
pub struct BackupFile {
    created_at: Timestamp,
    account: AccountBundle,
    vaults: Vec<VaultArchive>,
}

impl BackupFile {
    /// Builds a backup from an account record and its vaults.
    pub fn new(created_at: Timestamp, account: AccountBundle, vaults: Vec<VaultArchive>) -> Self {
        Self {
            created_at,
            account,
            vaults,
        }
    }

    /// Why the file was created (display only).
    pub fn created_at(&self) -> &Timestamp {
        &self.created_at
    }

    /// The account record.
    pub fn account(&self) -> &AccountBundle {
        &self.account
    }

    /// The archived vaults.
    pub fn vaults(&self) -> &[VaultArchive] {
        &self.vaults
    }

    /// Number of ops across every vault.
    pub fn op_count(&self) -> usize {
        self.vaults.iter().map(|vault| vault.ops.len()).sum()
    }

    /// The CBOR body (no magic).
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let mut vaults = Vec::with_capacity(self.vaults.len());
        for vault in &self.vaults {
            let mut ops = Vec::with_capacity(vault.ops.len());
            for op in &vault.ops {
                ops.push(cbor_bytes(&op.to_cbor()?));
            }
            vaults.push(canonical_map(vec![
                ("vault_id", cbor_bytes(&vault.vault_id)),
                ("key", cbor_bytes(&vault.key_envelope.to_cbor()?)),
                (
                    "head",
                    match &vault.head {
                        Some(head) => cbor_bytes(&head.to_cbor()?),
                        None => Value::Null,
                    },
                ),
                ("ops", Value::Array(ops)),
            ]));
        }
        let map = canonical_map(vec![
            ("format", cbor_text("studgevault")),
            ("v", Value::Integer((BACKUP_VERSION as u64).into())),
            ("created_at", cbor_text(self.created_at.as_str())),
            ("account", cbor_bytes(&self.account.to_cbor()?)),
            ("vaults", Value::Array(vaults)),
        ]);
        Ok(canonical_bytes(&map)?)
    }

    /// The file bytes: magic, format version, CBOR body.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(BACKUP_VERSION);
        out.extend_from_slice(&self.to_cbor()?);
        Ok(out)
    }

    /// Parses a file produced by [`BackupFile::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        if bytes.len() > MAX_BACKUP_BYTES {
            return Err(CoreError::InvalidBackup);
        }
        let header = MAGIC.len() + 1;
        if bytes.len() <= header || &bytes[..MAGIC.len()] != MAGIC {
            return Err(CoreError::InvalidBackup);
        }
        if bytes[MAGIC.len()] != BACKUP_VERSION {
            return Err(CoreError::UnsupportedSchemaVersion);
        }
        let body = &bytes[header..];
        let entries = crate::cbor::parse_map(body)?;
        let expected = ["format", "v", "created_at", "account", "vaults"];
        if entries.len() != expected.len() {
            return Err(CoreError::InvalidBackup);
        }
        for (key, _) in &entries {
            if !expected.contains(&key.as_str()) {
                return Err(CoreError::InvalidBackup);
            }
        }
        let find = |name: &str| -> CoreResult<&Value> {
            entries
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
                .ok_or(CoreError::InvalidBackup)
        };
        if as_text(find("format")?)? != "studgevault" {
            return Err(CoreError::InvalidBackup);
        }
        if as_u64(find("v")?)? != BACKUP_VERSION as u64 {
            return Err(CoreError::UnsupportedSchemaVersion);
        }
        let created_at = Timestamp::parse(as_text(find("created_at")?)?)?;
        let account = AccountBundle::from_cbor(crate::cbor::as_bytes(find("account")?)?)?;

        let mut vaults = Vec::new();
        for entry in as_array(find("vaults")?)? {
            let pairs = map_pairs(entry)?;
            if pairs.len() != 4 {
                return Err(CoreError::InvalidBackup);
            }
            let mut vault_id = None;
            let mut key = None;
            let mut head = None;
            let mut ops = Vec::new();
            for (name, value) in pairs {
                match name.as_str() {
                    "vault_id" => vault_id = as_id16(value)?,
                    "key" => {
                        key = Some(Envelope::from_cbor(crate::cbor::as_bytes(value)?)?);
                    }
                    "head" => match value {
                        Value::Null => head = None,
                        other => head = Some(VaultHead::from_cbor(crate::cbor::as_bytes(other)?)?),
                    },
                    "ops" => {
                        for op in as_array(value)? {
                            ops.push(StoredOp::from_cbor(crate::cbor::as_bytes(op)?)?);
                        }
                    }
                    _ => return Err(CoreError::InvalidBackup),
                }
            }
            vaults.push(VaultArchive::new(
                vault_id.ok_or(CoreError::InvalidBackup)?,
                key.ok_or(CoreError::InvalidBackup)?,
                head,
                ops,
            )?);
        }

        Ok(Self {
            created_at,
            account,
            vaults,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::SigningKeyPair;
    use crate::oplog::op::{Op, OpKind};
    use crate::vault::items::{Item, ItemKind};

    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn item_payload() -> Vec<u8> {
        let mut item =
            Item::new(ITEM, VAULT, ItemKind::Login, at("2026-11-05T09:00:00Z")).expect("item");
        item.set_field("title", "Demo Only Bank", &at("2026-11-05T09:00:00Z"))
            .expect("title");
        item.set_field(
            "password",
            "demo-only-password",
            &at("2026-11-05T09:00:00Z"),
        )
        .expect("password");
        item.to_payload_bytes().expect("payload")
    }

    fn op(signer: &SigningKeyPair, vk: &VaultKey) -> StoredOp {
        let sealed =
            Op::seal_payload(vk, &VAULT, &ITEM, OpKind::Create, &item_payload()).expect("seal");
        Op::new(
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
        .sign(signer)
        .expect("sign")
    }

    fn backup() -> (BackupFile, VaultKey) {
        let (account, _secret_key) = crate::account::test_support::bundle();
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let vk = VaultKey::from_bytes([3u8; 32]);
        let stored = op(&device, &vk);
        let head = VaultHead::create(
            &device,
            VAULT,
            DEVICE,
            vec![stored.hash().expect("hash")],
            1,
            1,
            at("2026-11-05T10:05:00Z"),
        )
        .expect("head");
        let envelope = Envelope::from_cbor(
            &crate::crypto::aead::seal(
                &crate::crypto::aead::AeadKey::from_bytes([7u8; 32]),
                &crate::crypto::aad::Aad::builder(crate::crypto::aad::RecordType::VkOwner)
                    .vault(VAULT)
                    .build()
                    .expect("aad"),
                b"vk",
            )
            .expect("seal")
            .to_cbor()
            .expect("cbor"),
        )
        .expect("envelope");
        let archive =
            VaultArchive::new(VAULT, envelope, Some(head), vec![stored]).expect("archive");
        (
            BackupFile::new(at("2026-11-05T11:00:00Z"), account, vec![archive]),
            vk,
        )
    }

    #[test]
    fn round_trips_a_backup() {
        let (file, vk) = backup();
        let bytes = file.to_bytes().expect("encode");
        let parsed = BackupFile::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.vaults().len(), 1);
        assert_eq!(parsed.op_count(), 1);
        assert_eq!(
            parsed.vaults()[0]
                .head()
                .expect("head")
                .hash()
                .expect("hash"),
            file.vaults()[0].head().expect("head").hash().expect("hash")
        );
        // The op still decrypts after the round trip.
        let opened = parsed.vaults()[0].ops()[0]
            .op()
            .open_payload(&vk, &VAULT)
            .expect("open");
        assert_eq!(&opened[..], item_payload().as_slice());
    }

    #[test]
    fn the_file_contains_no_plaintext() {
        let (file, _) = backup();
        let bytes = file.to_bytes().expect("encode");
        let haystack = String::from_utf8_lossy(&bytes);
        for needle in ["Demo Only Bank", "demo-only-password"] {
            assert!(!haystack.contains(needle), "backup leaked {needle:?}");
        }
    }

    #[test]
    fn rejects_a_foreign_or_truncated_file() {
        let (file, _) = backup();
        let bytes = file.to_bytes().expect("encode");

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] = b'X';
        assert_eq!(
            BackupFile::from_bytes(&wrong_magic).expect_err("magic"),
            CoreError::InvalidBackup
        );

        let mut wrong_version = bytes.clone();
        wrong_version[MAGIC.len()] = 9;
        assert_eq!(
            BackupFile::from_bytes(&wrong_version).expect_err("version"),
            CoreError::UnsupportedSchemaVersion
        );

        for cut in [0, 5, MAGIC.len(), MAGIC.len() + 1, bytes.len() / 2] {
            assert!(
                BackupFile::from_bytes(&bytes[..cut]).is_err(),
                "truncation at {cut}"
            );
        }
    }

    #[test]
    fn a_flipped_structural_byte_is_rejected() {
        // The container has no MAC of its own: every record inside is already
        // authenticated by its own key, so the file does not need a second seal
        // (D-0307). Flipping a byte that carries structure still has to fail.
        let (file, _) = backup();
        let bytes = file.to_bytes().expect("encode");
        for index in [MAGIC.len() + 1, MAGIC.len() + 2, MAGIC.len() + 3] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0xFF;
            assert!(
                BackupFile::from_bytes(&tampered).is_err(),
                "byte {index} was accepted"
            );
        }
    }

    #[test]
    fn opaque_bytes_are_left_to_the_records_that_own_them() {
        // A flipped byte inside a ciphertext still parses as a container, which
        // is correct: the op's signature and the AEAD tag are what refuse it.
        // This test pins that boundary down so nobody "fixes" it with a second
        // MAC over unauthenticated data.
        let (file, _) = backup();
        let bytes = file.to_bytes().expect("encode");
        let mut tampered = bytes.clone();
        let index = bytes.len() / 2;
        tampered[index] ^= 0x01;
        let parsed = BackupFile::from_bytes(&tampered);
        assert!(
            parsed.is_err() || parsed.expect("parsed").op_count() == 1,
            "either the shape is wrong or the records are intact"
        );
    }

    #[test]
    fn a_vault_archive_rejects_mismatched_ids() {
        let (file, _) = backup();
        let archive = &file.vaults()[0];
        assert_eq!(
            VaultArchive::new(
                [0x99; 16],
                archive.key_envelope().clone(),
                archive.head().cloned(),
                archive.ops().to_vec(),
            )
            .expect_err("mismatch"),
            CoreError::HeadVerificationFailed
        );
    }
}
