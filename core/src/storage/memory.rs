//! An in-memory [`LocalStore`] for tests and for hosts without a filesystem.

use crate::account::AccountBundle;
use crate::crypto::aead::Envelope;
use crate::error::{CoreError, CoreResult};
use crate::oplog::head::VaultHead;
use crate::oplog::op::{OpHash, StoredOp};
use crate::storage::{check_schema, LocalStore, META_SCHEMA_VERSION, SCHEMA_VERSION};
use std::collections::BTreeMap;

/// A store that lives in process memory.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    ops: BTreeMap<([u8; 16], OpHash), StoredOp>,
    heads: BTreeMap<[u8; 16], VaultHead>,
    bundles: BTreeMap<[u8; 16], AccountBundle>,
    vault_keys: BTreeMap<[u8; 16], Envelope>,
    meta: BTreeMap<String, Vec<u8>>,
}

impl MemoryStore {
    /// An empty store with the current schema version recorded.
    pub fn new() -> Self {
        let mut store = Self::default();
        store.meta.insert(
            META_SCHEMA_VERSION.to_string(),
            SCHEMA_VERSION.to_be_bytes().to_vec(),
        );
        store
    }
}

impl LocalStore for MemoryStore {
    fn schema_version(&self) -> CoreResult<u32> {
        let raw = self
            .meta
            .get(META_SCHEMA_VERSION)
            .ok_or(CoreError::UnsupportedSchemaVersion)?;
        if raw.len() != 4 {
            return Err(CoreError::UnsupportedSchemaVersion);
        }
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(raw);
        let version = u32::from_be_bytes(bytes);
        check_schema(version)?;
        Ok(version)
    }

    fn put_op(&mut self, op: &StoredOp) -> CoreResult<()> {
        let hash = op.hash()?;
        self.ops.insert((*op.op().vault_id(), hash), op.clone());
        Ok(())
    }

    fn get_op(&self, vault_id: &[u8; 16], hash: &OpHash) -> CoreResult<Option<StoredOp>> {
        Ok(self.ops.get(&(*vault_id, *hash)).cloned())
    }

    fn list_ops(&self, vault_id: &[u8; 16]) -> CoreResult<Vec<StoredOp>> {
        let mut ops: Vec<StoredOp> = self
            .ops
            .iter()
            .filter(|((id, _), _)| id == vault_id)
            .map(|(_, op)| op.clone())
            .collect();
        ops.sort_by_key(|op| (op.op().lamport(), *op.op().op_id()));
        Ok(ops)
    }

    fn count_ops(&self, vault_id: &[u8; 16]) -> CoreResult<usize> {
        Ok(self.ops.keys().filter(|(id, _)| id == vault_id).count())
    }

    fn put_head(&mut self, head: &VaultHead) -> CoreResult<()> {
        self.heads.insert(*head.vault_id(), head.clone());
        Ok(())
    }

    fn get_head(&self, vault_id: &[u8; 16]) -> CoreResult<Option<VaultHead>> {
        Ok(self.heads.get(vault_id).cloned())
    }

    fn put_bundle(&mut self, bundle: &AccountBundle) -> CoreResult<()> {
        self.bundles.insert(*bundle.account_id(), bundle.clone());
        Ok(())
    }

    fn get_bundle(&self, account_id: &[u8; 16]) -> CoreResult<Option<AccountBundle>> {
        Ok(self.bundles.get(account_id).cloned())
    }

    fn put_vault_key(&mut self, vault_id: &[u8; 16], envelope: &Envelope) -> CoreResult<()> {
        self.vault_keys.insert(*vault_id, envelope.clone());
        Ok(())
    }

    fn get_vault_key(&self, vault_id: &[u8; 16]) -> CoreResult<Option<Envelope>> {
        Ok(self.vault_keys.get(vault_id).cloned())
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> CoreResult<()> {
        if key == META_SCHEMA_VERSION {
            return Err(CoreError::StorageFailure);
        }
        self.meta.insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn get_meta(&self, key: &str) -> CoreResult<Option<Vec<u8>>> {
        Ok(self.meta.get(key).cloned())
    }

    fn delete_vault(&mut self, vault_id: &[u8; 16]) -> CoreResult<()> {
        self.ops.retain(|(id, _), _| id != vault_id);
        self.heads.remove(vault_id);
        self.vault_keys.remove(vault_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
    use crate::oplog::devices::DeviceRegistry;
    use crate::oplog::op::{Op, OpKind};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn op(signer: &SigningKeyPair, vk: &VaultKey) -> StoredOp {
        let payload =
            Op::seal_payload(vk, &VAULT, &ITEM, OpKind::Create, b"payload").expect("seal");
        Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            DEVICE,
            at("2026-11-05T10:00:00Z"),
            OpKind::Create,
            Some(ITEM),
            payload,
        )
        .expect("op")
        .sign(signer)
        .expect("sign")
    }

    fn head(signer: &SigningKeyPair, hash: [u8; 32]) -> VaultHead {
        VaultHead::create(
            signer,
            VAULT,
            DEVICE,
            vec![hash],
            1,
            1,
            at("2026-11-05T10:05:00Z"),
        )
        .expect("head")
    }

    #[test]
    fn stores_and_lists_ops_heads_and_keys() {
        let identity = SigningKeyPair::from_seed([1u8; 32]);
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let vk = VaultKey::from_bytes([3u8; 32]);
        let mut store = MemoryStore::new();
        assert_eq!(store.schema_version().expect("schema"), 1);

        let stored = op(&device, &vk);
        store.put_op(&stored).expect("put");
        store.put_op(&stored).expect("idempotent");
        assert_eq!(store.count_ops(&VAULT).expect("count"), 1);

        let head = head(&device, stored.hash().expect("hash"));
        store.put_head(&head).expect("head");
        assert_eq!(
            store
                .get_head(&VAULT)
                .expect("get")
                .expect("head")
                .hash()
                .expect("hash"),
            head.hash().expect("hash")
        );

        let envelope = crate::crypto::aead::seal(
            &crate::crypto::aead::AeadKey::from_bytes([7u8; 32]),
            &crate::crypto::aad::Aad::builder(crate::crypto::aad::RecordType::ItemField)
                .vault(VAULT)
                .item(ITEM)
                .field("password")
                .build()
                .expect("aad"),
            b"x",
        )
        .expect("seal");
        store.put_vault_key(&VAULT, &envelope).expect("vk");
        assert!(store.get_vault_key(&VAULT).expect("get").is_some());

        store.delete_vault(&VAULT).expect("delete");
        assert_eq!(store.count_ops(&VAULT).expect("count"), 0);
        assert!(store.get_head(&VAULT).expect("head").is_none());
        let _ = DeviceCertificate::create(
            &identity,
            ACCOUNT,
            DEVICE,
            device.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .expect("cert");
        let _ = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
    }

    #[test]
    fn the_schema_key_cannot_be_overwritten() {
        let mut store = MemoryStore::new();
        assert!(store.put_meta(META_SCHEMA_VERSION, &[9, 9, 9, 9]).is_err());
        store.put_meta("ui.theme", b"dark").expect("meta");
        assert_eq!(
            store.get_meta("ui.theme").expect("meta").expect("value"),
            b"dark"
        );
    }
}
