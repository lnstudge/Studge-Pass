//! In-memory transport: tests and the evil-relay harness (SPEC §7.10).
//!
//! `MemoryTransport` stores ops in a `BTreeMap<OpHash, Vec<u8>>` (raw CBOR,
//! no deserialisation) and a head per vault.  It applies no validation — that
//! is the client's job — so the evil-relay harness can insert arbitrary bytes.

use crate::oplog::head::VaultHead;
use crate::oplog::op::{OpHash, StoredOp};
use crate::sync::transport::{SyncError, Transport, VaultOps, NO_HEAD};
use std::collections::BTreeMap;

/// A vault's in-memory state.
#[derive(Debug, Default, Clone)]
struct VaultState {
    /// Op bytes in insertion order (topological order by construction).
    ops_ordered: Vec<Vec<u8>>,
    /// Op CBOR bytes keyed by op_hash, for deduplication.
    ops_by_hash: BTreeMap<OpHash, Vec<u8>>,
    /// Serialised head, if any.
    head: Option<Vec<u8>>,
    /// Hash of the current head, for CAS.
    head_hash: OpHash,
}

/// In-memory transport.  Not thread-safe by design; tests run single-threaded.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    vaults: BTreeMap<[u8; 16], VaultState>,
}

impl MemoryTransport {
    /// Creates an empty transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Directly inserts raw op bytes — used by the evil relay to inject
    /// malformed, replayed or tampered ops without going through `push`.
    ///
    /// If an op with the same hash already exists, its raw bytes are replaced
    /// (so tampered bytes overwrite good bytes).  If it is new, it is appended.
    pub fn inject_raw_op(&mut self, vault_id: [u8; 16], hash: OpHash, raw: Vec<u8>) {
        let state = self.vaults.entry(vault_id).or_default();
        if let Some(existing) = state.ops_by_hash.get_mut(&hash) {
            // Replace in the hash map.
            *existing = raw.clone();
            // Also replace in the ordered list.
            for slot in &mut state.ops_ordered {
                if let Ok(op) = StoredOp::from_cbor(slot) {
                    if let Ok(h) = op.hash() {
                        if h == hash {
                            *slot = raw.clone();
                            break;
                        }
                    }
                }
            }
        } else {
            state.ops_by_hash.insert(hash, raw.clone());
            state.ops_ordered.push(raw);
        }
    }

    /// Directly overwrites the head bytes — used by the evil relay to serve a
    /// stale or forged head.
    pub fn set_raw_head(&mut self, vault_id: [u8; 16], head_bytes: Vec<u8>, hash: OpHash) {
        let state = self.vaults.entry(vault_id).or_default();
        state.head = Some(head_bytes);
        state.head_hash = hash;
    }

    /// Returns all op CBOR bytes for a vault in insertion order.
    pub fn raw_ops(&self, vault_id: &[u8; 16]) -> Vec<Vec<u8>> {
        self.vaults
            .get(vault_id)
            .map(|s| s.ops_ordered.clone())
            .unwrap_or_default()
    }

    /// Returns the current head bytes for a vault.
    pub fn raw_head(&self, vault_id: &[u8; 16]) -> Option<Vec<u8>> {
        self.vaults.get(vault_id)?.head.clone()
    }

    /// Drops all ops after a certain position (for simulating a withheld tail).
    pub fn truncate_ops(&mut self, vault_id: [u8; 16], keep: usize) {
        let state = self.vaults.entry(vault_id).or_default();
        state.ops_ordered.truncate(keep);
        // Rebuild the hash map from the surviving ordered slice.
        state.ops_by_hash.clear();
        for raw in &state.ops_ordered {
            if let Ok(op) = StoredOp::from_cbor(raw) {
                if let Ok(hash) = op.hash() {
                    state.ops_by_hash.insert(hash, raw.clone());
                }
            }
        }
    }
}

impl Transport for MemoryTransport {
    fn push(&mut self, vault_id: [u8; 16], ops: &[StoredOp]) -> Result<usize, SyncError> {
        let state = self.vaults.entry(vault_id).or_default();
        let mut accepted = 0usize;
        for op in ops {
            let raw = op.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
            let hash = op.hash().map_err(|_| SyncError::MalformedPayload)?;
            if let std::collections::btree_map::Entry::Vacant(e) = state.ops_by_hash.entry(hash) {
                e.insert(raw.clone());
                state.ops_ordered.push(raw);
            }
            accepted += 1;
        }
        Ok(accepted)
    }

    fn pull(
        &mut self,
        vault_id: [u8; 16],
        cursor: Option<[u8; 32]>,
    ) -> Result<VaultOps, SyncError> {
        let state = match self.vaults.get(&vault_id) {
            Some(s) => s,
            None => {
                return Ok(VaultOps {
                    ops: vec![],
                    head: None,
                })
            }
        };

        // Determine the start position from the cursor.
        let start = match cursor {
            None => 0,
            Some(cursor_hash) => {
                // Find the position of the op with this hash.
                let pos = state.ops_ordered.iter().position(|raw| {
                    StoredOp::from_cbor(raw).and_then(|op| op.hash()) == Ok(cursor_hash)
                });
                match pos {
                    Some(p) => p + 1,
                    // Cursor not found: return all ops (client will deduplicate).
                    None => 0,
                }
            }
        };

        let mut ops = Vec::new();
        for raw in &state.ops_ordered[start..] {
            let op = StoredOp::from_cbor(raw).map_err(|_| SyncError::MalformedPayload)?;
            ops.push(op);
        }

        let head = match &state.head {
            Some(bytes) => {
                Some(VaultHead::from_cbor(bytes).map_err(|_| SyncError::MalformedPayload)?)
            }
            None => None,
        };

        Ok(VaultOps { ops, head })
    }

    fn put_head(
        &mut self,
        vault_id: [u8; 16],
        head: &VaultHead,
        expected_hash: [u8; 32],
    ) -> Result<(), SyncError> {
        let state = self.vaults.entry(vault_id).or_default();
        // Check that the expected hash matches.
        if expected_hash != NO_HEAD && state.head_hash != expected_hash {
            return Err(SyncError::ForkDetected);
        }
        if expected_hash == NO_HEAD && state.head.is_some() {
            return Err(SyncError::ForkDetected);
        }
        let bytes = head.to_cbor().map_err(|_| SyncError::MalformedPayload)?;
        let hash = head.hash().map_err(|_| SyncError::MalformedPayload)?;
        state.head = Some(bytes);
        state.head_hash = hash;
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

    const ACCOUNT: [u8; 16] = [0xAA; 16];
    const VAULT: [u8; 16] = [0xBB; 16];
    const ITEM: [u8; 16] = [0xCC; 16];
    const DEVICE: [u8; 16] = [0xDD; 16];

    fn at(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    fn make_device() -> (SigningKeyPair, SigningKeyPair, DeviceRegistry) {
        let identity = SigningKeyPair::from_seed([1u8; 32]);
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let mut reg = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
        let cert = DeviceCertificate::create(
            &identity,
            ACCOUNT,
            DEVICE,
            device.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .unwrap();
        reg.certify(&cert, &at("2026-11-05T10:00:00Z")).unwrap();
        (identity, device, reg)
    }

    fn make_genesis(device: &SigningKeyPair) -> StoredOp {
        let vk = VaultKey::from_bytes([3u8; 32]);
        let payload = Op::seal_payload(&vk, &VAULT, &ITEM, OpKind::Create, b"item").unwrap();
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
        .unwrap()
        .sign(device)
        .unwrap()
    }

    #[test]
    fn push_and_pull_round_trip() {
        let (_, device, _) = make_device();
        let mut transport = MemoryTransport::new();
        let op = make_genesis(&device);
        let hash = op.hash().unwrap();
        transport.push(VAULT, &[op]).unwrap();
        let result = transport.pull(VAULT, None).unwrap();
        assert_eq!(result.ops.len(), 1);
        assert_eq!(result.ops[0].hash().unwrap(), hash);
        assert!(result.head.is_none());
    }

    #[test]
    fn push_is_idempotent() {
        let (_, device, _) = make_device();
        let mut transport = MemoryTransport::new();
        let op = make_genesis(&device);
        transport.push(VAULT, std::slice::from_ref(&op)).unwrap();
        transport.push(VAULT, &[op]).unwrap(); // second push same op
        let result = transport.pull(VAULT, None).unwrap();
        assert_eq!(result.ops.len(), 1);
    }

    #[test]
    fn pull_with_cursor_returns_only_newer_ops() {
        let (_, device, _) = make_device();
        let mut transport = MemoryTransport::new();
        let op1 = make_genesis(&device);
        let hash1 = op1.hash().unwrap();
        // Second op
        let vk = VaultKey::from_bytes([3u8; 32]);
        let payload2 = Op::seal_payload(&vk, &VAULT, &ITEM, OpKind::Update, b"v2").unwrap();
        let op2 = Op::new(
            VAULT,
            [2u8; 16],
            vec![hash1],
            2,
            DEVICE,
            at("2026-11-05T10:01:00Z"),
            OpKind::Update,
            Some(ITEM),
            payload2,
        )
        .unwrap()
        .sign(&device)
        .unwrap();
        transport.push(VAULT, &[op1]).unwrap();
        transport.push(VAULT, &[op2]).unwrap();
        let result = transport.pull(VAULT, Some(hash1)).unwrap();
        assert_eq!(result.ops.len(), 1, "cursor should exclude first op");
    }

    #[test]
    fn cas_rejects_stale_hash() {
        let (_, device, _) = make_device();
        let mut transport = MemoryTransport::new();
        let op = make_genesis(&device);
        transport.push(VAULT, &[op]).unwrap();
        let head = VaultHead::create(
            &device,
            VAULT,
            DEVICE,
            vec![[1u8; 32]], // dummy hash for test
            1,
            1,
            at("2026-11-05T10:02:00Z"),
        )
        .unwrap();
        // First put with NO_HEAD succeeds (vacant).
        transport.put_head(VAULT, &head, NO_HEAD).unwrap();
        // Second put with NO_HEAD fails because head already exists.
        assert!(transport.put_head(VAULT, &head, NO_HEAD).is_err());
    }
}
