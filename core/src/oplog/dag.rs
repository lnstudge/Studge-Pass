//! The DAG of ops (SPEC §6.4–§6.5).
//!
//! `add` is the only way in, and it enforces every structural rule: the
//! signature verifies against a certified device, every parent is already
//! present, the Lamport clock is exactly `1 + max(parents)`, and a reused
//! `op_id` with different content is refused. A relay that withholds a parent
//! therefore produces a detectable error, never a silent gap.

use crate::crypto::signing::Timestamp;
use crate::error::{CoreError, CoreResult};
use crate::oplog::devices::DeviceRegistry;
use crate::oplog::op::{hash_eq, OpHash, OpId, StoredOp};
use std::collections::{BTreeMap, BTreeSet};

/// The verified history of one vault.
#[derive(Debug, Clone)]
pub struct Dag {
    vault_id: [u8; 16],
    ops: BTreeMap<OpHash, StoredOp>,
    by_id: BTreeMap<OpId, OpHash>,
}

impl Dag {
    /// An empty history for `vault_id`.
    pub fn new(vault_id: [u8; 16]) -> Self {
        Self {
            vault_id,
            ops: BTreeMap::new(),
            by_id: BTreeMap::new(),
        }
    }

    /// The vault this DAG belongs to.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// Verifies and inserts an op, returning its hash.
    ///
    /// Inserting the same op twice is idempotent; two different ops with the
    /// same `op_id` are rejected (SPEC §6.1).
    pub fn add(&mut self, stored: StoredOp, devices: &DeviceRegistry) -> CoreResult<OpHash> {
        if stored.op().vault_id() != &self.vault_id {
            return Err(CoreError::InvalidOp);
        }
        stored.verify(devices)?;
        let hash = stored.hash()?;

        if self.ops.contains_key(&hash) {
            return Ok(hash);
        }
        if let Some(existing) = self.by_id.get(stored.op().op_id()) {
            if !hash_eq(existing, &hash) {
                return Err(CoreError::DuplicateOp);
            }
        }

        let parents = stored.op().parents();
        if parents.is_empty() {
            if stored.op().lamport() != 1 {
                return Err(CoreError::InvalidOp);
            }
            if !self.ops.is_empty() {
                // A second genesis would fork the vault's root.
                return Err(CoreError::InvalidOp);
            }
        } else {
            let mut max_parent = 0u64;
            for parent in parents {
                let parent_op = self.ops.get(parent).ok_or(CoreError::UnknownParent)?;
                max_parent = max_parent.max(parent_op.op().lamport());
            }
            if stored.op().lamport() != max_parent + 1 {
                return Err(CoreError::InvalidOp);
            }
        }

        self.by_id.insert(*stored.op().op_id(), hash);
        self.ops.insert(hash, stored);
        Ok(hash)
    }

    /// An op by hash.
    pub fn get(&self, hash: &OpHash) -> Option<&StoredOp> {
        self.ops.get(hash)
    }

    /// Whether the hash is present.
    pub fn has(&self, hash: &OpHash) -> bool {
        self.ops.contains_key(hash)
    }

    /// Number of ops.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// The highest Lamport clock, or 0 for an empty history.
    pub fn lamport_max(&self) -> u64 {
        self.ops
            .values()
            .map(|op| op.op().lamport())
            .max()
            .unwrap_or(0)
    }

    /// The tips: ops that are not a parent of any other op, sorted.
    pub fn heads(&self) -> Vec<OpHash> {
        let mut referenced: BTreeSet<OpHash> = BTreeSet::new();
        for op in self.ops.values() {
            for parent in op.op().parents() {
                referenced.insert(*parent);
            }
        }
        self.ops
            .keys()
            .filter(|hash| !referenced.contains(*hash))
            .copied()
            .collect()
    }

    /// Every op reachable from `roots`, or `UnknownParent` if a parent is
    /// missing (SPEC §6.4).
    pub fn reachable_from(&self, roots: &[OpHash]) -> CoreResult<BTreeSet<OpHash>> {
        let mut seen: BTreeSet<OpHash> = BTreeSet::new();
        let mut stack: Vec<OpHash> = roots.to_vec();
        while let Some(hash) = stack.pop() {
            if !seen.insert(hash) {
                continue;
            }
            let op = self.ops.get(&hash).ok_or(CoreError::UnknownParent)?;
            for parent in op.op().parents() {
                if !self.ops.contains_key(parent) {
                    return Err(CoreError::UnknownParent);
                }
                stack.push(*parent);
            }
        }
        Ok(seen)
    }

    /// Whether `ancestor` is `of` itself or one of its ancestors.
    pub fn is_ancestor(&self, ancestor: &OpHash, of: &OpHash) -> bool {
        let mut seen: BTreeSet<OpHash> = BTreeSet::new();
        let mut stack = vec![*of];
        while let Some(hash) = stack.pop() {
            if hash_eq(&hash, ancestor) {
                return true;
            }
            if !seen.insert(hash) {
                continue;
            }
            if let Some(op) = self.ops.get(&hash) {
                for parent in op.op().parents() {
                    stack.push(*parent);
                }
            }
        }
        false
    }

    /// The ordered ops an item's history consists of, newest Lamport last.
    pub fn ops_for_item(&self, item_id: &[u8; 16]) -> Vec<&StoredOp> {
        let mut ops: Vec<&StoredOp> = self
            .ops
            .values()
            .filter(|op| op.op().item_id() == Some(item_id))
            .collect();
        ops.sort_by_key(|op| (op.op().lamport(), *op.op().device_id()));
        ops
    }

    /// The creation time of the earliest op, for display.
    pub fn earliest_created_at(&self) -> Option<&Timestamp> {
        self.ops
            .values()
            .map(|op| op.op().created_at())
            .min_by_key(|at| at.unix_seconds())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair};
    use crate::oplog::op::{Op, OpKind};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    struct Fixture {
        identity: SigningKeyPair,
        device: SigningKeyPair,
        registry: DeviceRegistry,
        vk: VaultKey,
        dag: Dag,
    }

    impl Fixture {
        fn new() -> Self {
            let identity = SigningKeyPair::from_seed([1u8; 32]);
            let device = SigningKeyPair::from_seed([2u8; 32]);
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
            Self {
                identity,
                device,
                registry,
                vk: VaultKey::from_bytes([3u8; 32]),
                dag: Dag::new(VAULT),
            }
        }

        fn op(
            &self,
            op_id: u8,
            parents: Vec<[u8; 32]>,
            lamport: u64,
            kind: OpKind,
            body: &[u8],
        ) -> StoredOp {
            let payload = Op::seal_payload(&self.vk, &VAULT, &ITEM, kind, body).expect("seal");
            Op::new(
                VAULT,
                [op_id; 16],
                parents,
                lamport,
                DEVICE,
                at("2026-11-05T10:00:00Z"),
                kind,
                Some(ITEM),
                payload,
            )
            .expect("op")
            .sign(&self.device)
            .expect("sign")
        }

        fn genesis(&mut self) -> [u8; 32] {
            let op = self.op(1, vec![], 1, OpKind::Create, b"v1");
            self.dag.add(op, &self.registry).expect("genesis")
        }
    }

    #[test]
    fn builds_a_linear_history_and_reports_heads() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let second = fixture.op(2, vec![first], 2, OpKind::Update, b"v2");
        let second_hash = fixture.dag.add(second, &fixture.registry).expect("add");
        assert_eq!(fixture.dag.len(), 2);
        assert_eq!(fixture.dag.heads(), vec![second_hash]);
        assert!(fixture.dag.is_ancestor(&first, &second_hash));
        assert!(!fixture.dag.is_ancestor(&second_hash, &first));
        assert_eq!(fixture.dag.lamport_max(), 2);
    }

    #[test]
    fn a_merge_has_two_parents_and_one_head() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let left = fixture.op(2, vec![first], 2, OpKind::Update, b"left");
        let left_hash = fixture.dag.add(left, &fixture.registry).expect("left");
        let right = fixture.op(3, vec![first], 2, OpKind::Update, b"right");
        let right_hash = fixture.dag.add(right, &fixture.registry).expect("right");
        assert_eq!(fixture.dag.heads().len(), 2);

        let merge = fixture.op(4, vec![left_hash, right_hash], 3, OpKind::Update, b"merge");
        let merge_hash = fixture.dag.add(merge, &fixture.registry).expect("merge");
        assert_eq!(fixture.dag.heads(), vec![merge_hash]);
        assert!(fixture.dag.is_ancestor(&left_hash, &merge_hash));
        assert!(fixture.dag.is_ancestor(&right_hash, &merge_hash));
    }

    #[test]
    fn rejects_a_missing_parent() {
        let mut fixture = Fixture::new();
        fixture.genesis();
        let orphan = fixture.op(2, vec![[0xAB; 32]], 2, OpKind::Update, b"x");
        assert_eq!(
            fixture
                .dag
                .add(orphan, &fixture.registry)
                .expect_err("orphan"),
            CoreError::UnknownParent
        );
    }

    #[test]
    fn rejects_a_wrong_lamport_clock() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        for lamport in [1, 3, 4] {
            let op = fixture.op(2, vec![first], lamport, OpKind::Update, b"x");
            assert_eq!(
                fixture.dag.add(op, &fixture.registry).expect_err("lamport"),
                CoreError::InvalidOp,
                "lamport {lamport}"
            );
        }
    }

    #[test]
    fn rejects_a_replayed_op_id_with_new_content() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let a = fixture.op(2, vec![first], 2, OpKind::Update, b"a");
        fixture.dag.add(a, &fixture.registry).expect("a");
        let b = fixture.op(2, vec![first], 2, OpKind::Update, b"b");
        assert_eq!(
            fixture.dag.add(b, &fixture.registry).expect_err("dup"),
            CoreError::DuplicateOp
        );
    }

    #[test]
    fn inserting_the_same_op_twice_is_idempotent() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let op = fixture.op(2, vec![first], 2, OpKind::Update, b"x");
        let hash = fixture
            .dag
            .add(op.clone(), &fixture.registry)
            .expect("first");
        assert_eq!(
            fixture.dag.add(op, &fixture.registry).expect("second"),
            hash
        );
        assert_eq!(fixture.dag.len(), 2);
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let op = fixture.op(2, vec![first], 2, OpKind::Update, b"x");
        let bytes = op.to_cbor().expect("encode");
        // Flip one bit of the signature by re-encoding with a bad sig.
        let mut cursor = std::io::Cursor::new(bytes);
        let mut value: ciborium::value::Value =
            ciborium::de::from_reader(&mut cursor).expect("decode");
        let ciborium::value::Value::Map(ref mut entries) = value else {
            panic!("map");
        };
        for (key, entry) in entries.iter_mut() {
            if key == &ciborium::value::Value::Text("sig".into()) {
                let ciborium::value::Value::Bytes(ref mut sig) = entry else {
                    panic!("sig");
                };
                sig[0] ^= 0xFF;
            }
        }
        let tampered = crate::crypto::aad::canonical_bytes(&value).expect("encode");
        let parsed = StoredOp::from_cbor(&tampered).expect("parse");
        assert_eq!(
            fixture
                .dag
                .add(parsed, &fixture.registry)
                .expect_err("signature"),
            CoreError::OpVerificationFailed
        );
        assert!(fixture.identity.public_bytes().len() == 32);
    }

    #[test]
    fn an_op_from_a_revoked_device_is_rejected() {
        let mut fixture = Fixture::new();
        let first = fixture.genesis();
        let revocation = crate::crypto::signing::DeviceRevocation::create(
            &fixture.identity,
            ACCOUNT,
            DEVICE,
            at("2026-11-05T09:45:00Z"),
            "lost",
        )
        .expect("revocation");
        fixture.registry.revoke(&revocation).expect("revoke");
        // The helper signs at 10:00, after the revocation.
        let op = fixture.op(2, vec![first], 2, OpKind::Update, b"x");
        assert!(fixture.dag.add(op, &fixture.registry).is_err());
    }

    #[test]
    fn a_second_genesis_is_rejected() {
        let mut fixture = Fixture::new();
        fixture.genesis();
        let second = fixture.op(9, vec![], 1, OpKind::Create, b"other");
        assert_eq!(
            fixture
                .dag
                .add(second, &fixture.registry)
                .expect_err("second genesis"),
            CoreError::InvalidOp
        );
    }
}
