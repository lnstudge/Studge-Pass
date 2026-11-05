//! Materialising a DAG into current item state (SPEC §6.6–§6.7).
//!
//! Every op carries a full item snapshot, so the state of an item is simply
//! its winning op: the highest `(lamport, device_id)` among the ops reachable
//! from the current heads. Ties on that pair are impossible between two honest
//! devices and resolved by the op hash between two forks of one device, which
//! keeps the rule total and identical on every client.
//!
//! Losing versions are never discarded — they stay in the DAG and in the item's
//! field history, which is what makes "an attacker cannot make a change
//! disappear" true (§6.7).

use crate::crypto::keys::VaultKey;
use crate::error::{CoreError, CoreResult};
use crate::oplog::dag::Dag;
use crate::oplog::op::{hash_eq, OpHash, OpKind};
use crate::vault::items::{Item, ItemId};
use std::collections::BTreeMap;

/// The materialised state of one vault.
#[derive(Debug, Clone)]
pub struct VaultState {
    vault_id: [u8; 16],
    items: BTreeMap<ItemId, Item>,
    heads: Vec<OpHash>,
    op_count: u64,
    lamport_max: u64,
}

impl VaultState {
    /// The vault id.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// An item by id.
    pub fn item(&self, id: &ItemId) -> Option<&Item> {
        self.items.get(id)
    }

    /// Every item, ordered by id.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    /// Number of live items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the vault has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The heads this state was built from.
    pub fn heads(&self) -> &[OpHash] {
        &self.heads
    }

    /// Number of ops that produced it.
    pub fn op_count(&self) -> u64 {
        self.op_count
    }

    /// Highest Lamport clock in it.
    pub fn lamport_max(&self) -> u64 {
        self.lamport_max
    }
}

/// The winning op for one item, by the total order of SPEC §6.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Candidate {
    lamport: u64,
    device_id: [u8; 16],
    hash: OpHash,
}

impl Candidate {
    fn beats(&self, other: &Self) -> bool {
        (self.lamport, self.device_id, self.hash) > (other.lamport, other.device_id, other.hash)
    }
}

/// Materialises the state at the DAG's current heads.
pub fn materialise(dag: &Dag, vk: &VaultKey) -> CoreResult<VaultState> {
    let heads = dag.heads();
    materialise_at(dag, &heads, vk)
}

/// Materialises the state at explicit heads.
///
/// Every op reachable from `heads` is decrypted; a missing parent, an
/// unsupported kind, a tag failure or a malformed payload stops the whole
/// materialisation (SPEC §5.8, §6.4).
pub fn materialise_at(dag: &Dag, heads: &[OpHash], vk: &VaultKey) -> CoreResult<VaultState> {
    if heads.is_empty() {
        return Ok(VaultState {
            vault_id: *dag.vault_id(),
            items: BTreeMap::new(),
            heads: Vec::new(),
            op_count: 0,
            lamport_max: 0,
        });
    }
    let reachable = dag.reachable_from(heads)?;

    let mut winners: BTreeMap<ItemId, Candidate> = BTreeMap::new();
    let mut lamport_max = 0u64;
    for hash in &reachable {
        let stored = dag.get(hash).ok_or(CoreError::UnknownParent)?;
        let op = stored.op();
        if !op.kind().is_supported() {
            return Err(CoreError::UnsupportedOpKind);
        }
        lamport_max = lamport_max.max(op.lamport());
        let item_id = *op.item_id().ok_or(CoreError::InvalidOp)?;
        let candidate = Candidate {
            lamport: op.lamport(),
            device_id: *op.device_id(),
            hash: *hash,
        };
        match winners.get(&item_id) {
            Some(existing) if !candidate.beats(existing) => {}
            _ => {
                winners.insert(item_id, candidate);
            }
        }
    }

    let mut items = BTreeMap::new();
    for (item_id, winner) in winners {
        let stored = dag.get(&winner.hash).ok_or(CoreError::UnknownParent)?;
        let op = stored.op();
        if op.kind() == OpKind::Delete {
            continue;
        }
        let plaintext = op.open_payload(vk, dag.vault_id())?;
        let item = Item::from_payload_bytes(*dag.vault_id(), item_id, &plaintext)?;
        if !hash_eq(&winner.hash, &stored.hash()?) {
            return Err(CoreError::OpVerificationFailed);
        }
        items.insert(item_id, item);
    }

    let mut sorted_heads = heads.to_vec();
    sorted_heads.sort_unstable();

    Ok(VaultState {
        vault_id: *dag.vault_id(),
        items,
        heads: sorted_heads,
        op_count: reachable.len() as u64,
        lamport_max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::{DeviceCertificate, SigningKeyPair, Timestamp};
    use crate::oplog::devices::DeviceRegistry;
    use crate::oplog::op::{Op, StoredOp};
    use crate::vault::items::{ItemKind, UrlMatch};

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0x22; 16];
    const ITEM: [u8; 16] = [0x33; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn item_bytes(title: &str, password: &str) -> Vec<u8> {
        let mut item =
            Item::new(ITEM, VAULT, ItemKind::Login, at("2026-11-05T09:00:00Z")).expect("item");
        item.set_field("title", title, &at("2026-11-05T09:00:00Z"))
            .expect("title");
        item.set_field("password", password, &at("2026-11-05T09:00:00Z"))
            .expect("password");
        item.add_url(
            "https://demo.example",
            UrlMatch::ExactHost,
            &at("2026-11-05T09:00:00Z"),
        )
        .expect("url");
        item.to_payload_bytes().expect("payload")
    }

    struct Fixture {
        registry: DeviceRegistry,
        vk: VaultKey,
        dag: Dag,
        device_a: SigningKeyPair,
        device_b: SigningKeyPair,
        id_a: [u8; 16],
        id_b: [u8; 16],
    }

    impl Fixture {
        fn new() -> Self {
            let identity = SigningKeyPair::from_seed([1u8; 32]);
            let device_a = SigningKeyPair::from_seed([2u8; 32]);
            let device_b = SigningKeyPair::from_seed([3u8; 32]);
            let id_a = [0x0A; 16];
            let id_b = [0x0B; 16];
            let mut registry = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
            for (id, key) in [(id_a, &device_a), (id_b, &device_b)] {
                let cert = DeviceCertificate::create(
                    &identity,
                    ACCOUNT,
                    id,
                    key.public_bytes(),
                    at("2026-11-05T09:00:00Z"),
                )
                .expect("cert");
                registry
                    .certify(&cert, &at("2026-11-05T09:30:00Z"))
                    .expect("certify");
            }
            Self {
                registry,
                vk: VaultKey::from_bytes([3u8; 32]),
                dag: Dag::new(VAULT),
                device_a,
                device_b,
                id_a,
                id_b,
            }
        }

        fn op(
            &mut self,
            op_id: u8,
            parents: Vec<[u8; 32]>,
            lamport: u64,
            device: bool,
            kind: OpKind,
            body: &[u8],
        ) -> [u8; 32] {
            let (signer, device_id) = if device {
                (&self.device_b, self.id_b)
            } else {
                (&self.device_a, self.id_a)
            };
            let payload =
                Op::seal_payload(&self.vk, &VAULT, &ITEM, kind, body).expect("seal payload");
            let op = Op::new(
                VAULT,
                [op_id; 16],
                parents,
                lamport,
                device_id,
                at("2026-11-05T10:00:00Z"),
                kind,
                Some(ITEM),
                payload,
            )
            .expect("op")
            .sign(signer)
            .expect("sign");
            self.dag.add(op, &self.registry).expect("add")
        }
    }

    #[test]
    fn builds_state_from_a_linear_history() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "one"),
        );
        fixture.op(
            2,
            vec![first],
            2,
            false,
            OpKind::Update,
            &item_bytes("Demo", "two"),
        );

        let state = materialise(&fixture.dag, &fixture.vk).expect("materialise");
        assert_eq!(state.len(), 1);
        assert_eq!(state.op_count(), 2);
        let item = state.item(&ITEM).expect("item");
        assert_eq!(item.field("password"), Some("two"));
        assert_eq!(item.urls().len(), 1);
    }

    #[test]
    fn the_higher_lamport_wins_a_conflict() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "base"),
        );
        // Branch A goes one step deeper, branch B stays at Lamport 2.
        let a1 = fixture.op(
            2,
            vec![first],
            2,
            false,
            OpKind::Update,
            &item_bytes("Demo", "a1"),
        );
        fixture.op(
            3,
            vec![a1],
            3,
            false,
            OpKind::Update,
            &item_bytes("Demo", "from-a"),
        );
        fixture.op(
            4,
            vec![first],
            2,
            true,
            OpKind::Update,
            &item_bytes("Demo", "from-b"),
        );

        // Lamport 3 beats Lamport 2 even though device B has the higher id.
        let state = materialise(&fixture.dag, &fixture.vk).expect("materialise");
        assert_eq!(
            state.item(&ITEM).expect("item").field("password"),
            Some("from-a")
        );
    }

    #[test]
    fn the_higher_device_id_breaks_a_lamport_tie() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "base"),
        );
        // Same Lamport clock, device A (0x0A) vs device B (0x0B): B wins.
        fixture.op(
            2,
            vec![first],
            2,
            false,
            OpKind::Update,
            &item_bytes("Demo", "from-a"),
        );
        fixture.op(
            3,
            vec![first],
            2,
            true,
            OpKind::Update,
            &item_bytes("Demo", "from-b"),
        );

        let state = materialise(&fixture.dag, &fixture.vk).expect("materialise");
        assert_eq!(
            state.item(&ITEM).expect("item").field("password"),
            Some("from-b")
        );
    }

    #[test]
    fn a_delete_removes_the_item_but_keeps_the_history() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "one"),
        );
        let second = fixture.op(
            2,
            vec![first],
            2,
            false,
            OpKind::Update,
            &item_bytes("Demo", "two"),
        );
        let deleted = fixture.op(3, vec![second], 3, false, OpKind::Delete, b"");

        let state = materialise(&fixture.dag, &fixture.vk).expect("materialise");
        assert!(state.is_empty());
        assert_eq!(state.op_count(), 3);
        // The ops are still there: deletion is a tombstone, not an erasure.
        assert!(fixture.dag.has(&deleted));
        assert_eq!(fixture.dag.len(), 3);
    }

    #[test]
    fn an_op_that_is_not_reachable_is_ignored() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "one"),
        );
        // A second statement of the same item on another branch.
        let branch = fixture.op(
            2,
            vec![first],
            2,
            true,
            OpKind::Update,
            &item_bytes("Demo", "two"),
        );

        let state = materialise_at(&fixture.dag, &[first], &fixture.vk).expect("materialise");
        assert_eq!(
            state.item(&ITEM).expect("item").field("password"),
            Some("one")
        );
        assert!(!state.heads().contains(&branch));
    }

    #[test]
    fn a_dropped_parent_is_a_hard_error() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "one"),
        );
        let second = fixture.op(
            2,
            vec![first],
            2,
            false,
            OpKind::Update,
            &item_bytes("Demo", "two"),
        );
        // Rebuild a DAG that only contains the second op, as a truncating relay
        // would serve it.
        let mut truncated = Dag::new(VAULT);
        let stored: StoredOp = fixture.dag.get(&second).expect("stored").clone();
        assert_eq!(
            truncated
                .add(stored, &fixture.registry)
                .expect_err("orphan"),
            CoreError::UnknownParent
        );
    }

    #[test]
    fn a_tampered_payload_fails_materialisation() {
        let mut fixture = Fixture::new();
        // A malicious certified device seals the item under one item id and
        // publishes the ciphertext under another. The signature is valid (the
        // device made the op); the AAD binding is what refuses it.
        let payload = Op::seal_payload(
            &fixture.vk,
            &VAULT,
            &[0x99; 16],
            OpKind::Create,
            &item_bytes("Demo", "one"),
        )
        .expect("seal");
        let op = Op::new(
            VAULT,
            [1u8; 16],
            vec![],
            1,
            fixture.id_a,
            at("2026-11-05T10:00:00Z"),
            OpKind::Create,
            Some(ITEM),
            payload,
        )
        .expect("op")
        .sign(&fixture.device_a)
        .expect("sign");

        fixture.dag.add(op, &fixture.registry).expect("add");
        assert!(matches!(
            materialise(&fixture.dag, &fixture.vk),
            Err(CoreError::Crypto(
                crate::crypto::CryptoError::DecryptionFailed
            ))
        ));
    }

    #[test]
    fn editing_the_payload_breaks_the_signature() {
        let mut fixture = Fixture::new();
        let first = fixture.op(
            1,
            vec![],
            1,
            false,
            OpKind::Create,
            &item_bytes("Demo", "one"),
        );
        let stored = fixture.dag.get(&first).expect("stored").clone();
        let bytes = stored.to_cbor().expect("encode");

        // Flip one ciphertext byte inside the envelope, keep everything else.
        let mut cursor = std::io::Cursor::new(bytes);
        let mut value: ciborium::value::Value =
            ciborium::de::from_reader(&mut cursor).expect("decode");
        let ciborium::value::Value::Map(ref mut entries) = value else {
            panic!("map");
        };
        for (key, entry) in entries.iter_mut() {
            if key == &ciborium::value::Value::Text("payload".into()) {
                let ciborium::value::Value::Bytes(env) = entry else {
                    panic!("payload");
                };
                let mut env_cursor = std::io::Cursor::new(env.clone());
                let mut env_value: ciborium::value::Value =
                    ciborium::de::from_reader(&mut env_cursor).expect("envelope");
                let ciborium::value::Value::Map(ref mut env_entries) = env_value else {
                    panic!("envelope map");
                };
                for (env_key, env_entry) in env_entries.iter_mut() {
                    if env_key == &ciborium::value::Value::Text("ct".into()) {
                        let ciborium::value::Value::Bytes(ref mut ct) = env_entry else {
                            panic!("ct");
                        };
                        ct[0] ^= 0x01;
                    }
                }
                *env = crate::crypto::aad::canonical_bytes(&env_value).expect("encode");
            }
        }
        let tampered = crate::crypto::aad::canonical_bytes(&value).expect("encode");
        let parsed = StoredOp::from_cbor(&tampered).expect("parse");
        // The payload is inside the signed op, so the hash changes and the
        // signature no longer covers it.
        assert_eq!(
            parsed.verify(&fixture.registry).expect_err("signature"),
            CoreError::OpVerificationFailed
        );
        let mut dag = Dag::new(VAULT);
        assert!(dag.add(parsed, &fixture.registry).is_err());
    }

    #[test]
    fn an_empty_vault_materialises_to_nothing() {
        let fixture = Fixture::new();
        let state = materialise(&fixture.dag, &fixture.vk).expect("materialise");
        assert!(state.is_empty());
        assert_eq!(state.op_count(), 0);
    }
}
