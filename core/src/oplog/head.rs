//! Vault heads and the freshness rules of SPEC §6.8–§6.9.
//!
//! A head is a signed summary of the DAG's tips. The relay can serve an old
//! head, so a client pins the last head it verified and refuses any head that
//! does not descend from it. `check_head_update` is that refusal, in one place,
//! with a distinct error for a rollback and for a fork.

use crate::cbor::{
    as_array, as_id16, as_text, as_u64, bytes as cbor_bytes, parse_map, text as cbor_text,
};
use crate::crypto::aad::{canonical_bytes, canonical_map};
use crate::crypto::error::CryptoError;
use crate::crypto::signing::{verify, SigningKeyPair, Timestamp, SIGNATURE_BYTES};
use crate::error::{CoreError, CoreResult};
use crate::oplog::dag::Dag;
use crate::oplog::devices::DeviceRegistry;
use crate::oplog::op::{hash_eq, OpHash};
use ciborium::value::Value;
use std::fmt;

/// A signed statement of the vault's current tips.
#[derive(Clone)]
pub struct VaultHead {
    vault_id: [u8; 16],
    heads: Vec<OpHash>,
    op_count: u64,
    lamport_max: u64,
    device_id: [u8; 16],
    created_at: Timestamp,
    signature: [u8; SIGNATURE_BYTES],
}

impl fmt::Debug for VaultHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultHead")
            .field("vault_id", &self.vault_id)
            .field("heads", &self.heads.len())
            .field("op_count", &self.op_count)
            .field("lamport_max", &self.lamport_max)
            .field("device_id", &self.device_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl VaultHead {
    /// Signs a head with a device key (SPEC §6.8).
    pub fn create(
        device: &SigningKeyPair,
        vault_id: [u8; 16],
        device_id: [u8; 16],
        mut heads: Vec<OpHash>,
        op_count: u64,
        lamport_max: u64,
        created_at: Timestamp,
    ) -> CoreResult<Self> {
        if heads.is_empty() || heads.len() > 64 {
            return Err(CoreError::TooManyEntries);
        }
        heads.sort_unstable();
        heads.dedup();
        if op_count == 0 || lamport_max == 0 {
            return Err(CoreError::InvalidOp);
        }
        let body = Self::body(
            &vault_id,
            &heads,
            op_count,
            lamport_max,
            &device_id,
            &created_at,
        )?;
        let signature = device.sign(blake3::hash(&body).as_bytes());
        Ok(Self {
            vault_id,
            heads,
            op_count,
            lamport_max,
            device_id,
            created_at,
            signature,
        })
    }

    fn body(
        vault_id: &[u8; 16],
        heads: &[OpHash],
        op_count: u64,
        lamport_max: u64,
        device_id: &[u8; 16],
        created_at: &Timestamp,
    ) -> CoreResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", cbor_text(crate::crypto::labels::SUITE_V1)),
            ("type", cbor_text("vault-head")),
            ("vault_id", cbor_bytes(vault_id)),
            (
                "heads",
                Value::Array(heads.iter().map(|hash| cbor_bytes(hash)).collect()),
            ),
            ("op_count", Value::Integer(op_count.into())),
            ("lamport_max", Value::Integer(lamport_max.into())),
            ("device_id", cbor_bytes(device_id)),
            ("created_at", cbor_text(created_at.as_str())),
        ]);
        Ok(canonical_bytes(&map)?)
    }

    /// The body bytes the device key signed.
    pub fn body_bytes(&self) -> CoreResult<Vec<u8>> {
        Self::body(
            &self.vault_id,
            &self.heads,
            self.op_count,
            self.lamport_max,
            &self.device_id,
            &self.created_at,
        )
    }

    /// `BLAKE3(body)` — the value clients pin (SPEC §6.9).
    pub fn hash(&self) -> CoreResult<OpHash> {
        Ok(*blake3::hash(&self.body_bytes()?).as_bytes())
    }

    /// The vault id.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// The tips.
    pub fn heads(&self) -> &[OpHash] {
        &self.heads
    }

    /// Number of ops in the vault.
    pub fn op_count(&self) -> u64 {
        self.op_count
    }

    /// Highest Lamport clock seen.
    pub fn lamport_max(&self) -> u64 {
        self.lamport_max
    }

    /// The device that signed it.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// When it was signed.
    pub fn created_at(&self) -> &Timestamp {
        &self.created_at
    }

    /// The signature.
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Verifies the head against the device registry.
    pub fn verify(&self, devices: &DeviceRegistry) -> CoreResult<()> {
        let key = devices.key_at(&self.device_id, &self.created_at)?;
        verify(&key, &self.hash()?, &self.signature).map_err(|_| CoreError::HeadVerificationFailed)
    }

    /// Canonical CBOR including the signature.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let entries = vec![
            ("suite", cbor_text(crate::crypto::labels::SUITE_V1)),
            ("type", cbor_text("vault-head")),
            ("vault_id", cbor_bytes(&self.vault_id)),
            (
                "heads",
                Value::Array(self.heads.iter().map(|hash| cbor_bytes(hash)).collect()),
            ),
            ("op_count", Value::Integer(self.op_count.into())),
            ("lamport_max", Value::Integer(self.lamport_max.into())),
            ("device_id", cbor_bytes(&self.device_id)),
            ("created_at", cbor_text(self.created_at.as_str())),
            ("sig", cbor_bytes(&self.signature)),
        ];
        Ok(canonical_bytes(&canonical_map(entries))?)
    }

    /// Parses a head, rejecting anything outside the SPEC's key set.
    pub fn from_cbor(bytes: &[u8]) -> CoreResult<Self> {
        let entries = parse_map(bytes)?;
        let expected = [
            "suite",
            "type",
            "vault_id",
            "heads",
            "op_count",
            "lamport_max",
            "device_id",
            "created_at",
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
        if as_text(find("type")?)? != "vault-head" {
            return Err(CoreError::MalformedPayload);
        }
        let vault_id = as_id16(find("vault_id")?)?.ok_or(CoreError::MalformedPayload)?;
        let device_id = as_id16(find("device_id")?)?.ok_or(CoreError::MalformedPayload)?;
        let mut heads = Vec::new();
        for entry in as_array(find("heads")?)? {
            heads.push(crate::cbor::as_hash32(entry)?);
        }
        if heads.is_empty() {
            return Err(CoreError::MalformedPayload);
        }
        let op_count = as_u64(find("op_count")?)?;
        let lamport_max = as_u64(find("lamport_max")?)?;
        let created_at = Timestamp::parse(as_text(find("created_at")?)?)?;
        let signature_bytes = crate::cbor::as_bytes(find("sig")?)?;
        if signature_bytes.len() != SIGNATURE_BYTES {
            return Err(CoreError::InvalidLength {
                expected: SIGNATURE_BYTES,
                actual: signature_bytes.len(),
            });
        }
        let mut signature = [0u8; SIGNATURE_BYTES];
        signature.copy_from_slice(signature_bytes);
        let head = Self {
            vault_id,
            heads,
            op_count,
            lamport_max,
            device_id,
            created_at,
            signature,
        };
        if head.to_cbor()? != bytes {
            return Err(CoreError::MalformedPayload);
        }
        Ok(head)
    }
}

/// What changed between a pinned head and a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadUpdate {
    /// Same head hash: nothing happened.
    NoChange,
    /// The new head descends from the pinned one.
    FastForward {
        /// Ops added since the pinned head.
        new_ops: u64,
    },
}

fn descends(ancestor: &VaultHead, descendant: &VaultHead, dag: &Dag) -> CoreResult<bool> {
    for head in &descendant.heads {
        if !dag.has(head) {
            return Err(CoreError::UnknownParent);
        }
    }
    for old in &ancestor.heads {
        if !dag.has(old) {
            // Without the old tip we cannot prove descent; treat it as a gap.
            return Ok(false);
        }
        if !descendant
            .heads
            .iter()
            .any(|new_head| dag.is_ancestor(old, new_head))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Requires `new_head` to descend from `last_trusted` (SPEC §6.9 checks 2–4).
pub fn verify_descends(
    last_trusted: &VaultHead,
    new_head: &VaultHead,
    dag: &Dag,
) -> CoreResult<()> {
    if last_trusted.vault_id != new_head.vault_id {
        return Err(CoreError::HeadVerificationFailed);
    }
    // §6.9 checks descent (3) before the counters (4): a served head that is an
    // ancestor of the pinned one is a rollback even though its counters are of
    // course lower.
    if !descends(last_trusted, new_head, dag)? {
        return Err(CoreError::RollbackDetected);
    }
    if new_head.op_count < last_trusted.op_count || new_head.lamport_max < last_trusted.lamport_max
    {
        return Err(CoreError::HeadCountersRegressed);
    }
    Ok(())
}

/// The full §6.9 step 3–4 decision: no change, fast-forward, rollback or fork.
pub fn check_head_update(
    pinned: &VaultHead,
    new_head: &VaultHead,
    dag: &Dag,
) -> CoreResult<HeadUpdate> {
    if pinned.vault_id != new_head.vault_id {
        return Err(CoreError::HeadVerificationFailed);
    }
    if hash_eq(&pinned.hash()?, &new_head.hash()?) {
        return Ok(HeadUpdate::NoChange);
    }
    if descends(pinned, new_head, dag)? {
        if new_head.op_count < pinned.op_count || new_head.lamport_max < pinned.lamport_max {
            return Err(CoreError::HeadCountersRegressed);
        }
        return Ok(HeadUpdate::FastForward {
            new_ops: new_head.op_count - pinned.op_count,
        });
    }
    if descends(new_head, pinned, dag)? {
        return Err(CoreError::RollbackDetected);
    }
    Err(CoreError::ForkDetected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use crate::crypto::signing::DeviceCertificate;
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

        fn add(&mut self, op_id: u8, parents: Vec<[u8; 32]>, lamport: u64) -> [u8; 32] {
            let payload =
                Op::seal_payload(&self.vk, &VAULT, &ITEM, OpKind::Create, b"x").expect("seal");
            let op = Op::new(
                VAULT,
                [op_id; 16],
                parents,
                lamport,
                DEVICE,
                at("2026-11-05T10:00:00Z"),
                OpKind::Create,
                Some(ITEM),
                payload,
            )
            .expect("op")
            .sign(&self.device)
            .expect("sign");
            self.dag.add(op, &self.registry).expect("add")
        }

        fn head(&self, heads: Vec<[u8; 32]>, op_count: u64, lamport: u64) -> VaultHead {
            VaultHead::create(
                &self.device,
                VAULT,
                DEVICE,
                heads,
                op_count,
                lamport,
                at("2026-11-05T10:05:00Z"),
            )
            .expect("head")
        }
    }

    #[test]
    fn creates_and_verifies_a_head() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let head = fixture.head(vec![first], 1, 1);
        head.verify(&fixture.registry).expect("verify");
        let bytes = head.to_cbor().expect("encode");
        let parsed = VaultHead::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed.hash().expect("hash"), head.hash().expect("hash"));
        assert_eq!(parsed.to_cbor().expect("re-encode"), bytes);
    }

    #[test]
    fn a_head_from_an_unknown_device_fails() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let stranger = SigningKeyPair::from_seed([9u8; 32]);
        let head = VaultHead::create(
            &stranger,
            VAULT,
            DEVICE,
            vec![first],
            1,
            1,
            at("2026-11-05T10:05:00Z"),
        )
        .expect("head");
        assert_eq!(
            head.verify(&fixture.registry).expect_err("unknown"),
            CoreError::HeadVerificationFailed
        );
        assert!(fixture.identity.public_bytes().len() == 32);
    }

    #[test]
    fn a_rollback_is_detected() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let second = fixture.add(2, vec![first], 2);
        let old = fixture.head(vec![first], 1, 1);
        let new = fixture.head(vec![second], 2, 2);
        assert_eq!(
            check_head_update(&new, &old, &fixture.dag).expect_err("rollback"),
            CoreError::RollbackDetected
        );
        assert_eq!(
            verify_descends(&new, &old, &fixture.dag).expect_err("rollback"),
            CoreError::RollbackDetected
        );
    }

    #[test]
    fn a_fork_is_detected() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let left = fixture.add(2, vec![first], 2);
        let right = fixture.add(3, vec![first], 2);
        let left_head = fixture.head(vec![left], 2, 2);
        let right_head = fixture.head(vec![right], 2, 2);
        assert_eq!(
            check_head_update(&left_head, &right_head, &fixture.dag).expect_err("fork"),
            CoreError::ForkDetected
        );
    }

    #[test]
    fn a_fast_forward_and_a_no_change_are_accepted() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let second = fixture.add(2, vec![first], 2);
        let old = fixture.head(vec![first], 1, 1);
        let new = fixture.head(vec![second], 2, 2);
        assert_eq!(
            check_head_update(&old, &new, &fixture.dag).expect("ff"),
            HeadUpdate::FastForward { new_ops: 1 }
        );
        assert_eq!(
            check_head_update(&old, &old, &fixture.dag).expect("same"),
            HeadUpdate::NoChange
        );
    }

    #[test]
    fn counters_may_not_regress() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let second = fixture.add(2, vec![first], 2);
        let pinned = fixture.head(vec![second], 2, 2);
        // A head that descends but claims fewer ops.
        let liar = fixture.head(vec![second], 1, 2);
        assert_eq!(
            check_head_update(&pinned, &liar, &fixture.dag).expect_err("counters"),
            CoreError::HeadCountersRegressed
        );
    }

    #[test]
    fn a_head_naming_an_unknown_op_fails() {
        let mut fixture = Fixture::new();
        let first = fixture.add(1, vec![], 1);
        let pinned = fixture.head(vec![first], 1, 1);
        let ghost = fixture.head(vec![[0xEE; 32]], 2, 2);
        assert_eq!(
            check_head_update(&pinned, &ghost, &fixture.dag).expect_err("ghost"),
            CoreError::UnknownParent
        );
    }
}
