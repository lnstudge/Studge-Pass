//! The account: key bundle, unlock and vault keys (SPEC §4.5–§4.11).
//!
//! `create_account` derives a MUK from the password and Secret Key, wraps a
//! fresh Account Key under it, and seals the key bundle. `unlock` reverses
//! that; dropping the result (or calling `lock`) wipes every secret. The bundle
//! is the only thing the relay ever stores besides ops, and every entry is its
//! own AEAD envelope with the entry name in the AAD, so entries cannot be
//! swapped or silently dropped.
//!
//! Phase 3 keeps the device signing key outside the bundle on purpose: a device
//! key belongs in the OS keystore, not in a synced blob (Phase 7).

use crate::cbor::{
    as_array, as_id16, as_text, as_u64, bytes as cbor_bytes, map_pairs, text as cbor_text,
};
use crate::crypto::aad::{canonical_bytes, canonical_map, Aad, BundleEntry, RecordType};
use crate::crypto::aead::{self, Envelope};
use crate::crypto::error::CryptoResult;
use crate::crypto::kdf::{derive_muk, KdfParams, SALT_BYTES};
use crate::crypto::keys::{
    key_bundle_key, unwrap_account_key, unwrap_vault_key, wrap_account_key, wrap_vault_key,
    AccountKey, MasterUnlockKey, VaultKey,
};
use crate::crypto::random;
use crate::crypto::secret_key::SecretKey;
use crate::crypto::signing::{DeviceCertificate, DeviceRevocation, SigningKeyPair, Timestamp};
use crate::error::{CoreError, CoreResult};
use crate::oplog::devices::DeviceRegistry;
use ciborium::value::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// Bundle format version (SPEC §4.5).
pub const BUNDLE_VERSION: u8 = 1;

/// How a MUK is derived. Production always passes [`derive_muk`]; the crate's
/// tests pass a cheap derivation so a unit-test run stays fast.
type MukDerivation =
    fn(&str, &[u8; SALT_BYTES], &SecretKey, KdfParams) -> CryptoResult<MasterUnlockKey>;

/// What the user writes down: the Secret Key and the account id (SPEC §10.1).
pub struct RecoveryKitData {
    account_id: [u8; 16],
    secret_key: SecretKey,
}

impl RecoveryKitData {
    /// The account the kit belongs to.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The Secret Key. Printing it is the explicit job of the recovery UI.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl fmt::Debug for RecoveryKitData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryKitData")
            .field("account_id", &self.account_id)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

/// The account record: everything the relay stores (SPEC §7.5).
#[derive(Clone)]
pub struct AccountBundle {
    account_id: [u8; 16],
    account_salt: [u8; SALT_BYTES],
    kdf: KdfParams,
    ak_envelope: Envelope,
    entries: BTreeMap<String, Envelope>,
}

impl fmt::Debug for AccountBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountBundle")
            .field("account_id", &self.account_id)
            .field("kdf", &self.kdf)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl AccountBundle {
    /// The account id.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The Argon2id salt.
    pub fn account_salt(&self) -> &[u8; SALT_BYTES] {
        &self.account_salt
    }

    /// The KDF parameters recorded with the account.
    pub fn kdf(&self) -> KdfParams {
        self.kdf
    }

    /// The wrapped Account Key.
    pub fn ak_envelope(&self) -> &Envelope {
        &self.ak_envelope
    }

    /// The sealed bundle entry `name`, if present.
    pub fn entry(&self, name: BundleEntry) -> Option<&Envelope> {
        self.entries.get(name.as_str())
    }

    /// Stored form: canonical CBOR with every envelope as a byte string.
    pub fn to_cbor(&self) -> CoreResult<Vec<u8>> {
        let kdf = canonical_map(vec![
            ("version", Value::Integer((self.kdf.version as u64).into())),
            ("m", Value::Integer((self.kdf.m_kib as u64).into())),
            ("t", Value::Integer((self.kdf.t as u64).into())),
            ("p", Value::Integer((self.kdf.p as u64).into())),
        ]);
        let mut sealed: Vec<(Value, Value)> = Vec::with_capacity(self.entries.len());
        for (name, envelope) in &self.entries {
            sealed.push((cbor_text(name), cbor_bytes(&envelope.to_cbor()?)));
        }
        let map = canonical_map(vec![
            ("suite", cbor_text(crate::crypto::labels::SUITE_V1)),
            ("account_id", cbor_bytes(&self.account_id)),
            ("account_salt", cbor_bytes(&self.account_salt)),
            ("kdf", kdf),
            ("ak", cbor_bytes(&self.ak_envelope.to_cbor()?)),
            ("bundle", Value::Map(sealed)),
        ]);
        Ok(canonical_bytes(&map)?)
    }

    /// Parses the stored form, rejecting unknown keys or entries.
    pub fn from_cbor(bytes: &[u8]) -> CoreResult<Self> {
        let entries = crate::cbor::parse_map(bytes)?;
        let expected = ["suite", "account_id", "account_salt", "kdf", "ak", "bundle"];
        if entries.len() != expected.len() {
            return Err(CoreError::InvalidBundle);
        }
        for (key, _) in &entries {
            if !expected.contains(&key.as_str()) {
                return Err(CoreError::InvalidBundle);
            }
        }
        let find = |name: &str| -> CoreResult<&Value> {
            entries
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
                .ok_or(CoreError::InvalidBundle)
        };
        if as_text(find("suite")?)? != crate::crypto::labels::SUITE_V1 {
            return Err(CoreError::InvalidBundle);
        }
        let account_id = as_id16(find("account_id")?)?.ok_or(CoreError::InvalidBundle)?;
        let salt_bytes = crate::cbor::as_bytes(find("account_salt")?)?;
        if salt_bytes.len() != SALT_BYTES {
            return Err(CoreError::InvalidLength {
                expected: SALT_BYTES,
                actual: salt_bytes.len(),
            });
        }
        let mut account_salt = [0u8; SALT_BYTES];
        account_salt.copy_from_slice(salt_bytes);

        let kdf_pairs = map_pairs(find("kdf")?)?;
        if kdf_pairs.len() != 4 {
            return Err(CoreError::InvalidBundle);
        }
        let (mut version, mut m, mut t, mut p) = (None, None, None, None);
        for (key, value) in kdf_pairs {
            match key.as_str() {
                "version" => version = Some(as_u64(value)?),
                "m" => m = Some(as_u64(value)?),
                "t" => t = Some(as_u64(value)?),
                "p" => p = Some(as_u64(value)?),
                _ => return Err(CoreError::InvalidBundle),
            }
        }
        let kdf = KdfParams {
            version: u8::try_from(version.ok_or(CoreError::InvalidBundle)?)
                .map_err(|_| CoreError::InvalidBundle)?,
            m_kib: u32::try_from(m.ok_or(CoreError::InvalidBundle)?)
                .map_err(|_| CoreError::InvalidBundle)?,
            t: u32::try_from(t.ok_or(CoreError::InvalidBundle)?)
                .map_err(|_| CoreError::InvalidBundle)?,
            p: u32::try_from(p.ok_or(CoreError::InvalidBundle)?)
                .map_err(|_| CoreError::InvalidBundle)?,
        };
        // The KDF minimums are enforced where the MUK is derived
        // (`derive_muk`), not here: a record must parse so that a client can
        // report "this account was downgraded" instead of "corrupt file".

        let ak_envelope = Envelope::from_cbor(crate::cbor::as_bytes(find("ak")?)?)?;

        let mut bundle_entries = BTreeMap::new();
        for (name, value) in map_pairs(find("bundle")?)? {
            if BundleEntry::parse(&name).is_none() {
                return Err(CoreError::InvalidBundle);
            }
            let envelope = Envelope::from_cbor(crate::cbor::as_bytes(value)?)?;
            bundle_entries.insert(name, envelope);
        }

        Ok(Self {
            account_id,
            account_salt,
            kdf,
            ak_envelope,
            entries: bundle_entries,
        })
    }
}

/// A new account: the record, the Secret Key and the recovery kit.
pub fn create_account(password: &str) -> CoreResult<(AccountBundle, SecretKey, RecoveryKitData)> {
    create_account_with(password, KdfParams::V1, derive_muk)
}

fn create_account_with(
    password: &str,
    kdf: KdfParams,
    derive: MukDerivation,
) -> CoreResult<(AccountBundle, SecretKey, RecoveryKitData)> {
    let account_id: [u8; 16] = random::array()?;
    let account_salt: [u8; SALT_BYTES] = random::array()?;
    let secret_key = SecretKey::generate()?;
    let muk = derive(password, &account_salt, &secret_key, kdf)?;

    let account_key = AccountKey::generate()?;
    let ak_envelope = wrap_account_key(&muk, &account_id, &account_key)?;

    let identity_signing = SigningKeyPair::generate()?;
    let identity_public = identity_signing.public_bytes();
    let identity_encryption: Zeroizing<[u8; 32]> = Zeroizing::new(random::array()?);
    let (kem_seed, kem_public) = generate_kem_key()?;

    let unlocked = UnlockedAccount {
        account_id,
        account_salt,
        kdf,
        ak_envelope,
        account_key,
        identity_signing,
        identity_public,
        identity_encryption,
        kem_seed,
        kem_public,
        devices: DeviceRegistry::new(account_id, identity_public),
        head_pins: BTreeMap::new(),
    };
    let bundle = unlocked.seal()?;
    let kit = RecoveryKitData {
        account_id,
        secret_key: SecretKey::from_bytes(*secret_key.as_bytes()),
    };
    Ok((bundle, secret_key, kit))
}

/// An unlocked account. Dropping it (or calling [`UnlockedAccount::lock`])
/// wipes every secret it holds.
pub struct UnlockedAccount {
    account_id: [u8; 16],
    account_salt: [u8; SALT_BYTES],
    kdf: KdfParams,
    ak_envelope: Envelope,
    account_key: AccountKey,
    identity_signing: SigningKeyPair,
    identity_public: [u8; 32],
    identity_encryption: Zeroizing<[u8; 32]>,
    kem_seed: Zeroizing<[u8; 64]>,
    kem_public: Vec<u8>,
    devices: DeviceRegistry,
    head_pins: BTreeMap<[u8; 16], [u8; 32]>,
}

impl fmt::Debug for UnlockedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedAccount")
            .field("account_id", &self.account_id)
            .field("devices", &self.devices.len())
            .field("vault_pins", &self.head_pins.len())
            .finish()
    }
}

impl UnlockedAccount {
    /// The account id.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The identity signing public key (published in the transparency log).
    pub fn identity_public(&self) -> &[u8; 32] {
        &self.identity_public
    }

    /// The X25519 identity public key (HPKE recipient for sharing).
    pub fn identity_encryption_public(&self) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*self.identity_encryption);
        x25519_dalek::PublicKey::from(&secret).to_bytes()
    }

    /// The ML-KEM-768 encapsulation key stored since v1 (D-0105).
    pub fn identity_kem_public(&self) -> &[u8] {
        &self.kem_public
    }

    /// The certified devices.
    pub fn devices(&self) -> &DeviceRegistry {
        &self.devices
    }

    /// Certifies a device key with the identity key (SPEC §4.7).
    pub fn certify_device(
        &mut self,
        device_id: [u8; 16],
        device_public: [u8; 32],
        now: &Timestamp,
    ) -> CoreResult<DeviceCertificate> {
        let cert = DeviceCertificate::create(
            &self.identity_signing,
            self.account_id,
            device_id,
            device_public,
            now.clone(),
        )?;
        self.devices.certify(&cert, now)?;
        Ok(cert)
    }

    /// Revokes a device (SPEC §4.8).
    pub fn revoke_device(
        &mut self,
        device_id: [u8; 16],
        now: &Timestamp,
        reason: &str,
    ) -> CoreResult<DeviceRevocation> {
        let revocation = DeviceRevocation::create(
            &self.identity_signing,
            self.account_id,
            device_id,
            now.clone(),
            reason,
        )?;
        self.devices.revoke(&revocation)?;
        Ok(revocation)
    }

    /// Creates a vault key and wraps it for the owner (SPEC §4.9).
    pub fn create_vault(&self) -> CoreResult<([u8; 16], VaultKey, Envelope)> {
        let vault_id: [u8; 16] = random::array()?;
        let vk = VaultKey::generate()?;
        let envelope = wrap_vault_key(&self.account_key, &vault_id, &vk)?;
        Ok((vault_id, vk, envelope))
    }

    /// Unwraps a vault key.
    pub fn open_vault(&self, vault_id: &[u8; 16], envelope: &Envelope) -> CoreResult<VaultKey> {
        Ok(unwrap_vault_key(&self.account_key, vault_id, envelope)?)
    }

    /// Records the last verified head hash for a vault (SPEC §6.9).
    pub fn pin_head(&mut self, vault_id: [u8; 16], head_hash: [u8; 32]) {
        self.head_pins.insert(vault_id, head_hash);
    }

    /// The pinned head hash for a vault.
    pub fn head_pin(&self, vault_id: &[u8; 16]) -> Option<&[u8; 32]> {
        self.head_pins.get(vault_id)
    }

    /// Re-seals every bundle entry into a fresh [`AccountBundle`].
    pub fn seal(&self) -> CoreResult<AccountBundle> {
        let key = key_bundle_key(&self.account_key, &self.account_id)?;
        let mut entries: BTreeMap<String, Envelope> = BTreeMap::new();

        let mut put = |entry: BundleEntry, plaintext: &[u8]| -> CoreResult<()> {
            let aad = Aad::builder(RecordType::Bundle(entry))
                .account(self.account_id)
                .build()?;
            let envelope = aead::seal(&key, &aad, plaintext)?;
            entries.insert(entry.as_str().to_string(), envelope);
            Ok(())
        };

        put(
            BundleEntry::BundleVersion,
            &canonical_bytes(&Value::Integer((BUNDLE_VERSION as u64).into()))?,
        )?;
        put(
            BundleEntry::IdentitySigning,
            &self.identity_signing.seed_bytes(),
        )?;
        put(
            BundleEntry::IdentityEncryption,
            &self.identity_encryption[..],
        )?;
        put(BundleEntry::IdentityKem, &self.kem_seed[..])?;

        let mut certs: Vec<Value> = Vec::new();
        for cert in self.devices.certificates() {
            certs.push(cbor_bytes(&cert.to_cbor()?));
        }
        let mut revocations: Vec<Value> = Vec::new();
        for revocation in self.devices.revocations() {
            revocations.push(cbor_bytes(&revocation.to_cbor()?));
        }
        let device_list = canonical_map(vec![
            ("certs", Value::Array(certs)),
            ("revocations", Value::Array(revocations)),
        ]);
        put(BundleEntry::DeviceList, &canonical_bytes(&device_list)?)?;

        let pins = Value::Map(
            self.head_pins
                .iter()
                .map(|(vault_id, head)| {
                    (
                        cbor_text(&crate::codec::base64url_encode(vault_id)),
                        cbor_bytes(head),
                    )
                })
                .collect(),
        );
        put(BundleEntry::HeadPins, &canonical_bytes(&pins)?)?;

        Ok(AccountBundle {
            account_id: self.account_id,
            account_salt: self.account_salt,
            kdf: self.kdf,
            ak_envelope: self.ak_envelope.clone(),
            entries,
        })
    }

    /// Zeroizes every secret this account holds.
    pub fn lock(self) {
        // Consuming `self` drops each secret; `Zeroizing` wipes the buffers.
    }
}

/// Unlocks an account with the password and the Secret Key (SPEC §4.3–§4.5).
pub fn unlock(
    password: &str,
    secret_key: &SecretKey,
    bundle: &AccountBundle,
) -> CoreResult<UnlockedAccount> {
    unlock_with(password, secret_key, bundle, derive_muk)
}

fn unlock_with(
    password: &str,
    secret_key: &SecretKey,
    bundle: &AccountBundle,
    derive: MukDerivation,
) -> CoreResult<UnlockedAccount> {
    // `derive_muk` (the production path) validates the parameters before any
    // Argon2 work, so a downgraded account fails here and never unlocks. Doing
    // it twice would stop the crate's own tests from using cheap parameters.
    let muk = derive(password, &bundle.account_salt, secret_key, bundle.kdf)?;
    let account_key = unwrap_account_key(&muk, &bundle.account_id, &bundle.ak_envelope)?;
    let key = key_bundle_key(&account_key, &bundle.account_id)?;

    let open_entry = |entry: BundleEntry| -> CoreResult<Zeroizing<Vec<u8>>> {
        let envelope = bundle.entry(entry).ok_or(CoreError::InvalidBundle)?;
        let aad = Aad::builder(RecordType::Bundle(entry))
            .account(bundle.account_id)
            .build()?;
        Ok(aead::open(&key, &aad, envelope)?)
    };

    let version_bytes = open_entry(BundleEntry::BundleVersion)?;
    if as_u64(&ciborium_value(&version_bytes)?)? != BUNDLE_VERSION as u64 {
        return Err(CoreError::UnsupportedSchemaVersion);
    }

    let signing_bytes = open_entry(BundleEntry::IdentitySigning)?;
    if signing_bytes.len() != 32 {
        return Err(CoreError::InvalidLength {
            expected: 32,
            actual: signing_bytes.len(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&signing_bytes);
    let identity_signing = SigningKeyPair::from_seed(seed);
    let identity_public = identity_signing.public_bytes();

    let encryption_bytes = open_entry(BundleEntry::IdentityEncryption)?;
    if encryption_bytes.len() != 32 {
        return Err(CoreError::InvalidLength {
            expected: 32,
            actual: encryption_bytes.len(),
        });
    }
    let mut encryption = [0u8; 32];
    encryption.copy_from_slice(&encryption_bytes);

    let kem_bytes = open_entry(BundleEntry::IdentityKem)?;
    if kem_bytes.len() != 64 {
        return Err(CoreError::InvalidLength {
            expected: 64,
            actual: kem_bytes.len(),
        });
    }
    let mut kem_seed = [0u8; 64];
    kem_seed.copy_from_slice(&kem_bytes);
    let kem_public = kem_public_from_seed(&kem_seed)?;

    let mut devices = DeviceRegistry::new(bundle.account_id, identity_public);
    let device_value = ciborium_value(&open_entry(BundleEntry::DeviceList)?)?;
    let pairs = map_pairs(&device_value)?;
    if pairs.len() != 2 {
        return Err(CoreError::InvalidBundle);
    }
    let now = Timestamp::now()?;
    for (name, value) in pairs {
        match name.as_str() {
            "certs" => {
                for entry in as_array(value)? {
                    let cert = DeviceCertificate::from_cbor(crate::cbor::as_bytes(entry)?)?;
                    devices.certify(&cert, &now)?;
                }
            }
            "revocations" => {
                for entry in as_array(value)? {
                    let revocation = DeviceRevocation::from_cbor(crate::cbor::as_bytes(entry)?)?;
                    devices.revoke(&revocation)?;
                }
            }
            _ => return Err(CoreError::InvalidBundle),
        }
    }

    let pin_value = ciborium_value(&open_entry(BundleEntry::HeadPins)?)?;
    let mut head_pins = BTreeMap::new();
    for (vault_key, head) in map_pairs(&pin_value)? {
        let vault_bytes = crate::codec::base64url_decode(&vault_key)?;
        if vault_bytes.len() != 16 {
            return Err(CoreError::InvalidLength {
                expected: 16,
                actual: vault_bytes.len(),
            });
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&vault_bytes);
        let head_bytes = crate::cbor::as_bytes(head)?;
        if head_bytes.len() != 32 {
            return Err(CoreError::InvalidLength {
                expected: 32,
                actual: head_bytes.len(),
            });
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(head_bytes);
        head_pins.insert(id, hash);
    }

    Ok(UnlockedAccount {
        account_id: bundle.account_id,
        account_salt: bundle.account_salt,
        kdf: bundle.kdf,
        ak_envelope: bundle.ak_envelope.clone(),
        account_key,
        identity_signing,
        identity_public,
        identity_encryption: Zeroizing::new(encryption),
        kem_seed: Zeroizing::new(kem_seed),
        kem_public,
        devices,
        head_pins,
    })
}

fn ciborium_value(bytes: &[u8]) -> CoreResult<Value> {
    let mut cursor = std::io::Cursor::new(bytes);
    ciborium::de::from_reader(&mut cursor).map_err(|_| CoreError::MalformedPayload)
}

/// Generates an ML-KEM-768 key pair and returns its 64-byte seed plus the
/// encapsulation key (SPEC §4.6, D-0105).
fn generate_kem_key() -> CoreResult<(Zeroizing<[u8; 64]>, Vec<u8>)> {
    let seed: Zeroizing<[u8; 64]> = Zeroizing::new(random::array()?);
    let public = kem_public_from_seed(&seed)?;
    Ok((seed, public))
}

fn kem_public_from_seed(seed: &[u8; 64]) -> CoreResult<Vec<u8>> {
    use ml_kem::kem::KeyExport;
    use ml_kem::DecapsulationKey768;
    let key = DecapsulationKey768::from_seed((*seed).into());
    Ok(key.encapsulation_key().to_bytes().as_slice().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::derive_muk_raw;

    /// Cheap parameters for unit tests. The production path is covered by the
    /// ignored test below and by `tests/kdf_slow.rs`.
    fn fast_params() -> KdfParams {
        KdfParams {
            version: 1,
            m_kib: 8,
            t: 1,
            p: 1,
        }
    }

    fn fast(
        password: &str,
        salt: &[u8; SALT_BYTES],
        secret_key: &SecretKey,
        params: KdfParams,
    ) -> CryptoResult<MasterUnlockKey> {
        derive_muk_raw(password, salt, secret_key, params)
    }

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    const PASSWORD: &str = "correct horse battery staple";

    fn account() -> (AccountBundle, SecretKey) {
        let (bundle, secret_key, _kit) =
            create_account_with(PASSWORD, fast_params(), fast).expect("create");
        (bundle, secret_key)
    }

    #[test]
    fn create_unlock_round_trip() {
        let (bundle, secret_key) = account();
        let unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        assert_eq!(unlocked.account_id(), bundle.account_id());
        assert_eq!(unlocked.identity_public().len(), 32);
        assert_eq!(unlocked.identity_kem_public().len(), 1184);
        assert!(unlocked.devices().is_empty());

        // The bundle survives storage and still unlocks.
        let bytes = bundle.to_cbor().expect("encode");
        let parsed = AccountBundle::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed.account_id(), bundle.account_id());
        unlock_with(PASSWORD, &secret_key, &parsed, fast).expect("unlock after round trip");
    }

    #[test]
    fn a_wrong_password_or_secret_key_fails() {
        let (bundle, secret_key) = account();
        assert!(unlock_with("wrong password", &secret_key, &bundle, fast).is_err());
        let other = SecretKey::from_bytes([0xAB; 16]);
        assert!(unlock_with(PASSWORD, &other, &bundle, fast).is_err());
    }

    #[test]
    fn every_bundle_entry_is_bound_to_its_name() {
        // Swap two entries: each is sealed with its own AAD, so opening fails.
        let (bundle, secret_key) = account();
        let mut swapped = bundle.clone();
        let signing = swapped
            .entries
            .get(BundleEntry::IdentitySigning.as_str())
            .expect("signing")
            .clone();
        let encryption = swapped
            .entries
            .get(BundleEntry::IdentityEncryption.as_str())
            .expect("encryption")
            .clone();
        swapped.entries.insert(
            BundleEntry::IdentitySigning.as_str().to_string(),
            encryption,
        );
        swapped.entries.insert(
            BundleEntry::IdentityEncryption.as_str().to_string(),
            signing,
        );
        assert!(unlock_with(PASSWORD, &secret_key, &swapped, fast).is_err());
    }

    #[test]
    fn a_dropped_entry_is_rejected() {
        let (bundle, secret_key) = account();
        let mut missing = bundle.clone();
        missing.entries.remove(BundleEntry::IdentityKem.as_str());
        assert!(unlock_with(PASSWORD, &secret_key, &missing, fast).is_err());
    }

    #[test]
    fn devices_can_be_certified_and_revoked() {
        let (bundle, secret_key) = account();
        let mut unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        let device = SigningKeyPair::from_seed([0x44; 32]);
        let cert = unlocked
            .certify_device(
                [0xD1; 16],
                device.public_bytes(),
                &at("2026-11-05T10:00:00Z"),
            )
            .expect("certify");
        assert!(unlocked.devices().knows(&[0xD1; 16]));
        assert_eq!(cert.device_id(), &[0xD1; 16]);

        unlocked
            .revoke_device([0xD1; 16], &at("2026-11-05T11:00:00Z"), "lost phone")
            .expect("revoke");
        assert_eq!(
            unlocked
                .devices()
                .revoked_at(&[0xD1; 16])
                .expect("revoked")
                .as_str(),
            "2026-11-05T11:00:00Z"
        );
    }

    #[test]
    fn a_sealed_bundle_carries_devices_and_head_pins() {
        let (bundle, secret_key) = account();
        let mut unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        let device = SigningKeyPair::from_seed([0x44; 32]);
        // Unlock verifies certificates against the real clock, so certify at
        // "now" rather than at a fixed date that may be in the future.
        let now = Timestamp::now().expect("clock");
        unlocked
            .certify_device([0xD1; 16], device.public_bytes(), &now)
            .expect("certify");
        unlocked.pin_head([0x77; 16], [0x88; 32]);

        let sealed = unlocked.seal().expect("seal");
        let reopened = unlock_with(PASSWORD, &secret_key, &sealed, fast).expect("reopen");
        assert!(reopened.devices().knows(&[0xD1; 16]));
        assert_eq!(reopened.head_pin(&[0x77; 16]), Some(&[0x88; 32]));
    }

    #[test]
    fn vault_keys_wrap_and_unwrap() {
        let (bundle, secret_key) = account();
        let unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        let (vault_id, vk, envelope) = unlocked.create_vault().expect("vault");
        let opened = unlocked.open_vault(&vault_id, &envelope).expect("open");
        assert_eq!(opened.as_bytes(), vk.as_bytes());
        assert!(unlocked.open_vault(&[0x11; 16], &envelope).is_err());
    }

    #[test]
    fn a_downgraded_kdf_is_rejected_at_unlock() {
        let (bundle, secret_key) = account();
        let bytes = bundle.to_cbor().expect("encode");
        let mut cursor = std::io::Cursor::new(bytes);
        let mut value: Value = ciborium::de::from_reader(&mut cursor).expect("decode");
        let Value::Map(ref mut entries) = value else {
            panic!("map");
        };
        for (key, entry) in entries.iter_mut() {
            if key == &cbor_text("kdf") {
                *entry = canonical_map(vec![
                    ("version", Value::Integer(1i64.into())),
                    ("m", Value::Integer(1024i64.into())),
                    ("t", Value::Integer(3i64.into())),
                    ("p", Value::Integer(1i64.into())),
                ]);
            }
        }
        let weakened = AccountBundle::from_cbor(&canonical_bytes(&value).expect("encode"))
            .expect("a record still parses");
        // The production unlock refuses the weakened parameters before it runs
        // Argon2, so this is fast and fail-closed.
        assert_eq!(
            unlock(PASSWORD, &secret_key, &weakened).expect_err("downgrade"),
            CoreError::Crypto(crate::crypto::CryptoError::WeakKdfParameters)
        );
    }

    #[test]
    fn debug_never_prints_key_material() {
        let (bundle, secret_key) = account();
        let unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        let kit = RecoveryKitData {
            account_id: *bundle.account_id(),
            secret_key: SecretKey::from_bytes(*secret_key.as_bytes()),
        };
        for printed in [
            format!("{bundle:?}"),
            format!("{unlocked:?}"),
            format!("{kit:?}"),
        ] {
            assert!(!printed.contains("SP1-"));
            assert!(!printed.contains("correct horse"));
        }
    }

    #[test]
    fn locking_drops_everything() {
        let (bundle, secret_key) = account();
        let unlocked = unlock_with(PASSWORD, &secret_key, &bundle, fast).expect("unlock");
        unlocked.lock();
        // Nothing to assert beyond "it compiles and consumes": the guarantee is
        // the move plus `Zeroizing`, and the test documents the contract.
    }

    #[test]
    #[ignore = "real Argon2id parameters take seconds; run explicitly"]
    fn create_and_unlock_with_real_parameters() {
        let (bundle, secret_key, kit) = create_account("a real password").expect("create");
        assert_eq!(kit.account_id(), bundle.account_id());
        let unlocked = unlock("a real password", &secret_key, &bundle).expect("unlock");
        assert_eq!(unlocked.account_id(), bundle.account_id());
    }
}
