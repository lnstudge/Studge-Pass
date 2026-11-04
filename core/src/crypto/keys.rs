//! Key newtypes and the wrap/unwrap hierarchy (SPEC §4.5, §4.9, §4.10).
//!
//! Four secret key types, each a `Zeroizing<[u8; 32]>` with a redacted `Debug`
//! and no `Clone`. Wrapping always goes through [`crate::crypto::aead`] with an
//! AAD built from the ids the key belongs to, so a wrapped key cannot be moved
//! to another account, vault or item.

use crate::crypto::aad::{Aad, RecordType};
use crate::crypto::aead::{self, AeadKey, Envelope, KEY_BYTES};
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::kdf::derive_subkey;
use crate::crypto::labels;
use crate::crypto::random;
use std::fmt;
use zeroize::Zeroizing;

macro_rules! secret_key_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(Zeroizing<[u8; KEY_BYTES]>);

        impl $name {
            /// Draws 32 bytes from the operating system's random source.
            pub fn generate() -> CryptoResult<Self> {
                Ok(Self(Zeroizing::new(random::array::<KEY_BYTES>()?)))
            }

            /// Wraps known bytes (unwrapping, tests, vectors).
            pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// The raw bytes. Callers must not log or serialise this.
            pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

secret_key_type!(
    MasterUnlockKey,
    "Derived from the master password and Secret Key; never stored."
);
secret_key_type!(AccountKey, "Wrapped by the MUK; unlocks the key bundle.");
secret_key_type!(VaultKey, "Wrapped by the AK for the owner; shared via HPKE.");
secret_key_type!(ItemKey, "Wrapped by the VK; encrypts one item's fields.");

/// The key that wraps the Account Key (SPEC §4.5).
pub fn account_key_wrapping_key(muk: &MasterUnlockKey) -> CryptoResult<AeadKey> {
    derive_subkey(muk.as_bytes(), None, labels::AK_WRAP)
}

/// The key that encrypts the account key bundle (SPEC §4.5).
pub fn key_bundle_key(ak: &AccountKey, account_id: &[u8; 16]) -> CryptoResult<AeadKey> {
    derive_subkey(ak.as_bytes(), Some(account_id), labels::KEY_BUNDLE)
}

/// Wraps the Account Key under the MUK.
pub fn wrap_account_key(
    muk: &MasterUnlockKey,
    account_id: &[u8; 16],
    ak: &AccountKey,
) -> CryptoResult<Envelope> {
    let key = account_key_wrapping_key(muk)?;
    let aad = Aad::builder(RecordType::Ak).account(*account_id).build()?;
    aead::seal(&key, &aad, ak.as_bytes())
}

/// Unwraps the Account Key. A wrong MUK or a different account id fails.
pub fn unwrap_account_key(
    muk: &MasterUnlockKey,
    account_id: &[u8; 16],
    envelope: &Envelope,
) -> CryptoResult<AccountKey> {
    let key = account_key_wrapping_key(muk)?;
    let aad = Aad::builder(RecordType::Ak).account(*account_id).build()?;
    let plaintext = aead::open(&key, &aad, envelope)?;
    Ok(AccountKey::from_bytes(key_from_plaintext(&plaintext)?))
}

/// Wraps a vault key for its owner (SPEC §4.9).
pub fn wrap_vault_key(
    ak: &AccountKey,
    vault_id: &[u8; 16],
    vk: &VaultKey,
) -> CryptoResult<Envelope> {
    let key = derive_subkey(ak.as_bytes(), Some(vault_id), labels::VK_WRAP)?;
    let aad = Aad::builder(RecordType::VkOwner)
        .vault(*vault_id)
        .build()?;
    aead::seal(&key, &aad, vk.as_bytes())
}

/// Unwraps a vault key. A wrong AK or a different vault id fails.
pub fn unwrap_vault_key(
    ak: &AccountKey,
    vault_id: &[u8; 16],
    envelope: &Envelope,
) -> CryptoResult<VaultKey> {
    let key = derive_subkey(ak.as_bytes(), Some(vault_id), labels::VK_WRAP)?;
    let aad = Aad::builder(RecordType::VkOwner)
        .vault(*vault_id)
        .build()?;
    let plaintext = aead::open(&key, &aad, envelope)?;
    Ok(VaultKey::from_bytes(key_from_plaintext(&plaintext)?))
}

/// Wraps an item key under its vault key (SPEC §4.10).
pub fn wrap_item_key(
    vk: &VaultKey,
    vault_id: &[u8; 16],
    item_id: &[u8; 16],
    ik: &ItemKey,
) -> CryptoResult<Envelope> {
    let key = derive_subkey(vk.as_bytes(), Some(item_id), labels::IK_WRAP)?;
    let aad = Aad::builder(RecordType::Ik)
        .vault(*vault_id)
        .item(*item_id)
        .build()?;
    aead::seal(&key, &aad, ik.as_bytes())
}

/// Unwraps an item key. A wrong VK, vault or item id fails.
pub fn unwrap_item_key(
    vk: &VaultKey,
    vault_id: &[u8; 16],
    item_id: &[u8; 16],
    envelope: &Envelope,
) -> CryptoResult<ItemKey> {
    let key = derive_subkey(vk.as_bytes(), Some(item_id), labels::IK_WRAP)?;
    let aad = Aad::builder(RecordType::Ik)
        .vault(*vault_id)
        .item(*item_id)
        .build()?;
    let plaintext = aead::open(&key, &aad, envelope)?;
    Ok(ItemKey::from_bytes(key_from_plaintext(&plaintext)?))
}

/// The key that encrypts one item's fields (SPEC §4.10).
pub fn item_field_key(ik: &ItemKey, item_id: &[u8; 16]) -> CryptoResult<AeadKey> {
    derive_subkey(ik.as_bytes(), Some(item_id), labels::ITEM_FIELD)
}

/// The key that encrypts op payloads in a vault (SPEC §5.4).
pub fn op_payload_key(vk: &VaultKey, vault_id: &[u8; 16]) -> CryptoResult<AeadKey> {
    derive_subkey(vk.as_bytes(), Some(vault_id), labels::OP_PAYLOAD)
}

fn key_from_plaintext(plaintext: &[u8]) -> CryptoResult<[u8; KEY_BYTES]> {
    if plaintext.len() != KEY_BYTES {
        return Err(CryptoError::InvalidLength {
            expected: KEY_BYTES,
            actual: plaintext.len(),
        });
    }
    let mut out = [0u8; KEY_BYTES];
    out.copy_from_slice(plaintext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const VAULT: [u8; 16] = [0xB2; 16];
    const ITEM: [u8; 16] = [0xC3; 16];

    fn muk() -> MasterUnlockKey {
        MasterUnlockKey::from_bytes([1u8; 32])
    }

    fn ak() -> AccountKey {
        AccountKey::from_bytes([2u8; 32])
    }

    fn vk() -> VaultKey {
        VaultKey::from_bytes([3u8; 32])
    }

    fn ik() -> ItemKey {
        ItemKey::from_bytes([4u8; 32])
    }

    #[test]
    fn account_key_round_trip() {
        let wrapped = wrap_account_key(&muk(), &ACCOUNT, &ak()).expect("wrap");
        let unwrapped = unwrap_account_key(&muk(), &ACCOUNT, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), ak().as_bytes());
    }

    #[test]
    fn account_key_wrong_key_or_id_fails() {
        let wrapped = wrap_account_key(&muk(), &ACCOUNT, &ak()).expect("wrap");
        let other_muk = MasterUnlockKey::from_bytes([9u8; 32]);
        assert_eq!(
            unwrap_account_key(&other_muk, &ACCOUNT, &wrapped).expect_err("muk"),
            CryptoError::DecryptionFailed
        );
        assert_eq!(
            unwrap_account_key(&muk(), &[0xFF; 16], &wrapped).expect_err("account id"),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn vault_key_round_trip_and_binding() {
        let wrapped = wrap_vault_key(&ak(), &VAULT, &vk()).expect("wrap");
        let unwrapped = unwrap_vault_key(&ak(), &VAULT, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), vk().as_bytes());
        assert_eq!(
            unwrap_vault_key(&ak(), &[0xEE; 16], &wrapped).expect_err("vault id"),
            CryptoError::DecryptionFailed
        );
        assert_eq!(
            unwrap_vault_key(&AccountKey::from_bytes([8u8; 32]), &VAULT, &wrapped)
                .expect_err("ak"),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn item_key_round_trip_and_binding() {
        let wrapped = wrap_item_key(&vk(), &VAULT, &ITEM, &ik()).expect("wrap");
        let unwrapped = unwrap_item_key(&vk(), &VAULT, &ITEM, &wrapped).expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), ik().as_bytes());
        assert_eq!(
            unwrap_item_key(&vk(), &VAULT, &[0xDD; 16], &wrapped).expect_err("item"),
            CryptoError::DecryptionFailed
        );
    }

    #[test]
    fn field_keys_differ_per_item() {
        let a = item_field_key(&ik(), &ITEM).expect("a");
        let b = item_field_key(&ik(), &[0xDD; 16]).expect("b");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn bundle_and_op_keys_are_domain_separated() {
        let bundle = key_bundle_key(&ak(), &ACCOUNT).expect("bundle");
        let op = op_payload_key(&vk(), &VAULT).expect("op");
        assert_ne!(bundle.as_bytes(), op.as_bytes());
        let ak_wrap = account_key_wrapping_key(&muk()).expect("ak wrap");
        assert_ne!(ak_wrap.as_bytes(), bundle.as_bytes());
    }

    #[test]
    fn debug_redacts_every_key_type() {
        for printed in [
            format!("{:?}", muk()),
            format!("{:?}", ak()),
            format!("{:?}", vk()),
            format!("{:?}", ik()),
        ] {
            assert!(printed.contains("redacted"), "{printed}");
        }
    }
}
