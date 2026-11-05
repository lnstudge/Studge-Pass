//! Property tests for the crypto module: whatever the bytes, sealing then
//! opening returns them, and a wrong key never opens.

use proptest::prelude::*;
use studge_core::crypto::aad::{Aad, RecordType};
use studge_core::crypto::aead::{self, AeadKey};
use studge_core::crypto::keys::{unwrap_vault_key, wrap_vault_key, AccountKey, VaultKey};

const VAULT: [u8; 16] = [0x10; 16];
const ITEM: [u8; 16] = [0x20; 16];

fn aad() -> Aad {
    Aad::builder(RecordType::ItemField)
        .vault(VAULT)
        .item(ITEM)
        .field("password")
        .build()
        .expect("valid aad")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn aead_round_trip(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        key_bytes in any::<[u8; 32]>(),
    ) {
        let key = AeadKey::from_bytes(key_bytes);
        let envelope = aead::seal(&key, &aad(), &plaintext).expect("seal");
        let opened = aead::open(&key, &aad(), &envelope).expect("open");
        prop_assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn a_wrong_key_never_opens(
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        sealing in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
    ) {
        prop_assume!(sealing != other);
        let envelope = aead::seal(&AeadKey::from_bytes(sealing), &aad(), &plaintext).expect("seal");
        prop_assert!(aead::open(&AeadKey::from_bytes(other), &aad(), &envelope).is_err());
    }

    #[test]
    fn vault_key_wrap_round_trip(
        ak_bytes in any::<[u8; 32]>(),
        vk_bytes in any::<[u8; 32]>(),
    ) {
        let ak = AccountKey::from_bytes(ak_bytes);
        let vk = VaultKey::from_bytes(vk_bytes);
        let wrapped = wrap_vault_key(&ak, &VAULT, &vk).expect("wrap");
        let unwrapped = unwrap_vault_key(&ak, &VAULT, &wrapped).expect("unwrap");
        prop_assert_eq!(unwrapped.as_bytes(), vk.as_bytes());
    }
}
