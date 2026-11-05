//! The set of devices allowed to sign ops for one account (SPEC §4.7–§4.8).
//!
//! An op is only trusted if its `device_id` has a certificate that chains to
//! the pinned identity key *and* the device was not revoked at the op's
//! `created_at`. Keeping both rules in one place means no caller can check a
//! signature while forgetting the revocation cut-off.

use crate::crypto::signing::{DeviceCertificate, DeviceRevocation, Timestamp, PUBLIC_KEY_BYTES};
use crate::error::{CoreError, CoreResult};
use std::collections::BTreeMap;

/// Certified devices and their revocations.
#[derive(Debug, Clone)]
pub struct DeviceRegistry {
    account_id: [u8; 16],
    identity_public: [u8; PUBLIC_KEY_BYTES],
    keys: BTreeMap<[u8; 16], [u8; PUBLIC_KEY_BYTES]>,
    revoked: BTreeMap<[u8; 16], Timestamp>,
}

impl DeviceRegistry {
    /// Starts an empty registry pinned to one identity key.
    pub fn new(account_id: [u8; 16], identity_public: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self {
            account_id,
            identity_public,
            keys: BTreeMap::new(),
            revoked: BTreeMap::new(),
        }
    }

    /// The account these devices belong to.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The pinned identity key.
    pub fn identity_public(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.identity_public
    }

    /// Adds a certified device after verifying the certificate.
    pub fn certify(&mut self, cert: &DeviceCertificate, now: &Timestamp) -> CoreResult<()> {
        let revoked_at = self.revoked.get(cert.device_id());
        cert.verify(&self.identity_public, &self.account_id, now, revoked_at)
            .map_err(CoreError::Crypto)?;
        if self
            .keys
            .insert(*cert.device_id(), *cert.device_public_key())
            .is_some()
        {
            // Re-certifying is not a protocol error, but a second certificate
            // with a different key would be a silent key swap.
            return Ok(());
        }
        Ok(())
    }

    /// Records a revocation after verifying it against the identity key.
    pub fn revoke(&mut self, revocation: &DeviceRevocation) -> CoreResult<()> {
        revocation
            .verify(&self.identity_public, &self.account_id)
            .map_err(CoreError::Crypto)?;
        let entry = self.revoked.entry(*revocation.device_id());
        // Keep the earliest revocation: a later one must not widen the window.
        entry
            .and_modify(|existing| {
                if revocation.revoked_at().unix_seconds() < existing.unix_seconds() {
                    *existing = revocation.revoked_at().clone();
                }
            })
            .or_insert_with(|| revocation.revoked_at().clone());
        Ok(())
    }

    /// Whether the device is known at all.
    pub fn knows(&self, device_id: &[u8; 16]) -> bool {
        self.keys.contains_key(device_id)
    }

    /// The device key valid at `at`, or a typed error.
    pub fn key_at(
        &self,
        device_id: &[u8; 16],
        at: &Timestamp,
    ) -> CoreResult<[u8; PUBLIC_KEY_BYTES]> {
        let key = *self
            .keys
            .get(device_id)
            .ok_or(CoreError::OpVerificationFailed)?;
        if let Some(revoked_at) = self.revoked.get(device_id) {
            if at.unix_seconds() >= revoked_at.unix_seconds() {
                return Err(CoreError::Crypto(crate::crypto::CryptoError::Revoked));
            }
        }
        Ok(key)
    }

    /// The revocation time of a device, if revoked.
    pub fn revoked_at(&self, device_id: &[u8; 16]) -> Option<&Timestamp> {
        self.revoked.get(device_id)
    }

    /// Number of certified devices.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no device is certified yet.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::SigningKeyPair;

    const ACCOUNT: [u8; 16] = [0xA1; 16];
    const DEVICE: [u8; 16] = [0xD1; 16];

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn setup() -> (SigningKeyPair, DeviceRegistry, DeviceCertificate) {
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
        (identity, registry, cert)
    }

    #[test]
    fn a_certified_device_is_usable_before_its_revocation() {
        let (identity, mut registry, _) = setup();
        assert_eq!(
            registry
                .key_at(&DEVICE, &at("2026-11-05T10:00:00Z"))
                .expect("key"),
            SigningKeyPair::from_seed([2u8; 32]).public_bytes()
        );
        let revocation = DeviceRevocation::create(
            &identity,
            ACCOUNT,
            DEVICE,
            at("2026-11-05T11:00:00Z"),
            "lost phone",
        )
        .expect("revocation");
        registry.revoke(&revocation).expect("revoke");
        assert_eq!(
            registry
                .key_at(&DEVICE, &at("2026-11-05T11:00:01Z"))
                .expect_err("revoked"),
            CoreError::Crypto(crate::crypto::CryptoError::Revoked)
        );
        // Before the cut-off the old signature still verifies, which is the
        // documented ±5 min residual (R-0107).
        assert!(registry
            .key_at(&DEVICE, &at("2026-11-05T10:59:59Z"))
            .is_ok());
    }

    #[test]
    fn an_unknown_device_is_rejected() {
        let (_, registry, _) = setup();
        assert_eq!(
            registry
                .key_at(&[0xFF; 16], &at("2026-11-05T10:00:00Z"))
                .expect_err("unknown"),
            CoreError::OpVerificationFailed
        );
    }

    #[test]
    fn a_certificate_for_another_account_is_rejected() {
        let identity = SigningKeyPair::from_seed([1u8; 32]);
        let device = SigningKeyPair::from_seed([2u8; 32]);
        let mut registry = DeviceRegistry::new(ACCOUNT, identity.public_bytes());
        let foreign = DeviceCertificate::create(
            &identity,
            [0xBB; 16],
            DEVICE,
            device.public_bytes(),
            at("2026-11-05T09:00:00Z"),
        )
        .expect("cert");
        assert!(registry
            .certify(&foreign, &at("2026-11-05T09:30:00Z"))
            .is_err());
    }

    #[test]
    fn the_earliest_revocation_wins() {
        let (identity, mut registry, _) = setup();
        for when in ["2026-11-05T12:00:00Z", "2026-11-05T11:00:00Z"] {
            let revocation = DeviceRevocation::create(&identity, ACCOUNT, DEVICE, at(when), "lost")
                .expect("rev");
            registry.revoke(&revocation).expect("revoke");
        }
        assert_eq!(
            registry.revoked_at(&DEVICE).expect("revoked").as_str(),
            "2026-11-05T11:00:00Z"
        );
    }
}
