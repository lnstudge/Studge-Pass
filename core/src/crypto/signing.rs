//! Ed25519 keys, device certificates, revocations and enrolment proofs
//! (SPEC §4.7–§4.8).
//!
//! Every signed body is a canonical CBOR map that carries `suite` and `type`,
//! so a signature can never be replayed in another role (D-0106). Timestamps
//! are fixed-width RFC 3339 UTC strings, which sort correctly as text and are
//! compared numerically through [`Timestamp::unix_seconds`].

use crate::crypto::aad::{canonical_bytes, canonical_map};
use crate::crypto::error::{CryptoError, CryptoResult};
use crate::crypto::labels::{DEVICE_CERT, DEVICE_ENROLL, DEVICE_REVOCATION, SUITE_V1};
use crate::crypto::random;
use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::fmt;
use zeroize::Zeroizing;

/// Ed25519 public key length.
pub const PUBLIC_KEY_BYTES: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_BYTES: usize = 64;
/// Clock skew allowed for `created_at` being in the future (SPEC §4.7).
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// An Ed25519 keypair (account identity or device).
pub struct SigningKeyPair(SigningKey);

impl SigningKeyPair {
    /// Generates a keypair from 32 random bytes.
    pub fn generate() -> CryptoResult<Self> {
        let seed = Zeroizing::new(random::array::<32>()?);
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Rebuilds a keypair from its 32-byte seed (storage, tests, vectors). The
    /// seed is zeroized after the key has copied it.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// The public key.
    pub fn public_bytes(&self) -> [u8; PUBLIC_KEY_BYTES] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a message and returns the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_BYTES] {
        self.0.sign(message).to_bytes()
    }

    /// The raw seed. Callers must not log or serialise this.
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKeyPair(<redacted>)")
    }
}

/// Verifies a signature over `message`.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    message: &[u8],
    signature: &[u8; SIGNATURE_BYTES],
) -> CryptoResult<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::VerificationFailed)?;
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// A fixed-width RFC 3339 UTC timestamp: `YYYY-MM-DDTHH:MM:SSZ`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(String);

impl Timestamp {
    /// Parses the fixed-width form. Anything else is rejected.
    pub fn parse(text: &str) -> CryptoResult<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 20 {
            return Err(CryptoError::InvalidTimestamp);
        }
        let digit = |i: usize| bytes[i].is_ascii_digit();
        for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
            if !digit(i) {
                return Err(CryptoError::InvalidTimestamp);
            }
        }
        if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[19] != b'Z' {
            return Err(CryptoError::InvalidTimestamp);
        }
        if bytes[13] != b':' || bytes[16] != b':' {
            return Err(CryptoError::InvalidTimestamp);
        }
        let number =
            |start: usize| -> u32 { text[start..start + 2].parse::<u32>().unwrap_or(u32::MAX) };
        let (month, day) = (number(5), number(8));
        let (hour, minute, second) = (number(11), number(14), number(17));
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(CryptoError::InvalidTimestamp);
        }
        let candidate = Self(text.to_string());
        // Reject impossible calendar dates (29 February in a non-leap year,
        // 31 April, …): a real date must survive the round trip through Unix
        // seconds unchanged.
        if Self::from_unix_seconds(candidate.unix_seconds())? != candidate {
            return Err(CryptoError::InvalidTimestamp);
        }
        Ok(candidate)
    }

    /// The current UTC time from the system clock.
    pub fn now() -> CryptoResult<Self> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| CryptoError::InvalidTimestamp)?
            .as_secs() as i64;
        Self::from_unix_seconds(seconds)
    }

    /// Builds a timestamp from Unix seconds.
    pub fn from_unix_seconds(seconds: i64) -> CryptoResult<Self> {
        let days = seconds.div_euclid(86_400);
        let rem = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        if !(0..=9999).contains(&year) {
            return Err(CryptoError::InvalidTimestamp);
        }
        let text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        );
        Ok(Self(text))
    }

    /// Unix seconds since the epoch.
    pub fn unix_seconds(&self) -> i64 {
        let number = |start: usize| -> i64 { self.0[start..start + 2].parse().unwrap_or(0) };
        let year: i64 = self.0[0..4].parse().unwrap_or(0);
        let month = number(5);
        let day = number(8);
        let hour = number(11);
        let minute = number(14);
        let second = number(17);
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
    }

    /// The text form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` is later than `other` plus `skew` seconds.
    pub fn is_later_than(&self, other: &Self, skew: u64) -> bool {
        self.unix_seconds() > other.unix_seconds() + skew as i64
    }
}

/// Days from 1970-01-01 to the given civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { y + 1 } else { y }, month, day)
}

fn text(value: &str) -> Value {
    Value::Text(value.to_string())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn fixed16(value: &Value) -> CryptoResult<[u8; 16]> {
    let Value::Bytes(raw) = value else {
        return Err(CryptoError::MalformedCbor);
    };
    if raw.len() != 16 {
        return Err(CryptoError::InvalidLength {
            expected: 16,
            actual: raw.len(),
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(raw);
    Ok(out)
}

/// BLAKE3-256 over a canonical body — what signatures actually cover
/// (SPEC §4.7, §4.8, consistent with the operation hash in §6.3).
fn signing_digest(body: &[u8]) -> [u8; 32] {
    *blake3::hash(body).as_bytes()
}

/// A certified device (SPEC §4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    account_id: [u8; 16],
    device_id: [u8; 16],
    device_public_key: [u8; PUBLIC_KEY_BYTES],
    created_at: Timestamp,
    signature: [u8; SIGNATURE_BYTES],
}

impl DeviceCertificate {
    /// Creates a certificate signed by the account identity key.
    pub fn create(
        identity: &SigningKeyPair,
        account_id: [u8; 16],
        device_id: [u8; 16],
        device_public_key: [u8; PUBLIC_KEY_BYTES],
        created_at: Timestamp,
    ) -> CryptoResult<Self> {
        let body = Self::body(&account_id, &device_id, &device_public_key, &created_at)?;
        let signature = identity.sign(&signing_digest(&body));
        Ok(Self {
            account_id,
            device_id,
            device_public_key,
            created_at,
            signature,
        })
    }

    fn body(
        account_id: &[u8; 16],
        device_id: &[u8; 16],
        device_public_key: &[u8; PUBLIC_KEY_BYTES],
        created_at: &Timestamp,
    ) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-cert")),
            ("account_id", bytes(account_id)),
            ("device_id", bytes(device_id)),
            ("device_pubkey", bytes(device_public_key)),
            ("created_at", text(created_at.as_str())),
        ]);
        canonical_bytes(&map)
    }

    /// The exact bytes the identity key signed (vectors use this).
    pub fn body_bytes(&self) -> CryptoResult<Vec<u8>> {
        Self::body(
            &self.account_id,
            &self.device_id,
            &self.device_public_key,
            &self.created_at,
        )
    }

    /// The certified device's public key.
    pub fn device_public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.device_public_key
    }

    /// The certified device id.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// The certificate signature (storage, vectors).
    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// The account the device belongs to.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The certification time.
    pub fn created_at(&self) -> &Timestamp {
        &self.created_at
    }

    /// Rebuilds a certificate from stored parts. The signature is not checked
    /// here; [`DeviceCertificate::verify`] is the only thing that decides
    /// whether a certificate is trusted.
    pub fn from_parts(
        account_id: [u8; 16],
        device_id: [u8; 16],
        device_public_key: [u8; PUBLIC_KEY_BYTES],
        created_at: Timestamp,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        Self {
            account_id,
            device_id,
            device_public_key,
            created_at,
            signature,
        }
    }

    /// The stored form: the signed body map plus `sig`.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-cert")),
            ("account_id", bytes(&self.account_id)),
            ("device_id", bytes(&self.device_id)),
            ("device_pubkey", bytes(&self.device_public_key)),
            ("created_at", text(self.created_at.as_str())),
            ("sig", bytes(&self.signature)),
        ]);
        canonical_bytes(&map)
    }

    /// Parses the stored form, rejecting anything outside the exact key set.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value = crate::crypto::aad::parse_strict(bytes)?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::MalformedCbor);
        };
        let mut account_id: Option<[u8; 16]> = None;
        let mut device_id: Option<[u8; 16]> = None;
        let mut public_key: Option<[u8; PUBLIC_KEY_BYTES]> = None;
        let mut created_at: Option<Timestamp> = None;
        let mut signature: Option<[u8; SIGNATURE_BYTES]> = None;
        let mut suite: Option<String> = None;
        let mut kind: Option<String> = None;
        if entries.len() != 7 {
            return Err(CryptoError::MalformedCbor);
        }
        for (key, value) in entries {
            let Value::Text(name) = key else {
                return Err(CryptoError::MalformedCbor);
            };
            let set_once = |slot: &mut Option<String>| -> CryptoResult<()> {
                let Value::Text(text) = value.clone() else {
                    return Err(CryptoError::MalformedCbor);
                };
                *slot = Some(text);
                Ok(())
            };
            match name.as_str() {
                "suite" => set_once(&mut suite)?,
                "type" => set_once(&mut kind)?,
                "account_id" => account_id = Some(fixed16(&value)?),
                "device_id" => device_id = Some(fixed16(&value)?),
                "device_pubkey" => {
                    let Value::Bytes(raw) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    if raw.len() != PUBLIC_KEY_BYTES {
                        return Err(CryptoError::InvalidLength {
                            expected: PUBLIC_KEY_BYTES,
                            actual: raw.len(),
                        });
                    }
                    let mut out = [0u8; PUBLIC_KEY_BYTES];
                    out.copy_from_slice(&raw);
                    public_key = Some(out);
                }
                "created_at" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    created_at = Some(Timestamp::parse(&text)?);
                }
                "sig" => {
                    let Value::Bytes(raw) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    if raw.len() != SIGNATURE_BYTES {
                        return Err(CryptoError::InvalidLength {
                            expected: SIGNATURE_BYTES,
                            actual: raw.len(),
                        });
                    }
                    let mut out = [0u8; SIGNATURE_BYTES];
                    out.copy_from_slice(&raw);
                    signature = Some(out);
                }
                _ => return Err(CryptoError::MalformedCbor),
            }
        }
        if suite.as_deref() != Some(SUITE_V1) {
            return Err(CryptoError::UnknownSuite);
        }
        if kind.as_deref() != Some("device-cert") {
            return Err(CryptoError::MalformedCbor);
        }
        let cert = Self::from_parts(
            account_id.ok_or(CryptoError::MalformedCbor)?,
            device_id.ok_or(CryptoError::MalformedCbor)?,
            public_key.ok_or(CryptoError::MalformedCbor)?,
            created_at.ok_or(CryptoError::MalformedCbor)?,
            signature.ok_or(CryptoError::MalformedCbor)?,
        );
        if cert.to_cbor()? != bytes {
            return Err(CryptoError::NonCanonicalCbor);
        }
        Ok(cert)
    }

    /// Verifies the certificate.
    ///
    /// Checks the signature against the pinned identity key, the account id,
    /// that the device was not revoked before `created_at`, and that
    /// `created_at` is not in the future beyond the skew allowance.
    pub fn verify(
        &self,
        identity_public: &[u8; PUBLIC_KEY_BYTES],
        expected_account: &[u8; 16],
        now: &Timestamp,
        revoked_at: Option<&Timestamp>,
    ) -> CryptoResult<()> {
        if &self.account_id != expected_account {
            return Err(CryptoError::VerificationFailed);
        }
        let body = self.body_bytes()?;
        verify(identity_public, &signing_digest(&body), &self.signature)?;
        if self.created_at.is_later_than(now, MAX_CLOCK_SKEW_SECONDS) {
            return Err(CryptoError::ClockSkew);
        }
        if let Some(revoked) = revoked_at {
            // Compare numerically (SPEC §4.7 wants calendar semantics, not a
            // string comparison).
            if self.created_at.unix_seconds() >= revoked.unix_seconds() {
                return Err(CryptoError::Revoked);
            }
        }
        Ok(())
    }
}

/// An append-only device revocation signed by the identity key (SPEC §4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    account_id: [u8; 16],
    device_id: [u8; 16],
    revoked_at: Timestamp,
    reason: String,
    signature: [u8; SIGNATURE_BYTES],
}

impl DeviceRevocation {
    /// Signs a revocation.
    pub fn create(
        identity: &SigningKeyPair,
        account_id: [u8; 16],
        device_id: [u8; 16],
        revoked_at: Timestamp,
        reason: &str,
    ) -> CryptoResult<Self> {
        if reason.len() > 128 {
            return Err(CryptoError::InvalidLength {
                expected: 128,
                actual: reason.len(),
            });
        }
        let body = Self::body(&account_id, &device_id, &revoked_at, reason)?;
        let signature = identity.sign(&signing_digest(&body));
        Ok(Self {
            account_id,
            device_id,
            revoked_at,
            reason: reason.to_string(),
            signature,
        })
    }

    fn body(
        account_id: &[u8; 16],
        device_id: &[u8; 16],
        revoked_at: &Timestamp,
        reason: &str,
    ) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-revocation")),
            ("account_id", bytes(account_id)),
            ("device_id", bytes(device_id)),
            ("revoked_at", text(revoked_at.as_str())),
            ("reason", text(reason)),
        ]);
        canonical_bytes(&map)
    }

    /// The exact bytes the identity key signed.
    pub fn body_bytes(&self) -> CryptoResult<Vec<u8>> {
        Self::body(
            &self.account_id,
            &self.device_id,
            &self.revoked_at,
            &self.reason,
        )
    }

    /// The revoked device id.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// The revocation time.
    pub fn revoked_at(&self) -> &Timestamp {
        &self.revoked_at
    }

    /// The human-readable reason.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The revocation signature (storage, vectors).
    pub fn signature_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }

    /// Rebuilds a revocation from stored parts; verification is separate.
    pub fn from_parts(
        account_id: [u8; 16],
        device_id: [u8; 16],
        revoked_at: Timestamp,
        reason: &str,
        signature: [u8; SIGNATURE_BYTES],
    ) -> Self {
        Self {
            account_id,
            device_id,
            revoked_at,
            reason: reason.to_string(),
            signature,
        }
    }

    /// The stored form: the signed body map plus `sig`.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-revocation")),
            ("account_id", bytes(&self.account_id)),
            ("device_id", bytes(&self.device_id)),
            ("revoked_at", text(self.revoked_at.as_str())),
            ("reason", text(&self.reason)),
            ("sig", bytes(&self.signature)),
        ]);
        canonical_bytes(&map)
    }

    /// Parses the stored form, rejecting anything outside the exact key set.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value = crate::crypto::aad::parse_strict(bytes)?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::MalformedCbor);
        };
        if entries.len() != 7 {
            return Err(CryptoError::MalformedCbor);
        }
        let mut suite: Option<String> = None;
        let mut kind: Option<String> = None;
        let mut account_id: Option<[u8; 16]> = None;
        let mut device_id: Option<[u8; 16]> = None;
        let mut revoked_at: Option<Timestamp> = None;
        let mut reason: Option<String> = None;
        let mut signature: Option<[u8; SIGNATURE_BYTES]> = None;
        for (key, value) in entries {
            let Value::Text(name) = key else {
                return Err(CryptoError::MalformedCbor);
            };
            match name.as_str() {
                "suite" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    suite = Some(text);
                }
                "type" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    kind = Some(text);
                }
                "account_id" => account_id = Some(fixed16(&value)?),
                "device_id" => device_id = Some(fixed16(&value)?),
                "revoked_at" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    revoked_at = Some(Timestamp::parse(&text)?);
                }
                "reason" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    reason = Some(text);
                }
                "sig" => {
                    let Value::Bytes(raw) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    if raw.len() != SIGNATURE_BYTES {
                        return Err(CryptoError::InvalidLength {
                            expected: SIGNATURE_BYTES,
                            actual: raw.len(),
                        });
                    }
                    let mut out = [0u8; SIGNATURE_BYTES];
                    out.copy_from_slice(&raw);
                    signature = Some(out);
                }
                _ => return Err(CryptoError::MalformedCbor),
            }
        }
        if suite.as_deref() != Some(SUITE_V1) {
            return Err(CryptoError::UnknownSuite);
        }
        if kind.as_deref() != Some("device-revocation") {
            return Err(CryptoError::MalformedCbor);
        }
        let revocation = Self::from_parts(
            account_id.ok_or(CryptoError::MalformedCbor)?,
            device_id.ok_or(CryptoError::MalformedCbor)?,
            revoked_at.ok_or(CryptoError::MalformedCbor)?,
            &reason.ok_or(CryptoError::MalformedCbor)?,
            signature.ok_or(CryptoError::MalformedCbor)?,
        );
        if revocation.to_cbor()? != bytes {
            return Err(CryptoError::NonCanonicalCbor);
        }
        Ok(revocation)
    }

    /// Verifies the revocation against the pinned identity key.
    pub fn verify(
        &self,
        identity_public: &[u8; PUBLIC_KEY_BYTES],
        expected_account: &[u8; 16],
    ) -> CryptoResult<()> {
        if &self.account_id != expected_account {
            return Err(CryptoError::VerificationFailed);
        }
        verify(
            identity_public,
            &signing_digest(&self.body_bytes()?),
            &self.signature,
        )
    }
}

/// Proof that a new device holds the key it asks to have certified
/// (SPEC §4.7, D-0107).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentProof {
    account_id: [u8; 16],
    device_id: [u8; 16],
    nonce: [u8; 32],
    signature: [u8; SIGNATURE_BYTES],
}

impl EnrolmentProof {
    /// Signed by the **new device's** key over the approving device's nonce.
    pub fn create(
        device: &SigningKeyPair,
        account_id: [u8; 16],
        device_id: [u8; 16],
        nonce: [u8; 32],
    ) -> CryptoResult<Self> {
        let body = Self::body(&account_id, &device_id, &nonce)?;
        let signature = device.sign(&signing_digest(&body));
        Ok(Self {
            account_id,
            device_id,
            nonce,
            signature,
        })
    }

    fn body(
        account_id: &[u8; 16],
        device_id: &[u8; 16],
        nonce: &[u8; 32],
    ) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-enroll")),
            ("account_id", bytes(account_id)),
            ("device_id", bytes(device_id)),
            ("nonce", bytes(nonce)),
        ]);
        canonical_bytes(&map)
    }

    /// The exact bytes the device signed.
    pub fn body_bytes(&self) -> CryptoResult<Vec<u8>> {
        Self::body(&self.account_id, &self.device_id, &self.nonce)
    }

    /// The account the proof is for.
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account_id
    }

    /// The device the proof is for.
    pub fn device_id(&self) -> &[u8; 16] {
        &self.device_id
    }

    /// The approving device's single-use nonce (opaque to the relay).
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// The stored form: the signed body map plus `sig`.
    pub fn to_cbor(&self) -> CryptoResult<Vec<u8>> {
        let map = canonical_map(vec![
            ("suite", text(SUITE_V1)),
            ("type", text("device-enroll")),
            ("account_id", bytes(&self.account_id)),
            ("device_id", bytes(&self.device_id)),
            ("nonce", bytes(&self.nonce)),
            ("sig", bytes(&self.signature)),
        ]);
        canonical_bytes(&map)
    }

    /// Parses the stored form, rejecting anything outside the exact key set.
    pub fn from_cbor(bytes: &[u8]) -> CryptoResult<Self> {
        let value = crate::crypto::aad::parse_strict(bytes)?;
        let Value::Map(entries) = value else {
            return Err(CryptoError::MalformedCbor);
        };
        if entries.len() != 6 {
            return Err(CryptoError::MalformedCbor);
        }
        let mut suite = None;
        let mut kind = None;
        let mut account_id = None;
        let mut device_id = None;
        let mut nonce = None;
        let mut signature = None;
        for (key, value) in entries {
            let Value::Text(name) = key else {
                return Err(CryptoError::MalformedCbor);
            };
            match name.as_str() {
                "suite" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    suite = Some(text);
                }
                "type" => {
                    let Value::Text(text) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    kind = Some(text);
                }
                "account_id" => account_id = Some(fixed16(&value)?),
                "device_id" => device_id = Some(fixed16(&value)?),
                "nonce" => {
                    let Value::Bytes(raw) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    if raw.len() != 32 {
                        return Err(CryptoError::InvalidLength {
                            expected: 32,
                            actual: raw.len(),
                        });
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&raw);
                    nonce = Some(out);
                }
                "sig" => {
                    let Value::Bytes(raw) = value else {
                        return Err(CryptoError::MalformedCbor);
                    };
                    if raw.len() != SIGNATURE_BYTES {
                        return Err(CryptoError::InvalidLength {
                            expected: SIGNATURE_BYTES,
                            actual: raw.len(),
                        });
                    }
                    let mut out = [0u8; SIGNATURE_BYTES];
                    out.copy_from_slice(&raw);
                    signature = Some(out);
                }
                _ => return Err(CryptoError::MalformedCbor),
            }
        }
        if suite.as_deref() != Some(SUITE_V1) || kind.as_deref() != Some("device-enroll") {
            return Err(CryptoError::MalformedCbor);
        }
        let proof = Self {
            account_id: account_id.ok_or(CryptoError::MalformedCbor)?,
            device_id: device_id.ok_or(CryptoError::MalformedCbor)?,
            nonce: nonce.ok_or(CryptoError::MalformedCbor)?,
            signature: signature.ok_or(CryptoError::MalformedCbor)?,
        };
        if proof.to_cbor()? != bytes {
            return Err(CryptoError::NonCanonicalCbor);
        }
        Ok(proof)
    }

    /// Verifies the proof against the new device's public key and the expected
    /// account, device and nonce.
    pub fn verify(
        &self,
        device_public: &[u8; PUBLIC_KEY_BYTES],
        expected_account: &[u8; 16],
        expected_device: &[u8; 16],
        expected_nonce: &[u8; 32],
    ) -> CryptoResult<()> {
        if &self.account_id != expected_account
            || &self.device_id != expected_device
            || &self.nonce != expected_nonce
        {
            return Err(CryptoError::VerificationFailed);
        }
        verify(
            device_public,
            &signing_digest(&Self::body(&self.account_id, &self.device_id, &self.nonce)?),
            &self.signature,
        )
    }
}

// Keep the labels module referenced so the domain strings cannot drift silently.
const _: &str = DEVICE_CERT;
const _: &str = DEVICE_ENROLL;
const _: &str = DEVICE_REVOCATION;

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: [u8; 16] = [0x11; 16];
    const DEVICE: [u8; 16] = [0x22; 16];

    fn identity() -> SigningKeyPair {
        SigningKeyPair::from_seed([0x42; 32])
    }

    fn device() -> SigningKeyPair {
        SigningKeyPair::from_seed([0x24; 32])
    }

    fn now() -> Timestamp {
        Timestamp::parse("2026-11-05T10:00:00Z").expect("valid")
    }

    fn cert() -> DeviceCertificate {
        DeviceCertificate::create(&identity(), ACCOUNT, DEVICE, device().public_bytes(), now())
            .expect("cert")
    }

    #[test]
    fn certificate_round_trip() {
        let cert = cert();
        cert.verify(&identity().public_bytes(), &ACCOUNT, &now(), None)
            .expect("verify");
        assert_eq!(cert.device_id(), &DEVICE);
        assert_eq!(cert.account_id(), &ACCOUNT);
    }

    #[test]
    fn certificate_signature_binds_every_field() {
        let base = cert();
        let other_account = DeviceCertificate::create(
            &identity(),
            [0x33; 16],
            DEVICE,
            device().public_bytes(),
            now(),
        )
        .expect("cert");
        let other_device = DeviceCertificate::create(
            &identity(),
            ACCOUNT,
            [0x44; 16],
            device().public_bytes(),
            now(),
        )
        .expect("cert");
        let other_time = DeviceCertificate::create(
            &identity(),
            ACCOUNT,
            DEVICE,
            device().public_bytes(),
            Timestamp::parse("2026-11-05T10:00:01Z").expect("valid"),
        )
        .expect("cert");
        let bodies = [
            base.body_bytes().expect("body"),
            other_account.body_bytes().expect("body"),
            other_device.body_bytes().expect("body"),
            other_time.body_bytes().expect("body"),
        ];
        for (i, a) in bodies.iter().enumerate() {
            for b in bodies.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn certificate_rejects_wrong_identity_account_and_time() {
        let cert = cert();
        let wrong_key = SigningKeyPair::from_seed([0x99; 32]).public_bytes();
        assert_eq!(
            cert.verify(&wrong_key, &ACCOUNT, &now(), None)
                .expect_err("wrong key"),
            CryptoError::VerificationFailed
        );
        assert_eq!(
            cert.verify(&identity().public_bytes(), &[0x77; 16], &now(), None)
                .expect_err("wrong account"),
            CryptoError::VerificationFailed
        );
        let earlier = Timestamp::parse("2026-11-05T09:54:59Z").expect("valid");
        assert_eq!(
            cert.verify(&identity().public_bytes(), &ACCOUNT, &earlier, None)
                .expect_err("future"),
            CryptoError::ClockSkew
        );
    }

    #[test]
    fn certificate_respects_revocation_cutoff() {
        let cert = cert();
        // Revoked one second after the certificate was created: still valid.
        let after = Timestamp::parse("2026-11-05T10:00:01Z").expect("valid");
        // Revoked at the same instant: the certificate is already invalid.
        let at = Timestamp::parse("2026-11-05T10:00:00Z").expect("valid");
        cert.verify(&identity().public_bytes(), &ACCOUNT, &now(), Some(&after))
            .expect("certified before revocation");
        assert_eq!(
            cert.verify(&identity().public_bytes(), &ACCOUNT, &now(), Some(&at))
                .expect_err("certified at revocation"),
            CryptoError::Revoked
        );
    }

    #[test]
    fn revocation_round_trip_and_tamper() {
        let revocation =
            DeviceRevocation::create(&identity(), ACCOUNT, DEVICE, now(), "lost phone")
                .expect("revocation");
        revocation
            .verify(&identity().public_bytes(), &ACCOUNT)
            .expect("verify");
        assert_eq!(revocation.reason(), "lost phone");
        let wrong = SigningKeyPair::from_seed([0x01; 32]).public_bytes();
        assert!(revocation.verify(&wrong, &ACCOUNT).is_err());
    }

    #[test]
    fn enrolment_proof_binds_nonce_device_and_account() {
        let nonce = [7u8; 32];
        let proof = EnrolmentProof::create(&device(), ACCOUNT, DEVICE, nonce).expect("proof");
        proof
            .verify(&device().public_bytes(), &ACCOUNT, &DEVICE, &nonce)
            .expect("verify");
        assert_eq!(
            proof
                .verify(&device().public_bytes(), &ACCOUNT, &DEVICE, &[8u8; 32])
                .expect_err("nonce"),
            CryptoError::VerificationFailed
        );
        assert_eq!(
            proof
                .verify(&device().public_bytes(), &ACCOUNT, &[0x55; 16], &nonce)
                .expect_err("device"),
            CryptoError::VerificationFailed
        );
    }

    #[test]
    fn timestamps_parse_and_convert() {
        let t = Timestamp::parse("2026-11-05T10:00:00Z").expect("valid");
        assert_eq!(t.unix_seconds(), 1_793_872_800);
        assert_eq!(
            Timestamp::from_unix_seconds(t.unix_seconds()).expect("round"),
            t
        );
        for bad in [
            "2026-11-05 10:00:00Z",
            "2026-13-05T10:00:00Z",
            "2026-11-05T25:00:00Z",
            "2026-11-05T10:00:00+01:00",
            "2026-11-05T10:00:0Z",
        ] {
            assert!(Timestamp::parse(bad).is_err(), "should reject {bad}");
        }
    }

    #[test]
    fn timestamps_reject_impossible_dates() {
        for bad in [
            "2026-02-29T00:00:00Z", // not a leap year
            "2026-02-31T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-11-05T10:00:60Z", // leap second is not accepted
        ] {
            assert!(Timestamp::parse(bad).is_err(), "should reject {bad}");
        }
        assert!(
            Timestamp::parse("2028-02-29T00:00:00Z").is_ok(),
            "2028 is a leap year"
        );
        assert!(Timestamp::parse("2026-04-30T23:59:59Z").is_ok());
    }

    #[test]
    fn certificates_round_trip_through_storage_cbor() {
        let identity = identity();
        let device_public = device().public_bytes();
        let cert = DeviceCertificate::create(&identity, ACCOUNT, DEVICE, device_public, now())
            .expect("cert");
        let bytes = cert.to_cbor().expect("encode");
        let parsed = DeviceCertificate::from_cbor(&bytes).expect("parse");
        assert_eq!(
            parsed.body_bytes().expect("body"),
            cert.body_bytes().expect("body")
        );
        assert_eq!(parsed.to_cbor().expect("re-encode"), bytes);
        parsed
            .verify(&identity.public_bytes(), &ACCOUNT, &now(), None)
            .expect("verify");

        // A flipped byte either breaks the encoding or breaks verification;
        // it never yields a certificate that both parses and verifies.
        for index in [0, 5, bytes.len() / 2, bytes.len() - 1] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            let parsed = DeviceCertificate::from_cbor(&tampered);
            let trusted = parsed.map(|cert| {
                cert.verify(&identity.public_bytes(), &ACCOUNT, &now(), None)
                    .is_ok()
            });
            assert!(
                !matches!(trusted, Ok(true)),
                "byte {index} produced a trusted certificate"
            );
        }
    }

    #[test]
    fn revocations_round_trip_through_storage_cbor() {
        let identity = identity();
        let revocation = DeviceRevocation::create(&identity, ACCOUNT, DEVICE, now(), "lost phone")
            .expect("revocation");
        let bytes = revocation.to_cbor().expect("encode");
        let parsed = DeviceRevocation::from_cbor(&bytes).expect("parse");
        assert_eq!(parsed.reason(), revocation.reason());
        assert_eq!(parsed.to_cbor().expect("re-encode"), bytes);
        parsed
            .verify(&identity.public_bytes(), &ACCOUNT)
            .expect("verify");
    }

    #[test]
    fn storage_parsers_reject_a_replayed_certificate_type() {
        // A certificate body relabelled as a revocation must not parse.
        let identity = identity();
        let cert =
            DeviceCertificate::create(&identity, ACCOUNT, DEVICE, device().public_bytes(), now())
                .expect("cert");
        let bytes = cert.to_cbor().expect("encode");
        assert!(DeviceRevocation::from_cbor(&bytes).is_err());
    }

    #[test]
    fn debug_redacts_the_seed() {
        let printed = format!("{:?}", identity());
        assert!(printed.contains("redacted"));
    }

    #[test]
    fn signatures_cover_the_digest_not_the_raw_body() {
        let identity = identity();
        let device_public = device().public_bytes();
        let created = now();
        let body =
            DeviceCertificate::body(&ACCOUNT, &DEVICE, &device_public, &created).expect("body");
        let digest = signing_digest(&body);

        // A signature over the raw body must not verify as a certificate.
        let forged = DeviceCertificate {
            account_id: ACCOUNT,
            device_id: DEVICE,
            device_public_key: device_public,
            created_at: created.clone(),
            signature: identity.sign(&body),
        };
        assert_eq!(
            forged
                .verify(&identity.public_bytes(), &ACCOUNT, &now(), None)
                .expect_err("raw body signature must not verify"),
            CryptoError::VerificationFailed
        );

        // A signature over the digest must verify.
        let good = DeviceCertificate {
            account_id: ACCOUNT,
            device_id: DEVICE,
            device_public_key: device_public,
            created_at: created,
            signature: identity.sign(&digest),
        };
        good.verify(&identity.public_bytes(), &ACCOUNT, &now(), None)
            .expect("digest signature verifies");
    }

    #[test]
    fn revocation_signatures_cover_the_digest_too() {
        let identity = identity();
        let revoked_at = now();
        let body =
            DeviceRevocation::body(&ACCOUNT, &DEVICE, &revoked_at, "lost phone").expect("body");
        let forged = DeviceRevocation {
            account_id: ACCOUNT,
            device_id: DEVICE,
            revoked_at: revoked_at.clone(),
            reason: "lost phone".to_string(),
            signature: identity.sign(&body),
        };
        assert_eq!(
            forged
                .verify(&identity.public_bytes(), &ACCOUNT)
                .expect_err("raw body signature must not verify"),
            CryptoError::VerificationFailed
        );

        let good = DeviceRevocation {
            account_id: ACCOUNT,
            device_id: DEVICE,
            revoked_at,
            reason: "lost phone".to_string(),
            signature: identity.sign(&signing_digest(&body)),
        };
        good.verify(&identity.public_bytes(), &ACCOUNT)
            .expect("digest signature verifies");
    }
}
