//! RFC 6238 TOTP and `otpauth://` URIs (task item 8).
//!
//! The secret is a zeroizing buffer, the parameters are validated against the
//! four shapes the brief allows (SHA-1/256/512, 6 or 8 digits, 30 or 60 s), and
//! URI parsing is strict: an unknown parameter or a value outside the allowed
//! set is an error, never a silent default. Code generation itself is delegated
//! to the approved `totp-rs` crate — nothing here reimplements HMAC.

use crate::codec::{base32_decode, base32_encode, percent_decode};
use crate::crypto::signing::Timestamp;
use crate::error::{CoreError, CoreResult};
use std::fmt;
use totp_rs::{Algorithm, Builder, Totp};
use zeroize::Zeroizing;

/// Digits allowed by the brief.
pub const DIGITS_ALLOWED: [u8; 2] = [6, 8];
/// Step durations allowed by the brief, in seconds.
pub const STEPS_ALLOWED: [u64; 2] = [30, 60];
/// Default step.
pub const DEFAULT_STEP: u64 = 30;
/// Default digits.
pub const DEFAULT_DIGITS: u8 = 6;
/// Clock drift tolerated when verifying, in steps (±1 is the RFC's advice).
pub const DEFAULT_SKEW: u8 = 1;

/// The hash behind the one-time code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// SHA-1 — what almost every service uses.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl TotpAlgorithm {
    /// The name used in an `otpauth://` URI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Parses the URI name (case-insensitive).
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(CoreError::InvalidParameter),
        }
    }

    fn to_totp(self) -> Algorithm {
        match self {
            Self::Sha1 => Algorithm::SHA1,
            Self::Sha256 => Algorithm::SHA256,
            Self::Sha512 => Algorithm::SHA512,
        }
    }
}

/// A validated TOTP configuration.
#[derive(Clone)]
pub struct TotpConfig {
    secret: Zeroizing<Vec<u8>>,
    algorithm: TotpAlgorithm,
    digits: u8,
    step: u64,
    issuer: Option<String>,
    account: Option<String>,
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret_len", &self.secret.len())
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("step", &self.step)
            .field("issuer", &self.issuer)
            .field("account_len", &self.account.as_ref().map(|a| a.len()))
            .finish()
    }
}

impl TotpConfig {
    /// Builds a configuration from a raw secret.
    pub fn new(secret: &[u8], algorithm: TotpAlgorithm, digits: u8, step: u64) -> CoreResult<Self> {
        if secret.is_empty() || secret.len() > 1024 {
            return Err(CoreError::InvalidParameter);
        }
        if !DIGITS_ALLOWED.contains(&digits) {
            return Err(CoreError::InvalidParameter);
        }
        if !STEPS_ALLOWED.contains(&step) {
            return Err(CoreError::InvalidParameter);
        }
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
            algorithm,
            digits,
            step,
            issuer: None,
            account: None,
        })
    }

    /// Builds a configuration from a bare base32 secret (the common case in
    /// exports), defaulting to SHA-1 / 6 digits / 30 s.
    pub fn from_base32(secret: &str) -> CoreResult<Self> {
        let bytes = base32_decode(secret)?;
        Self::new(&bytes, TotpAlgorithm::Sha1, DEFAULT_DIGITS, DEFAULT_STEP)
    }

    /// A configuration stored in an item field: an `otpauth://` URI when one is
    /// given, otherwise a bare base32 secret.
    pub fn from_field(value: &str) -> CoreResult<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CoreError::InvalidParameter);
        }
        if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
            Self::from_uri(trimmed)
        } else {
            Self::from_base32(trimmed)
        }
    }

    /// Parses `otpauth://totp/LABEL?secret=…&issuer=…&algorithm=…&digits=…&period=…`.
    pub fn from_uri(uri: &str) -> CoreResult<Self> {
        let lower = uri.to_ascii_lowercase();
        let rest = if let Some(rest) = lower.strip_prefix("otpauth://totp/") {
            &uri[uri.len() - rest.len()..]
        } else if lower.starts_with("otpauth://hotp/") {
            // Counter-based codes are not v1.
            return Err(CoreError::InvalidParameter);
        } else {
            return Err(CoreError::InvalidParameter);
        };

        let (label, query) = match rest.split_once('?') {
            Some((label, query)) => (label, Some(query)),
            None => (rest, None),
        };
        let query = query.ok_or(CoreError::InvalidParameter)?;

        let label = percent_decode(label)?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => {
                (Some(issuer.trim().to_string()), account.trim().to_string())
            }
            None => (None, label.trim().to_string()),
        };
        if account.is_empty() || account.len() > 256 {
            return Err(CoreError::InvalidParameter);
        }

        let mut secret: Option<Vec<u8>> = None;
        let mut issuer = label_issuer;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = DEFAULT_DIGITS;
        let mut step = DEFAULT_STEP;
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').ok_or(CoreError::InvalidParameter)?;
            let value = percent_decode(value)?;
            let key = key.to_ascii_lowercase();
            // A repeated parameter is ambiguous: whichever value a client picks,
            // another client may pick the other.
            if !seen.insert(key.clone()) {
                return Err(CoreError::InvalidParameter);
            }
            match key.as_str() {
                "secret" => {
                    if secret.is_some() {
                        return Err(CoreError::InvalidParameter);
                    }
                    let bytes = base32_decode(&value)?;
                    if bytes.is_empty() {
                        return Err(CoreError::InvalidParameter);
                    }
                    secret = Some(bytes);
                }
                "issuer" => {
                    if value.len() > 128 {
                        return Err(CoreError::InvalidParameter);
                    }
                    // A mismatch between the label prefix and `issuer` is a
                    // phishing trick: the two must agree when both exist.
                    match &issuer {
                        Some(from_label) if from_label != &value => {
                            return Err(CoreError::InvalidParameter)
                        }
                        _ => issuer = Some(value),
                    }
                }
                "algorithm" => algorithm = TotpAlgorithm::parse(&value)?,
                "digits" => {
                    digits = value
                        .parse::<u8>()
                        .map_err(|_| CoreError::InvalidParameter)?
                }
                "period" => {
                    step = value
                        .parse::<u64>()
                        .map_err(|_| CoreError::InvalidParameter)?
                }
                // Unknown parameters are refused rather than ignored: a typo
                // in `digits` must not silently produce wrong codes.
                _ => return Err(CoreError::InvalidParameter),
            }
        }

        let secret = secret.ok_or(CoreError::InvalidParameter)?;
        let mut config = Self::new(&secret, algorithm, digits, step)?;
        config.issuer = issuer;
        config.account = Some(account);
        Ok(config)
    }

    /// The canonical `otpauth://` URI for this configuration.
    pub fn to_uri(&self) -> CoreResult<String> {
        let account = self
            .account
            .clone()
            .unwrap_or_else(|| "account".to_string());
        let mut uri = String::from("otpauth://totp/");
        if let Some(issuer) = &self.issuer {
            uri.push_str(&percent_encode(issuer));
            uri.push(':');
        }
        uri.push_str(&percent_encode(&account));
        uri.push_str("?secret=");
        uri.push_str(&base32_encode(&self.secret));
        if let Some(issuer) = &self.issuer {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(issuer));
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}&period={}",
            self.algorithm.as_str(),
            self.digits,
            self.step
        ));
        Ok(uri)
    }

    /// The secret as base32, the form an export or a QR code wants.
    pub fn secret_base32(&self) -> String {
        base32_encode(&self.secret)
    }

    /// The hash algorithm.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// Digits per code.
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// Step duration in seconds.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The issuer shown next to the code.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The account the code belongs to.
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Sets the display labels.
    pub fn with_labels(mut self, issuer: Option<&str>, account: Option<&str>) -> Self {
        self.issuer = issuer.map(|value| value.to_string());
        self.account = account.map(|value| value.to_string());
        self
    }

    fn totp(&self) -> CoreResult<Totp> {
        let builder = Builder::new()
            .with_algorithm(self.algorithm.to_totp())
            .with_digits(self.digits)
            .with_secret(self.secret.to_vec())
            .with_step_duration(self.step)
            .with_skew(u16::from(DEFAULT_SKEW));
        // totp-rs refuses secrets shorter than 128 bits in `build`, and rightly
        // so by RFC 4226. Real services still issue 80-bit secrets, and refusing
        // one means refusing the user's account, so a shorter secret is accepted
        // only through the non-compliant path — with our own parameter checks
        // already applied above and `is_legacy_strength` telling the UI to warn.
        if self.is_legacy_strength() {
            Ok(builder.build_noncompliant())
        } else {
            builder.build().map_err(|_| CoreError::InvalidParameter)
        }
    }

    /// Whether the secret is shorter than the 128 bits RFC 4226 recommends.
    /// Such a secret still yields unguessable codes, but the UI should say that
    /// the service chose a short secret.
    pub fn is_legacy_strength(&self) -> bool {
        self.secret.len() < 16
    }

    /// The code for a Unix timestamp.
    pub fn code_at(&self, unix_seconds: u64) -> CoreResult<Zeroizing<String>> {
        let totp = self.totp()?;
        Ok(Zeroizing::new(totp.generate(unix_seconds).to_string()))
    }

    /// The code for the current time.
    pub fn current(&self) -> CoreResult<Zeroizing<String>> {
        let now = Timestamp::now()?;
        let seconds = u64::try_from(now.unix_seconds()).map_err(|_| CoreError::InvalidParameter)?;
        self.code_at(seconds)
    }

    /// Checks a code at a Unix timestamp, allowing ±`DEFAULT_SKEW` steps.
    pub fn verify_at(&self, code: &str, unix_seconds: u64) -> CoreResult<bool> {
        let code = code.trim();
        if code.len() != self.digits as usize || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }
        let totp = self.totp()?;
        Ok(totp.check(code, unix_seconds).is_some())
    }
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B: the seeds are the ASCII digits 1..=n truncated to
    /// the hash's block size, the codes are 8 digits, the step is 30 s.
    fn rfc_seed(length: usize) -> Vec<u8> {
        b"1234567890123456789012345678901234567890123456789012345678901234"[..length].to_vec()
    }

    const VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_vectors_pass() {
        for (time, sha1, sha256, sha512) in VECTORS {
            for (algorithm, expected, seed_len) in [
                (TotpAlgorithm::Sha1, sha1, 20),
                (TotpAlgorithm::Sha256, sha256, 32),
                (TotpAlgorithm::Sha512, sha512, 64),
            ] {
                let config =
                    TotpConfig::new(&rfc_seed(seed_len), algorithm, 8, 30).expect("config");
                let code = config.code_at(time).expect("code");
                assert_eq!(code.as_str(), expected, "{} at {time}", algorithm.as_str());
                assert!(config.verify_at(expected, time).expect("verify"));
                assert!(!config.verify_at("00000000", time).expect("verify"));
            }
        }
    }

    #[test]
    fn six_digit_codes_and_sixty_second_steps_work() {
        let config = TotpConfig::new(&rfc_seed(20), TotpAlgorithm::Sha1, 6, 60).expect("config");
        let code = config.code_at(59).expect("code");
        assert_eq!(code.len(), 6);
        assert!(config.verify_at(&code, 59).expect("verify"));
        // The next step starts at 60.
        assert_ne!(
            config.code_at(59).expect("a").as_str(),
            config.code_at(60).expect("b").as_str()
        );
    }

    #[test]
    fn rejects_parameters_outside_the_brief() {
        let seed = rfc_seed(20);
        assert!(TotpConfig::new(&[], TotpAlgorithm::Sha1, 6, 30).is_err());
        for digits in [4, 5, 7, 9, 10] {
            assert!(
                TotpConfig::new(&seed, TotpAlgorithm::Sha1, digits, 30).is_err(),
                "digits {digits}"
            );
        }
        for step in [1, 15, 45, 120] {
            assert!(
                TotpConfig::new(&seed, TotpAlgorithm::Sha1, 6, step).is_err(),
                "step {step}"
            );
        }
    }

    #[test]
    fn parses_a_real_world_uri() {
        let uri = "otpauth://totp/Example%20Co:demo%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60";
        let config = TotpConfig::from_uri(uri).expect("parse");
        assert_eq!(config.issuer(), Some("Example Co"));
        assert_eq!(config.account(), Some("demo@example.test"));
        assert_eq!(config.algorithm(), TotpAlgorithm::Sha256);
        assert_eq!(config.digits(), 8);
        assert_eq!(config.step(), 60);
        assert_eq!(config.secret_base32(), "JBSWY3DPEHPK3PXP");

        let again = config.to_uri().expect("uri");
        let reparsed = TotpConfig::from_uri(&again).expect("reparse");
        assert_eq!(reparsed.secret_base32(), config.secret_base32());
        assert_eq!(reparsed.digits(), config.digits());
    }

    #[test]
    fn rejects_hostile_or_malformed_uris() {
        for uri in [
            "otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/Example?issuer=Example",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=7",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&period=90",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6&digits=8",
            "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&image=https://evil.test/x.png",
            "otpauth://totp/Example?secret=not-base32!",
            "https://example.test/",
            "otpauth://totp/",
        ] {
            assert!(TotpConfig::from_uri(uri).is_err(), "accepted {uri}");
        }
    }

    #[test]
    fn a_label_and_issuer_must_agree() {
        let mismatch = "otpauth://totp/Evil:demo?secret=JBSWY3DPEHPK3PXP&issuer=Bank";
        assert!(TotpConfig::from_uri(mismatch).is_err());
    }

    #[test]
    fn a_bare_base32_secret_gets_the_defaults() {
        let config = TotpConfig::from_field("jbswy3dpehpk3pxp").expect("field");
        assert_eq!(config.algorithm(), TotpAlgorithm::Sha1);
        assert_eq!(config.digits(), 6);
        assert_eq!(config.step(), 30);
        assert_eq!(
            TotpConfig::from_field("  JBSWY3DPEHPK3PXP  ")
                .expect("trim")
                .secret_base32(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn codes_are_stable_within_a_step_and_change_across_it() {
        let config = TotpConfig::from_base32("JBSWY3DPEHPK3PXP").expect("config");
        // A step boundary: 1_700_000_010 is 0 mod 30.
        let base = 1_700_000_010u64;
        assert_eq!(base % 30, 0);
        let a = config.code_at(base).expect("a");
        let b = config.code_at(base + 29).expect("b");
        let c = config.code_at(base + 30).expect("c");
        assert_eq!(a.as_str(), b.as_str());
        assert_ne!(a.as_str(), c.as_str());
    }

    #[test]
    fn verification_rejects_non_digits_and_wrong_lengths() {
        let config = TotpConfig::from_base32("JBSWY3DPEHPK3PXP").expect("config");
        for code in ["", "12345", "1234567", "abcdef", " 12345x "] {
            assert!(!config.verify_at(code, 59).expect("verify"), "{code:?}");
        }
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let config = TotpConfig::from_base32("JBSWY3DPEHPK3PXP").expect("config");
        let printed = format!("{config:?}");
        assert!(!printed.contains("JBSWY3DP"));
        assert!(printed.contains("secret_len"));
    }
}
