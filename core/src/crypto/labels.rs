//! Every HKDF label and domain-separation string, in one file.
//!
//! SPEC §5.4: no key is used for two purposes, and every label is
//! `studge/v1/<purpose>`. Nothing outside this file may spell a label.

/// The only cipher suite id in v1.
pub const SUITE_V1: &str = "v1";

/// MUK from the Argon2id output plus the Secret Key.
pub const MUK: &str = "studge/v1/muk";

/// OPAQUE password input derived from the MUK.
pub const OPAQUE_PASSWORD: &str = "studge/v1/opaque-password";

/// Account-key wrapping key derived from the MUK.
pub const AK_WRAP: &str = "studge/v1/ak-wrap";

/// Key-bundle key derived from the AK.
pub const KEY_BUNDLE: &str = "studge/v1/key-bundle";

/// Vault-key wrapping key derived from the AK (salt: vault id).
pub const VK_WRAP: &str = "studge/v1/vk-wrap";

/// Item-key wrapping key derived from the VK (salt: item id).
pub const IK_WRAP: &str = "studge/v1/ik-wrap";

/// Item field key derived from the IK (salt: item id).
pub const ITEM_FIELD: &str = "studge/v1/item-field";

/// Operation payload key derived from the VK (salt: vault id).
pub const OP_PAYLOAD: &str = "studge/v1/op-payload";

/// HPKE `info` context for a shared vault key (Phase 11).
pub const VK_SHARE: &str = "studge/v1/vk-share";

/// Guardian share encryption context (Phase 12).
pub const RECOVERY_SHARE: &str = "studge/v1/recovery-share";

/// Emergency-access grant context (Phase 12).
pub const EMERGENCY_GRANT: &str = "studge/v1/emergency-grant";

/// Key-transparency leaf context (Phase 11).
pub const KT_ENTRY: &str = "studge/v1/kt-entry";

/// Safety-code digest context.
pub const SAFETY_CODE: &str = "studge/v1/safety-code";

/// Printed Secret Key checksum context.
pub const SECRET_KEY_CHECKSUM: &str = "studge/v1/secret-key-checksum";

/// Signature domain: device certificate.
pub const DEVICE_CERT: &str = "studge/v1/device-cert";

/// Signature domain: device enrolment proof.
pub const DEVICE_ENROLL: &str = "studge/v1/device-enroll";

/// Signature domain: device revocation.
pub const DEVICE_REVOCATION: &str = "studge/v1/device-revocation";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_has_the_required_prefix() {
        let labels = [
            MUK,
            OPAQUE_PASSWORD,
            AK_WRAP,
            KEY_BUNDLE,
            VK_WRAP,
            IK_WRAP,
            ITEM_FIELD,
            OP_PAYLOAD,
            VK_SHARE,
            RECOVERY_SHARE,
            EMERGENCY_GRANT,
            KT_ENTRY,
            SAFETY_CODE,
            SECRET_KEY_CHECKSUM,
            DEVICE_CERT,
            DEVICE_ENROLL,
            DEVICE_REVOCATION,
        ];
        for label in labels {
            assert!(
                label.starts_with("studge/v1/"),
                "label {label} must start with studge/v1/"
            );
        }
    }

    #[test]
    fn labels_are_unique() {
        let labels = [
            MUK,
            OPAQUE_PASSWORD,
            AK_WRAP,
            KEY_BUNDLE,
            VK_WRAP,
            IK_WRAP,
            ITEM_FIELD,
            OP_PAYLOAD,
            VK_SHARE,
            RECOVERY_SHARE,
            EMERGENCY_GRANT,
            KT_ENTRY,
            SAFETY_CODE,
            SECRET_KEY_CHECKSUM,
            DEVICE_CERT,
            DEVICE_ENROLL,
            DEVICE_REVOCATION,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for label in labels {
            assert!(seen.insert(label), "duplicate label {label}");
        }
    }
}
