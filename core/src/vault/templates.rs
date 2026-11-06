//! Item templates: the closed set of field names for each item kind.
//!
//! SPEC §5.6: field names come from the template, never from free text. A name
//! outside the template is rejected when an item is built *and* when a stored
//! payload is parsed, so a malicious member cannot inject a look-alike label
//! such as a Cyrillic "password" field (R-0114).

use crate::vault::items::ItemKind;

/// One scalar field of a template.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    /// The wire name, also used in the AAD if the field is ever sealed alone.
    pub name: &'static str,
    /// Secret fields are tracked in the item's last-10 history.
    pub secret: bool,
    /// Whether a new item must set it (the UI uses this; parsing does not).
    pub required: bool,
    /// The label the UI shows for this known field name.
    pub label: &'static str,
}

/// A template: its scalar fields and which list-shaped sections it allows.
#[derive(Debug)]
pub struct Template {
    /// The item kind this template describes.
    pub kind: ItemKind,
    /// Scalar (single-value) fields.
    pub fields: &'static [FieldSpec],
    /// Whether the kind carries a list of URLs with match rules.
    pub urls: bool,
    /// Whether the kind carries user-labelled custom fields.
    pub custom: bool,
    /// Whether the kind carries linked passkey credential ids.
    pub passkeys: bool,
}

const fn field(name: &'static str, label: &'static str, secret: bool) -> FieldSpec {
    FieldSpec {
        name,
        secret,
        required: false,
        label,
    }
}

const TITLE: FieldSpec = FieldSpec {
    name: "title",
    secret: false,
    required: true,
    label: "Title",
};
const NOTES: FieldSpec = field("notes", "Notes", false);

const LOGIN_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("username", "Username", false),
    field("password", "Password", true),
    field("totp", "One-time code secret", true),
    NOTES,
];

const PASSKEY_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("credential_id", "Credential ID", false),
    field("rp_id", "Relying party", false),
    field("user_handle", "User handle", false),
    field("user_name", "User name", false),
    field("display_name", "Display name", false),
    field("private_key_pkcs8", "Private key", true),
    field("sign_count", "Signature counter", false),
    field("backup_eligible", "Backup eligible", false),
    field("backup_state", "Backed up", false),
    field("created_at", "Created", false),
];

const NOTE_FIELDS: &[FieldSpec] = &[TITLE, NOTES];

const CARD_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("cardholder", "Cardholder", false),
    field("number", "Card number", true),
    field("expiry_month", "Expiry month", false),
    field("expiry_year", "Expiry year", false),
    field("cvv", "Security code", true),
    field("pin", "PIN", true),
    NOTES,
];

const IDENTITY_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("full_name", "Full name", false),
    field("first_name", "First name", false),
    field("last_name", "Last name", false),
    field("email", "Email", false),
    field("phone", "Phone", false),
    field("address", "Address", false),
    field("dob", "Date of birth", false),
    NOTES,
];

const SSH_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("private_key", "Private key", true),
    field("public_key", "Public key", false),
    field("fingerprint", "Fingerprint", false),
    field("passphrase", "Passphrase", true),
    NOTES,
];

const AADHAAR_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("aadhaar_number", "Aadhaar number", true),
    field("full_name", "Full name", false),
    field("dob", "Date of birth", false),
    field("gender", "Gender", false),
    field("address", "Address", false),
    field("mobile", "Mobile", false),
    NOTES,
];

const PAN_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("pan_number", "PAN", true),
    field("full_name", "Full name", false),
    field("dob", "Date of birth", false),
    NOTES,
];

const UPI_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("upi_id", "UPI ID", false),
    field("pin", "UPI PIN", true),
    field("linked_bank", "Linked bank", false),
    field("mobile", "Mobile", false),
    NOTES,
];

const NETBANKING_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("customer_id", "Customer ID", false),
    field("login_password", "Login password", true),
    field("mpin", "MPIN", true),
    field("transaction_password", "Transaction password", true),
    field("bank", "Bank", false),
    NOTES,
];

const DIGILOCKER_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("username", "Username", false),
    field("password", "Password", true),
    field("aadhaar_number", "Aadhaar number", true),
    NOTES,
];

const PASSPORT_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("passport_number", "Passport number", true),
    field("full_name", "Full name", false),
    field("dob", "Date of birth", false),
    field("issue_date", "Issued", false),
    field("expiry_date", "Expires", false),
    field("place_of_issue", "Place of issue", false),
    NOTES,
];

const VOTER_FIELDS: &[FieldSpec] = &[
    TITLE,
    field("epic_number", "EPIC number", true),
    field("full_name", "Full name", false),
    field("dob", "Date of birth", false),
    field("address", "Address", false),
    NOTES,
];

static LOGIN: Template = Template {
    kind: ItemKind::Login,
    fields: LOGIN_FIELDS,
    urls: true,
    custom: true,
    passkeys: true,
};

static PASSKEY: Template = Template {
    kind: ItemKind::Passkey,
    fields: PASSKEY_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static SECURE_NOTE: Template = Template {
    kind: ItemKind::SecureNote,
    fields: NOTE_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static CARD: Template = Template {
    kind: ItemKind::Card,
    fields: CARD_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static IDENTITY: Template = Template {
    kind: ItemKind::Identity,
    fields: IDENTITY_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static SSH_KEY: Template = Template {
    kind: ItemKind::SshKey,
    fields: SSH_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static AADHAAR: Template = Template {
    kind: ItemKind::Aadhaar,
    fields: AADHAAR_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static PAN: Template = Template {
    kind: ItemKind::Pan,
    fields: PAN_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static UPI: Template = Template {
    kind: ItemKind::Upi,
    fields: UPI_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static NETBANKING: Template = Template {
    kind: ItemKind::Netbanking,
    fields: NETBANKING_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static DIGILOCKER: Template = Template {
    kind: ItemKind::DigiLocker,
    fields: DIGILOCKER_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static PASSPORT: Template = Template {
    kind: ItemKind::Passport,
    fields: PASSPORT_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

static VOTER_ID: Template = Template {
    kind: ItemKind::VoterId,
    fields: VOTER_FIELDS,
    urls: false,
    custom: false,
    passkeys: false,
};

/// The template for an item kind.
pub fn template(kind: ItemKind) -> &'static Template {
    match kind {
        ItemKind::Login => &LOGIN,
        ItemKind::Passkey => &PASSKEY,
        ItemKind::SecureNote => &SECURE_NOTE,
        ItemKind::Card => &CARD,
        ItemKind::Identity => &IDENTITY,
        ItemKind::SshKey => &SSH_KEY,
        ItemKind::Aadhaar => &AADHAAR,
        ItemKind::Pan => &PAN,
        ItemKind::Upi => &UPI,
        ItemKind::Netbanking => &NETBANKING,
        ItemKind::DigiLocker => &DIGILOCKER,
        ItemKind::Passport => &PASSPORT,
        ItemKind::VoterId => &VOTER_ID,
    }
}

/// The field spec for `name`, if the kind has it.
pub fn field_spec(kind: ItemKind, name: &str) -> Option<&'static FieldSpec> {
    template(kind).fields.iter().find(|spec| spec.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_kind_has_a_template_with_a_title() {
        for kind in ItemKind::ALL {
            let template = template(kind);
            assert_eq!(template.kind, kind);
            assert!(
                template.fields.iter().any(|spec| spec.name == "title"),
                "{kind:?} needs a title"
            );
        }
    }

    #[test]
    fn field_names_are_unique_and_aad_safe() {
        for kind in ItemKind::ALL {
            let mut seen = BTreeSet::new();
            for spec in template(kind).fields {
                assert!(
                    seen.insert(spec.name),
                    "duplicate {} in {kind:?}",
                    spec.name
                );
                assert!(
                    spec.name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                    "{} must be AAD-safe",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn india_templates_carry_the_briefed_fields() {
        assert!(field_spec(ItemKind::Aadhaar, "aadhaar_number").is_some());
        assert!(field_spec(ItemKind::Pan, "pan_number").is_some());
        assert!(field_spec(ItemKind::Upi, "upi_id").is_some());
        for name in [
            "customer_id",
            "login_password",
            "mpin",
            "transaction_password",
        ] {
            assert!(
                field_spec(ItemKind::Netbanking, name).is_some(),
                "netbanking needs {name}"
            );
        }
        for kind in [
            ItemKind::DigiLocker,
            ItemKind::Passport,
            ItemKind::VoterId,
            ItemKind::Aadhaar,
            ItemKind::Pan,
            ItemKind::Upi,
            ItemKind::Netbanking,
        ] {
            assert!(template(kind).fields.iter().any(|spec| spec.secret));
        }
    }

    #[test]
    fn only_login_has_urls_custom_fields_and_passkeys() {
        for kind in ItemKind::ALL {
            let template = template(kind);
            let expected = kind == ItemKind::Login;
            assert_eq!(template.urls, expected, "{kind:?}");
            assert_eq!(template.custom, expected, "{kind:?}");
            assert_eq!(template.passkeys, expected, "{kind:?}");
        }
    }

    #[test]
    fn secret_fields_are_the_ones_with_history() {
        assert!(
            field_spec(ItemKind::Login, "password")
                .expect("password")
                .secret
        );
        assert!(
            !field_spec(ItemKind::Login, "username")
                .expect("username")
                .secret
        );
        assert!(field_spec(ItemKind::Card, "cvv").expect("cvv").secret);
        assert!(
            field_spec(ItemKind::SshKey, "private_key")
                .expect("key")
                .secret
        );
    }
}
