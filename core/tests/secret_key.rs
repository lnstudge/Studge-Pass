//! The SP1 Secret Key format (SPEC §4.2): 128 bits, 26 key characters plus one
//! check character, Crockford base32.

use studge_core::crypto::secret_key::SecretKey;

#[test]
fn generated_keys_round_trip() {
    for _ in 0..16 {
        let key = SecretKey::generate().expect("OsRng should be available");
        let text = key.encode();
        assert!(text.starts_with("SP1-"), "prefix: {text}");
        // SP1- + 27 characters + 5 hyphens = 36.
        assert_eq!(text.len(), 36, "printed length: {text}");
        let decoded = SecretKey::decode(&text).expect("a generated key must decode");
        assert_eq!(decoded.as_bytes(), key.as_bytes());
    }
}

#[test]
fn decoding_forgives_case_hyphens_and_confusables() {
    let key = SecretKey::from_bytes([0x42; 16]);
    let canonical = key.encode();

    let lower = canonical.to_lowercase();
    assert_eq!(
        SecretKey::decode(&lower).expect("lower-case input").as_bytes(),
        key.as_bytes()
    );

    let no_hyphens = canonical.replace('-', "");
    assert_eq!(
        SecretKey::decode(&no_hyphens)
            .expect("hyphens are optional")
            .as_bytes(),
        key.as_bytes()
    );

    // Crockford: I and L mean 1, O means 0. Only the body is rewritten — the
    // "SP1" prefix is fixed and must stay intact.
    let (prefix, body) = canonical.split_at(4);
    let confusable = format!("{prefix}{}", body.replace('1', "I").replace('0', "O"));
    assert_eq!(
        SecretKey::decode(&confusable)
            .expect("Crockford confusables are normalised")
            .as_bytes(),
        key.as_bytes()
    );
}

#[test]
fn rejects_a_bad_checksum() {
    let key = SecretKey::from_bytes([7u8; 16]);
    let mut chars: Vec<char> = key.encode().chars().collect();
    let last = chars.len() - 1;
    let replacement = if chars[last] == 'A' { 'B' } else { 'A' };
    chars[last] = replacement;
    let tampered: String = chars.into_iter().collect();
    let err = SecretKey::decode(&tampered).expect_err("checksum must fail");
    assert_eq!(format!("{err}"), "invalid checksum");
}

#[test]
fn rejects_wrong_lengths() {
    let key = SecretKey::from_bytes([1u8; 16]);
    let text = key.encode();
    for cut in [1usize, 2, 5] {
        let short = &text[..text.len() - cut];
        assert!(SecretKey::decode(short).is_err(), "short input: {short}");
    }
    let long = format!("{text}A");
    assert!(SecretKey::decode(&long).is_err(), "long input must fail");
}

#[test]
fn rejects_characters_outside_the_alphabet() {
    let key = SecretKey::from_bytes([3u8; 16]);
    let text = key.encode();
    let mut chars: Vec<char> = text.chars().collect();
    // 'U' is not in Crockford base32.
    chars[6] = 'U';
    let bad: String = chars.into_iter().collect();
    assert!(SecretKey::decode(&bad).is_err());

    let mut chars: Vec<char> = text.chars().collect();
    chars[6] = '!';
    let bad: String = chars.into_iter().collect();
    assert!(SecretKey::decode(&bad).is_err());
}

#[test]
fn debug_never_prints_the_key() {
    let key = SecretKey::from_bytes([0xAB; 16]);
    let printed = format!("{key:?}");
    assert!(printed.contains("redacted"), "debug output: {printed}");
    assert!(!printed.contains("AB"), "debug output leaked bytes: {printed}");
}

#[test]
fn fixed_bytes_encode_deterministically() {
    // Same bytes, same string, every time — vectors depend on this.
    let a = SecretKey::from_bytes([0u8; 16]).encode();
    let b = SecretKey::from_bytes([0u8; 16]).encode();
    assert_eq!(a, b);
    assert!(a.starts_with("SP1-00000-00000-00000-00000-00000-0"), "{a}");
    assert_eq!(a.len(), 36);
}
