//! Password and passphrase generation (task item 7).
//!
//! Randomness comes only from [`crate::crypto::random`] (the OS), selections
//! use rejection sampling so no value is favoured by modulo bias, and the
//! result is a zeroizing string. Entropy is reported as a **lower bound**:
//! `length × log2(alphabet)`, which the "every class must appear" rule can only
//! reduce, never increase.

use crate::crypto::random;
use crate::error::{CoreError, CoreResult};
use std::sync::OnceLock;
use zeroize::Zeroizing;

/// Lower-case letters.
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
/// Upper-case letters.
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Digits.
pub const DIGITS: &str = "0123456789";
/// Symbols that survive most password fields.
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
/// Characters that are easy to confuse in print.
pub const AMBIGUOUS: &str = "0OoIl1|`'\"";

/// The EFF large wordlist, compiled in.
const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

/// Words in the bundled list (7776).
pub const WORDLIST_LEN: usize = 7776;

/// Shortest password this generator will produce.
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// Longest password this generator will produce.
pub const MAX_PASSWORD_LENGTH: usize = 256;
/// Fewest words in a passphrase.
pub const MIN_PASSPHRASE_WORDS: usize = 3;
/// Most words in a passphrase.
pub const MAX_PASSPHRASE_WORDS: usize = 16;

/// Password shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    /// Number of characters.
    pub length: usize,
    /// Include lower-case letters.
    pub lowercase: bool,
    /// Include upper-case letters.
    pub uppercase: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Drop characters that look alike in print.
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl PasswordOptions {
    /// The alphabet implied by the options, after ambiguity filtering.
    pub fn alphabet(&self) -> String {
        let mut alphabet = String::new();
        if self.lowercase {
            alphabet.push_str(LOWERCASE);
        }
        if self.uppercase {
            alphabet.push_str(UPPERCASE);
        }
        if self.digits {
            alphabet.push_str(DIGITS);
        }
        if self.symbols {
            alphabet.push_str(SYMBOLS);
        }
        if self.exclude_ambiguous {
            alphabet.retain(|character| !AMBIGUOUS.contains(character));
        }
        alphabet
    }

    fn classes(&self) -> Vec<String> {
        let mut classes = Vec::new();
        let current = self.alphabet();
        for set in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
            let selected = match set {
                LOWERCASE => self.lowercase,
                UPPERCASE => self.uppercase,
                DIGITS => self.digits,
                _ => self.symbols,
            };
            if !selected {
                continue;
            }
            let filtered: String = set
                .chars()
                .filter(|character| current.contains(*character))
                .collect();
            if !filtered.is_empty() {
                classes.push(filtered);
            }
        }
        classes
    }
}

/// Passphrase shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    /// Number of words.
    pub words: usize,
    /// Placed between words.
    pub separator: char,
    /// Capitalise (randomly, per word) the first letter.
    pub capitalise: bool,
    /// Append one random digit.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: '-',
            capitalise: true,
            include_number: true,
        }
    }
}

/// A uniformly random integer in `0..bound` by rejection sampling.
fn random_below(bound: u32) -> CoreResult<u32> {
    if bound == 0 {
        return Err(CoreError::InvalidParameter);
    }
    // Reject values in the incomplete final block so every residue is equally
    // likely; the expected number of draws is below 2.
    let limit = u32::MAX - (u32::MAX % bound);
    for _ in 0..64 {
        let bytes: [u8; 4] = random::array()?;
        let value = u32::from_le_bytes(bytes);
        if value < limit {
            return Ok(value % bound);
        }
    }
    Err(CoreError::InvalidParameter)
}

/// Generates a password.
pub fn generate_password(options: &PasswordOptions) -> CoreResult<Zeroizing<String>> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&options.length) {
        return Err(CoreError::InvalidParameter);
    }
    let alphabet: Vec<char> = options.alphabet().chars().collect();
    if alphabet.is_empty() {
        return Err(CoreError::InvalidParameter);
    }
    let classes = options.classes();
    if classes.len() > options.length {
        return Err(CoreError::InvalidParameter);
    }

    // Rejection sampling over whole strings: the result is uniform over the
    // passwords that contain at least one character of every selected class.
    for _ in 0..64 {
        let mut candidate = String::with_capacity(options.length);
        for _ in 0..options.length {
            let index = random_below(alphabet.len() as u32)? as usize;
            candidate.push(alphabet[index]);
        }
        let complete = classes
            .iter()
            .all(|set| candidate.chars().any(|character| set.contains(character)));
        if complete {
            return Ok(Zeroizing::new(candidate));
        }
    }
    Err(CoreError::InvalidParameter)
}

/// The entropy of [`generate_password`] with these options, in bits, as a lower
/// bound: `length × log2(alphabet)`.
pub fn password_entropy_bits(options: &PasswordOptions) -> f64 {
    let alphabet = options.alphabet().chars().count();
    if alphabet < 2 {
        return 0.0;
    }
    options.length as f64 * (alphabet as f64).log2()
}

/// Generates a passphrase from the EFF large wordlist.
pub fn generate_passphrase(options: &PassphraseOptions) -> CoreResult<Zeroizing<String>> {
    if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&options.words) {
        return Err(CoreError::InvalidParameter);
    }
    if options.separator.is_control() {
        return Err(CoreError::InvalidParameter);
    }
    let words = wordlist();
    if words.len() != WORDLIST_LEN {
        return Err(CoreError::InvalidParameter);
    }
    let mut phrase = String::with_capacity(options.words * 8);
    for index in 0..options.words {
        if index > 0 {
            phrase.push(options.separator);
        }
        let word = words[random_below(words.len() as u32)? as usize];
        if options.capitalise && random_below(2)? == 1 {
            let mut characters = word.chars();
            if let Some(first) = characters.next() {
                phrase.extend(first.to_uppercase());
                phrase.push_str(characters.as_str());
                continue;
            }
        }
        phrase.push_str(word);
    }
    if options.include_number {
        let digit = random_below(10)?;
        phrase.push(char::from_digit(digit, 10).ok_or(CoreError::InvalidParameter)?);
    }
    Ok(Zeroizing::new(phrase))
}

/// The entropy of [`generate_passphrase`] in bits: `words × log2(7776)`, plus
/// one bit per word when capitalisation is on and `log2(10)` for the digit.
pub fn passphrase_entropy_bits(options: &PassphraseOptions) -> f64 {
    let mut bits = options.words as f64 * (WORDLIST_LEN as f64).log2();
    if options.capitalise {
        bits += options.words as f64;
    }
    if options.include_number {
        bits += 10f64.log2();
    }
    bits
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
            .filter(|word| !word.is_empty())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_complete_and_unique() {
        let words = wordlist();
        assert_eq!(words.len(), WORDLIST_LEN);
        let mut seen = std::collections::BTreeSet::new();
        for word in words {
            assert!(seen.insert(*word), "duplicate word {word}");
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "unexpected word {word}"
            );
        }
    }

    #[test]
    fn passwords_have_the_requested_shape() {
        let options = PasswordOptions::default();
        for _ in 0..50 {
            let password = generate_password(&options).expect("generate");
            assert_eq!(password.chars().count(), options.length);
            let alphabet = options.alphabet();
            for character in password.chars() {
                assert!(alphabet.contains(character), "unexpected {character}");
            }
        }
    }

    #[test]
    fn every_selected_class_appears() {
        let options = PasswordOptions {
            length: 12,
            ..PasswordOptions::default()
        };
        for _ in 0..100 {
            let password = generate_password(&options).expect("generate");
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_characters_can_be_excluded() {
        let options = PasswordOptions {
            length: 40,
            symbols: true,
            exclude_ambiguous: true,
            ..PasswordOptions::default()
        };
        for _ in 0..20 {
            let password = generate_password(&options).expect("generate");
            for character in AMBIGUOUS.chars() {
                assert!(
                    !password.contains(character),
                    "ambiguous {character} was used"
                );
            }
        }
        let noisy = PasswordOptions {
            exclude_ambiguous: false,
            ..options
        };
        assert!(noisy.alphabet().chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn rejects_impossible_options() {
        for options in [
            PasswordOptions {
                length: 4,
                ..PasswordOptions::default()
            },
            PasswordOptions {
                length: 300,
                ..PasswordOptions::default()
            },
            PasswordOptions {
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: false,
                ..PasswordOptions::default()
            },
        ] {
            assert_eq!(
                generate_password(&options).expect_err("reject"),
                CoreError::InvalidParameter
            );
        }
    }

    #[test]
    fn entropy_is_a_lower_bound() {
        let options = PasswordOptions {
            length: 20,
            ..PasswordOptions::default()
        };
        let bits = password_entropy_bits(&options);
        // 20 characters over the ambiguity-filtered alphabet: about 129 bits.
        assert!(bits > 120.0 && bits < 132.0, "bits={bits}");
        let empty = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert_eq!(password_entropy_bits(&empty), 0.0);
    }

    #[test]
    fn passphrases_use_the_requested_words() {
        // A space separator keeps the word count unambiguous: the EFF list
        // contains four hyphenated words, so '-' would collide with the words
        // themselves (a usability wart, not a security one).
        let options = PassphraseOptions {
            separator: ' ',
            capitalise: false,
            include_number: false,
            ..PassphraseOptions::default()
        };
        for _ in 0..30 {
            let phrase = generate_passphrase(&options).expect("generate");
            let parts: Vec<&str> = phrase.split(' ').collect();
            assert_eq!(parts.len(), options.words);
            for word in parts {
                assert!(
                    wordlist().contains(&word),
                    "{word:?} is not in the EFF list"
                );
            }
        }
    }

    #[test]
    fn the_default_passphrase_has_a_digit_and_a_separator() {
        let options = PassphraseOptions::default();
        let phrase = generate_passphrase(&options).expect("generate");
        assert!(phrase.chars().last().expect("digit").is_ascii_digit());
        assert!(phrase.contains(options.separator));
        assert!(phrase.chars().count() > options.words * 2);
    }

    #[test]
    fn passphrase_entropy_matches_the_formula() {
        let options = PassphraseOptions {
            words: 6,
            separator: '-',
            capitalise: false,
            include_number: false,
        };
        let bits = passphrase_entropy_bits(&options);
        assert!((bits - 6.0 * 12.925).abs() < 0.01, "bits={bits}");
        let with_extras = passphrase_entropy_bits(&PassphraseOptions::default());
        assert!(with_extras > 5.0 * 12.925);
    }

    #[test]
    fn two_generations_differ() {
        let a = generate_password(&PasswordOptions::default()).expect("a");
        let b = generate_password(&PasswordOptions::default()).expect("b");
        assert_ne!(a.as_str(), b.as_str());
        let c = generate_passphrase(&PassphraseOptions::default()).expect("c");
        let d = generate_passphrase(&PassphraseOptions::default()).expect("d");
        assert_ne!(c.as_str(), d.as_str());
    }

    #[test]
    fn rejects_impossible_passphrase_shapes() {
        for options in [
            PassphraseOptions {
                words: 1,
                ..PassphraseOptions::default()
            },
            PassphraseOptions {
                words: 99,
                ..PassphraseOptions::default()
            },
        ] {
            assert!(generate_passphrase(&options).is_err());
        }
    }
}
