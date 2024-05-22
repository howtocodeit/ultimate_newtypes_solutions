/*!
   # ascii_character_policy

   Implements a password policy which validates that password candidates contain only a subset of
   ASCII characters.
*/

use std::fmt::{Display, Formatter};
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

use crate::ex3::password_policy::PasswordPolicy;

/// The minimum length of a password in bytes.
// Caution: this may be as few as two UTF-8 codepoints, which might even render as a single
// "character". See
// https://stackoverflow.com/questions/71011343/maximum-number-of-codepoints-in-a-grapheme-cluster
// if you don't want to sleep for a week.
// This is why it's important to enforce the types of characters that can be used in a password, as
// well as the count of bytes.
const PASSWORD_MIN_BYTES: usize = 8;

/// The maximum length of a password in bytes.
// Depending on your hashing algorithm, this may be a hard limit (bcrypt) or just a sensible upper
// bound to prevent giant password spam.
const PASSWORD_MAX_BYTES: usize = 72;

/// Static regex defining the characters allowed in a password. Does not validate length, which
/// should be done separately.
fn password_allowed_chars() -> &'static Regex {
    static ALLOWED_CHARS: OnceLock<Regex> = OnceLock::new();
    ALLOWED_CHARS.get_or_init(|| Regex::new(r"^[a-zA-Z0-9!@#$%^&*()-_+=]*$").unwrap())
}

/// Enforces:
/// - minimum password length
/// - maximum password length
/// - allowed characters from a subset of ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsciiCharacterPolicy;

/// Error type for password policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AsciiCharacterPolicyError {
    #[error("passwords must be at least {PASSWORD_MIN_BYTES} bytes long, but candidate was only {0} bytes")]
    TooShort(usize),
    #[error(
        "passwords must be at most {PASSWORD_MAX_BYTES} bytes long, but candidate was {0} bytes"
    )]
    TooLong(usize),
    #[error("password candidate contained invalid characters")]
    InvalidChars,
}

impl PasswordPolicy for AsciiCharacterPolicy {
    type Error = AsciiCharacterPolicyError;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error> {
        if candidate.len() < PASSWORD_MIN_BYTES {
            return Err(AsciiCharacterPolicyError::TooShort(candidate.len()));
        }

        if candidate.len() > PASSWORD_MAX_BYTES {
            return Err(AsciiCharacterPolicyError::TooLong(candidate.len()));
        }

        if !password_allowed_chars().is_match(candidate) {
            return Err(AsciiCharacterPolicyError::InvalidChars);
        }

        Ok(())
    }
}

impl Display for AsciiCharacterPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AsciiCharacterPolicy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid() {
        let candidate = "password123";
        let result = AsciiCharacterPolicy.validate(candidate);
        assert!(
            result.is_ok(),
            "expected candidate '{}' to be valid, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_new_too_short() {
        let candidate = "short";
        let result = AsciiCharacterPolicy.validate(candidate);
        let expected = Err(AsciiCharacterPolicyError::TooShort(candidate.len()));
        assert_eq!(
            result, expected,
            "expected candidate '{}' to be too short, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_new_too_long() {
        let candidate = "a".repeat(PASSWORD_MAX_BYTES + 1);
        let result = AsciiCharacterPolicy.validate(&candidate);
        let expected = Err(AsciiCharacterPolicyError::TooLong(candidate.len()));
        assert_eq!(
            result, expected,
            "expected candidate '{}' to be too long, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_new_invalid_chars() {
        let candidate = "abcdefghあ";
        let result = AsciiCharacterPolicy.validate(candidate);
        let expected = Err(AsciiCharacterPolicyError::InvalidChars);
        assert_eq!(
            result, expected,
            "expected candidate '{}' to contain invalid characters, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_display() {
        let display = format!("{}", AsciiCharacterPolicy);
        let expected = "AsciiCharacterPolicy";
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
