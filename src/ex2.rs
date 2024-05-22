/*! # Exercise 2
    Implement a method on `Password` allowing it to be compared with candidate password strings
    submitted by users during login attempts.

    Your method should return a `Result`: `0k()` if Password matches the candidate, or an `Err` of
    your choice if not.
 */

use std::fmt;
use std::fmt::{Debug, Display};
use std::sync::OnceLock;

use argon2::{Argon2, password_hash::{PasswordHasher, rand_core, SaltString}, password_hash, PasswordVerifier};
use regex::Regex;
use thiserror::Error;

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

/// Error type for [Password] instantiation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PasswordError {
    #[error("passwords must be at least {PASSWORD_MIN_BYTES} bytes long, but candidate was only {0} bytes")]
    TooShort(usize),
    #[error("passwords must be at most {PASSWORD_MAX_BYTES} bytes long, but candidate was {0} bytes")]
    TooLong(usize),
    #[error("password candidate contained invalid characters")]
    InvalidChars,
    // Unreachable in practice, since password validations should prevent pathological inputs to
    // the hashing algorithm.
    #[error(transparent)]
    Unhashable(#[from] password_hash::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(transparent)]
pub struct PasswordVerificationError(#[from] password_hash::Error);

/// A hashed password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password {
    hash: String,
}

impl Password {
    /// Create a new, hashed `Password` from a candidate string.
    ///
    /// # Errors
    ///
    /// Returns [PasswordError] variants according to the specific validation failure.
    pub fn new(candidate: &str) -> Result<Self, PasswordError> {
        validate_password_candidate(candidate)?;
        let hash = hash_password_candidate(candidate)?;
        Ok(Self { hash })
    }

    /// Returns a byte slice of the `Password`'s hash.
    pub fn as_bytes(&self) -> &[u8] {
        self.hash.as_bytes()
    }

    /// Verifies whether `candidate` matches the password hash.
    pub fn verify_candidate(&self, candidate: &str) -> Result<(), PasswordVerificationError> {
        let parsed_hash = argon2::PasswordHash::new(&self.hash).unwrap_or_else(|e| {
            // Should be unreachable, since all `Password` instances are valid, and all valid
            // `Password` instances contain a hash produced by `argon2`.
            unreachable!("failed to instantiate `argon2::PasswordHash` from `Password.hash`: {:?}", e)
        });
        Argon2::default().verify_password(candidate.as_bytes(), &parsed_hash)?;
        Ok(())
    }
}

// We don't want to log password hashes, so we implement Debug manually to redact the hash.
impl Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password")
            .field("hash", &"REDACTED")
            .finish()
    }
}

impl Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PASSWORD_REDACTED")
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.hash
    }
}

impl TryFrom<&str> for Password {
    type Error = PasswordError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

fn validate_password_candidate(candidate: &str) -> Result<(), PasswordError> {
    if candidate.len() < PASSWORD_MIN_BYTES {
        return Err(PasswordError::TooShort(candidate.len()));
    }

    if candidate.len() > PASSWORD_MAX_BYTES {
        return Err(PasswordError::TooLong(candidate.len()));
    }

    if !password_allowed_chars().is_match(candidate) {
        return Err(PasswordError::InvalidChars);
    }

    Ok(())
}

/// Hash a password candidate using the Argon2id algorithm.
fn hash_password_candidate(candidate: &str) -> Result<String, password_hash::Error> {
    // Note: `OsRng` only implements `CryptoRngCore` if the `std` feature of `argon2` is enabled.
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(candidate.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn test_new_valid() {
        let candidate = "password123";
        let result = Password::new(candidate);
        assert!(result.is_ok(), "expected candidate '{}' to be valid, but got {:?}", candidate, result);

        let password = result.unwrap();
        assert!(password.verify_candidate(candidate).is_ok(), "expected hash to match candidate '{}'", candidate);
    }

    #[test]
    fn test_new_too_short() {
        let candidate = "short";
        let result = Password::new(candidate);
        let expected = Err(PasswordError::TooShort(candidate.len()));
        assert_eq!(result, expected, "expected candidate '{}' to be too short, but got {:?}", candidate, result);
    }

    #[test]
    fn test_new_too_long() {
        let candidate = "a".repeat(PASSWORD_MAX_BYTES + 1);
        let result = Password::new(&candidate);
        let expected = Err(PasswordError::TooLong(candidate.len()));
        assert_eq!(result, expected, "expected candidate '{}' to be too long, but got {:?}", candidate, result);
    }

    #[test]
    fn test_new_invalid_chars() {
        let candidate = "abcdefghあ";
        let result = Password::new(candidate);
        let expected = Err(PasswordError::InvalidChars);
        assert_eq!(result, expected, "expected candidate '{}' to contain invalid characters, but got {:?}", candidate, result);
    }

    #[test]
    fn test_debug() {
        let password = Password::new("password123").unwrap();
        let debug = format!("{:?}", password);
        let expected = "Password { hash: \"REDACTED\" }";
        assert_eq!(debug, expected, "expected debug output to redact hash, but got '{}'", debug);
    }

    #[test]
    fn test_display() {
        let password = Password::new("password123").unwrap();
        let display = format!("{}", password);
        let expected = "PASSWORD_REDACTED";
        assert_eq!(display, expected, "expected display output to redact hash, but got '{}'", display);
    }

    #[test]
    fn test_as_ref() {
        let password = Password::new("password123").unwrap();
        let as_ref = password.as_ref();
        let expected = &password.hash;
        assert_eq!(as_ref, expected);
    }

    #[test]
    fn test_as_bytes() {
        let password = Password::new("password123").unwrap();
        let as_bytes = password.as_bytes();
        let expected = password.hash.as_bytes();
        assert_eq!(as_bytes, expected);
    }

    // Ordinarily, we'd test try_from by simply comparing the result of try_from to the result of
    // new. However, since two hashes of the same password will not be equal, we have to verify the
    // hash directly.
    #[test]
    fn test_try_from_str() {
        let candidate = "password123";
        let result = Password::try_from(candidate);
        assert!(result.is_ok(), "expected candidate '{}' to be valid, but got {:?}", candidate, result);

        let password = result.unwrap();
        assert!(password.verify_candidate(candidate).is_ok(), "expected candidate '{}' to match password", candidate);

    }

    #[test]
    fn test_verify_candidate_match() {
        let candidate = "password123";
        let password = Password::new(candidate).unwrap();
        let result = password.verify_candidate(candidate);
        assert!(result.is_ok(), "expected candidate to match password, but got {:?}", result);
    }

    #[test]
    fn test_verify_candidate_no_match() {
        let password = Password::new("password123").unwrap();
        let candidate = "wrongpassword";
        let result = password.verify_candidate(candidate);
        assert!(result.is_err(), "expected candidate '{}' not to match password", candidate);
    }

    #[test]
    #[should_panic]
    fn test_verify_candidate_unreachable() {
        let password = Password {
            hash: String::new(), // bypass the constructor to create a pathological hash
        };
        let candidate = "password123";
        let _ = password.verify_candidate(candidate);
    }
}