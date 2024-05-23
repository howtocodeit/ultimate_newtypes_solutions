/*!
   # ascii_charset_policy

   Implements a password policy which incorporates the requirement that password candidates contain
    only a subset of ASCII characters into the policy defined by [LengthPolicy].
*/

use std::fmt::{Display, Formatter};
use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;

use crate::ex3::password_policy::length_policy::{LengthPolicy, LengthPolicyViolationError};
use crate::ex3::password_policy::PasswordPolicy;

/// Static regex defining the characters allowed in a password. Does not validate length, which
/// should be done separately via [LengthPolicy].
fn password_allowed_chars() -> &'static Regex {
    static ALLOWED_CHARS: OnceLock<Regex> = OnceLock::new();
    ALLOWED_CHARS.get_or_init(|| Regex::new(r"^[a-zA-Z0-9!@#$%^&*()-_+=]*$").unwrap())
}

/// Enforces:
/// - password length
/// - allowed characters from a subset of ASCII.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
// Rather than reimplementing the `LengthPolicy`, we decorate it with additional charset
// validation logic.
pub struct AsciiCharsetPolicy(LengthPolicy);

impl AsciiCharsetPolicy {
    /// Creates a new [AsciiCharsetPolicy] with a custom [LengthPolicy].
    pub fn new(length_policy: LengthPolicy) -> Self {
        Self(length_policy)
    }
}

/// Error type for password policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AsciiCharsetPolicyViolationError {
    #[error(transparent)]
    LengthViolation(#[from] LengthPolicyViolationError),
    #[error("password candidate contained invalid characters")]
    CharsetViolation,
}

impl PasswordPolicy for AsciiCharsetPolicy {
    type Error = AsciiCharsetPolicyViolationError;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error> {
        self.0.validate(candidate)?;

        if !password_allowed_chars().is_match(candidate) {
            return Err(AsciiCharsetPolicyViolationError::CharsetViolation);
        }

        Ok(())
    }
}

impl Display for AsciiCharsetPolicy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AsciiCharacterPolicy({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid() {
        let candidate = "password123";
        let result = AsciiCharsetPolicy::default().validate(candidate);
        assert!(
            result.is_ok(),
            "expected candidate '{}' to be valid, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_validate_length_violation() {
        let candidate = "short";
        let result = AsciiCharsetPolicy::default().validate(candidate);
        assert!(
            matches!(
                result,
                Err(AsciiCharsetPolicyViolationError::LengthViolation(_))
            ),
            "expected candidate '{}' to trigger `LengthViolation`, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_validate_invalid_chars() {
        let candidate = "abcdefghあ";
        let result = AsciiCharsetPolicy::default().validate(candidate);
        let expected = Err(AsciiCharsetPolicyViolationError::CharsetViolation);
        assert_eq!(
            result, expected,
            "expected candidate '{}' to contain invalid characters, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_display() {
        let length_policy = LengthPolicy::default();
        let display = format!("{}", AsciiCharsetPolicy::default());
        let expected = format!("AsciiCharacterPolicy({})", length_policy);
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}

#[cfg(test)]
mod ascii_charset_policy_violation_error_tests {
    use super::*;

    #[test]
    fn test_display_charset_violation() {
        let expected = "password candidate contained invalid characters";
        let display = AsciiCharsetPolicyViolationError::CharsetViolation.to_string();
        assert_eq!(
            expected, display,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }

    #[test]
    fn test_display_length_violation() {
        let length_policy_error = LengthPolicyViolationError {
            min: 8,
            max: 12,
            actual: 7,
        };
        let expected = length_policy_error.to_string();
        let display =
            AsciiCharsetPolicyViolationError::LengthViolation(length_policy_error.clone())
                .to_string();
        assert_eq!(
            expected, display,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
