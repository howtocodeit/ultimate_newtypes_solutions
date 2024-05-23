/*!
   # ascii_character_policy

   Exposes a password policy which validates the length of password candidates in bytes.
*/

use std::fmt::Display;
use std::ops::RangeInclusive;

use thiserror::Error;

use crate::ex3::PasswordPolicy;

/// The default minimum length of a password in bytes.
// Caution: this may be as few as two UTF-8 codepoints, which might even render as a single
// "character". See
// https://stackoverflow.com/questions/71011343/maximum-number-of-codepoints-in-a-grapheme-cluster
// if you don't want to sleep for a week.
// This is why it's important to enforce the types of characters that can be used in a password, as
// well as the count of bytes.
pub const DEFAULT_PASSWORD_MIN_BYTES: usize = 8;

/// The default maximum length of a password in bytes.
// Depending on your hashing algorithm, this may be a hard limit (bcrypt) or just a sensible upper
// bound to prevent giant password spam.
pub const DEFAULT_PASSWORD_MAX_BYTES: usize = 72;

/// A password policy which validates that the length of password candidates lies in `range`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPolicy(RangeInclusive<usize>);

impl LengthPolicy {
    /// Creates a new `LengthPolicy` that validates the byte length of password candidates.
    pub fn new(range: RangeInclusive<usize>) -> Self {
        Self(range)
    }
}

impl Default for LengthPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_PASSWORD_MIN_BYTES..=DEFAULT_PASSWORD_MAX_BYTES)
    }
}

/// Error type for password policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("passwords must have length in the range {min}..={max}, but candidate was {actual} bytes")]
pub struct LengthPolicyViolationError {
    pub min: usize,
    pub max: usize,
    pub actual: usize,
}

impl PasswordPolicy for LengthPolicy {
    type Error = LengthPolicyViolationError;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error> {
        if !self.0.contains(&candidate.len()) {
            return Err(LengthPolicyViolationError {
                min: *self.0.start(),
                max: *self.0.end(),
                actual: candidate.len(),
            });
        }

        Ok(())
    }
}

impl Display for LengthPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LengthPolicy({}..={})", self.0.start(), self.0.end())
    }
}

#[cfg(test)]
mod length_policy_tests {
    use super::*;

    #[test]
    fn test_new() {
        let range = 8..=12;
        let policy = LengthPolicy::new(range.clone());
        assert_eq!(
            range.clone(),
            policy.0,
            "expected range to be {:?}, but was {:?}",
            range,
            policy.0
        );
    }

    #[test]
    fn test_default() {
        let policy = LengthPolicy::default();
        let expected = DEFAULT_PASSWORD_MIN_BYTES..=DEFAULT_PASSWORD_MAX_BYTES;
        assert_eq!(
            expected, policy.0,
            "expected default range to be {:?}, but was {:?}",
            expected, policy.0
        );
    }

    #[test]
    fn test_validate_valid() {
        let candidate = "password123";
        let policy = LengthPolicy::new(8..=12);
        let result = policy.validate(candidate);
        assert!(
            result.is_ok(),
            "expected candidate '{}' to be valid, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_validate_too_short() {
        let candidate = "short";
        let policy = LengthPolicy::new(8..=12);
        let expected = Err(LengthPolicyViolationError {
            min: 8,
            max: 12,
            actual: candidate.len(),
        });
        let result = policy.validate(candidate);
        assert_eq!(
            expected, result,
            "expected candidate '{}' to be invalid, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_validate_too_long() {
        let candidate = "thispasswordistoolong";
        let policy = LengthPolicy::new(8..=12);
        let expected = Err(LengthPolicyViolationError {
            min: 8,
            max: 12,
            actual: candidate.len(),
        });
        let result = policy.validate(candidate);
        assert_eq!(
            expected, result,
            "expected candidate '{}' to be invalid, but got {:?}",
            candidate, result
        );
    }

    #[test]
    #[allow(clippy::reversed_empty_ranges)]
    fn test_validate_empty_range() {
        let candidate = "password123";
        let policy = LengthPolicy::new(12..=8);
        let expected = Err(LengthPolicyViolationError {
            min: 12,
            max: 8,
            actual: candidate.len(),
        });
        let result = policy.validate(candidate);
        assert_eq!(
            expected, result,
            "expected candidate '{}' to be invalid, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_display() {
        let policy = LengthPolicy::new(8..=12);
        let display = format!("{}", policy);
        let expected = "LengthPolicy(8..=12)";
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}

#[cfg(test)]
mod length_policy_error_tests {
    use super::*;

    #[test]
    fn test_display() {
        let error = LengthPolicyViolationError {
            min: 8,
            max: 12,
            actual: 7,
        };
        let display = format!("{}", error);
        let expected = "passwords must have length in the range 8..=12, but candidate was 7 bytes";
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
