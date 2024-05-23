/*!
   # one_emoji_policy

   Implements a password policy which incorporates the requirement that passwords contain at least
   one emoji into the policy defined by [LengthPolicy].
*/

use std::fmt::Display;

use thiserror::Error;
use unicode_segmentation::UnicodeSegmentation;

use crate::ex3::password_policy::length_policy::{LengthPolicy, LengthPolicyViolationError};
use crate::ex3::password_policy::PasswordPolicy;

/// Enforces:
/// - a [LengthPolicy]
/// - at least one emoji.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OneEmojiPolicy(LengthPolicy);

impl OneEmojiPolicy {
    /// Creates a new [OneEmojiPolicy] with a custom [LengthPolicy].
    pub fn new(length_policy: LengthPolicy) -> Self {
        Self(length_policy)
    }
}

/// Error type for password policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OneEmojiPolicyViolationError {
    #[error(transparent)]
    LengthViolation(#[from] LengthPolicyViolationError),
    #[error("passwords must contain at least one emoji, but candidate had none")]
    EmojiViolation,
}

impl PasswordPolicy for OneEmojiPolicy {
    type Error = OneEmojiPolicyViolationError;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error> {
        self.0.validate(candidate)?;

        if !contains_emoji(candidate) {
            return Err(OneEmojiPolicyViolationError::EmojiViolation);
        }

        Ok(())
    }
}

/// Returns `true` if `string` contains at least one emoji.
// You might be tempted to use a regex with the `\p{Emoji}` character class for this, but what
// Unicode considers an emoji might surprise you. For example, digits like 1, 2 and 3 are Unicode
// emojis, because they may form part of a cluster of codepoints that render as an emoji.
fn contains_emoji(string: &str) -> bool {
    // Break the string into grapheme clusters, which are clusters of two or more codepoints that
    // appear to users as single characters.
    let graphemes = string.graphemes(true);
    // Check whether any of these clusters are emoji.
    graphemes
        .into_iter()
        .any(|g: &str| emojis::get(g).is_some())
}

impl Display for OneEmojiPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OneEmojiPolicy({})", self.0)
    }
}

#[cfg(test)]
mod one_emoji_policy_tests {
    use super::*;

    #[test]
    fn test_new() {
        let length_policy = LengthPolicy::new(11..=20);
        let policy = OneEmojiPolicy::new(length_policy.clone());
        assert_eq!(
            length_policy.clone(),
            policy.0,
            "expected length policy to be {:?}, but was {:?}",
            length_policy,
            policy.0
        );
    }

    #[test]
    fn test_validate_valid() {
        let candidate = "password123😀";
        let result = OneEmojiPolicy::default().validate(candidate);
        assert!(
            result.is_ok(),
            "expected candidate '{}' to be valid, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_validate_no_emoji() {
        let candidate = "password123";
        let result = OneEmojiPolicy::default().validate(candidate);
        let expected = Err(OneEmojiPolicyViolationError::EmojiViolation);
        assert_eq!(
            result, expected,
            "expected candidate '{}' to be invalid, but was ok",
            candidate
        );
    }

    #[test]
    fn test_validate_length_policy_violation() {
        let candidate = "short";
        let result = OneEmojiPolicy::default().validate(candidate);
        assert!(
            matches!(
                result,
                Err(OneEmojiPolicyViolationError::LengthViolation(_))
            ),
            "expected candidate '{}' to trigger `LengthViolation`, but got {:?}",
            candidate,
            result
        );
    }

    #[test]
    fn test_display() {
        let length_policy = LengthPolicy::default();
        let display = OneEmojiPolicy::default().to_string();
        let expected = format!("OneEmojiPolicy({})", length_policy);
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}

#[cfg(test)]
mod one_emoji_policy_violation_error_tests {
    use super::*;

    #[test]
    fn test_display_emoji_violation() {
        let expected = "passwords must contain at least one emoji, but candidate had none";
        let display = OneEmojiPolicyViolationError::EmojiViolation.to_string();
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
            OneEmojiPolicyViolationError::LengthViolation(length_policy_error.clone()).to_string();
        assert_eq!(
            expected, display,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
