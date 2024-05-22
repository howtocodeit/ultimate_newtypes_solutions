/*!
   # one_emoji_policy

   Implements a password policy which incorporates the requirement that passwords contain at least
   one emoji into the policy defined by [AsciiCharacterPolicy].
*/

use std::fmt::Display;
use thiserror::Error;
use unicode_segmentation::UnicodeSegmentation;

use crate::ex3::password_policy::ascii_character_policy::{
    AsciiCharacterPolicy, AsciiCharacterPolicyError,
};
use crate::ex3::password_policy::PasswordPolicy;

/// Enforces:
/// - at least one emoji
/// - all rules from [AsciiCharacterPolicy].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OneEmojiPolicy;

/// Error type for password policy violations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OneEmojiPolicyError {
    #[error(transparent)]
    AsciiPolicyViolation(#[from] AsciiCharacterPolicyError),
    #[error("passwords must contain at least one emoji, but candidate had none")]
    NoEmoji,
}

impl PasswordPolicy for OneEmojiPolicy {
    type Error = OneEmojiPolicyError;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error> {
        AsciiCharacterPolicy.validate(candidate)?;
        if !contains_emoji(candidate) {
            return Err(OneEmojiPolicyError::NoEmoji);
        }

        Ok(())
    }
}

/// Returns `true` if `string` contains at least one emoji.
// You might be tempted to use a regex with the `\p{Emoji}` character class for this, but what
// Unicode considers an emoji might surprise you. For example, digits like 1, 2 and 3 are Unicode
// emojis, because they may form part of a cluster of codepoints that render as an emoji.
fn contains_emoji(string: &str) -> bool {
    // Break the string into grapheme clusters, which appear to users as single characters.
    let graphemes = string.graphemes(true);
    // Check whether any of these clusters are emojis.
    graphemes
        .into_iter()
        .any(|g: &str| emojis::get(g).is_some())
}

impl Display for OneEmojiPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OneEmojiPolicy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validate_valid() {
        let candidate = "password123😀";
        let result = OneEmojiPolicy.validate(candidate);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_no_emoji() {
        let candidate = "password123";
        let result = OneEmojiPolicy.validate(candidate);
        let expected = Err(OneEmojiPolicyError::NoEmoji);
        assert_eq!(
            result, expected,
            "expected candidate '{}' to be invalid, but was ok",
            candidate
        );
    }

    #[test]
    fn test_validate_ascii_policy_violation() {
        let candidate = "short";
        let result = OneEmojiPolicy.validate(candidate);
        let expected = Err(OneEmojiPolicyError::AsciiPolicyViolation(
            AsciiCharacterPolicy.validate(candidate).err().unwrap(),
        ));
        assert_eq!(
            result, expected,
            "expected error {:?}, but got {:?}",
            expected, result
        );
    }

    #[test]
    fn test_display() {
        let display = format!("{}", OneEmojiPolicy);
        let expected = "OneEmojiPolicy";
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
