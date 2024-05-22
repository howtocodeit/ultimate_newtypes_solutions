/*!
    # password_policy

    Provides a trait for validating passwords against business rules, and reexports concrete
    password policies.
*/

pub mod ascii_character_policy;
pub mod one_emoji_policy;

pub use ascii_character_policy::ASCIICharacterPolicy;
pub use one_emoji_policy::OneEmojiPolicy;

/// `PasswordPolicy` represents a set of business rules for determining whether a password is valid.
pub trait PasswordPolicy {
    type Error: std::error::Error;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error>;
}