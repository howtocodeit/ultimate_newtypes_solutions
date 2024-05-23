/*!
    # password_policy

    Provides a trait for validating passwords against business rules, and reexports concrete
    password policies.
*/

pub use ascii_charset_policy::AsciiCharsetPolicy;
#[cfg(test)]
pub use impossible_policy::ImpossiblePolicy;
#[cfg(test)]
pub use no_op_policy::NoOpPolicy;
pub use one_emoji_policy::OneEmojiPolicy;

pub mod ascii_charset_policy;
pub mod impossible_policy;
pub mod length_policy;
pub mod no_op_policy;
pub mod one_emoji_policy;

/// `PasswordPolicy` represents a set of business rules for determining whether a password is valid.
pub trait PasswordPolicy {
    type Error: std::error::Error;

    fn validate(&self, candidate: &str) -> Result<(), Self::Error>;
}
