/*!
    # Exercise 3

   Company password policies change over time! Redesign `Password` so that future changes to the
   password policy won't require changes to the `Password` type.

   For example, the password policy in question 1 is that all passwords must be at least 8 ASCII
   characters long. A product manager has now had the great idea that all passwords must contain at
   least one emoji. 🙃

   This means ensuring that new passwords comply with the emoji policy, but also that existing
   passwords continue to be valid according to the old policy, or your users will be locked out!

   The Password newtype is maintainable to the extent that we can implement any new password policy
   without changing how the Password type works. That is, we must decouple the representation of
   the password from the implementation detail of the password policy.

   This will require some Rust that I haven't demonstrated in this article, so don't be afraid to
   think outside the box.
*/

use argon2::password_hash::{rand_core, SaltString};
use argon2::{password_hash, Argon2, PasswordHasher, PasswordVerifier};
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

use crate::ex2::PasswordVerificationError;
pub use password_policy::PasswordPolicy;

pub mod password_policy;

/// A hashed password.
#[derive(Clone, PartialEq, Eq)]
pub struct Password {
    hash: String,
}

// Note the absence of an associated constructor. Creation of `Password`s is now handled by
// `PasswordBuilder`, which decouples the password policy from the `Password` type.
//
// However, this implementation is still tightly coupled to the Argon2id hashing algorithm. If you
// had an unusual use case that called for multiple hashing algorithms, this could also be injected
// as a `PasswordBuilder` dependency. Otherwise, avoid the complexity.
impl Password {
    /// Creates a new `Password` instance with the given `hash`, bypassing validation and hashing.
    ///
    /// # Invariants
    /// The caller must ensure that `hash` is a valid Argon2id password hash.
    pub unsafe fn new_unchecked(hash: String) -> Self {
        Self { hash }
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
            unreachable!(
                "failed to instantiate `argon2::PasswordHash` from `Password.hash`: {:?}",
                e
            )
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

#[cfg(test)]
mod password_tests {
    use super::*;
    use crate::ex3::password_policy::no_op_policy::NoOpPolicy;
    use std::sync::OnceLock;

    #[test]
    fn test_new_unchecked() {
        let hash = "hash".to_string();
        let password = unsafe { Password::new_unchecked(hash.clone()) };
        assert_eq!(
            password.hash, hash,
            "expected hash to be '{}', but got '{}'",
            hash, password.hash
        );
    }

    #[test]
    fn test_debug() {
        let password = Password {
            hash: "hash".to_string(),
        };
        let debug = format!("{:?}", password);
        let expected = "Password { hash: \"REDACTED\" }";
        assert_eq!(
            debug, expected,
            "expected debug output to redact hash, but got '{}'",
            debug
        );
    }

    #[test]
    fn test_display() {
        let password = Password {
            hash: "hash".to_string(),
        };
        let display = format!("{}", password);
        let expected = "PASSWORD_REDACTED";
        assert_eq!(
            display, expected,
            "expected display output to redact hash, but got '{}'",
            display
        );
    }

    #[test]
    fn test_as_ref() {
        let password = Password {
            hash: "hash".to_string(),
        };
        let as_ref = password.as_ref();
        let expected = &password.hash;
        assert_eq!(as_ref, expected);
    }

    #[test]
    fn test_as_bytes() {
        let password = Password {
            hash: "hash".to_string(),
        };
        let as_bytes = password.as_bytes();
        let expected = password.hash.as_bytes();
        assert_eq!(as_bytes, expected);
    }

    // A convenience function to simplifiy `PasswordBuilder` access in tests where validation is
    // unimportant.
    fn password_builder() -> &'static PasswordBuilder<NoOpPolicy> {
        static BUILDER: OnceLock<PasswordBuilder<NoOpPolicy>> = OnceLock::new();
        BUILDER.get_or_init(|| PasswordBuilder::new(NoOpPolicy))
    }

    #[test]
    fn test_verify_candidate_match() {
        let candidate = "password123";
        let password = password_builder().new_password(candidate).unwrap();
        let result = password.verify_candidate(candidate);
        assert!(
            result.is_ok(),
            "expected candidate to match password, but got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_candidate_no_match() {
        let password = password_builder().new_password("password123").unwrap();
        let candidate = "wrongpassword";
        let result = password.verify_candidate(candidate);
        assert!(
            result.is_err(),
            "expected candidate '{}' not to match password",
            candidate
        );
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

/// Builds [Password] instances according to the injected [PasswordPolicy].
///
/// # Examples
/// ```
/// use ultimate_newtypes_solutions::ex3::{password_policy, PasswordBuilder};
///
/// let policy = password_policy::AsciiCharacterPolicy;
/// let password_builder = PasswordBuilder::new(policy);
/// let candidate = "password123";
/// let password = password_builder.new_password(candidate).unwrap();
/// ```
///
/// In a real application, the `PasswordBuilder` instance would be injected into a struct with an
/// effectively static lifetime (such as an HTTP handler), and reused for multiple password
/// creations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordBuilder<P: PasswordPolicy> {
    policy: P,
}

/// Error type for [Password] construction failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PasswordError<P: PasswordPolicy> {
    #[error(transparent)]
    PolicyViolation(P::Error), // thiserror doesn't support derivation of `From` for generic errors

    // Unreachable in practice, since password validations should prevent pathological inputs to
    // Argon2id. However, this could be tested by injecting the hashing algorithm as a
    // `PasswordBuilder` dependency.
    #[error(transparent)]
    Unhashable(#[from] password_hash::Error),
}

impl<P: PasswordPolicy> PasswordBuilder<P> {
    pub fn new(policy: P) -> Self {
        Self { policy }
    }

    pub fn new_password(&self, candidate: &str) -> Result<Password, PasswordError<P>> {
        self.policy
            .validate(candidate)
            .map_err(|e| PasswordError::PolicyViolation(e))?;
        let hash = hash_password_candidate(candidate)?;
        Ok(Password { hash })
    }
}

impl<P: PasswordPolicy + Display> Display for PasswordBuilder<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PasswordBuilder<{}>", self.policy)
    }
}

/// Hash a password candidate using the Argon2id algorithm.
// If you expected the password hashing algorithm to change alongside the password policy, or
// needed to support multiple hashing algorithms, you could also inject the hashing algorithm as a
// dependency. This is pretty unlikely unless you're running a security platform, though, so I've
// kept things simple.
fn hash_password_candidate(candidate: &str) -> Result<String, password_hash::Error> {
    // Note: `OsRng` only implements `CryptoRngCore` if the `std` feature of `argon2` is enabled.
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(candidate.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod password_builder_tests {
    use super::*;
    use crate::ex3::password_policy::insurmountable_policy::{
        InsurmountablePolicy, UnavoidableError,
    };
    use crate::ex3::password_policy::no_op_policy::NoOpPolicy;

    #[test]
    fn test_valid_password() {
        let builder = PasswordBuilder::new(NoOpPolicy);
        let candidate = "password123";
        let result = builder.new_password(candidate);
        assert!(
            result.is_ok(),
            "expected candidate '{}' to be valid, but got {:?}",
            candidate,
            result
        );

        let password = result.unwrap();
        let verification = password.verify_candidate(candidate);
        assert!(
            verification.is_ok(),
            "expected password to match candidate '{}', but got {:?}",
            candidate,
            verification
        );
    }

    #[test]
    fn test_invalid_password() {
        let builder = PasswordBuilder::new(InsurmountablePolicy);
        let candidate = "password123";
        let result = builder.new_password(candidate);
        let expected: Result<_, PasswordError<InsurmountablePolicy>> =
            Err(PasswordError::PolicyViolation(UnavoidableError));
        assert_eq!(
            result, expected,
            "expected candidate '{}' to be invalid, but got {:?}",
            candidate, result
        );
    }

    #[test]
    fn test_display() {
        let builder = PasswordBuilder::new(NoOpPolicy);
        let display = format!("{}", builder);
        let expected = "PasswordBuilder<NoOpPolicy>";
        assert_eq!(
            display, expected,
            "expected display output to be '{}', but got '{}'",
            expected, display
        );
    }
}
