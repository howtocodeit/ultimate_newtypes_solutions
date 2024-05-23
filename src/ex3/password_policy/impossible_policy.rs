#![cfg(test)]

/*!
   # impossible_policy

   A test-only module that provides a mock password policy that rejects all candidates.
*/

use std::fmt::Display;

use thiserror::Error;

use crate::ex3::PasswordPolicy;

/// A mock password policy that rejects all candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpossiblePolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unavoidable error")]
pub struct UnavoidableViolationError;

impl PasswordPolicy for ImpossiblePolicy {
    type Error = UnavoidableViolationError;

    fn validate(&self, _candidate: &str) -> Result<(), Self::Error> {
        Err(UnavoidableViolationError)
    }
}

impl Display for ImpossiblePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InsurmountablePolicy")
    }
}
