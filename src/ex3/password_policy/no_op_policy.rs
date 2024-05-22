#![cfg(test)]

/*!
   # no_op_policy

   A test-only module that provides a mock password policy that accepts all candidates.
*/

use crate::ex3::PasswordPolicy;
use std::convert::Infallible;
use std::fmt::Display;

/// A mock password policy that accepts all candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoOpPolicy;

impl PasswordPolicy for NoOpPolicy {
    type Error = Infallible;

    fn validate(&self, _candidate: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Display for NoOpPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoOpPolicy")
    }
}
