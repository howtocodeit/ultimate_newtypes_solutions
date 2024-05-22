/*! # Exercise 3
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


use crate::ex3::password_policy::PasswordPolicy;

mod password_policy;

pub struct PasswordSource<P: PasswordPolicy> {
    policy: P
}