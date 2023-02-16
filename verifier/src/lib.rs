// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

use std::fmt::{Debug, Formatter};

type Result<T> = std::result::Result<T, VerificationError>;

#[derive(Debug, Eq, PartialEq)]
/// Failed to verify: {0}.
pub struct VerificationError(String);

impl<S: Into<String>> From<S> for VerificationError {
    fn from(message: S) -> Self {
        Self(message.into())
    }
}

/// A verification step. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait VerificationStep {
    /// Performs a verification operation for the [`VerificationStep`].
    ///
    /// When verification fails the [`VerificationError`] should contain a
    /// message communicating the cause of the failure.
    fn verify(&self) -> Result<()>;
}

impl Debug for dyn VerificationStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationStep").finish()
    }
}

/// Will perform a logical and operation for the [`VerificationStep::verify()`]
/// operation.
///
/// This is will be a short circuiting operation. If the `left` side fails
/// the `right` side will *not* be exercised.
#[derive(Debug)]
pub struct And<L, R> {
    left: L,
    right: R,
}

impl<L: VerificationStep, R: VerificationStep> And<L, R> {
    /// Create a new [`And`] instance
    ///
    /// # Arguments:
    /// * `left` - The left, or first, [`VerificationStep`] to perform. If this
    ///    fails the `right` will not be attempted.
    /// * `right` - The right, or second, [`VerificationStep`] to perform.
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }

    /// The left side of this logical and instance.
    pub fn left(&self) -> &L {
        &self.left
    }

    /// The right side of this logical and instance.
    pub fn right(&self) -> &R {
        &self.right
    }
}

impl<L: VerificationStep, R: VerificationStep> VerificationStep for And<L, R> {
    fn verify(&self) -> Result<()> {
        self.left.verify()?;
        self.right.verify()
    }
}

/// Will perform a logical or operation for the [`VerificationStep::verify()`]
/// operation.
///
/// This is will be a short circuiting operation. If the `left` side succeeds
/// the `right` side will *not* be exercised.
#[derive(Debug)]
pub struct Or<L, R> {
    left: L,
    right: R,
}

impl<L: VerificationStep, R: VerificationStep> Or<L, R> {
    /// Create a new [`Or`] instance
    ///
    /// # Arguments:
    /// * `left` - The left, or first, [`VerificationStep`] to perform. If this
    ///    succeeds the `right` will not be attempted.
    /// * `right` - The right, or second, [`VerificationStep`] to perform.
    pub fn new(left: L, right: R) -> Self {
        Self { left, right }
    }

    /// The left side of this logical or instance.
    pub fn left(&self) -> &L {
        &self.left
    }

    /// The right side of this logical or instance.
    pub fn right(&self) -> &R {
        &self.right
    }
}

impl<L: VerificationStep, R: VerificationStep> VerificationStep for Or<L, R> {
    fn verify(&self) -> Result<()> {
        self.left.verify().or_else(|_| self.right.verify())
    }
}

/// Will always succeed for the [`VerificationStep::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysTrue;

impl VerificationStep for AlwaysTrue {
    fn verify(&self) -> Result<()> {
        Ok(())
    }
}

/// Will always fail for the [`VerificationStep::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysFalse;

impl VerificationStep for AlwaysFalse {
    fn verify(&self) -> Result<()> {
        Err(VerificationError::from("AlwaysFalse"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    pub struct Node {
        pub succeed: bool,
        pub message: String,
        pub verified_called: Cell<bool>,
    }

    impl Node {
        pub fn new(succeed: bool, message: impl Into<String>) -> Self {
            Self {
                succeed,
                message: message.into(),
                verified_called: Cell::new(false),
            }
        }
    }

    impl VerificationStep for Node {
        fn verify(&self) -> Result<()> {
            self.verified_called.replace(true);
            if self.succeed {
                Ok(())
            } else {
                Err(VerificationError::from(self.message.clone()))
            }
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        assert_eq!(and.verify(), Ok(()));
    }

    #[test]
    fn and_short_circuits() {
        let and = And::new(Node::new(false, "First"), Node::new(true, "Second"));
        assert_eq!(and.verify(), Err(VerificationError::from("First")));
        assert!(!and.right().verified_called.get());
    }

    #[test]
    fn and_fails_on_tail() {
        let and = And::new(Node::new(true, "First"), Node::new(false, "Second"));
        assert_eq!(and.verify(), Err(VerificationError::from("Second")));
        assert!(and.left().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        assert_eq!(or.verify(), Err(VerificationError::from("AlwaysFalse")));
    }

    #[test]
    fn or_short_circuits() {
        let or = Or::new(Node::new(true, "First"), Node::new(false, "Second"));
        assert_eq!(or.verify(), Ok(()));
        assert!(!or.right().verified_called.get());
    }

    #[test]
    fn or_is_true_when_tail_is_true() {
        let or = Or::new(Node::new(false, "First"), Node::new(true, "Second"));
        assert_eq!(or.verify(), Ok(()));
        assert!(or.left().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(
            And::new(Node::new(true, "First"), Node::new(false, "Second")),
            Node::new(true, "Third"),
        );
        assert_eq!(or.verify(), Ok(()));
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(
            Or::new(Node::new(true, "First"), Node::new(false, "Second")),
            Node::new(true, "Third"),
        );
        assert_eq!(and.verify(), Ok(()));
    }
}
