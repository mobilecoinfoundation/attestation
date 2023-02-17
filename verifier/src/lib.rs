// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

use core::fmt::Debug;

type Result<T> = core::result::Result<T, VerificationError>;

#[derive(Debug, Eq, PartialEq)]
/// Failed to verify.
pub struct VerificationError;

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier: Debug {
    /// Performs a verification operation for the [`Verifier`].
    fn verify(&self) -> Result<()>;
}

/// Will perform a logical and operation for the [`Verifier::verify()`]
/// operation.
///
/// This is will be a long operation. If the `left` side fails
/// the `right` side will *still* be exercised.
#[derive(Debug)]
pub struct And<L, R> {
    left: L,
    right: R,
}

impl<L: Verifier, R: Verifier> And<L, R> {
    /// Create a new [`And`] instance
    ///
    /// # Arguments:
    /// * `left` - The left, or first, [`Verifier`] to perform. If this
    ///    fails the `right` will *still* be attempted.
    /// * `right` - The right, or second, [`Verifier`] to perform.
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

impl<L: Verifier, R: Verifier> Verifier for And<L, R> {
    fn verify(&self) -> Result<()> {
        let result_l = self.left.verify();
        let result_r = self.right.verify();
        match (result_l, result_r) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(e), _) => Err(e),
            (_, Err(e)) => Err(e),
        }
    }
}

/// Will perform a logical or operation for the [`Verifier::verify()`]
/// operation.
///
/// This is will be a long operation. If the `left` side succeeds
/// the `right` side will *still* be exercised.
#[derive(Debug)]
pub struct Or<L, R> {
    left: L,
    right: R,
}

impl<L: Verifier, R: Verifier> Or<L, R> {
    /// Create a new [`Or`] instance
    ///
    /// # Arguments:
    /// * `left` - The left, or first, [`Verifier`] to perform. If this
    ///    succeeds the `right` will *still* be attempted.
    /// * `right` - The right, or second, [`Verifier`] to perform.
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

impl<L: Verifier, R: Verifier> Verifier for Or<L, R> {
    fn verify(&self) -> Result<()> {
        let result_l = self.left.verify();
        let result_r = self.right.verify();
        match (result_l, result_r) {
            (Err(e), Err(_)) => Err(e),
            _ => Ok(()),
        }
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysTrue;

impl Verifier for AlwaysTrue {
    fn verify(&self) -> Result<()> {
        Ok(())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysFalse;

impl Verifier for AlwaysFalse {
    fn verify(&self) -> Result<()> {
        Err(VerificationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[derive(Debug, Eq, PartialEq)]
    pub struct Node {
        pub succeed: bool,
        pub verified_called: Cell<bool>,
    }

    impl Node {
        pub fn new(succeed: bool) -> Self {
            Self {
                succeed,
                verified_called: Cell::new(false),
            }
        }
    }

    impl Verifier for Node {
        fn verify(&self) -> Result<()> {
            self.verified_called.replace(true);
            if self.succeed {
                Ok(())
            } else {
                Err(VerificationError)
            }
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        assert_eq!(and.verify(), Ok(()));
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        assert_eq!(and.verify(), Err(VerificationError));
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        assert_eq!(and.verify(), Err(VerificationError));
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        assert_eq!(or.verify(), Err(VerificationError));
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        assert_eq!(or.verify(), Ok(()));
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        assert_eq!(or.verify(), Ok(()));
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        assert_eq!(or.verify(), Ok(()));
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        assert_eq!(and.verify(), Ok(()));
    }
}
