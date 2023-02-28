// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
pub use report_body::{AttributesVerifier, ReportBodyVerifier};

use core::fmt::Debug;
use mc_sgx_core_types::{Attributes, ConfigId};
use subtle::CtOption;

/// Failed to verify.
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// A general error.
    General,
    /// The attributes did not match expected:{expected} actual:{actual}
    AttributeMismatch {
        /// The expected attributes
        expected: Attributes,
        /// The actual attributes that were present
        actual: Attributes,
    },
    /// The config id did not match expected:{expected} actual:{actual}
    ConfigIdMismatch {
        /// The expected attributes
        expected: ConfigId,
        /// The actual attributes that were present
        actual: ConfigId,
    },
}

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier: Debug {
    /// The error that this verification will return in failure cases.
    type Error;

    /// Performs a verification operation for the [`Verifier`].
    ///
    /// In order to accommodate constant time operations this returns a
    /// [`CtOption`] instead of a [`Result`].
    fn verify(&self) -> CtOption<Self::Error>;
}

/// An error that occurs during an `and` operation.
#[derive(Debug)]
pub struct AndError<L, R> {
    _left: CtOption<L>,
    _right: CtOption<R>,
}

impl<L, R> AndError<L, R> {
    /// Create a new instance
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self {
            _left: left,
            _right: right,
        }
    }
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

impl<L, R> And<L, R> {
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
    type Error = AndError<L::Error, R::Error>;
    fn verify(&self) -> CtOption<Self::Error> {
        let left_err = self.left.verify();
        let right_err = self.right.verify();
        let is_some = left_err.is_some() | right_err.is_some();
        CtOption::new(AndError::new(left_err, right_err), is_some)
    }
}

/// An error that occurs during an `or` operation.
#[derive(Debug)]
pub struct OrError<L, R> {
    _left: CtOption<L>,
    _right: CtOption<R>,
}

impl<L, R> OrError<L, R> {
    /// Create a new instance
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self {
            _left: left,
            _right: right,
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

impl<L, R> Or<L, R> {
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
    type Error = OrError<L::Error, R::Error>;
    fn verify(&self) -> CtOption<Self::Error> {
        let left_err = self.left.verify();
        let right_err = self.right.verify();
        let is_some = left_err.is_some() & right_err.is_some();
        CtOption::new(OrError::new(left_err, right_err), is_some)
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysTrue;

impl Verifier for AlwaysTrue {
    type Error = VerificationError;
    fn verify(&self) -> CtOption<Self::Error> {
        CtOption::new(VerificationError::General, 0.into())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysFalse;

impl Verifier for AlwaysFalse {
    type Error = VerificationError;
    fn verify(&self) -> CtOption<Self::Error> {
        CtOption::new(VerificationError::General, 1.into())
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
        type Error = VerificationError;
        fn verify(&self) -> CtOption<Self::Error> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 0 } else { 1 };
            CtOption::new(VerificationError::General, succeed.into())
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        let verification = and.verify();
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        let verification = and.verify();
        assert_eq!(verification.is_some().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        let verification = and.verify();
        assert_eq!(verification.is_some().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        let verification = or.verify();
        assert_eq!(verification.is_some().unwrap_u8(), 1);
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        let verification = or.verify();
        assert_eq!(verification.is_none().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        let verification = or.verify();
        assert_eq!(verification.is_none().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = or.verify();
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify();
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }
}
