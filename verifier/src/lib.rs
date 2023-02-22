// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

use core::fmt::Debug;
use subtle::CtOption;

/// A trait for types that can be converted into a [`Result`].
pub trait IntoResult<T, E> {
    /// Convert `self` into a [`Result`]
    fn into_result(self) -> Result<T, E>;
}

/// Convert an `CtOption<T>` which could contain `Some(Error)` into a
/// `Result<(), E>`.
///
/// This is *not* constant time.
impl<T: IntoResult<(), E>, E> IntoResult<(), E> for CtOption<T> {
    fn into_result(self) -> Result<(), E> {
        let option: Option<T> = self.into();
        match option {
            None => Ok(()),
            Some(e) => e.into_result(),
        }
    }
}

/// Failed to verify.
#[derive(Debug, Eq, PartialEq)]
pub struct VerificationError;

impl IntoResult<(), VerificationError> for VerificationError {
    fn into_result(self) -> Result<(), Self> {
        Err(self)
    }
}

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier: Debug {
    /// The error that this verification will return in failure cases.
    type Error;

    /// Performs a verification operation for the [`Verifier`].
    ///
    /// In order to accommodate constant time operations this returns a
    /// [`CtOption`] instead of a [`Result`]. One should use the non constant
    /// time [`IntoResult::into_result()`] on this returned value. To determine
    /// if verification succeeded or not.
    fn verify(&self) -> CtOption<Self::Error>;
}

/// An error that occurs during an `and` operation.
///
/// One should use the [`IntoResult::into_result()`] to determine if this is a
/// failure or not.
#[derive(Debug)]
pub struct AndError<L, R> {
    left: CtOption<L>,
    right: CtOption<R>,
}

impl<L, R> AndError<L, R> {
    /// Create a new instance
    ///
    /// Both the results of `left` and `right` can be `None`. Calling
    /// [`IntoResult::into_result()`] on this instance will determine if this is
    /// a failure or not.
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self { left, right }
    }
}

impl<L, R> IntoResult<(), VerificationError> for AndError<L, R>
where
    L: IntoResult<(), VerificationError>,
    R: IntoResult<(), VerificationError>,
{
    fn into_result(self) -> Result<(), VerificationError> {
        self.left.into_result()?;
        self.right.into_result()
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
        CtOption::new(
            AndError::new(self.left.verify(), self.right.verify()),
            1.into(),
        )
    }
}

/// An error that occurs during an `or` operation.
///
/// One should use the [`IntoResult::into_result()`] to determine if this is a
/// failure or not.
#[derive(Debug)]
pub struct OrError<L, R> {
    left: CtOption<L>,
    right: CtOption<R>,
}

impl<L, R> OrError<L, R> {
    /// Create a new instance
    ///
    /// Both the results of `left` and `right` can be `None`. Calling
    /// [`IntoResult::into_result()`] on this instance will determine if this is
    /// a failure or not.
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self { left, right }
    }
}

impl<L, R> IntoResult<(), VerificationError> for OrError<L, R>
where
    L: IntoResult<(), VerificationError>,
    R: IntoResult<(), VerificationError>,
{
    fn into_result(self) -> Result<(), VerificationError> {
        let left = self.left.into_result();
        let right = self.right.into_result();
        match (left, right) {
            (Err(_), Err(_)) => Err(VerificationError),
            _ => Ok(()),
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
        CtOption::new(
            OrError::new(self.left.verify(), self.right.verify()),
            1.into(),
        )
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysTrue;

impl Verifier for AlwaysTrue {
    type Error = VerificationError;
    fn verify(&self) -> CtOption<Self::Error> {
        CtOption::new(VerificationError, 0.into())
    }
}

impl IntoResult<(), VerificationError> for AlwaysTrue {
    fn into_result(self) -> Result<(), VerificationError> {
        Ok(())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Debug, Eq, PartialEq)]
pub struct AlwaysFalse;

impl Verifier for AlwaysFalse {
    type Error = VerificationError;
    fn verify(&self) -> CtOption<Self::Error> {
        CtOption::new(VerificationError, 1.into())
    }
}

impl IntoResult<(), VerificationError> for AlwaysFalse {
    fn into_result(self) -> Result<(), VerificationError> {
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
        type Error = VerificationError;
        fn verify(&self) -> CtOption<Self::Error> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 0 } else { 1 };
            CtOption::new(VerificationError, succeed.into())
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        let verification = and.verify();
        assert_eq!(verification.into_result(), Ok(()));
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        let verification = and.verify();
        assert_eq!(verification.into_result(), Err(VerificationError));
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        let verification = and.verify();
        assert_eq!(verification.into_result(), Err(VerificationError));
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        let verification = or.verify();
        assert_eq!(verification.into_result(), Err(VerificationError));
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        let verification = or.verify();
        assert_eq!(verification.into_result(), Ok(()));
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        let verification = or.verify();
        assert_eq!(verification.into_result(), Ok(()));
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = or.verify();
        assert_eq!(verification.into_result(), Ok(()));
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify();
        assert_eq!(verification.into_result(), Ok(()));
    }
}
