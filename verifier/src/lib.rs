// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
mod struct_name;

pub use report_body::{
    AttributesVerifier, ConfigIdVerifier, ConfigSvnVerifier, CpuSvnVerifier,
    ExtendedProductIdVerifier, FamilyIdVerifier, IsvProductIdVerifier, IsvSvnVerifier,
    MiscellaneousSelectVerifier, MrEnclaveVerifier, MrSignerVerifier, ReportDataVerifier,
};

use core::fmt::{Debug, Display, Formatter};
use subtle::Choice;

/// Number of spaces to indent nested messages.
const MESSAGE_INDENT: usize = 2;

/// Success checkbox indicator
const SUCCESS_MESSAGE_INDICATOR: &str = "- [x]";

/// Failure checkbox indicator
const FAILURE_MESSAGE_INDICATOR: &str = "- [ ]";

/// The result of a [`Verifier::verify`] method.
///
/// This is a constant time [`Result`] like structure.
///
/// The [`Display`] implementation is *not* constant time.
#[derive(Debug, Clone)]
pub struct VerificationResult<T> {
    // The expected and actual values that were used in the verification
    values: T,
    // A `true` [`Choice`] if the verification step was successful.
    is_ok: Choice,
}

impl<T: VerificationMessage> VerificationResult<T> {
    /// Create a new [`VerificationResult`].
    pub fn new(values: T, is_ok: Choice) -> Self {
        Self { values, is_ok }
    }

    /// Returns a `true` [`Choice`] if the verification step was successful.
    pub fn is_ok(&self) -> Choice {
        self.is_ok
    }

    /// Returns a `false` [`Choice`] if the verification step did not succeed.
    pub fn is_err(&self) -> Choice {
        !self.is_ok
    }

    /// Format the instance with preceding padding
    ///
    /// The `pad` is the number of spaces to precede each line of the displayed
    /// representation with.
    pub fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        if self.is_ok.into() {
            self.values.fmt_success(f, pad)?;
        } else {
            self.values.fmt_failure(f, pad)?;
        }
        Ok(())
    }
}

impl<T: VerificationMessage> Display for VerificationResult<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.fmt_padded(f, 0)
    }
}

/// A message that can be used in [`VerificationResult`]'s [`Display`]
/// implementation.
pub trait VerificationMessage {
    /// Formatting of a successful verification with this message type
    ///
    /// The `pad` is the number of spaces to precede each line of the message
    /// with.
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result;

    /// Formatting of a failure verification with this message type
    ///
    /// The `pad` is the number of spaces to precede each line of the message
    /// with.
    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result;
}

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier<T>: Debug {
    /// The values that were used in this verification
    type VerificationValues: VerificationMessage;

    /// Performs a verification operation on `evidence`.
    fn verify(&self, evidence: &T) -> VerificationResult<Self::VerificationValues>;

    /// Or this verifier with another.
    fn or<U, V: Verifier<U>>(self, other: V) -> Or<Self, V>
    where
        Self: Sized,
    {
        Or::new(self, other)
    }

    /// And this verifier with another.
    fn and<U, V: Verifier<U>>(self, other: V) -> And<Self, V>
    where
        Self: Sized,
    {
        And::new(self, other)
    }
}

/// The values used during an `and` verification operation.
#[derive(Debug, Clone)]
pub struct AndVerificationValues<L, R> {
    left: VerificationResult<L>,
    right: VerificationResult<R>,
}

impl<L, R> AndVerificationValues<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationResult<L>, right: VerificationResult<R>) -> Self {
        Self { left, right }
    }
}

impl<L: VerificationMessage, R: VerificationMessage> VerificationMessage
    for AndVerificationValues<L, R>
{
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        writeln!(f, "{:pad$}{status} Both of the following are true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        self.left.fmt_padded(f, pad)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad)
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        writeln!(f, "{:pad$}{status} Both of the following must be true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        self.left.fmt_padded(f, pad)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad)
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

impl<T, L: Verifier<T>, R: Verifier<T>> Verifier<T> for And<L, R> {
    type VerificationValues = AndVerificationValues<L::VerificationValues, R::VerificationValues>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::VerificationValues> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_ok = left_err.is_ok() & right_err.is_ok();
        VerificationResult::new(AndVerificationValues::new(left_err, right_err), is_ok)
    }
}

/// The values used during an `or` verification operation.
#[derive(Debug, Clone)]
pub struct OrVerificationValues<L, R> {
    left: VerificationResult<L>,
    right: VerificationResult<R>,
}

impl<L, R> OrVerificationValues<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationResult<L>, right: VerificationResult<R>) -> Self {
        Self { left, right }
    }
}

impl<L: VerificationMessage, R: VerificationMessage> VerificationMessage
    for OrVerificationValues<L, R>
{
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        writeln!(f, "{:pad$}{status} One of the following was true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        self.left.fmt_padded(f, pad)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad)
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        writeln!(f, "{:pad$}{status} One of the following must be true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        self.left.fmt_padded(f, pad)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad)
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

impl<T, L: Verifier<T>, R: Verifier<T>> Verifier<T> for Or<L, R> {
    type VerificationValues = OrVerificationValues<L::VerificationValues, R::VerificationValues>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::VerificationValues> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_ok = left_err.is_ok() | right_err.is_ok();
        VerificationResult::new(OrVerificationValues::new(left_err, right_err), is_ok)
    }
}

/// The values used during an `not` verification operation.
#[derive(Debug, Clone)]
pub struct NotValues<T> {
    // The [`VerificationResult`] that was negated by the [`Not`] operation.
    inner: VerificationResult<T>,
}

impl<T> NotValues<T> {
    /// Create a new instance
    pub fn new(inner: VerificationResult<T>) -> Self {
        Self { inner }
    }
}

impl<T: VerificationMessage> VerificationMessage for NotValues<T> {
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        writeln!(
            f,
            "{:pad$}{status} Inverted expectation of the following:",
            ""
        )?;
        self.inner.fmt_padded(f, pad + MESSAGE_INDENT)
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        writeln!(
            f,
            "{:pad$}{status} Inverted expectation of the following:",
            ""
        )?;
        self.inner.fmt_padded(f, pad + MESSAGE_INDENT)
    }
}

/// Will negate the result of the [`Verifier::verify()`] operation.
#[derive(Debug)]
pub struct Not<V> {
    verifier: V,
}

impl<V> Not<V> {
    /// Create a new [`Not`] instance
    pub fn new(verifier: V) -> Self {
        Self { verifier }
    }
}

impl<T, V: Verifier<T>> Verifier<T> for Not<V> {
    type VerificationValues = NotValues<V::VerificationValues>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::VerificationValues> {
        let original = self.verifier.verify(evidence);
        let is_ok = original.is_ok();
        VerificationResult::new(NotValues::new(original), !is_ok)
    }
}

/// Placeholder values for an [`AlwaysTrue`] verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrueVerificationValues;

impl VerificationMessage for AlwaysTrueVerificationValues {
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} Forced success via `AlwaysTrue`", "")
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} `AlwaysTrue` shouldn't fail", "")
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrue;

impl<T> Verifier<T> for AlwaysTrue {
    type VerificationValues = AlwaysTrueVerificationValues;
    fn verify(&self, _evidence: &T) -> VerificationResult<Self::VerificationValues> {
        VerificationResult::new(AlwaysTrueVerificationValues, 1.into())
    }
}

/// Placeholder values for an [`AlwaysFalse`] verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalseVerificationValues;

impl VerificationMessage for AlwaysFalseVerificationValues {
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} `AlwaysFalse` shouldn't succeed", "")
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} Forced failure via `AlwaysFalse`", "")
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalse;

impl<T> Verifier<T> for AlwaysFalse {
    type VerificationValues = AlwaysFalseVerificationValues;
    fn verify(&self, _evidence: &T) -> VerificationResult<Self::VerificationValues> {
        VerificationResult::new(AlwaysFalseVerificationValues, 0.into())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::report_body::{IsvSvnVerificationValues, MiscellaneousSelectVerificationValues};
    use alloc::format;
    use core::cell::Cell;

    // The `And` and `Or` logic tests below don't care about the evidence, but
    // they need to be provided something.
    const NO_EVIDENCE: &Option<usize> = &None;

    /// Data to be used in [`Node`] verification output.
    pub struct NodeVerificationValues;

    impl VerificationMessage for NodeVerificationValues {
        fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
            let status = SUCCESS_MESSAGE_INDICATOR;
            write!(f, "{:pad$}{status} the generic test node succeeded", "")
        }

        fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
            let status = FAILURE_MESSAGE_INDICATOR;
            write!(f, "{:pad$}{status} the generic test node failed", "")
        }
    }

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

    impl<T> Verifier<T> for Node {
        type VerificationValues = NodeVerificationValues;
        fn verify(&self, _evidence: &T) -> VerificationResult<Self::VerificationValues> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 1 } else { 0 };
            VerificationResult::new(NodeVerificationValues, succeed.into())
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_err().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_err().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_err().unwrap_u8(), 1);
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn display_of_successful_option() {
        let success = VerificationResult::new(
            IsvSvnVerificationValues {
                expected: 3.into(),
                actual: 3.into(),
            },
            1.into(),
        );
        assert_eq!(
            format!("{success}"),
            "- [x] The provided ISV SVN: IsvSvn(3)"
        );
    }

    #[test]
    fn display_of_fail_option() {
        let failure = VerificationResult::new(
            IsvSvnVerificationValues {
                expected: 3.into(),
                actual: 2.into(),
            },
            0.into(),
        );
        assert_eq!(
            format!("{failure}"),
            "- [ ] The ISV SVN value of IsvSvn(2) is less than the expected value of IsvSvn(3)"
        );
    }

    #[test]
    fn display_of_success_for_and_failure() {
        let success = VerificationResult::new(
            AndVerificationValues::new(
                VerificationResult::new(AlwaysTrueVerificationValues, 1.into()),
                VerificationResult::new(
                    MiscellaneousSelectVerificationValues {
                        expected: 3.into(),
                        actual: 3.into(),
                    },
                    1.into(),
                ),
            ),
            1.into(),
        );
        let expected = r#"
            - [x] Both of the following are true:
              - [x] Forced success via `AlwaysTrue`
              - [x] The provided miscellaneous select: MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{success}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_and_failure() {
        let failure = VerificationResult::new(
            AndVerificationValues::new(
                VerificationResult::new(AlwaysTrueVerificationValues, 1.into()),
                VerificationResult::new(
                    MiscellaneousSelectVerificationValues {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    0.into(),
                ),
            ),
            0.into(),
        );
        let expected = r#"
            - [ ] Both of the following must be true:
              - [x] Forced success via `AlwaysTrue`
              - [ ] The miscellaneous select did not match, expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{failure}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_or_with_and_failure() {
        let failure = VerificationResult::new(
            OrVerificationValues::new(
                VerificationResult::new(
                    AndVerificationValues::new(
                        VerificationResult::new(AlwaysTrueVerificationValues, 1.into()),
                        VerificationResult::new(
                            IsvSvnVerificationValues {
                                expected: 3.into(),
                                actual: 1.into(),
                            },
                            0.into(),
                        ),
                    ),
                    0.into(),
                ),
                VerificationResult::new(
                    MiscellaneousSelectVerificationValues {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    0.into(),
                ),
            ),
            0.into(),
        );
        let expected = r#"
            - [ ] One of the following must be true:
              - [ ] Both of the following must be true:
                - [x] Forced success via `AlwaysTrue`
                - [ ] The ISV SVN value of IsvSvn(1) is less than the expected value of IsvSvn(3)
              - [ ] The miscellaneous select did not match, expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{failure}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_always_false_option() {
        let failure = AlwaysFalse.verify(NO_EVIDENCE);
        assert_eq!(
            format!("{failure}"),
            "- [ ] Forced failure via `AlwaysFalse`"
        );
    }

    #[test]
    fn not_negates_success() {
        let not = Not::new(AlwaysTrue);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_err().unwrap_u8(), 1);
        let expected = r#"
            - [ ] Inverted expectation of the following:
              - [x] Forced success via `AlwaysTrue`"#;
        assert_eq!(format!("\n{verification}"), textwrap::dedent(expected));
    }

    #[test]
    fn not_negates_failure() {
        let not = Not::new(AlwaysFalse);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_ok().unwrap_u8(), 1);
        let expected = r#"
            - [x] Inverted expectation of the following:
              - [ ] Forced failure via `AlwaysFalse`"#;
        assert_eq!(format!("\n{verification}"), textwrap::dedent(expected));
    }
}
