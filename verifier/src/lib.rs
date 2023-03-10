// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
pub use report_body::{
    AttributesVerifier, ConfigIdVerifier, ConfigSvnVerifier, CpuSvnVerifier,
    ExtendedProductIdVerifier, FamilyIdVerifier, IsvProductIdVerifier, IsvSvnVerifier,
    MiscellaneousSelectVerifier, MrEnclaveVerifier, MrSignerVerifier, ReportDataVerifier,
};

use core::fmt::{Debug, Display, Formatter};
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportData,
};
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
    metadata: T,
    is_ok: Choice,
}

impl<T: ResultMessage> VerificationResult<T> {
    /// Create a new [`VerificationResult`].
    pub fn new(metadata: T, is_ok: Choice) -> Self {
        Self { metadata, is_ok }
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
            self.metadata.fmt_success(f, pad)?;
        } else {
            self.metadata.fmt_failure(f, pad)?;
        }
        Ok(())
    }
}

impl<T: ResultMessage> Display for VerificationResult<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.fmt_padded(f, 0)
    }
}

/// A message that can be used in [`VerificationResult`]'s [`Display`]
/// implementation.
pub trait ResultMessage {
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

/// Failed to verify.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum VerificationResultMetadata {
    /// Generic no extra info.
    General,
    /// Forced failure via `AlwaysFalse`
    AlwaysFalse,
    /// [`Attributes`] verification data
    Attributes {
        /// The expected attributes
        expected: Attributes,
        /// The actual attributes that were present
        actual: Attributes,
    },
    /// [`ConfigId`] verification data
    ConfigId {
        /// The expected config id
        expected: ConfigId,
        /// The actual config id that was present
        actual: ConfigId,
    },
    /// [`ConfigSvn`] verification data
    ConfigSvn {
        /// The minimum SVN
        expected: ConfigSvn,
        /// The actual SVN that was present
        actual: ConfigSvn,
    },
    /// [`CpuSvn`] verification data
    CpuSvn {
        /// The minimum SVN
        expected: CpuSvn,
        /// The actual SVN that was present
        actual: CpuSvn,
    },
    /// [`ExtendedProductId`] verification data
    ExtendedProductId {
        /// The expected extended product ID
        expected: ExtendedProductId,
        /// The actual extended product ID that was present
        actual: ExtendedProductId,
    },
    /// [`FamilyId`] verification data
    FamilyId {
        /// The expected family ID
        expected: FamilyId,
        /// The actual family ID that was present
        actual: FamilyId,
    },
    /// [`IsvProductId`] verification data
    IsvProductId {
        /// The expected product ID
        expected: IsvProductId,
        /// The actual product ID that was present
        actual: IsvProductId,
    },
    /// [`IsvSvn`] verification data
    IsvSvn {
        /// The minimum SVN
        expected: IsvSvn,
        /// The actual SVN that was present
        actual: IsvSvn,
    },
    /// [`MiscellaneousSelect`] verification data
    MiscellaneousSelect {
        /// The expected selection
        expected: MiscellaneousSelect,
        /// The actual selections that were present
        actual: MiscellaneousSelect,
    },
    /// [`MrEnclave`] verification data
    MrEnclave {
        /// The expected measurement
        expected: MrEnclave,
        /// The actual measurement that was present
        actual: MrEnclave,
    },
    /// [`MrSigner`] verification data
    MrSignerKey {
        /// The expected key
        expected: MrSigner,
        /// The actual key that was present
        actual: MrSigner,
    },
    /// [`ReportData`] verification data
    ReportData {
        /// The expected report data
        expected: ReportData,
        /// The actual report data that was present
        actual: ReportData,
        /// Mask of which bytes were expected to match
        mask: ReportData,
    },
}

impl ResultMessage for VerificationResultMetadata {
    fn fmt_success(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        match self {
            Self::General => write!(f, "{:pad$}{status} Success", "")?,
            Self::AlwaysFalse => write!(f, "{:pad$}{status} How did you get here", "")?,
            Self::Attributes {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The attributes were {actual:?}", "")?,
            Self::ConfigId {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The config ID was {actual:?}", "")?,
            Self::ConfigSvn {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The config SVN was {actual:?}", "")?,
            Self::CpuSvn {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The CPU SVN was {actual:?}", "")?,
            Self::ExtendedProductId {
                expected: _,
                actual,
            } => write!(
                f,
                "{:pad$}{status} The extended product ID was {actual:?}",
                ""
            )?,
            Self::FamilyId {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The family ID was {actual:?}", "")?,
            Self::IsvProductId {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The ISV product ID was {actual:?}", "")?,
            Self::IsvSvn {
                expected: _,
                actual,
            } => write!(f, "{:pad$}{status} The ISV SVN was {actual:?}", "")?,
            Self::MiscellaneousSelect {
                expected: _,
                actual,
            } => write!(
                f,
                "{:pad$}{status} The miscellaneous select was {actual:?}",
                ""
            )?,
            Self::MrEnclave {
                expected: _,
                actual,
            } => write!(
                f,
                "{:pad$}{status} The MRENCLAVE measurement was {actual:?}",
                ""
            )?,
            Self::MrSignerKey {
                expected: _,
                actual,
            } => write!(
                f,
                "{:pad$}{status} The MRSIGNER key hash was {actual:?}",
                ""
            )?,
            Self::ReportData {
                expected: _,
                actual,
                mask: _,
            } => write!(f, "{:pad$}{status} The report data was {actual:?}", "")?,
        }
        Ok(())
    }

    fn fmt_failure(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        match self {
            Self::General => write!(f, "{:pad$}{status} A general failure", "")?,
            Self::AlwaysFalse => write!(f, "{:pad$}{status} Forced failure via `AlwaysFalse`", "")?,
            Self::Attributes {expected, actual} => write!(f, "{:pad$}{status} The attributes did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::ConfigId {expected, actual} => write!(f, "{:pad$}{status} The config ID did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::ConfigSvn {expected, actual} => write!(f, "{:pad$}{status} The config SVN value of {actual:?} is less than the expected value of {expected:?}", "")?,
            Self::CpuSvn {expected, actual} => write!(f, "{:pad$}{status} The CPU SVN value of {actual:?} is less than the expected value of {expected:?}", "")?,
            Self::ExtendedProductId {expected, actual} => write!(f, "{:pad$}{status} The extended product ID did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::FamilyId {expected, actual} => write!(f, "{:pad$}{status} The family ID did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::IsvProductId {expected, actual} => write!(f, "{:pad$}{status} The ISV product ID did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::IsvSvn {expected, actual} => write!(f, "{:pad$}{status} The ISV SVN value of {actual:?} is less than the expected value of {expected:?}", "")?,
            Self::MiscellaneousSelect {expected, actual} => write!(f, "{:pad$}{status} The miscellaneous select did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::MrEnclave {expected, actual} => write!(f, "{:pad$}{status} The MRENCLAVE measurement did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::MrSignerKey {expected, actual} => write!(f, "{:pad$}{status} The MRSIGNER key hash did not match, expected:{expected:?} actual:{actual:?}", "")?,
            Self::ReportData {expected, actual, mask} => write!(f, "{:pad$}{status} The report data did not match expected:{expected:?} actual:{actual:?} mask:{mask:?}", "")?,
        }
        Ok(())
    }
}

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier<T>: Debug {
    /// The metadata that was used in this verification
    type ResultMetadata: ResultMessage;

    /// Performs a verification operation on `evidence`.
    fn verify(&self, evidence: &T) -> VerificationResult<Self::ResultMetadata>;

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

/// A result message for an `and` operation.
#[derive(Debug, Clone)]
pub struct AndResultMessage<L, R> {
    left: VerificationResult<L>,
    right: VerificationResult<R>,
}

impl<L, R> AndResultMessage<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationResult<L>, right: VerificationResult<R>) -> Self {
        Self { left, right }
    }
}

impl<L: ResultMessage, R: ResultMessage> ResultMessage for AndResultMessage<L, R> {
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
    type ResultMetadata = AndResultMessage<L::ResultMetadata, R::ResultMetadata>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::ResultMetadata> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_ok = left_err.is_ok() & right_err.is_ok();
        VerificationResult::new(AndResultMessage::new(left_err, right_err), is_ok)
    }
}

/// A result message that occurs during an `or` operation.
#[derive(Debug, Clone)]
pub struct OrResultMessage<L, R> {
    left: VerificationResult<L>,
    right: VerificationResult<R>,
}

impl<L, R> OrResultMessage<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationResult<L>, right: VerificationResult<R>) -> Self {
        Self { left, right }
    }
}

impl<L: ResultMessage, R: ResultMessage> ResultMessage for OrResultMessage<L, R> {
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
    type ResultMetadata = OrResultMessage<L::ResultMetadata, R::ResultMetadata>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::ResultMetadata> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_ok = left_err.is_ok() | right_err.is_ok();
        VerificationResult::new(OrResultMessage::new(left_err, right_err), is_ok)
    }
}

/// A result message that occurs due to a [`Not`] operation.
#[derive(Debug, Clone)]
pub struct NotResultMessage<T> {
    // The [`VerificationResult`] that was negated by the [`Not`] operation.
    inner: VerificationResult<T>,
}

impl<T> NotResultMessage<T> {
    /// Create a new instance
    pub fn new(inner: VerificationResult<T>) -> Self {
        Self { inner }
    }
}

impl<T: ResultMessage> ResultMessage for NotResultMessage<T> {
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
    type ResultMetadata = NotResultMessage<V::ResultMetadata>;
    fn verify(&self, evidence: &T) -> VerificationResult<Self::ResultMetadata> {
        let original = self.verifier.verify(evidence);
        let is_ok = original.is_ok();
        VerificationResult::new(NotResultMessage::new(original), !is_ok)
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrue;

impl<T> Verifier<T> for AlwaysTrue {
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, _evidence: &T) -> VerificationResult<Self::ResultMetadata> {
        VerificationResult::new(VerificationResultMetadata::General, 1.into())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalse;

impl<T> Verifier<T> for AlwaysFalse {
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, _evidence: &T) -> VerificationResult<Self::ResultMetadata> {
        VerificationResult::new(VerificationResultMetadata::AlwaysFalse, 0.into())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::format;
    use core::cell::Cell;

    // The `And` and `Or` logic tests below don't care about the evidence, but
    // they need to be provided something.
    const NO_EVIDENCE: &Option<usize> = &None;

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
        type ResultMetadata = VerificationResultMetadata;
        fn verify(&self, _evidence: &T) -> VerificationResult<Self::ResultMetadata> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 1 } else { 0 };
            VerificationResult::new(VerificationResultMetadata::General, succeed.into())
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
            VerificationResultMetadata::IsvSvn {
                expected: 3.into(),
                actual: 3.into(),
            },
            1.into(),
        );
        assert_eq!(format!("{success}"), "- [x] The ISV SVN was IsvSvn(3)");
    }

    #[test]
    fn display_of_fail_option() {
        let failure = VerificationResult::new(
            VerificationResultMetadata::IsvSvn {
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
            AndResultMessage::new(
                VerificationResult::new(VerificationResultMetadata::General, 1.into()),
                VerificationResult::new(
                    VerificationResultMetadata::MiscellaneousSelect {
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
              - [x] Success
              - [x] The miscellaneous select was MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{success}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_and_failure() {
        let failure = VerificationResult::new(
            AndResultMessage::new(
                VerificationResult::new(VerificationResultMetadata::General, 1.into()),
                VerificationResult::new(
                    VerificationResultMetadata::MiscellaneousSelect {
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
              - [x] Success
              - [ ] The miscellaneous select did not match, expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{failure}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_or_with_and_failure() {
        let failure = VerificationResult::new(
            OrResultMessage::new(
                VerificationResult::new(
                    AndResultMessage::new(
                        VerificationResult::new(VerificationResultMetadata::General, 1.into()),
                        VerificationResult::new(
                            VerificationResultMetadata::IsvSvn {
                                expected: 3.into(),
                                actual: 1.into(),
                            },
                            0.into(),
                        ),
                    ),
                    0.into(),
                ),
                VerificationResult::new(
                    VerificationResultMetadata::MiscellaneousSelect {
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
                - [x] Success
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
              - [x] Success"#;
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
