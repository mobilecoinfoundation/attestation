// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
pub use report_body::{
    AttributesVerifier, ConfigIdVerifier, ConfigSvnVerifier, IsvSvnVerifier,
    MiscellaneousSelectVerifier, MrEnclaveVerifier, MrSignerVerifier, ReportDataVerifier,
};

use core::fmt::{Debug, Display, Formatter};
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, IsvSvn, MiscellaneousSelect, MrEnclave, MrSigner, ReportData,
};
use subtle::CtOption;

/// An error that implements the [`Display`] trait.
pub trait DisplayableError: Display + Clone {}

/// Failed to verify.
#[derive(displaydoc::Display, Debug, Eq, PartialEq, Clone)]
pub enum VerificationError {
    /// A general error.
    General,
    /// Forced failure via `AlwaysFalse`
    AlwaysFalse,
    /// The attributes did not match expected:{expected:?} actual:{actual:?}
    AttributeMismatch {
        /// The expected attributes
        expected: Attributes,
        /// The actual attributes that were present
        actual: Attributes,
    },
    /// The config id did not match expected:{expected:?} actual:{actual:?}
    ConfigIdMismatch {
        /// The expected config id
        expected: ConfigId,
        /// The actual config id that was present
        actual: ConfigId,
    },
    /// The config SVN value of {actual:?} is less than the expected value of {expected:?}
    ConfigSvnTooSmall {
        /// The minimum SVN
        expected: ConfigSvn,
        /// The actual SVN that was present
        actual: ConfigSvn,
    },
    /// The ISV svn value of {actual:?} is less than the expected value of {expected:?}
    IsvSvnTooSmall {
        /// The minimum SVN
        expected: IsvSvn,
        /// The actual SVN that was present
        actual: IsvSvn,
    },
    /// The MiscellaneousSelect did not match expected:{expected:?} actual:{actual:?}
    MiscellaneousSelectMismatch {
        /// The expected selection
        expected: MiscellaneousSelect,
        /// The actual selections that were present
        actual: MiscellaneousSelect,
    },
    /// The MRENCLAVE measurement did not match expected:{expected:?} actual:{actual:?}
    MrEnclaveMismatch {
        /// The expected measurement
        expected: MrEnclave,
        /// The actual measurement that was present
        actual: MrEnclave,
    },
    /// The MRSIGNER measurement did not match expected:{expected:?} actual:{actual:?}
    MrSignerMismatch {
        /// The expected measurement
        expected: MrSigner,
        /// The actual measurement that was present
        actual: MrSigner,
    },
    /// The report data did not match expected:{expected:?} actual:{actual:?}
    ReportDataMismatch {
        /// The expected report data
        expected: ReportData,
        /// The actual report data that was present
        actual: ReportData,
    },
}

impl DisplayableError for VerificationError {}

#[derive(Debug, Clone)]
/// A [`CtOption`] wrapped to implement the [`Display`] trait.
pub struct DisplayableCtOption<T>(CtOption<T>);

impl<T> From<CtOption<T>> for DisplayableCtOption<T> {
    fn from(ct_option: CtOption<T>) -> Self {
        Self(ct_option)
    }
}

impl<T: DisplayableError> Display for DisplayableCtOption<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let option: Option<T> = self.0.clone().into();
        match option {
            Some(value) => match f.alternate() {
                true => write!(f, "{value:#}")?,
                false => write!(f, "{value}")?,
            },
            None => write!(f, "passed")?,
        }

        Ok(())
    }
}

/// A verifier. These can chained together using the [`Or`] and [`And`]
/// types.
pub trait Verifier<T>: Debug {
    /// The error that this verification will return in failure cases.
    type Error: DisplayableError;

    /// Performs a verification operation on `evidence`.
    ///
    /// In order to accommodate constant time operations this returns a
    /// [`CtOption`] instead of a [`Result`].
    fn verify(&self, evidence: &T) -> CtOption<Self::Error>;

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

/// An error that occurs during an `and` operation.
#[derive(Debug, Clone)]
pub struct AndError<L, R> {
    left: CtOption<L>,
    right: CtOption<R>,
}

impl<L, R> AndError<L, R> {
    /// Create a new instance
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self { left, right }
    }
}

impl<L: DisplayableError, R: DisplayableError> DisplayableError for AndError<L, R> {}

impl<L: DisplayableError, R: DisplayableError> Display for AndError<L, R> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("AndError")
            .field(
                "left",
                &format_args!("{:#}", DisplayableCtOption(self.left.clone())),
            )
            .field(
                "right",
                &format_args!("{:#}", DisplayableCtOption(self.right.clone())),
            )
            .finish()
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
    type Error = AndError<L::Error, R::Error>;
    fn verify(&self, evidence: &T) -> CtOption<Self::Error> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_some = left_err.is_some() | right_err.is_some();
        CtOption::new(AndError::new(left_err, right_err), is_some)
    }
}

/// An error that occurs during an `or` operation.
#[derive(Debug, Clone)]
pub struct OrError<L, R> {
    left: CtOption<L>,
    right: CtOption<R>,
}

impl<L, R> OrError<L, R> {
    /// Create a new instance
    pub fn new(left: CtOption<L>, right: CtOption<R>) -> Self {
        Self { left, right }
    }
}

impl<L: DisplayableError, R: DisplayableError> DisplayableError for OrError<L, R> {}

impl<L: DisplayableError, R: DisplayableError> Display for OrError<L, R> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("OrError")
            .field(
                "left",
                &format_args!("{:#}", DisplayableCtOption(self.left.clone())),
            )
            .field(
                "right",
                &format_args!("{:#}", DisplayableCtOption(self.right.clone())),
            )
            .finish()
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
    type Error = OrError<L::Error, R::Error>;
    fn verify(&self, evidence: &T) -> CtOption<Self::Error> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_some = left_err.is_some() & right_err.is_some();
        CtOption::new(OrError::new(left_err, right_err), is_some)
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrue;

impl<T> Verifier<T> for AlwaysTrue {
    type Error = VerificationError;
    fn verify(&self, _evidence: &T) -> CtOption<Self::Error> {
        CtOption::new(VerificationError::General, 0.into())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalse;

impl<T> Verifier<T> for AlwaysFalse {
    type Error = VerificationError;
    fn verify(&self, _evidence: &T) -> CtOption<Self::Error> {
        CtOption::new(VerificationError::AlwaysFalse, 1.into())
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
        type Error = VerificationError;
        fn verify(&self, _evidence: &T) -> CtOption<Self::Error> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 0 } else { 1 };
            CtOption::new(VerificationError::General, succeed.into())
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_some().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_some().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_some().unwrap_u8(), 1);
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }

    #[test]
    fn display_of_successful_option() {
        let success = CtOption::new(
            VerificationError::IsvSvnTooSmall {
                expected: 3.into(),
                actual: 3.into(),
            },
            0.into(),
        );
        let displayable: DisplayableCtOption<_> = success.into();
        assert_eq!(format!("{displayable}"), "passed");
    }

    #[test]
    fn display_of_fail_option() {
        let failure = CtOption::new(
            VerificationError::IsvSvnTooSmall {
                expected: 3.into(),
                actual: 2.into(),
            },
            1.into(),
        );
        let displayable: DisplayableCtOption<_> = failure.into();
        assert_eq!(
            format!("{displayable:}"),
            "The ISV svn value of IsvSvn(2) is less than the expected value of IsvSvn(3)"
        );
    }

    #[test]
    fn display_of_success_for_and_error() {
        let success = CtOption::new(
            AndError::new(
                CtOption::new(VerificationError::General, 0.into()),
                CtOption::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 3.into(),
                        actual: 3.into(),
                    },
                    0.into(),
                ),
            ),
            0.into(),
        );
        let displayable: DisplayableCtOption<_> = success.into();
        assert_eq!(format!("{displayable}"), "passed");
    }

    #[test]
    fn display_of_failure_for_and_error() {
        let failure = CtOption::new(
            AndError::new(
                CtOption::new(VerificationError::General, 0.into()),
                CtOption::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 3.into(),
                        actual: 3.into(),
                    },
                    1.into(),
                ),
            ),
            1.into(),
        );
        let displayable: DisplayableCtOption<_> = failure.into();
        let expected = r#"AndError { left: passed, right: The MiscellaneousSelect did not match expected:MiscellaneousSelect(3) actual:MiscellaneousSelect(3) }"#;
        assert_eq!(format!("{displayable:}"), textwrap::dedent(expected));
    }

    #[test]
    fn pretty_display_of_failure_for_and_error() {
        let failure = CtOption::new(
            AndError::new(
                CtOption::new(VerificationError::General, 0.into()),
                CtOption::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    1.into(),
                ),
            ),
            1.into(),
        );
        let displayable: DisplayableCtOption<_> = failure.into();
        let expected = r#"
            AndError {
                left: passed,
                right: The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3),
            }"#;
        assert_eq!(format!("\n{displayable:#}"), textwrap::dedent(expected));
    }

    #[test]
    fn pretty_display_of_failure_for_or_with_and_error() {
        let failure = CtOption::new(
            OrError::new(
                CtOption::new(
                    AndError::new(
                        CtOption::new(VerificationError::General, 0.into()),
                        CtOption::new(
                            VerificationError::IsvSvnTooSmall {
                                expected: 3.into(),
                                actual: 1.into(),
                            },
                            1.into(),
                        ),
                    ),
                    1.into(),
                ),
                CtOption::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    1.into(),
                ),
            ),
            1.into(),
        );
        let displayable: DisplayableCtOption<_> = failure.into();
        let expected = r#"
            OrError {
                left: AndError {
                    left: passed,
                    right: The ISV svn value of IsvSvn(1) is less than the expected value of IsvSvn(3),
                },
                right: The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3),
            }"#;
        assert_eq!(format!("\n{displayable:#}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_always_false_option() {
        let failure = AlwaysFalse.verify(NO_EVIDENCE);
        let displayable: DisplayableCtOption<_> = failure.into();
        assert_eq!(
            format!("{displayable:}"),
            "Forced failure via `AlwaysFalse`"
        );
    }
}
