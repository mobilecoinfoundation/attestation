// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
mod struct_name;
#[cfg(feature = "alloc")]
mod x509;

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
use subtle::{Choice, CtOption};

/// Number of spaces to indent nested error messages.
const ERROR_INDENT: usize = 2;

/// An error that implements the [`Display`] trait.
pub trait DisplayableError: Display + Clone {
    /// Format the error with preceding padding
    ///
    /// The `pad` is the number of spaces to precede each line of the error
    /// with.
    fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        write!(f, "{:pad$}{self}", "")
    }
}

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
    /// The CPU SVN value of {actual:?} is less than the expected value of {expected:?}
    CpuSvnTooSmall {
        /// The minimum SVN
        expected: CpuSvn,
        /// The actual SVN that was present
        actual: CpuSvn,
    },
    /// The extended product ID did not match expected:{expected:?} actual:{actual:?}
    ExtendedProductIdMismatch {
        /// The expected extended product ID
        expected: ExtendedProductId,
        /// The actual extended product ID that was present
        actual: ExtendedProductId,
    },
    /// The family ID did not match expected:{expected:?} actual:{actual:?}
    FamilyIdMismatch {
        /// The expected family ID
        expected: FamilyId,
        /// The actual family ID that was present
        actual: FamilyId,
    },
    /// The ISV product ID did not match expected:{expected:?} actual:{actual:?}
    IsvProductIdMismatch {
        /// The expected product ID
        expected: IsvProductId,
        /// The actual product ID that was present
        actual: IsvProductId,
    },
    /// The ISV SVN value of {actual:?} is less than the expected value of {expected:?}
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
    /// The MRSIGNER key did not match expected:{expected:?} actual:{actual:?}
    MrSignerKeyMismatch {
        /// The expected key
        expected: MrSigner,
        /// The actual key that was present
        actual: MrSigner,
    },
    /// The report data did not match expected:{expected:?} actual:{actual:?} mask:{mask:?}
    ReportDataMismatch {
        /// The expected report data
        expected: ReportData,
        /// The actual report data that was present
        actual: ReportData,
        /// Mask of which bytes were expected to match
        mask: ReportData,
    },
}

impl DisplayableError for VerificationError {}

/// Trait to convert a [`CtOption<T>`] into a [`CtOptionDisplay<'a, T>`].
///
/// # Examples
/// ```
/// use subtle::CtOption;
/// use mc_attestation_verifier::{VerificationError, DisplayableCtOption};
///
/// let ct_option = CtOption::new(VerificationError::General, 0.into());
///
/// assert_eq!(format!("{}", ct_option.display()), "Passed");
/// ```
pub trait DisplayableCtOption<'a, T> {
    /// Returns an object that implements [`Display`] for a wrapped
    /// [`CtOption<T>`].
    #[must_use = "this does not display the [`CtOption<T>`], \
                  it returns an object that can be displayed"]
    fn display(&'a self) -> CtOptionDisplay<'a, T>
    where
        Self: Sized;
}

impl<'a, T> DisplayableCtOption<'a, T> for CtOption<T> {
    fn display(&'a self) -> CtOptionDisplay<'a, T> {
        self.into()
    }
}

#[derive(Debug, Clone)]
/// Helper struct for displaying [`CtOption`] with
/// [`format`](https://doc.rust-lang.org/std/macro.format.html) and `{}`.
pub struct CtOptionDisplay<'a, T>(&'a CtOption<T>);
impl<'a, T: DisplayableError> CtOptionDisplay<'a, T> {
    /// Format the instance with preceding padding
    ///
    /// The `pad` is the number of spaces to precede each line of the displayed
    /// representation with.
    pub fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        let option: Option<T> = Option::<T>::from(self.0.clone());
        match option {
            Some(value) => value.fmt_padded(f, pad)?,
            None => write!(f, "{:pad$}Passed", "")?,
        }
        Ok(())
    }
}

impl<'a, T> From<&'a CtOption<T>> for CtOptionDisplay<'a, T> {
    fn from(ct_option: &'a CtOption<T>) -> Self {
        Self(ct_option)
    }
}

impl<'a, T: DisplayableError> Display for CtOptionDisplay<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.fmt_padded(f, 0)
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

/// Turn a `Choice` into a markdown checkbox
///
/// Will return one of:
/// ```raw
///     - [ ]
///     - [x]
/// ```
fn choice_to_checkbox(choice: Choice) -> &'static str {
    if bool::from(choice) {
        "- [x]"
    } else {
        "- [ ]"
    }
}

/// Common logic to display an [`AndError`] or an [`OrError`]
///
/// Results in output in the formatter similar to:
/// ```raw
///     <type_name>:
///       - [ ]
///         <left>
///       - [ ]
///         <right>
/// ```
///
/// The `type_name` will be indented by `pad` spaces. Subsequent lines will be
/// indented by multiples of `ERROR_INDENT` to communicate message hierarchy.
fn and_or_error_fmt_padded<L: DisplayableError, R: DisplayableError>(
    f: &mut Formatter,
    pad: usize,
    type_name: &str,
    left: &CtOption<L>,
    right: &CtOption<R>,
) -> core::fmt::Result {
    Display::fmt(&format_args!("{:pad$}{type_name}:", ""), f)?;
    writeln!(f)?;

    let status_pad = pad + ERROR_INDENT;
    let left_status = choice_to_checkbox(left.is_none());
    writeln!(f, "{:status_pad$}{left_status}", "")?;

    let nested_pad = status_pad + 2;
    left.display().fmt_padded(f, nested_pad)?;
    writeln!(f)?;

    let right_status = choice_to_checkbox(right.is_none());
    writeln!(f, "{:status_pad$}{right_status}", "")?;
    right.display().fmt_padded(f, nested_pad)
    // No trailing newline to prevent nested `AndError`s and `OrError`s from
    // resulting in multiple consecutive newlines
}

impl<L: DisplayableError, R: DisplayableError> DisplayableError for AndError<L, R> {
    fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        and_or_error_fmt_padded(f, pad, "AndError", &self.left, &self.right)
    }
}

impl<L: DisplayableError, R: DisplayableError> Display for AndError<L, R> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.fmt_padded(f, 0)
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

impl<L: DisplayableError, R: DisplayableError> DisplayableError for OrError<L, R> {
    fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        and_or_error_fmt_padded(f, pad, "OrError", &self.left, &self.right)
    }
}

impl<L: DisplayableError, R: DisplayableError> Display for OrError<L, R> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.fmt_padded(f, 0)
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

/// An error that occurs due to a [`Not`] operation.
#[derive(Debug, Clone)]
pub struct NotError<E> {
    // The [`CtOption`] that was negated by the [`Not`] operation.
    inner: CtOption<E>,
}

impl<E> NotError<E> {
    /// Create a new instance
    pub fn new(inner: CtOption<E>) -> Self {
        Self { inner }
    }
}

impl<E: DisplayableError> DisplayableError for NotError<E> {}

impl<E: DisplayableError> Display for NotError<E> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("NotError")
            .field("inner", &format_args!("{:#}", self.inner.display()))
            .finish()
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
    type Error = NotError<V::Error>;
    fn verify(&self, evidence: &T) -> CtOption<Self::Error> {
        let original = self.verifier.verify(evidence);
        let is_some = original.is_some();
        CtOption::new(NotError::new(original), !is_some)
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
        let displayable = success.display();
        assert_eq!(format!("{displayable}"), "Passed");
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
        let displayable = failure.display();
        assert_eq!(
            format!("{displayable}"),
            "The ISV SVN value of IsvSvn(2) is less than the expected value of IsvSvn(3)"
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
        let displayable = success.display();
        assert_eq!(format!("{displayable}"), "Passed");
    }

    #[test]
    fn display_of_failure_for_and_error() {
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
        let displayable = failure.display();
        let expected = r#"
            AndError:
              - [x]
                Passed
              - [ ]
                The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_or_with_and_error() {
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
        let displayable = failure.display();
        let expected = r#"
            OrError:
              - [ ]
                AndError:
                  - [x]
                    Passed
                  - [ ]
                    The ISV SVN value of IsvSvn(1) is less than the expected value of IsvSvn(3)
              - [ ]
                The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_always_false_option() {
        let failure = AlwaysFalse.verify(NO_EVIDENCE);
        let displayable = failure.display();
        assert_eq!(
            format!("{displayable:}"),
            "Forced failure via `AlwaysFalse`"
        );
    }

    #[test]
    fn not_negates_success() {
        let not = Not::new(AlwaysTrue);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_some().unwrap_u8(), 1);
    }

    #[test]
    fn not_negates_failure() {
        let not = Not::new(AlwaysFalse);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_none().unwrap_u8(), 1);
    }
}
