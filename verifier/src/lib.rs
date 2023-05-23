// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

mod report_body;
mod struct_name;
#[cfg(feature = "tcb")]
mod tcb;
#[cfg(feature = "alloc")]
mod x509;

pub use report_body::{
    AttributesVerifier, ConfigIdVerifier, ConfigSvnVerifier, CpuSvnVerifier,
    ExtendedProductIdVerifier, FamilyIdVerifier, IsvProductIdVerifier, IsvSvnVerifier,
    MiscellaneousSelectVerifier, MrEnclaveVerifier, MrSignerVerifier, ReportDataVerifier,
};

use crate::struct_name::SpacedStructName;
use core::fmt::{Debug, Display, Formatter};
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportData,
};
use subtle::Choice;

/// Number of spaces to indent nested error messages.
const ERROR_INDENT: usize = 2;

/// The output of a verification operation, [`Verifier::verify()`].
#[derive(Debug, Clone)]
pub struct VerificationOutput<T> {
    // Whether or not this verification was successful.
    succeeded: Choice,
    // The value that was used in the verification.
    value: T,
}

impl<T> VerificationOutput<T> {
    /// Create a new instance.
    ///
    /// # Arguments
    /// * `value` - The value that was used in the verification.
    /// * `succeeded` - Whether or not the verification succeeded.
    pub fn new(value: T, succeeded: Choice) -> VerificationOutput<T> {
        Self { value, succeeded }
    }

    /// Was the verification successful?
    pub fn is_success(&self) -> Choice {
        self.succeeded
    }

    /// Was the verification a failure?
    pub fn is_failure(&self) -> Choice {
        !self.succeeded
    }
}

impl<T> VerificationOutput<T>
where
    T: DisplayableError,
{
    /// Format the instance with preceding padding
    ///
    /// The `pad` is the number of spaces to precede each line of the displayed
    /// representation with.
    pub fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        match self.succeeded.unwrap_u8() {
            1 => write!(f, "{:pad$}Passed", "")?,
            _ => self.value.fmt_padded(f, pad)?,
        }
        Ok(())
    }
}

impl<T> Display for VerificationOutput<T>
where
    T: DisplayableError,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        self.fmt_padded(f, 0)
    }
}

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

trait IntoVerificationError {
    fn into_verification_error(expected: Self, actual: Self) -> VerificationError;
}

impl DisplayableError for VerificationError {}

/// A verifier. These can composed using the [`Or`] and [`And`]
/// types.
pub trait Verifier<E>: Debug {
    /// The value that was attempted to be verified.
    type Value;

    /// Performs a verification operation on `evidence`.
    ///
    /// In order to accommodate constant time operations this returns a
    /// [`VerificationOutput`] instead of a [`Result`].
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value>;

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

/// Common implementation for [`Verifier`]s that test for equality between
/// an expected and actual value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EqualityVerifier<T> {
    expected: T,
}

impl<T> EqualityVerifier<T> {
    /// Create a new instance.
    pub fn new(expected: T) -> Self {
        Self { expected }
    }
}

impl<T> Display for EqualityVerifier<T>
where
    T: SpacedStructName + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "The {} should be {}",
            T::spaced_struct_name(),
            self.expected
        )
    }
}

impl<T, E> Verifier<E> for EqualityVerifier<T>
where
    T: Debug + Clone + PartialEq,
    E: Accessor<T>,
{
    type Value = T;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let expected = self.expected.clone();
        let actual = evidence.get();
        // TODO - This should be a constant time comparison.
        let is_success = if expected == actual { 1 } else { 0 };
        VerificationOutput::new(actual, is_success.into())
    }
}

/// Common implementation for [`Verifier`]s that test for an actual value being
/// greater than or equal to an expected value
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GreaterThanEqualVerifier<T> {
    expected: T,
}

impl<T> GreaterThanEqualVerifier<T> {
    /// Create a new instance.
    pub fn new(expected: T) -> Self {
        Self { expected }
    }
}

impl<T> Display for GreaterThanEqualVerifier<T>
where
    T: SpacedStructName + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "The {} should be at least {}",
            T::spaced_struct_name(),
            self.expected
        )
    }
}

/// Trait for getting access to the type `T` that needs to be verified.
///
/// The intent is to implement this for a higher level type that contains the
/// `T`
///
/// ```
/// use mc_attestation_verifier::Accessor;
/// pub struct Container {
///    field: u8,
/// }
/// impl Container {
///    fn field(&self) -> u8 {
///       self.field
///    }
/// }
/// impl Accessor<u8> for Container {
///     fn get(&self) -> u8 {
///         self.field()
///     }
/// }
/// ```
pub trait Accessor<T> {
    /// Get access to the value that needs to be verified.
    fn get(&self) -> T;
}

/// [`Accessor`] for returning Self, i.e. T -> T
impl<T: Clone> Accessor<T> for T {
    fn get(&self) -> T {
        self.clone()
    }
}

/// The output of an `and` operation.
#[derive(Debug, Clone)]
pub struct AndOutput<L, R> {
    left: VerificationOutput<L>,
    right: VerificationOutput<R>,
}

impl<L, R> AndOutput<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationOutput<L>, right: VerificationOutput<R>) -> Self {
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

/// Common logic to display an [`AndOutput`] or an [`OrOutput`]
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
    left: &VerificationOutput<L>,
    right: &VerificationOutput<R>,
) -> core::fmt::Result {
    Display::fmt(&format_args!("{:pad$}{type_name}:", ""), f)?;
    writeln!(f)?;

    let status_pad = pad + ERROR_INDENT;
    let left_status = choice_to_checkbox(left.is_success());
    writeln!(f, "{:status_pad$}{left_status}", "")?;

    let nested_pad = status_pad + 2;
    left.fmt_padded(f, nested_pad)?;
    writeln!(f)?;

    let right_status = choice_to_checkbox(right.is_success());
    writeln!(f, "{:status_pad$}{right_status}", "")?;
    right.fmt_padded(f, nested_pad)
    // No trailing newline to prevent nested `AndOutput`s and `OrOutput`s from
    // resulting in multiple consecutive newlines
}

impl<L: DisplayableError, R: DisplayableError> DisplayableError for AndOutput<L, R> {
    fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        and_or_error_fmt_padded(f, pad, "AndOutput", &self.left, &self.right)
    }
}

impl<L: DisplayableError, R: DisplayableError> Display for AndOutput<L, R> {
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

impl<E, L: Verifier<E>, R: Verifier<E>> Verifier<E> for And<L, R> {
    type Value = AndOutput<L::Value, R::Value>;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_success = left_err.is_success() & right_err.is_success();
        VerificationOutput::new(AndOutput::new(left_err, right_err), is_success)
    }
}

/// The output of an `or` operation.
#[derive(Debug, Clone)]
pub struct OrOutput<L, R> {
    left: VerificationOutput<L>,
    right: VerificationOutput<R>,
}

impl<L, R> OrOutput<L, R> {
    /// Create a new instance
    pub fn new(left: VerificationOutput<L>, right: VerificationOutput<R>) -> Self {
        Self { left, right }
    }
}

impl<L: DisplayableError, R: DisplayableError> DisplayableError for OrOutput<L, R> {
    fn fmt_padded(&self, f: &mut Formatter, pad: usize) -> core::fmt::Result {
        and_or_error_fmt_padded(f, pad, "OrOutput", &self.left, &self.right)
    }
}

impl<L: DisplayableError, R: DisplayableError> Display for OrOutput<L, R> {
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

impl<E, L: Verifier<E>, R: Verifier<E>> Verifier<E> for Or<L, R> {
    type Value = OrOutput<L::Value, R::Value>;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let left_err = self.left.verify(evidence);
        let right_err = self.right.verify(evidence);
        let is_success = left_err.is_success() | right_err.is_success();
        VerificationOutput::new(OrOutput::new(left_err, right_err), is_success)
    }
}

/// The output of a [`Not`] operation.
#[derive(Debug, Clone)]
pub struct NotOutput<O> {
    // The [`VerificationOutput`] that was negated by the [`Not`] operation.
    inner: VerificationOutput<O>,
}

impl<O> NotOutput<O> {
    /// Create a new instance
    pub fn new(inner: VerificationOutput<O>) -> Self {
        Self { inner }
    }
}

impl<E: DisplayableError> DisplayableError for NotOutput<E> {}

impl<E: DisplayableError> Display for NotOutput<E> {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.debug_struct("NotOutput")
            .field("inner", &format_args!("{:#}", self.inner))
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

impl<E, V: Verifier<E>> Verifier<E> for Not<V> {
    type Value = NotOutput<V::Value>;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let original = self.verifier.verify(evidence);
        let is_success = original.is_success();
        VerificationOutput::new(NotOutput::new(original), !is_success)
    }
}

/// Will always succeed for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrue;

impl<E> Verifier<E> for AlwaysTrue {
    type Value = VerificationError;
    fn verify(&self, _evidence: &E) -> VerificationOutput<Self::Value> {
        VerificationOutput::new(VerificationError::General, 1.into())
    }
}

/// Will always fail for the [`Verifier::verify()`] operation.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalse;

impl<E> Verifier<E> for AlwaysFalse {
    type Value = VerificationError;
    fn verify(&self, _evidence: &E) -> VerificationOutput<Self::Value> {
        VerificationOutput::new(VerificationError::AlwaysFalse, 0.into())
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
        type Value = ();
        fn verify(&self, _evidence: &T) -> VerificationOutput<Self::Value> {
            self.verified_called.replace(true);
            let succeed = if self.succeed { 1 } else { 0 };
            VerificationOutput::new((), succeed.into())
        }
    }

    #[test]
    fn and_succeeds() {
        let and = And::new(AlwaysTrue, AlwaysTrue);
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn and_fails_at_left() {
        let and = And::new(Node::new(false), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn and_fails_at_right() {
        let and = And::new(Node::new(true), Node::new(false));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert!(and.left().verified_called.get());
        assert!(and.right().verified_called.get());
    }

    #[test]
    fn or_fails_for_both_failing() {
        let or = Or::new(AlwaysFalse, AlwaysFalse);
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn or_succeeds_when_left_is_false() {
        let or = Or::new(Node::new(false), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn or_succeeds_when_right_is_false() {
        let or = Or::new(Node::new(true), Node::new(false));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
        assert!(or.left().verified_called.get());
        assert!(or.right().verified_called.get());
    }

    #[test]
    fn composing_or_and_and() {
        let or = Or::new(And::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = or.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }

    #[test]
    fn display_of_successful_option() {
        let success = VerificationOutput::new(
            VerificationError::IsvSvnTooSmall {
                expected: 3.into(),
                actual: 3.into(),
            },
            1.into(),
        );
        assert_eq!(format!("{success}"), "Passed");
    }

    #[test]
    fn display_of_fail_option() {
        let failure = VerificationOutput::new(
            VerificationError::IsvSvnTooSmall {
                expected: 3.into(),
                actual: 2.into(),
            },
            0.into(),
        );
        assert_eq!(
            format!("{failure}"),
            "The ISV SVN value of IsvSvn(2) is less than the expected value of IsvSvn(3)"
        );
    }

    #[test]
    fn display_of_success_for_and_error() {
        let success = VerificationOutput::new(
            AndOutput::new(
                VerificationOutput::new(VerificationError::General, 1.into()),
                VerificationOutput::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 3.into(),
                        actual: 3.into(),
                    },
                    1.into(),
                ),
            ),
            1.into(),
        );
        assert_eq!(format!("{success}"), "Passed");
    }

    #[test]
    fn display_of_failure_for_and_error() {
        let failure = VerificationOutput::new(
            AndOutput::new(
                VerificationOutput::new(VerificationError::General, 1.into()),
                VerificationOutput::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    0.into(),
                ),
            ),
            0.into(),
        );
        let expected = r#"
            AndOutput:
              - [x]
                Passed
              - [ ]
                The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{failure}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_failure_for_or_with_and_error() {
        let failure = VerificationOutput::new(
            OrOutput::new(
                VerificationOutput::new(
                    AndOutput::new(
                        VerificationOutput::new(VerificationError::General, 1.into()),
                        VerificationOutput::new(
                            VerificationError::IsvSvnTooSmall {
                                expected: 3.into(),
                                actual: 1.into(),
                            },
                            0.into(),
                        ),
                    ),
                    0.into(),
                ),
                VerificationOutput::new(
                    VerificationError::MiscellaneousSelectMismatch {
                        expected: 2.into(),
                        actual: 3.into(),
                    },
                    0.into(),
                ),
            ),
            0.into(),
        );
        let expected = r#"
            OrOutput:
              - [ ]
                AndOutput:
                  - [x]
                    Passed
                  - [ ]
                    The ISV SVN value of IsvSvn(1) is less than the expected value of IsvSvn(3)
              - [ ]
                The MiscellaneousSelect did not match expected:MiscellaneousSelect(2) actual:MiscellaneousSelect(3)"#;
        assert_eq!(format!("\n{failure}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_of_always_false_option() {
        let failure = AlwaysFalse.verify(NO_EVIDENCE);
        assert_eq!(format!("{failure}"), "Forced failure via `AlwaysFalse`");
    }

    #[test]
    fn not_negates_success() {
        let not = Not::new(AlwaysTrue);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn not_negates_failure() {
        let not = Not::new(AlwaysFalse);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);
    }
}
