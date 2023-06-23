// Copyright (c) 2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
#![no_std]

#[cfg(feature = "tcb")]
mod advisories;
#[cfg(feature = "tcb")]
mod error;
#[cfg(feature = "tcb")]
mod evidence;
mod quote;
mod report_body;
mod struct_name;
#[cfg(feature = "tcb")]
mod tcb;
#[cfg(feature = "x509")]
mod x509;

#[cfg(feature = "tcb")]
pub use advisories::{Advisories, AdvisoriesVerifier, AdvisoryStatus};

#[cfg(feature = "tcb")]
pub use error::Error;
#[cfg(feature = "tcb")]
pub(crate) use error::Result;

#[cfg(feature = "tcb")]
pub use evidence::Evidence;

pub use quote::Quote3Verifier;

pub use report_body::{
    AttributesVerifier, ConfigIdVerifier, ConfigSvnVerifier, CpuSvnVerifier,
    ExtendedProductIdVerifier, FamilyIdVerifier, IsvProductIdVerifier, IsvSvnVerifier,
    MiscellaneousSelectVerifier, MrEnclaveVerifier, MrSignerVerifier, ReportDataVerifier,
};

#[cfg(feature = "tcb")]
pub use tcb::{TcbInfo, TcbInfoRaw, TcbInfoRawVerifier};

#[cfg(feature = "x509")]
pub use x509::{
    CertificateRevocationList, Error as X509Error, TrustAnchor, UnverifiedCertChain,
    VerifiedCertChain,
};

use crate::struct_name::SpacedStructName;
use core::fmt::{Debug, Display, Formatter};
use subtle::Choice;

/// Number of spaces to indent nested messages.
const MESSAGE_INDENT: usize = 2;

/// Success checkbox indicator
const SUCCESS_MESSAGE_INDICATOR: &str = "- [x]";

/// Failure checkbox indicator
const FAILURE_MESSAGE_INDICATOR: &str = "- [ ]";

pub(crate) fn choice_to_status_message(choice: Choice) -> &'static str {
    if choice.into() {
        SUCCESS_MESSAGE_INDICATOR
    } else {
        FAILURE_MESSAGE_INDICATOR
    }
}

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

    /// The value used in the verification.
    pub fn value(&self) -> &T {
        &self.value
    }
}

/// A helper struct for displaying the verification results.
///
/// ```
/// use mc_attestation_verifier::{VerificationOutput, VerificationTreeDisplay, EqualityVerifier, Verifier};
/// pub type MyVerifier = EqualityVerifier<u8>;
/// let verifier = MyVerifier::new(42);
/// let result = verifier.verify(&43);
///
/// let display_tree = VerificationTreeDisplay::new(&verifier, result);
/// assert_eq!(display_tree.to_string(), "- [ ] The Unsigned byte should be 42, but the actual Unsigned byte was 43");
/// ```
#[derive(Debug, Clone)]
pub struct VerificationTreeDisplay<'a, V, O> {
    verifier: &'a V,
    result: VerificationOutput<O>,
}

impl<'a, V, O> VerificationTreeDisplay<'a, V, O> {
    /// Create a new instance.
    ///
    /// # Arguments
    /// * `verifier` - The verifier that was used to perform the verification.
    /// * `result` - The result of the verification.
    pub fn new(verifier: &'a V, result: VerificationOutput<O>) -> Self {
        Self { verifier, result }
    }
}

impl<'a, V: VerificationMessage<O>, O> Display for VerificationTreeDisplay<'a, V, O> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.verifier.fmt_padded(f, 0, &self.result)
    }
}

trait VerificationMessage<O> {
    /// Format this verification phase.
    ///
    /// # Arguments
    /// * `f` - The formatter to use.
    /// * `pad` - The number of spaces to pad, or indent, the message with.
    /// * `output` - The output of this verification phase
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        output: &VerificationOutput<O>,
    ) -> core::fmt::Result;
}

impl<V: Display, O: SpacedStructName + Display> VerificationMessage<O> for V {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        output: &VerificationOutput<O>,
    ) -> core::fmt::Result {
        let is_success = output.is_success();
        let status = choice_to_status_message(is_success);
        write!(f, "{:pad$}{status} {self}", "")?;
        if (!is_success).into() {
            let name = O::spaced_struct_name();
            let actual = &output.value;
            write!(f, ", but the actual {name} was {actual}")?;
        }
        Ok(())
    }
}

/// A verifier. These can composed using the [`Or`] and [`And`]
/// types.
pub trait Verifier<E> {
    /// The value that was attempted to be verified.
    type Value;

    /// Performs a verification operation on `evidence`.
    ///
    /// In order to accommodate constant time operations this returns a
    /// [`VerificationOutput`] instead of a [`Result`].
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value>;
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

impl<LO, RO, L: VerificationMessage<LO>, R: VerificationMessage<RO>>
    VerificationMessage<AndOutput<LO, RO>> for And<L, R>
{
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<AndOutput<LO, RO>>,
    ) -> core::fmt::Result {
        let status = choice_to_status_message(result.is_success());

        write!(f, "{:pad$}{status} Both of the following must be true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f)?;
        self.left.fmt_padded(f, pad, &result.value.left)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad, &result.value.right)
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

impl<LO, RO, L: VerificationMessage<LO>, R: VerificationMessage<RO>>
    VerificationMessage<OrOutput<LO, RO>> for Or<L, R>
{
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<OrOutput<LO, RO>>,
    ) -> core::fmt::Result {
        let status = choice_to_status_message(result.is_success());

        write!(f, "{:pad$}{status} One of the following must be true:", "")?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f)?;
        self.left.fmt_padded(f, pad, &result.value.left)?;
        writeln!(f)?;
        self.right.fmt_padded(f, pad, &result.value.right)
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

/// Negated due to `Not`
#[derive(displaydoc::Display, Debug)]
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

impl<O, V> VerificationMessage<NotOutput<O>> for Not<V>
where
    V: VerificationMessage<O> + Display,
{
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<NotOutput<O>>,
    ) -> core::fmt::Result {
        let status = choice_to_status_message(result.is_success());

        write!(f, "{:pad$}{status} {self}:", "")?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f)?;
        self.verifier.fmt_padded(f, pad, &result.value.inner)
    }
}

/// Marker struct to ensure a node in the `VerificationOutput` was for an
/// `AlwaysTrue`
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AlwaysTrueValue;

/// Success due to `AlwaysTrue`
#[derive(displaydoc::Display, Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysTrue;

impl<E> Verifier<E> for AlwaysTrue {
    type Value = AlwaysTrueValue;
    fn verify(&self, _evidence: &E) -> VerificationOutput<Self::Value> {
        VerificationOutput::new(AlwaysTrueValue, 1.into())
    }
}

impl VerificationMessage<AlwaysTrueValue> for AlwaysTrue {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        _result: &VerificationOutput<AlwaysTrueValue>,
    ) -> core::fmt::Result {
        let status = SUCCESS_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} {self}", "")
    }
}

/// Marker struct to ensure a node in the `VerificationOutput` was for an
/// `AlwaysFalse`
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AlwaysFalseValue;

/// Failure due to `AlwaysFalse`
#[derive(displaydoc::Display, Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct AlwaysFalse;

impl<E> Verifier<E> for AlwaysFalse {
    type Value = AlwaysFalseValue;
    fn verify(&self, _evidence: &E) -> VerificationOutput<Self::Value> {
        VerificationOutput::new(AlwaysFalseValue, 0.into())
    }
}

impl VerificationMessage<AlwaysFalseValue> for AlwaysFalse {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        _result: &VerificationOutput<AlwaysFalseValue>,
    ) -> core::fmt::Result {
        let status = FAILURE_MESSAGE_INDICATOR;
        write!(f, "{:pad$}{status} {self}", "")
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

    impl<E> VerificationMessage<E> for Node {
        fn fmt_padded(
            &self,
            f: &mut Formatter<'_>,
            pad: usize,
            result: &VerificationOutput<E>,
        ) -> core::fmt::Result {
            let is_success = result.is_success();
            let status = choice_to_status_message(is_success);
            let message = if is_success.into() {
                "Node succeeded!!!"
            } else {
                "Node failed :("
            };

            write!(f, "{:pad$}{status} {message}", "")
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
        let displayable = VerificationTreeDisplay::new(&or, verification);
        let expected = r#"
            - [x] One of the following must be true:
              - [ ] Both of the following must be true:
                - [x] Node succeeded!!!
                - [ ] Node failed :(
              - [x] Node succeeded!!!"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn composing_and_and_or() {
        let and = And::new(Or::new(Node::new(true), Node::new(false)), Node::new(true));
        let verification = and.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&and, verification);
        let expected = r#"
            - [x] Both of the following must be true:
              - [x] One of the following must be true:
                - [x] Node succeeded!!!
                - [ ] Node failed :(
              - [x] Node succeeded!!!"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn not_negates_success() {
        let not = Not::new(AlwaysTrue);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&not, verification);
        let expected = r#"
            - [ ] Negated due to `Not`:
              - [x] Success due to `AlwaysTrue`"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn not_negates_failure() {
        let not = Not::new(AlwaysFalse);
        let verification = not.verify(NO_EVIDENCE);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&not, verification);
        let expected = r#"
            - [x] Negated due to `Not`:
              - [ ] Failure due to `AlwaysFalse`"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
