// Copyright (c) 2023 The MobileCoin Foundation

//! Provides logic for verifying MRENCLAVE and MRSIGNER identities in combination with allowed
//! [`Advisories`].
//!
//! Section 3.8 of
//! [Intel SGX ECDSA QuoteLibReference DCAP API](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A63%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C468%2C0%5D)
//! documents the identity types, Strict Policy and Security Policy.

use crate::report_body::MrSignerValue;
use crate::struct_name::SpacedStructName;
use crate::{
    Accessor, Advisories, AdvisoriesVerifier, AdvisoryStatus, And, AndOutput, MrEnclaveVerifier,
    MrSignerVerifier, VerificationMessage, VerificationOutput, Verifier, MESSAGE_INDENT,
};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Formatter;
use core::ops::Not;
use mc_sgx_core_types::{IsvProductId, IsvSvn, MrEnclave, MrSigner};
use serde::{Deserialize, Serialize};

/// Trusted identity for MRENCLAVE values.
///
/// This identity is also referred to as "Strict Enclave Modification
/// Policy", in
/// [Intel SGX ECDSA QuoteLibReference DCAP API](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A63%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C468%2C0%5D)
/// It uses a MRENCLAVE measurement which is a hash over the enclave pages loaded into the SGX
/// protected memory. Whenever the contents of the signed enclave have changed, its MRENCLAVE will
/// change.
///
/// The "trusted" part is the known mitigated advisories.
///
/// Supports de/serialization to/from JSON. Unknown JSON fields are flagged as an error.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMrEnclaveIdentity {
    /// The MRENCLAVE measurement
    ///
    /// For JSON this will be hex-encoded bytes.
    #[serde(with = "hex", rename = "MRENCLAVE")]
    mr_enclave: MrEnclave,
    /// The list of config advisories that are known to be mitigated in software at this enclave
    /// revision.
    #[serde(default)]
    mitigated_config_advisories: Vec<String>,
    /// The list of hardening advisories that are known to be mitigated in software at this enclave
    /// revision.
    #[serde(default)]
    mitigated_hardening_advisories: Vec<String>,
}

impl TrustedMrEnclaveIdentity {
    /// Create a new instance.
    pub fn new<'a, CA, I, HA, J>(
        mr_enclave: MrEnclave,
        config_advisories: I,
        hardening_advisories: J,
    ) -> Self
    where
        I: IntoIterator<Item = &'a CA>,
        CA: ToString + 'a + ?Sized,
        J: IntoIterator<Item = &'a HA>,
        HA: ToString + 'a + ?Sized,
    {
        Self {
            mr_enclave,
            mitigated_config_advisories: config_advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            mitigated_hardening_advisories: hardening_advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        }
    }

    /// Get the MRENCLAVE measurement for this identity
    pub fn mr_enclave(&self) -> MrEnclave {
        self.mr_enclave
    }

    /// Get the known allowed [`Advisories`] for this identity.
    pub fn advisories(&self) -> Advisories {
        mitigated_advisories_to_advisories(
            &self.mitigated_config_advisories,
            &self.mitigated_hardening_advisories,
        )
    }
}

/// Trusted MRSIGNER identity.
///
/// This identity is also referred to as "Security Enclave Modification
/// Policy" of
/// [Intel SGX ECDSA QuoteLibReference DCAP API](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A63%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C468%2C0%5D)
/// It uses a MRSIGNER hash, which is a hash of the public portion of the key used to sign the
/// enclave. The product ID is used to distinguish different enclaves signed with the same key.
/// Using the MRSIGNER + product ID allows for the same values to be used for updates to the
/// enclave.
///
/// The "trusted" part is the security version number (SVN) used to distinguish different versions
/// of the same enclave along with the known mitigated advisories.
///
///
/// Supports de/serialization to/from JSON. Unknown JSON fields are flagged as an error.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMrSignerIdentity {
    /// The MRSIGNER public key hash
    ///
    /// For JSON this will be hex-encoded bytes.
    #[serde(with = "hex", rename = "MRSIGNER")]
    mr_signer: MrSigner,
    /// The product ID for this enclave.
    product_id: u16,
    /// The minimum security version number that is trusted
    minimum_svn: u16,
    /// The list of config advisories that are known to be mitigated in software at this enclave
    /// revision.
    #[serde(default)]
    mitigated_config_advisories: Vec<String>,
    /// The list of hardening advisories that are known to be mitigated in software at this enclave
    /// revision.
    #[serde(default)]
    mitigated_hardening_advisories: Vec<String>,
}

impl TrustedMrSignerIdentity {
    /// Create a new instance.
    pub fn new<'a, CA, I, HA, J>(
        mr_signer: MrSigner,
        isv_product_id: IsvProductId,
        isv_svn: IsvSvn,
        config_advisories: I,
        hardening_advisories: J,
    ) -> Self
    where
        I: IntoIterator<Item = &'a CA>,
        CA: ToString + 'a + ?Sized,
        J: IntoIterator<Item = &'a HA>,
        HA: ToString + 'a + ?Sized,
    {
        Self {
            mr_signer,
            product_id: isv_product_id.into(),
            minimum_svn: isv_svn.into(),
            mitigated_config_advisories: config_advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
            mitigated_hardening_advisories: hardening_advisories
                .into_iter()
                .map(ToString::to_string)
                .collect(),
        }
    }

    /// Get the MRSIGNER hash value for this identity
    pub fn mr_signer(&self) -> MrSigner {
        self.mr_signer
    }

    /// Get the ISV product ID for this identity
    pub fn isv_product_id(&self) -> IsvProductId {
        self.product_id.into()
    }

    /// Get the ISV SVN for this identity
    pub fn isv_svn(&self) -> IsvSvn {
        self.minimum_svn.into()
    }

    /// Get the known allowed [`Advisories`] for this identity.
    pub fn advisories(&self) -> Advisories {
        mitigated_advisories_to_advisories(
            &self.mitigated_config_advisories,
            &self.mitigated_hardening_advisories,
        )
    }
}

/// Trusted identity for an enclave.
///
/// Either a MRENCLAVE or MRSIGNER type
///
/// Supports de/serialization to/from JSON.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum TrustedIdentity {
    /// MRENCLAVE identity type
    MrEnclave(TrustedMrEnclaveIdentity),
    /// MRSIGNER identity type
    MrSigner(TrustedMrSignerIdentity),
}

impl From<&TrustedIdentity> for TrustedIdentity {
    fn from(identity: &TrustedIdentity) -> Self {
        identity.clone()
    }
}

impl From<TrustedMrEnclaveIdentity> for TrustedIdentity {
    fn from(mr_enclave: TrustedMrEnclaveIdentity) -> Self {
        Self::MrEnclave(mr_enclave)
    }
}

impl From<TrustedMrSignerIdentity> for TrustedIdentity {
    fn from(mr_signer: TrustedMrSignerIdentity) -> Self {
        Self::MrSigner(mr_signer)
    }
}

// Convert two separate lists of config and sw hardening advisories into [`Advisories`]
fn mitigated_advisories_to_advisories(
    config_advisories: &[String],
    sw_hardening_advisories: &[String],
) -> Advisories {
    let config_needed = config_advisories.is_empty().not();
    let sw_hardening_needed = sw_hardening_advisories.is_empty().not();
    let status = match (config_needed, sw_hardening_needed) {
        (true, true) => AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
        (true, false) => AdvisoryStatus::ConfigurationNeeded,
        (false, true) => AdvisoryStatus::SWHardeningNeeded,
        (false, false) => AdvisoryStatus::UpToDate,
    };

    let advisories = config_advisories
        .iter()
        .chain(sw_hardening_advisories.iter());
    Advisories::new(advisories, status)
}

/// A verifier for determining if one of the provided identities matches the enclave.
#[derive(Clone, Debug)]
pub struct TrustedIdentitiesVerifier {
    identity_verifiers: Vec<TrustedIdentityVerifier>,
}

impl TrustedIdentitiesVerifier {
    /// Create a new instance
    ///
    /// # Arguments
    /// - `identities` - The iterator of identities to check against
    pub fn new<I, ID>(identities: I) -> Self
    where
        I: IntoIterator<Item = ID>,
        ID: Into<TrustedIdentity>,
    {
        let identity_verifiers = identities
            .into_iter()
            .map(|id| TrustedIdentityVerifier::from(id.into()))
            .collect();

        Self { identity_verifiers }
    }
}

impl<E> Verifier<E> for TrustedIdentitiesVerifier
where
    E: Accessor<MrEnclave>
        + Accessor<MrSigner>
        + Accessor<Advisories>
        + Accessor<IsvProductId>
        + Accessor<IsvSvn>,
{
    type Value = TrustedIdentityValue;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let result = self
            .identity_verifiers
            .iter()
            .find_map(|identity_verifier| {
                let result = identity_verifier.verify(evidence);
                match result.is_success().unwrap_u8() {
                    1 => Some(result),
                    _ => None,
                }
            });

        result.unwrap_or_else(|| {
            VerificationOutput::new(TrustedIdentityValue::Identity(evidence.into()), 0.into())
        })
    }
}

impl VerificationMessage<TrustedIdentityValue> for TrustedIdentitiesVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<TrustedIdentityValue>,
    ) -> core::fmt::Result {
        let is_success = result.is_success();
        if is_success.unwrap_u8() == 1 {
            return result.value.fmt_padded(f, pad);
        }

        let status = crate::choice_to_status_message(is_success);
        writeln!(f, "{:pad$}{status} No enclave identity matched for:", "")?;

        let pad = pad + MESSAGE_INDENT;
        result.value.fmt_padded(f, pad)?;

        let TrustedIdentityValue::Identity(identity) = &result.value else {
            panic!("Should have an IdentityOutput if we failed to verify");
        };

        writeln!(f)?;
        write!(f, "{:pad$}Searched through the following identities:", "")?;
        if self.identity_verifiers.is_empty() {
            write!(f, " None")?;
        } else {
            for identity_verifier in &self.identity_verifiers {
                writeln!(f)?;
                identity_verifier.fmt_padded(f, pad, identity)?;
            }
        }
        Ok(())
    }
}

/// A verifier for looking at a single identity
///
/// This can be a bit confusing with the `TrustedIdentitiesVerifier`. This type is to handle *one*
/// identity, while the `TrustedIdentitiesVerifier` is for verifying one of *multiple* identities.
#[derive(Debug, Clone)]
enum TrustedIdentityVerifier {
    MrEnclave(And<MrEnclaveVerifier, AdvisoriesVerifier>),
    MrSigner(And<MrSignerVerifier, AdvisoriesVerifier>),
}

impl TrustedIdentityVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        identity: &IdentityOutput,
    ) -> core::fmt::Result {
        // We re-verify here, in order to leverage the `fmt_padded` method on the `Verifier` trait
        match self {
            Self::MrEnclave(verifier) => {
                let result = verifier.verify(identity);
                verifier.fmt_padded(f, pad, &result)
            }
            Self::MrSigner(verifier) => {
                let result = verifier.verify(identity);
                verifier.fmt_padded(f, pad, &result)
            }
        }
    }
}

impl From<TrustedIdentity> for TrustedIdentityVerifier {
    fn from(identity: TrustedIdentity) -> Self {
        match identity {
            TrustedIdentity::MrEnclave(mr_enclave) => Self::MrEnclave(And::new(
                MrEnclaveVerifier::new(mr_enclave.mr_enclave()),
                AdvisoriesVerifier::new(mr_enclave.advisories()),
            )),
            TrustedIdentity::MrSigner(mr_signer) => Self::MrSigner(And::new(
                MrSignerVerifier::new(
                    mr_signer.mr_signer(),
                    mr_signer.isv_product_id(),
                    mr_signer.isv_svn(),
                ),
                AdvisoriesVerifier::new(mr_signer.advisories()),
            )),
        }
    }
}

impl<E> Verifier<E> for TrustedIdentityVerifier
where
    E: Accessor<MrEnclave>
        + Accessor<MrSigner>
        + Accessor<Advisories>
        + Accessor<IsvProductId>
        + Accessor<IsvSvn>,
{
    type Value = TrustedIdentityValue;

    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        match self {
            Self::MrEnclave(verifier) => {
                let result = verifier.verify(evidence);
                let is_success = result.is_success();
                VerificationOutput::new(
                    TrustedIdentityValue::MrEnclave(verifier.clone(), result),
                    is_success,
                )
            }
            Self::MrSigner(verifier) => {
                let result = verifier.verify(evidence);
                let is_success = result.is_success();
                VerificationOutput::new(
                    TrustedIdentityValue::MrSigner(verifier.clone(), result),
                    is_success,
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrustedIdentityValue {
    Identity(IdentityOutput),
    MrEnclave(
        And<MrEnclaveVerifier, AdvisoriesVerifier>,
        VerificationOutput<AndOutput<MrEnclave, Advisories>>,
    ),
    MrSigner(
        And<MrSignerVerifier, AdvisoriesVerifier>,
        VerificationOutput<AndOutput<MrSignerValue, Advisories>>,
    ),
}

impl TrustedIdentityValue {
    pub fn fmt_padded(&self, f: &mut Formatter<'_>, pad: usize) -> core::fmt::Result {
        match self {
            Self::Identity(identity) => identity.fmt_padded(f, pad),
            Self::MrEnclave(verifier, value) => verifier.fmt_padded(f, pad, value),
            Self::MrSigner(verifier, value) => verifier.fmt_padded(f, pad, value),
        }
    }
}

/// The output of a failed verification of an enclave identity
///
/// This contains the identity values that were found in the enclave
#[derive(Debug, Clone)]
pub struct IdentityOutput {
    mr_enclave: MrEnclave,
    mr_signer: MrSigner,
    isv_product_id: IsvProductId,
    isv_svn: IsvSvn,
    advisories: Advisories,
}

/// Macro to generate boilerplate for implementing [`Accessor`] for a field of
/// the [`IdentityOutput`].
///
/// # Arguments
/// * `field_type` - The type of the field in
/// * `field_name` - The name of the field on
macro_rules! identity_accessor {
    ($($field_type:ty, $field_name:ident;)*) => {$(
        impl Accessor<$field_type> for IdentityOutput {
            fn get(&self) -> $field_type {
                self.$field_name.clone()
            }
        }
    )*}
}

identity_accessor! {
    MrEnclave, mr_enclave;
    MrSigner, mr_signer;
    IsvProductId, isv_product_id;
    IsvSvn, isv_svn;
    Advisories, advisories;
}

impl<E> From<&E> for IdentityOutput
where
    E: Accessor<MrEnclave>
        + Accessor<MrSigner>
        + Accessor<Advisories>
        + Accessor<IsvProductId>
        + Accessor<IsvSvn>,
{
    fn from(evidence: &E) -> Self {
        Self {
            mr_enclave: evidence.get(),
            mr_signer: evidence.get(),
            isv_product_id: evidence.get(),
            isv_svn: evidence.get(),
            advisories: evidence.get(),
        }
    }
}

impl IdentityOutput {
    fn fmt_padded(&self, f: &mut Formatter<'_>, pad: usize) -> core::fmt::Result {
        writeln!(
            f,
            "{:pad$}- {}: {}",
            "",
            MrEnclave::spaced_struct_name(),
            self.mr_enclave
        )?;
        writeln!(
            f,
            "{:pad$}- {}: {}",
            "",
            MrSigner::spaced_struct_name(),
            self.mr_signer
        )?;
        writeln!(
            f,
            "{:pad$}- {}: {}",
            "",
            IsvProductId::spaced_struct_name(),
            self.isv_product_id
        )?;
        writeln!(
            f,
            "{:pad$}- {}: {}",
            "",
            IsvSvn::spaced_struct_name(),
            self.isv_svn
        )?;
        write!(
            f,
            "{:pad$}- {}: {}",
            "",
            Advisories::spaced_struct_name(),
            self.advisories
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VerificationTreeDisplay;
    use alloc::format;

    /// An identity for use in tests.
    ///
    /// All of the values are fixed because the individual verifiers are robustly tested and these
    /// tests are to ensure the identity verifiers are composed correctly.
    fn identity() -> IdentityOutput {
        IdentityOutput {
            mr_enclave: [1; 32].into(),
            mr_signer: [2; 32].into(),
            isv_product_id: 3.into(),
            isv_svn: 4.into(),
            advisories: Advisories::new(
                ["one", "two", "three", "four"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded,
            ),
        }
    }

    #[test]
    fn up_to_date_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity =
            TrustedMrEnclaveIdentity::new([5; 32].into(), [] as [&str; 0], [] as [&str; 0]);
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new([] as [&str; 0], AdvisoryStatus::UpToDate)
        );
    }

    #[test]
    fn config_needed_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity = TrustedMrEnclaveIdentity::new(
            [5; 32].into(),
            ["an advisory", "another one"],
            [] as [&str; 0],
        );
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new(
                ["an advisory", "another one"],
                AdvisoryStatus::ConfigurationNeeded
            )
        );
    }

    #[test]
    fn sw_hardening_needed_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity =
            TrustedMrEnclaveIdentity::new([5; 32].into(), [] as [&str; 0], ["what's", "up", "doc"]);
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new(["what's", "up", "doc"], AdvisoryStatus::SWHardeningNeeded)
        );
    }

    #[test]
    fn config_and_sw_hardening_needed_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity =
            TrustedMrEnclaveIdentity::new([5; 32].into(), ["one", "two"], ["three", "four"]);
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new(
                ["one", "two", "three", "four"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded
            )
        );
    }

    #[test]
    fn up_to_date_advisories_for_mr_signer_identity() {
        let mr_signer_identity = TrustedMrSignerIdentity::new(
            [8; 32].into(),
            9.into(),
            10.into(),
            [] as [&str; 0],
            [] as [&str; 0],
        );
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new([] as [&str; 0], AdvisoryStatus::UpToDate)
        );
    }

    #[test]
    fn config_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity = TrustedMrSignerIdentity::new(
            [8; 32].into(),
            9.into(),
            10.into(),
            ["mr", "signer"],
            [] as [&str; 0],
        );
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(["mr", "signer"], AdvisoryStatus::ConfigurationNeeded)
        );
    }

    #[test]
    fn sw_hardening_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity = TrustedMrSignerIdentity::new(
            [5; 32].into(),
            9.into(),
            10.into(),
            [] as [&str; 0],
            ["who's", "there?"],
        );
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(["who's", "there?"], AdvisoryStatus::SWHardeningNeeded)
        );
    }

    #[test]
    fn config_and_sw_hardening_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity = TrustedMrSignerIdentity::new(
            [5; 32].into(),
            9.into(),
            10.into(),
            ["nine", "8"],
            ["seven", "6"],
        );
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(
                ["nine", "8", "seven", "6"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded
            )
        );
    }

    #[test]
    fn identity_verifiers_one_identity_matches() {
        let identity = identity();
        let allowed_identities: &[TrustedIdentity] = &[TrustedMrEnclaveIdentity::new(
            identity.mr_enclave,
            ["one", "two"],
            ["three", "four"],
        )
        .into()];
        let verifier = TrustedIdentitiesVerifier::new(allowed_identities);
        let verification = verifier.verify(&identity);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] Both of the following must be true:
              - [x] The MRENCLAVE should be 0101010101010101010101010101010101010101010101010101010101010101
              - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn identity_verifiers_middle_identity_matches() {
        let identity = identity();

        let allowed_identities: &[TrustedIdentity] = &[
            TrustedMrEnclaveIdentity::new([11; 32].into(), ["one", "two"], ["three", "four"])
                .into(),
            TrustedMrSignerIdentity::new(
                identity.mr_signer,
                identity.isv_product_id,
                identity.isv_svn,
                ["one", "two"],
                ["three", "four"],
            )
            .into(),
            TrustedMrEnclaveIdentity::new(identity.mr_enclave, ["two"], ["three", "four"]).into(),
        ];
        let verifier = TrustedIdentitiesVerifier::new(allowed_identities);
        let verification = verifier.verify(&identity);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] Both of the following must be true:
              - [x] MRSIGNER all of the following must be true:
                - [x] The MRSIGNER key hash should be 0202020202020202020202020202020202020202020202020202020202020202
                - [x] The ISV product ID should be 3
                - [x] The ISV SVN should be at least 4
              - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn identities_verifier_no_identities() {
        let identity = identity();

        let allowed_identities: &[TrustedIdentity] = &[];

        let verifier = TrustedIdentitiesVerifier::new(allowed_identities);
        let verification = verifier.verify(&identity);
        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] No enclave identity matched for:
              - MRENCLAVE: 0101010101010101010101010101010101010101010101010101010101010101
              - MRSIGNER key hash: 0202020202020202020202020202020202020202020202020202020202020202
              - ISV product ID: 3
              - ISV SVN: 4
              - advisories: IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              Searched through the following identities: None"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn identities_verifier_no_matches() {
        let identity = identity();

        let allowed_identities: &[TrustedIdentity] = &[
            // Mismatched MRENCLAVE
            TrustedMrEnclaveIdentity::new([11; 32].into(), ["one", "two"], ["three", "four"])
                .into(),
            // Mismatched MRSIGNER
            TrustedMrSignerIdentity::new(
                [12; 32].into(),
                identity.isv_product_id,
                identity.isv_svn,
                ["one", "two"],
                ["three", "four"],
            )
            .into(),
            // Mismatched product ID
            TrustedMrSignerIdentity::new(
                identity.mr_signer,
                (identity.isv_product_id.as_ref() - 1).into(),
                identity.isv_svn,
                ["one", "two"],
                ["three", "four"],
            )
            .into(),
            // Required SVN is greater than the identity's SVN
            TrustedMrSignerIdentity::new(
                identity.mr_signer,
                identity.isv_product_id,
                (identity.isv_svn.as_ref() + 1).into(),
                ["one", "two"],
                ["three", "four"],
            )
            .into(),
            // Requires an advisory status no worse than AdvisoryStatus::ConfigurationNeeded
            TrustedMrSignerIdentity::new(
                identity.mr_signer,
                identity.isv_product_id,
                identity.isv_svn,
                ["one", "two", "three", "four"],
                [] as [&str; 0],
            )
            .into(),
            // Requires an advisory status no worse than AdvisoryStatus::SWHardeningNeeded
            TrustedMrEnclaveIdentity::new(
                identity.mr_enclave,
                [] as [&str; 0],
                ["one", "two", "three", "four"],
            )
            .into(),
            // Doesn't allow the "four" advisory id
            TrustedMrEnclaveIdentity::new(identity.mr_enclave, ["one", "two"], ["three"]).into(),
        ];

        let verifier = TrustedIdentitiesVerifier::new(allowed_identities);
        let verification = verifier.verify(&identity);
        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] No enclave identity matched for:
              - MRENCLAVE: 0101010101010101010101010101010101010101010101010101010101010101
              - MRSIGNER key hash: 0202020202020202020202020202020202020202020202020202020202020202
              - ISV product ID: 3
              - ISV SVN: 4
              - advisories: IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              Searched through the following identities:
              - [ ] Both of the following must be true:
                - [ ] The MRENCLAVE should be 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, but the actual MRENCLAVE was 0101010101010101010101010101010101010101010101010101010101010101
                - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [ ] MRSIGNER all of the following must be true:
                  - [ ] The MRSIGNER key hash should be 0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c, but the actual MRSIGNER key hash was 0202020202020202020202020202020202020202020202020202020202020202
                  - [x] The ISV product ID should be 3
                  - [x] The ISV SVN should be at least 4
                - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [ ] MRSIGNER all of the following must be true:
                  - [x] The MRSIGNER key hash should be 0202020202020202020202020202020202020202020202020202020202020202
                  - [ ] The ISV product ID should be 2, but the actual ISV product ID was 3
                  - [x] The ISV SVN should be at least 4
                - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [ ] MRSIGNER all of the following must be true:
                  - [x] The MRSIGNER key hash should be 0202020202020202020202020202020202020202020202020202020202020202
                  - [x] The ISV product ID should be 3
                  - [ ] The ISV SVN should be at least 5, but the actual ISV SVN was 4
                - [x] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [x] MRSIGNER all of the following must be true:
                  - [x] The MRSIGNER key hash should be 0202020202020202020202020202020202020202020202020202020202020202
                  - [x] The ISV product ID should be 3
                  - [x] The ISV SVN should be at least 4
                - [ ] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: ConfigurationNeeded, but the actual advisories was IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [x] The MRENCLAVE should be 0101010101010101010101010101010101010101010101010101010101010101
                - [ ] The allowed advisories are IDs: {"four", "one", "three", "two"} Status: SWHardeningNeeded, but the actual advisories was IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded
              - [ ] Both of the following must be true:
                - [x] The MRENCLAVE should be 0101010101010101010101010101010101010101010101010101010101010101
                - [ ] The allowed advisories are IDs: {"one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded, but the actual advisories was IDs: {"four", "one", "three", "two"} Status: ConfigurationAndSWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
