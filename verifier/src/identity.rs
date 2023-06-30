// Copyright (c) 2023 The MobileCoin Foundation

//! Provides logic for verifying MRENCLAVE and MRSIGNER identities in combination with allowed
//! [`Advisories`].
//!
//! Section 3.8 of
//! [Intel SGX ECDSA QuoteLibReference DCAP API](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A63%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C468%2C0%5D)
//! documents the identity types, Strict Policy and Security Policy.

use crate::{Advisories, AdvisoryStatus};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::ops::Not;
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
    mr_enclave: [u8; 32],
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
        mr_enclave: &[u8; 32],
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
            mr_enclave: *mr_enclave,
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
    mr_signer: [u8; 32],
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
        mr_signer: &[u8; 32],
        product_id: u16,
        minimum_svn: u16,
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
            mr_signer: *mr_signer,
            product_id,
            minimum_svn,
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn up_to_date_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity =
            TrustedMrEnclaveIdentity::new(&[5; 32], [] as [&str; 0], [] as [&str; 0]);
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new([] as [&str; 0], AdvisoryStatus::UpToDate)
        );
    }

    #[test]
    fn config_needed_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity = TrustedMrEnclaveIdentity::new(
            &[5; 32],
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
            TrustedMrEnclaveIdentity::new(&[5; 32], [] as [&str; 0], ["what's", "up", "doc"]);
        assert_eq!(
            mr_enclave_identity.advisories(),
            Advisories::new(["what's", "up", "doc"], AdvisoryStatus::SWHardeningNeeded)
        );
    }

    #[test]
    fn config_and_sw_hardening_needed_advisories_for_mr_enclave_identity() {
        let mr_enclave_identity =
            TrustedMrEnclaveIdentity::new(&[5; 32], ["one", "two"], ["three", "four"]);
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
        let mr_signer_identity =
            TrustedMrSignerIdentity::new(&[8; 32], 9, 10, [] as [&str; 0], [] as [&str; 0]);
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new([] as [&str; 0], AdvisoryStatus::UpToDate)
        );
    }

    #[test]
    fn config_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity =
            TrustedMrSignerIdentity::new(&[8; 32], 9, 10, ["mr", "signer"], [] as [&str; 0]);
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(["mr", "signer"], AdvisoryStatus::ConfigurationNeeded)
        );
    }

    #[test]
    fn sw_hardening_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity =
            TrustedMrSignerIdentity::new(&[5; 32], 9, 10, [] as [&str; 0], ["who's", "there?"]);
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(["who's", "there?"], AdvisoryStatus::SWHardeningNeeded)
        );
    }

    #[test]
    fn config_and_sw_hardening_needed_advisories_for_mr_signer_identity() {
        let mr_signer_identity =
            TrustedMrSignerIdentity::new(&[5; 32], 9, 10, ["nine", "8"], ["seven", "6"]);
        assert_eq!(
            mr_signer_identity.advisories(),
            Advisories::new(
                ["nine", "8", "seven", "6"],
                AdvisoryStatus::ConfigurationAndSWHardeningNeeded
            )
        );
    }
}
