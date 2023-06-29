// Copyright (c) 2023 The MobileCoin Foundation

//! Provides logic for verifying MRENCLAVE and MRSIGNER identities in combination with allowed
//! [`Advisories`].
//!
//! Section 3.8 of
//! [Intel SGX ECDSA QuoteLibReference DCAP API](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A63%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C468%2C0%5D)
//! documents the identity types, Strict Policy and Security Policy.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
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
