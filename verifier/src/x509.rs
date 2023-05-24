// Copyright (c) 2023 The MobileCoin Foundation

extern crate alloc;
use alloc::string::String;
use alloc::vec;
use core::fmt::{Debug, Formatter};

use mbedtls::{
    alloc::List as MbedtlsList,
    hash::Type as HashType,
    pk::{EcGroupId, Type as PkType},
    x509::{Certificate, Profile},
};

pub type Result<T> = core::result::Result<T, Error>;

/// Error type for decoding and verifying certificates.
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum Error {
    /// An error occurred working with MbedTls: {0}
    MbedTls(mbedtls::Error),
}

impl From<mbedtls::Error> for Error {
    fn from(src: mbedtls::Error) -> Self {
        Error::MbedTls(src)
    }
}

/// Trust anchor for a certificate chain.
#[derive(Clone)]
pub struct TrustAnchor(MbedtlsList<Certificate>);

impl Debug for TrustAnchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "TrustAnchor{{...}}")
    }
}

/// Try to get a trust anchor from a PEM-encoded string.
///
/// # Errors
/// `Error::MbedTls` if the string is not valid PEM certificate.
impl TryFrom<&str> for TrustAnchor {
    type Error = Error;

    fn try_from(pem: &str) -> Result<Self> {
        Self::try_from(String::from(pem))
    }
}

/// Try to get a trust anchor from a PEM-encoded string.
///
/// # Errors
/// `Error::MbedTls` if the string is not valid PEM certificate.
impl TryFrom<String> for TrustAnchor {
    type Error = Error;

    fn try_from(mut pem: String) -> Result<Self> {
        // Null terminate for Mbedtls
        pem.push('\0');
        let certs = Certificate::from_pem_multiple(pem.as_bytes())?;
        Ok(Self(certs))
    }
}

/// An unverified certificate chain.
///
/// This is mostly opaque meant to be used to verify and create a
/// [`VerifiedCertChain`].
#[derive(Clone)]
pub struct UnverifiedCertChain(MbedtlsList<Certificate>);

impl Debug for UnverifiedCertChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "UnverifiedCertChain{{...}}")
    }
}

impl UnverifiedCertChain {
    /// Verify the certificate chain is valid for the given `trust_anchor`.
    ///
    /// # Errors
    /// `Error::MbedTls` if the certificate chain is not valid.
    pub fn verify(self, trust_anchor: &TrustAnchor) -> Result<VerifiedCertChain> {
        let profile = Profile::new(
            vec![HashType::Sha256, HashType::Sha384, HashType::Sha512],
            // The note on `PkType::Ecdsa` is a lie:
            //
            // > This type is never returned by the mbedTLS key parsing routines
            //
            // It comes back when using the Intel cert chain.
            vec![PkType::Rsa, PkType::Eckey, PkType::Ecdsa],
            vec![
                EcGroupId::Curve25519,
                EcGroupId::SecP256K1,
                EcGroupId::SecP256R1,
                EcGroupId::SecP384R1,
                EcGroupId::SecP521R1,
            ],
            2048,
        );
        Certificate::verify_with_profile(&self.0, &trust_anchor.0, None, Some(&profile), None)?;
        Ok(VerifiedCertChain(self.0))
    }
}

/// Try to get a certificate chain from a PEM-encoded string.
///
/// # Errors
/// `Error::MbedTls` if the string is not valid PEM certificate(s).
impl TryFrom<&str> for UnverifiedCertChain {
    type Error = Error;

    fn try_from(pem: &str) -> Result<Self> {
        Self::try_from(String::from(pem))
    }
}

/// Try to get a certificate chain from a PEM-encoded string.
///
/// # Errors
/// `Error::MbedTls` if the string is not valid PEM certificate(s).
impl TryFrom<String> for UnverifiedCertChain {
    type Error = Error;

    fn try_from(mut pem: String) -> Result<Self> {
        // Null terminate for Mbedtls
        pem.push('\0');
        let certs = Certificate::from_pem_multiple(pem.as_bytes())?;
        Ok(Self(certs))
    }
}

/// A verified certificate chain.
///
/// See [`UnverifiedCertChain::verify`] for creating one.
pub struct VerifiedCertChain(MbedtlsList<Certificate>);

impl Debug for VerifiedCertChain {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "VerifiedCertChain{{...}}")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::format;

    const LEAF_CERT: &str = include_str!("../data/tests/leaf_cert.pem");
    const PROCESSOR_CA: &str = include_str!("../data/tests/processor_ca.pem");
    const ROOT_CA: &str = include_str!("../data/tests/root_ca.pem");

    #[test]
    fn cert_chain_from_one_pem_cert() {
        let cert_chain =
            UnverifiedCertChain::try_from(LEAF_CERT).expect("failed to parse cert chain");
        // Counting manually, because `MbedtlsList` is a linked list without
        // `len()` method.
        let count = cert_chain.0.iter().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn cert_chain_from_two_pem_certs() {
        let raw_pems = format!("{LEAF_CERT}\n{PROCESSOR_CA}");
        let cert_chain =
            UnverifiedCertChain::try_from(raw_pems.as_str()).expect("failed to parse cert chain");
        let count = cert_chain.0.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn cert_chain_from_invalid_pem_cert() {
        assert!(matches!(
            UnverifiedCertChain::try_from(&LEAF_CERT[1..]),
            Err(Error::MbedTls(_))
        ));
    }

    #[test]
    fn verify_valid_cert_chain() {
        let raw_pems = format!("{LEAF_CERT}\n{PROCESSOR_CA}\n{ROOT_CA}");
        let cert_chain =
            UnverifiedCertChain::try_from(raw_pems.as_str()).expect("failed to parse cert chain");
        let trust_anchor = TrustAnchor::try_from(ROOT_CA).expect("failed to parse root cert");
        assert!(cert_chain.verify(&trust_anchor).is_ok());
    }

    #[test]
    fn invalid_cert_chain() {
        let raw_pems = format!("{LEAF_CERT}\n{ROOT_CA}");
        let cert_chain =
            UnverifiedCertChain::try_from(raw_pems.as_str()).expect("failed to parse cert chain");
        let trust_anchor = TrustAnchor::try_from(ROOT_CA).expect("failed to parse root cert");
        assert!(matches!(
            cert_chain.verify(&trust_anchor),
            Err(Error::MbedTls(_))
        ));
    }

    #[test]
    fn unordered_cert_chain_succeeds() {
        let raw_pems = format!("{PROCESSOR_CA}\n{ROOT_CA}\n{LEAF_CERT}");
        let cert_chain =
            UnverifiedCertChain::try_from(raw_pems.as_str()).expect("failed to parse cert chain");
        let trust_anchor = TrustAnchor::try_from(ROOT_CA).expect("failed to parse root cert");
        assert!(cert_chain.verify(&trust_anchor).is_ok());
    }
}
