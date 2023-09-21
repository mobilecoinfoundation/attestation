// Copyright (c) 2023 The MobileCoin Foundation

//! Trait and Error for verifying certificate chains

use der::DateTime;
use x509_cert::{crl::CertificateList, Certificate};

/// Error verifying a certificate chain
#[derive(displaydoc::Display, Debug, Clone, PartialEq)]
pub enum CertificateChainVerifierError {
    /// X509 certificate not yet valid
    CertificateNotYetValid,
    /// X509 certificate has expired
    CertificateExpired,
    /// X509 certificate has been revoked
    CertificateRevoked,
    /// General error trying to verify a certificate chain
    GeneralCertificateError,
    /// Error verifying the signature
    SignatureVerification,
}

/// A trait whose implementation will verify multiple certificate chains which all use the same
/// trust anchor.
pub trait CertificateChainVerifier {
    /// Verify a certificate chain.
    ///
    /// # Returns
    /// The public signing key from the leaf certificate.
    ///
    /// # Arguments
    /// * `certificate_chain` - The certificate chain to verify.
    /// * `crls` - The certificate revocation lists to use when verifying the certificate chain.
    /// * `time` - The time to use when verifying the certificate chain. Due to implementation
    ///   details, some implementations may ignore this value and use the system time directly.
    ///   A None value for time can be used in cases where the caller is unable to provide time. In
    ///   such cases, time validation will be skipped.
    ///
    fn verify_certificate_chain<'a, 'b>(
        &self,
        certificate_chain: impl IntoIterator<Item = &'a Certificate>,
        crls: impl IntoIterator<Item = &'b CertificateList>,
        time: impl Into<Option<DateTime>>,
    ) -> Result<(), CertificateChainVerifierError>;
}
