// Copyright (c) 2023 The MobileCoin Foundation

//! Implementation of certificate chain verification using MbedTls.

extern crate alloc;
use alloc::{string::String, vec, vec::Vec};
use core::fmt::{Debug, Formatter};
use der::{DateTime, Encode};

use ::mbedtls::{
    alloc::List as MbedtlsList,
    hash::Type as HashType,
    pk::{EcGroupId, Type as PkType},
    x509::{Certificate as MbedTlsCertificate, Crl, Profile},
};

use crate::{CertificateChainVerifier, CertificateChainVerifierError};
use x509_cert::{crl::CertificateList, Certificate};

pub type Result<T> = core::result::Result<T, Error>;

/// Error type for decoding and verifying certificates.
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum Error {
    /// An error occurred working with MbedTls: {0}
    MbedTls(mbedtls::Error),
    /// An error occurred encoding to DER: {0}
    Der(der::Error),
}

impl From<mbedtls::Error> for Error {
    fn from(src: mbedtls::Error) -> Self {
        Error::MbedTls(src)
    }
}

impl From<der::Error> for Error {
    fn from(src: der::Error) -> Self {
        Error::Der(src)
    }
}

impl From<Error> for CertificateChainVerifierError {
    fn from(error: Error) -> Self {
        match error {
            // Any error (expired, revoked, etc) in certificate chain verification comes back as
            // `X509CertVerifyFailed`
            Error::MbedTls(mbedtls::Error::X509CertVerifyFailed) => {
                CertificateChainVerifierError::SignatureVerification
            }
            _ => CertificateChainVerifierError::GeneralCertificateError,
        }
    }
}

/// A certificate chain verifier that uses MbedTls as the backend
#[derive(Debug)]
pub struct MbedTlsCertificateChainVerifier {
    trust_anchor: TrustAnchor,
}

impl MbedTlsCertificateChainVerifier {
    /// Create a new instance
    pub fn new(trust_anchor: TrustAnchor) -> Self {
        Self { trust_anchor }
    }
}

impl CertificateChainVerifier for MbedTlsCertificateChainVerifier {
    // Note: `_time` is ignored because MbedTls will either, call out to a system timer or ignore
    // time checks depending on how it's built. The common build we use, ignores time checks.
    fn verify_certificate_chain<'a, 'b>(
        &self,
        certificate_chain: impl IntoIterator<Item = &'a Certificate>,
        crls: impl IntoIterator<Item = &'b CertificateList>,
        _time: DateTime,
    ) -> core::result::Result<(), CertificateChainVerifierError> {
        let unverified = UnverifiedCertChain::try_from_certificates(certificate_chain)
            .map_err(|_| CertificateChainVerifierError::GeneralCertificateError)?;
        let crls = CertificateRevocationList::try_from_crls(crls)?;
        Ok(unverified.verify(&self.trust_anchor, crls)?)
    }
}

/// Trust anchor for a certificate chain.
#[derive(Clone)]
pub struct TrustAnchor(MbedtlsList<MbedTlsCertificate>);

impl Debug for TrustAnchor {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "TrustAnchor{{...}}")
    }
}

impl TrustAnchor {
    /// Try to get a trust anchor from a PEM encoded string.
    ///
    /// # Errors
    /// `Error::MbedTls` if the string is not valid PEM certificate.
    pub fn try_from_pem(pem: impl Into<String>) -> Result<Self> {
        let mut certs = MbedtlsList::<MbedTlsCertificate>::new();
        let mut pem = pem.into();

        // Null terminate for Mbedtls
        pem.push('\0');
        let cert = MbedTlsCertificate::from_pem(pem.as_bytes())?;
        certs.push(cert);
        Ok(Self(certs))
    }

    /// Try to get a trust anchor from DER encoded bytes.
    ///
    /// # Errors
    /// `Error::MbedTls` if the bytes are not a valid DER certificate.
    pub fn try_from_der(der: impl AsRef<[u8]>) -> Result<Self> {
        let mut certs = MbedtlsList::<MbedTlsCertificate>::new();
        let cert = MbedTlsCertificate::from_der(der.as_ref())?;
        certs.push(cert);
        Ok(Self(certs))
    }
}

/// An unverified certificate chain.
///
/// This is mostly opaque meant to be used to verify and create a
/// [`VerifiedCertChain`].
#[derive(Clone)]
struct UnverifiedCertChain(MbedtlsList<MbedTlsCertificate>);

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
    fn verify(self, trust_anchor: &TrustAnchor, mut crl: CertificateRevocationList) -> Result<()> {
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
        Ok(MbedTlsCertificate::verify_with_profile(
            &self.0,
            &trust_anchor.0,
            Some(&mut crl.0),
            Some(&profile),
            None,
        )?)
    }

    /// Try to get a certificate chain from an iterator of DER encoded byte
    /// slices.
    ///
    /// # Errors
    /// `Error::MbedTls` if one of the bytes was not valid a DER certificate.
    pub fn try_from_der<E, I>(ders: I) -> Result<Self>
    where
        I: IntoIterator<Item = E>,
        E: AsRef<[u8]>,
    {
        let mut certs = MbedtlsList::<MbedTlsCertificate>::new();
        for der in ders {
            let cert = MbedTlsCertificate::from_der(der.as_ref())?;
            certs.push(cert);
        }
        Ok(Self(certs))
    }

    /// Try to get a certificate chain from an iterator of X509Certificates
    ///
    /// # Errors
    /// `Error::MbedTls` if there is a problem decoding a certificate by mbedtls
    /// `Error::Der` if there is an error converting a certificate to DER
    pub fn try_from_certificates<'a, I>(certs: I) -> Result<Self>
    where
        I: IntoIterator<Item = &'a Certificate>,
    {
        let certs = certs
            .into_iter()
            .map(|crl| crl.to_der())
            .collect::<core::result::Result<Vec<_>, _>>()?;
        Self::try_from_der(certs)
    }
}

/// Certificate revocation list.
#[derive(Debug)]
struct CertificateRevocationList(Crl);

impl CertificateRevocationList {
    /// Try to get a set of certificate revocation lists from an iterator of
    /// DER encoded byte slices.
    ///
    /// # Errors
    /// `Error::MbedTls` if one of the slices is not a valid DER CRL.
    fn try_from_der<E, I>(ders: I) -> Result<Self>
    where
        I: IntoIterator<Item = E>,
        E: AsRef<[u8]>,
    {
        let mut crl = Crl::new();
        for der in ders {
            crl.push_from_der(der.as_ref())?;
        }
        Ok(Self(crl))
    }

    /// Try to get a set of certificate revocation lists from an iterator of `CertificateList`
    ///
    /// # Errors
    /// `Error::MbedTls` if there is a problem decoding a CRL by mbedtls
    /// `Error::Der` if there is an error converting a CRL to DER
    fn try_from_crls<'a, I>(crls: I) -> Result<Self>
    where
        I: IntoIterator<Item = &'a CertificateList>,
    {
        let crls = crls
            .into_iter()
            .map(|crl| crl.to_der())
            .collect::<core::result::Result<Vec<_>, _>>()?;
        Self::try_from_der(crls)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use der::{Decode, DecodePem};

    const LEAF_CERT: &str = include_str!("../data/tests/leaf_cert.pem");
    const PROCESSOR_CA: &str = include_str!("../data/tests/processor_ca.pem");
    const ROOT_CA: &str = include_str!("../data/tests/root_ca.pem");
    const PROCESSOR_CRL: &[u8] = include_bytes!("../data/tests/processor_crl.der");
    const ROOT_CRL: &[u8] = include_bytes!("../data/tests/root_crl.der");

    // common PKITs tests data
    const TRUST_ANCHOR_ROOT_CERTIFICATE: &[u8] =
        include_bytes!("../data/tests/pkits/certs/TrustAnchorRootCertificate.crt");
    const TRUST_ANCHOR_ROOT_CRL: &[u8] =
        include_bytes!("../data/tests/pkits/crls/TrustAnchorRootCRL.crl");
    const GOOD_CA_CERT: &[u8] = include_bytes!("../data/tests/pkits/certs/GoodCACert.crt");
    const GOOD_CA_CRL: &[u8] = include_bytes!("../data/tests/pkits/crls/GoodCACRL.crl");

    #[test]
    fn trust_anchor_from_pem() {
        assert!(TrustAnchor::try_from_pem(ROOT_CA).is_ok());
    }

    #[test]
    fn trust_anchor_from_bad_pem_fails() {
        assert!(matches!(
            TrustAnchor::try_from_pem(&ROOT_CA[1..]),
            Err(Error::MbedTls(_))
        ));
    }

    #[test]
    fn trust_anchor_from_der() {
        assert!(TrustAnchor::try_from_der(&TRUST_ANCHOR_ROOT_CERTIFICATE).is_ok());
    }

    #[test]
    fn trust_anchor_from_bad_der_fails() {
        assert!(matches!(
            TrustAnchor::try_from_der(&TRUST_ANCHOR_ROOT_CERTIFICATE[1..]),
            Err(Error::MbedTls(_))
        ));
    }

    #[test]
    fn cert_chain_from_one_der_cert() {
        let cert_chain = UnverifiedCertChain::try_from_der([TRUST_ANCHOR_ROOT_CERTIFICATE])
            .expect("failed to parse cert chain");
        let count = cert_chain.0.iter().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn cert_chain_from_multiple_der_certs() {
        let cert_chain =
            UnverifiedCertChain::try_from_der([GOOD_CA_CERT, TRUST_ANCHOR_ROOT_CERTIFICATE])
                .expect("failed to parse cert chain");
        let count = cert_chain.0.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn cert_chain_from_invalid_der_cert() {
        assert!(matches!(
            UnverifiedCertChain::try_from_der([&TRUST_ANCHOR_ROOT_CERTIFICATE[1..]]),
            Err(Error::MbedTls(_))
        ));
    }

    #[test]
    fn verify_valid_cert_chain() {
        let chain = [LEAF_CERT, PROCESSOR_CA, ROOT_CA]
            .iter()
            .map(|cert| Certificate::from_pem(cert).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_pem(ROOT_CA).expect("failed to parse root cert");
        let crls = [ROOT_CRL, PROCESSOR_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        assert!(verifier
            .verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY)
            .is_ok());
    }

    #[test]
    fn invalid_cert_chain() {
        let chain = [LEAF_CERT, ROOT_CA]
            .iter()
            .map(|cert| Certificate::from_pem(cert).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_pem(ROOT_CA).expect("failed to parse root cert");
        let crls = [ROOT_CRL, PROCESSOR_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        assert_eq!(
            verifier.verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY),
            Err(CertificateChainVerifierError::SignatureVerification)
        );
    }

    #[test]
    fn unordered_cert_chain_succeeds() {
        let chain = [PROCESSOR_CA, ROOT_CA, LEAF_CERT]
            .iter()
            .map(|cert| Certificate::from_pem(cert).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_pem(ROOT_CA).expect("failed to parse root cert");
        let crls = [ROOT_CRL, PROCESSOR_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        assert!(verifier
            .verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY)
            .is_ok());
    }

    // The below tests are from the
    // [Public Key Infrastructure Test Suite)[https://csrc.nist.gov/projects/pki-testing]
    // also known as PKITS. The numbers in the test names are the sections in
    // the test description document,
    // <https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf>
    //
    // The point of the tests are to show that we've correctly hooked up CRL
    // logic with mbedtls, not to test out mbedtls with respect to PKITS.
    #[test]
    fn missing_crl_4_4_1() {
        const NO_CRL_CA_CERT: &[u8] = include_bytes!("../data/tests/pkits/certs/NoCRLCACert.crt");
        const INVALID_MISSING_CRL_TEST1_EE: &[u8] =
            include_bytes!("../data/tests/pkits/certs/InvalidMissingCRLTest1EE.crt");
        let ders = [
            INVALID_MISSING_CRL_TEST1_EE,
            NO_CRL_CA_CERT,
            TRUST_ANCHOR_ROOT_CERTIFICATE,
        ];
        let chain = ders
            .iter()
            .map(|der| Certificate::from_der(der).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_der(TRUST_ANCHOR_ROOT_CERTIFICATE)
            .expect("failed to parse root cert");
        let crls = [TRUST_ANCHOR_ROOT_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();

        // As the name suggests, this test should fail, however Mbedtls doesn't
        // seem to conform to the RFC,
        // <https://datatracker.ietf.org/doc/html/rfc5280#section-6.3.3>
        // It's a bit hard to parse in the RFC, but when CRLs are the
        // invalidation mechanism there should be a CRL for every CA.
        //
        // > After processing such CRLs, if the revocation status has
        // > still not been determined, then return the cert_status
        // > UNDETERMINED.
        //
        // It looks like mbedtls will ignore the missing CRL and continue,
        // <https://github.com/mobilecoinfoundation/rust-mbedtls/blob/6d8fe323a3292f87a6bce4b35963d47139a583f9/mbedtls-sys/vendor/library/x509_crt.c#L2337>
        //
        // > Skip validation if no CRL for the given CA is present.
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);
        assert!(verifier
            .verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY)
            .is_ok());
    }

    #[test]
    fn invalid_revoked_ca_4_4_2() {
        const REVOKED_SUB_CA_CERT: &[u8] =
            include_bytes!("../data/tests/pkits/certs/RevokedsubCACert.crt");
        const INVALID_REVOKED_CA_TEST2_EE: &[u8] =
            include_bytes!("../data/tests/pkits/certs/InvalidRevokedCATest2EE.crt");
        const REVOKED_SUB_CA_CRL: &[u8] =
            include_bytes!("../data/tests/pkits/crls/RevokedsubCACRL.crl");
        let ders = [
            INVALID_REVOKED_CA_TEST2_EE,
            REVOKED_SUB_CA_CERT,
            GOOD_CA_CERT,
            TRUST_ANCHOR_ROOT_CERTIFICATE,
        ];
        let chain = ders
            .iter()
            .map(|der| Certificate::from_der(der).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_der(TRUST_ANCHOR_ROOT_CERTIFICATE)
            .expect("failed to parse root cert");
        let crls = [REVOKED_SUB_CA_CRL, GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);

        assert_eq!(
            verifier.verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY),
            Err(CertificateChainVerifierError::SignatureVerification)
        );
    }

    #[test]
    fn invalid_revoked_ee_4_4_3() {
        const INVALID_REVOKED_EE_TEST3_EE: &[u8] =
            include_bytes!("../data/tests/pkits/certs/InvalidRevokedEETest3EE.crt");
        let ders = [
            INVALID_REVOKED_EE_TEST3_EE,
            GOOD_CA_CERT,
            TRUST_ANCHOR_ROOT_CERTIFICATE,
        ];
        let chain = ders
            .iter()
            .map(|der| Certificate::from_der(der).expect("failed to parse cert"))
            .collect::<Vec<_>>();
        let trust_anchor = TrustAnchor::try_from_der(TRUST_ANCHOR_ROOT_CERTIFICATE)
            .expect("failed to parse root cert");
        let crls = [GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CRL]
            .iter()
            .map(|crl| CertificateList::from_der(crl).expect("failed to parse CRL"))
            .collect::<Vec<_>>();
        let verifier = MbedTlsCertificateChainVerifier::new(trust_anchor);

        assert_eq!(
            verifier.verify_certificate_chain(chain.iter(), crls.iter(), DateTime::INFINITY),
            Err(CertificateChainVerifierError::SignatureVerification)
        );
    }

    #[test]
    fn invalid_bad_crl_signature_4_4_4() {
        const BAD_CRL_SIGNATURE_CA_CRL: &[u8] =
            include_bytes!("../data/tests/pkits/crls/BadCRLSignatureCACRL.crl");
        // The CRL signature is invalid so parsing the CRL will fail
        assert!(matches!(
            CertificateRevocationList::try_from_der([
                BAD_CRL_SIGNATURE_CA_CRL,
                TRUST_ANCHOR_ROOT_CRL
            ]),
            Err(Error::MbedTls(_))
        ));
    }
}
