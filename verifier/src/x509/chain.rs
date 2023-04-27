// Copyright (c) 2023 The MobileCoin Foundation

//! Support for verifying certificate chains

extern crate alloc;

use super::certs::UnverifiedCertificate;
use super::Result;
use crate::x509::certs::VerifiedCertificate;
use alloc::vec::Vec;
use core::time::Duration;
use p256::ecdsa::VerifyingKey;

/// An X509 certificate chain. This is a valid path from the trust root to the
/// leaf certificate.
pub struct CertificateChain {
    certificates: Vec<UnverifiedCertificate>,
}

impl CertificateChain {
    /// Create a new certificate chain from a path from a trust root to the
    /// leaf certificate.
    ///
    /// A certificate chain without a valid path will result in errors for
    /// functions like [`CertificateChain::signing_key`].
    pub fn new(certificates: Vec<UnverifiedCertificate>) -> Self {
        Self { certificates }
    }

    /// Returning the signing key from the leaf certificate
    ///
    /// The chain will be verified against the `trust_root` and the `unix_time`.
    pub fn signing_key(
        &self,
        trust_root: VerifiedCertificate,
        unix_time: Duration,
    ) -> Result<VerifyingKey> {
        let mut key = trust_root.public_key();
        for cert in &self.certificates {
            let verified_cert = cert.verify(&key, unix_time)?;
            key = verified_cert.public_key();
        }
        Ok(key)
    }
}

#[cfg(test)]
mod test {
    use super::super::Error;
    use super::*;

    use x509_cert::der::Decode;
    use x509_cert::Certificate as X509Certificate;
    use yare::parameterized;

    const LEAF_CERT: &str = include_str!("../../data/tests/leaf_cert.pem");
    const PROCESSOR_CA: &str = include_str!("../../data/tests/processor_ca.pem");
    const ROOT_CA: &str = include_str!("../../data/tests/root_ca.pem");

    fn key_and_start_time(cert: &str) -> (VerifyingKey, Duration) {
        let (_, der_bytes) = pem_rfc7468::decode_vec(cert.as_bytes()).expect("Failed decoding PEM");
        let cert = X509Certificate::from_der(der_bytes.as_slice()).expect("Falied decoding DER");

        // The leaf certificate should have the narrowest time range.
        let unix_time = cert.tbs_certificate.validity.not_before.to_unix_duration();
        let key = VerifyingKey::from_sec1_bytes(
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .expect("Failed decoding key"),
        )
        .expect("Failed decoding key");

        (key, unix_time)
    }

    #[parameterized(
        full_chain = { &[ROOT_CA, PROCESSOR_CA, LEAF_CERT] },
        to_intermediate = { &[ROOT_CA, PROCESSOR_CA] },
        only_root = { &[ROOT_CA] },
    )]
    fn signing_key_from_certificate_chain(pem_chain: &[&str]) {
        let certs = pem_chain
            .iter()
            .map(|pem| UnverifiedCertificate::try_from(*pem).expect("Failed decoding pem"))
            .collect::<Vec<_>>();

        let end = pem_chain
            .last()
            .expect("Should be at least one certificate");
        let (expected_key, unix_time) = key_and_start_time(end);

        let chain = CertificateChain::new(certs);
        let unverified_root =
            UnverifiedCertificate::try_from(ROOT_CA).expect("Failed decoding pem");
        let root = unverified_root
            .verify_self_signed(unix_time)
            .expect("Failed verifying root certificate");

        let signing_key = chain
            .signing_key(root, unix_time)
            .expect("Failed getting signing key");
        assert_eq!(signing_key, expected_key);
    }

    #[test]
    fn signing_key_fails_when_outside_valid_time() {
        let pem_chain = [ROOT_CA, PROCESSOR_CA, LEAF_CERT];
        let certs = pem_chain
            .iter()
            .map(|pem| UnverifiedCertificate::try_from(*pem).expect("Failed decoding pem"))
            .collect::<Vec<_>>();

        let (_, mut unix_time) = key_and_start_time(LEAF_CERT);

        unix_time -= Duration::from_nanos(1);

        let chain = CertificateChain::new(certs);
        let unverified_root =
            UnverifiedCertificate::try_from(ROOT_CA).expect("Failed decoding pem");
        let root = unverified_root
            .verify_self_signed(unix_time)
            .expect("Failed verifying root certificate");
        assert_eq!(
            chain.signing_key(root, unix_time),
            Err(Error::CertificateNotYetValid)
        );
    }

    #[test]
    fn cert_chain_out_of_order_fails() {
        let pem_chain = [ROOT_CA, LEAF_CERT, PROCESSOR_CA];
        let certs = pem_chain
            .iter()
            .map(|pem| UnverifiedCertificate::try_from(*pem).expect("Failed decoding pem"))
            .collect::<Vec<_>>();

        let (_, unix_time) = key_and_start_time(LEAF_CERT);

        let chain = CertificateChain::new(certs);
        let unverified_root =
            UnverifiedCertificate::try_from(ROOT_CA).expect("Failed decoding pem");
        let root = unverified_root
            .verify_self_signed(unix_time)
            .expect("Failed verifying root certificate");
        assert_eq!(
            chain.signing_key(root, unix_time),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn cert_chain_missing_intermediate_ca_fails() {
        let pem_chain = [ROOT_CA, LEAF_CERT];
        let certs = pem_chain
            .iter()
            .map(|pem| UnverifiedCertificate::try_from(*pem).expect("Failed decoding pem"))
            .collect::<Vec<_>>();

        let (_, unix_time) = key_and_start_time(LEAF_CERT);

        let chain = CertificateChain::new(certs);
        let unverified_root =
            UnverifiedCertificate::try_from(ROOT_CA).expect("Failed decoding pem");
        let root = unverified_root
            .verify_self_signed(unix_time)
            .expect("Failed verifying root certificate");
        assert_eq!(
            chain.signing_key(root, unix_time),
            Err(Error::SignatureVerification)
        );
    }
}
