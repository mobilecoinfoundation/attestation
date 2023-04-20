// Copyright (c) 2023 The MobileCoin Foundation

//! Verifier(s) for [`CertificationData`]

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate as X509Certificate;

/// Offset from the start of a certificate to the "to be signed" (TBS) portion
/// of the certificate.
const TBS_OFFSET: usize = 4;

pub type Result<T> = core::result::Result<T, Error>;

/// Error type for decoding and verifying certificates.
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum Error {
    /// An error occurred decoding the signature from a certificate
    SignatureDecoding,
    /// The certification signature does not match with the verifying key
    SignatureVerification,
    /// An error occurred decoding the certificate
    CertificateDecoding(x509_cert::der::Error),
    /// An error occurred decoding the key from a certificate
    KeyDecoding,
}

impl From<x509_cert::der::Error> for Error {
    fn from(src: x509_cert::der::Error) -> Self {
        Error::CertificateDecoding(src)
    }
}

/// A certificate whose signature has not been verified.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedCertificate<'a> {
    // In order to verify the signature, we need to access the original DER
    // bytes
    der_bytes: &'a [u8],
    certificate: X509Certificate,
    // The signature and key are persisted here since they are fallible
    // operations and it's more ergonomic to fail fast than fail later for a
    // bad key or signature
    signature: Signature,
    key: VerifyingKey,
}

/// A certificate whose signature has been verified.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCertificate<'a> {
    _der_bytes: &'a [u8],
    _certificate: X509Certificate,
    _signature: Signature,
    _key: VerifyingKey,
}

impl<'a> UnverifiedCertificate<'a> {
    /// Verify the certificate signature.
    pub fn verify(self, key: &VerifyingKey) -> Result<VerifiedCertificate<'a>> {
        let tbs_length = self.certificate.tbs_certificate.encoded_len()?;
        let tbs_size = u32::from(tbs_length) as usize;
        let tbs_contents = &self.der_bytes[TBS_OFFSET..tbs_size + TBS_OFFSET];
        key.verify(tbs_contents, &self.signature)
            .map_err(|_| Error::SignatureVerification)?;
        Ok(VerifiedCertificate {
            _der_bytes: self.der_bytes,
            _certificate: self.certificate,
            _signature: self.signature,
            _key: self.key,
        })
    }
}

/// Convert a DER-encoded certificate into an [`UnverifiedCertificate`].
impl<'a> TryFrom<&'a [u8]> for UnverifiedCertificate<'a> {
    type Error = Error;

    fn try_from(der_bytes: &'a [u8]) -> ::core::result::Result<Self, Self::Error> {
        let certificate = X509Certificate::from_der(der_bytes)?;
        let signature_bytes = certificate
            .signature
            .as_bytes()
            .ok_or(Error::SignatureDecoding)?;
        let signature =
            Signature::from_der(signature_bytes).map_err(|_| Error::SignatureDecoding)?;
        let key = VerifyingKey::from_sec1_bytes(
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or(Error::KeyDecoding)?,
        )
        .map_err(|_| Error::KeyDecoding)?;
        Ok(UnverifiedCertificate {
            der_bytes,
            certificate,
            signature,
            key,
        })
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use const_oid::ObjectIdentifier;
    use yare::parameterized;

    const LEAF_CERT: &str = include_str!("../data/tests/leaf_cert.pem");
    const INTERMEDIATE_CA: &str = include_str!("../data/tests/intermediate_ca.pem");
    const ROOT_CA: &str = include_str!("../data/tests/root_ca.pem");

    #[parameterized(
        root = { ROOT_CA },
        intermediate = { INTERMEDIATE_CA },
        leaf = { LEAF_CERT },
    )]
    fn try_from_der(pem: &str) {
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(pem.as_bytes()).expect("Failed to decode DER from PEM");
        assert!(UnverifiedCertificate::try_from(der_bytes.as_slice()).is_ok());
    }

    #[test]
    fn certificate_decoding_error_with_invalid_der() {
        let pem = ROOT_CA;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(pem.as_bytes()).expect("Failed to decode DER from PEM");
        assert!(matches!(
            UnverifiedCertificate::try_from(&der_bytes.as_slice()[1..]),
            Err(Error::CertificateDecoding(_))
        ));
    }

    #[test]
    fn signature_decoding_error() {
        let pem = ROOT_CA;
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(pem.as_bytes()).expect("Failed to decode DER from PEM");

        // The signature is and the end of the certificate.
        // If iether of the points are 0 it will fail to decode so we force the
        // last point to 0
        let last_point = der_bytes.len() - 32;
        der_bytes[last_point..].copy_from_slice(&[0; 32]);

        assert_eq!(
            UnverifiedCertificate::try_from(der_bytes.as_slice()),
            Err(Error::SignatureDecoding)
        );
    }

    #[test]
    fn key_decoding_error() {
        let pem = ROOT_CA;
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(pem.as_bytes()).expect("Failed to decode DER from PEM");

        // There isn't a good way to get the offset to the key, so we look for
        // the bytes that represent the key object identifier (OID)
        let key_oid = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
        let key_oid_bytes = key_oid.as_bytes();
        let key_oid_offset = der_bytes
            .windows(key_oid_bytes.len())
            .position(|window| window == key_oid_bytes)
            .expect("Failed to find key OID");

        // 2 Bytes for the key tag [TYPE, SIZE]
        let key_offset = key_oid_offset + key_oid_bytes.len() + 2;
        let key_end = key_offset + 64;
        der_bytes[key_offset..key_end].copy_from_slice(&[0; 64]);

        assert_eq!(
            UnverifiedCertificate::try_from(der_bytes.as_slice()),
            Err(Error::KeyDecoding)
        );
    }

    #[test]
    fn verify_root_certificate() {
        let root = ROOT_CA;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.as_bytes()).expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        // The root certificate is self-signed, ideally this key will be stored
        // by the application.
        let key = cert.key;

        assert_eq!(cert.verify(&key).is_ok(), true);
    }

    #[test]
    fn verify_intermediate_certificate() {
        let root = ROOT_CA;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let intermediate = INTERMEDIATE_CA;
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.as_bytes())
            .expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        assert_eq!(cert.verify(&root_cert.key).is_ok(), true);
    }

    #[test]
    fn verify_leaf_certificate() {
        let intermediate = INTERMEDIATE_CA;
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.as_bytes())
            .expect("Failed to decode DER from PEM");
        let intermediate_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let leaf = LEAF_CERT;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(leaf.as_bytes()).expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        assert_eq!(cert.verify(&intermediate_cert.key).is_ok(), true);
    }

    #[test]
    fn verify_certificate_fails_with_wrong_key() {
        let intermediate = INTERMEDIATE_CA;
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.as_bytes())
            .expect("Failed to decode DER from PEM");
        let intermediate_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        // The intermediate cert should *not* be self signed so using it's key
        // should fail verification
        let key = intermediate_cert.key;

        assert_eq!(
            intermediate_cert.verify(&key),
            Err(Error::SignatureVerification)
        );
    }
}
