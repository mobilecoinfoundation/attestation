// Copyright (c) 2023 The MobileCoin Foundation

//! Verifier(s) for [`CertificationData`](`mc-sgx-dcap-types::CertificationData`).

extern crate alloc;

use super::{Error, Result};
use alloc::vec::Vec;
use core::time::Duration;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate as X509Certificate;

/// A certificate whose signature has not been verified.
#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedCertificate {
    // In order to verify the signature, we need to access the original DER
    // bytes
    der_bytes: Vec<u8>,
    pub(crate) certificate: X509Certificate,
    // The signature and key are persisted here since they are fallible
    // operations and it's more ergonomic to fail fast than fail later for a
    // bad key or signature
    signature: Signature,
    key: VerifyingKey,
}

/// A certificate whose signature has been verified.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCertificate {
    _certificate: X509Certificate,
    key: VerifyingKey,
}

impl VerifiedCertificate {
    pub(crate) fn public_key(&self) -> VerifyingKey {
        self.key
    }
}

impl UnverifiedCertificate {
    pub fn verify_self_signed(&self, unix_time: Duration) -> Result<VerifiedCertificate> {
        self.verify(&self.key, unix_time)
    }

    /// Verify the certificate signature and time are valid.
    ///
    /// # Arguments
    /// - `key` - The public key to verify the certificate signature with
    /// - `unix_time` - The duration since
    ///   [`UNIX_EPOCH`](https://doc.rust-lang.org/std/time/constant.UNIX_EPOCH.html).
    ///   This is expected to be generated by the caller using:
    ///     ```ignore
    ///     SystemTime::now().duration_since(UNIX_EPOCH)
    ///     ```
    ///   or equivalent
    pub fn verify(&self, key: &VerifyingKey, unix_time: Duration) -> Result<VerifiedCertificate> {
        self.verify_time(unix_time)?;
        self.verify_signature(key)?;

        Ok(VerifiedCertificate {
            _certificate: self.certificate.clone(),
            key: self.key,
        })
    }

    fn verify_signature(&self, key: &VerifyingKey) -> Result<()> {
        let tbs_size = u32::from(self.certificate.tbs_certificate.encoded_len()?) as usize;
        let signature_size = u32::from(self.certificate.signature.encoded_len()?) as usize;
        let algorithm_size =
            u32::from(self.certificate.signature_algorithm.encoded_len()?) as usize;
        let overall_size = u32::from(self.certificate.encoded_len()?) as usize;

        let tbs_offset = overall_size - (tbs_size + signature_size + algorithm_size);
        let tbs_contents = &self.der_bytes[tbs_offset..tbs_size + tbs_offset];
        key.verify(tbs_contents, &self.signature)
            .map_err(|_| Error::SignatureVerification)?;
        Ok(())
    }

    fn verify_time(&self, unix_time: Duration) -> Result<()> {
        let validity = &self.certificate.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration();
        let not_after = validity.not_after.to_unix_duration();

        // Per https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5 time is
        // inclusive
        if unix_time < not_before {
            Err(Error::CertificateNotYetValid)
        } else if unix_time > not_after {
            Err(Error::CertificateExpired)
        } else {
            Ok(())
        }
    }
}

/// Convert a PEM-encoded certificate into an [`UnverifiedCertificate`].
impl TryFrom<&str> for UnverifiedCertificate {
    type Error = Error;

    fn try_from(pem: &str) -> ::core::result::Result<Self, Self::Error> {
        let (_, der_bytes) = pem_rfc7468::decode_vec(pem.as_bytes())?;
        Self::try_from(&der_bytes[..])
    }
}

/// Convert a DER-encoded certificate into an [`UnverifiedCertificate`].
impl TryFrom<&[u8]> for UnverifiedCertificate {
    type Error = Error;

    fn try_from(der_bytes: &[u8]) -> ::core::result::Result<Self, Self::Error> {
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
            der_bytes: der_bytes.to_vec(),
            certificate,
            signature,
            key,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::string::ToString;
    use const_oid::ObjectIdentifier;
    use yare::parameterized;

    const LEAF_CERT: &str = include_str!("../../data/tests/leaf_cert.pem");
    const PROCESSOR_CA: &str = include_str!("../../data/tests/processor_ca.pem");
    const ROOT_CA: &str = include_str!("../../data/tests/root_ca.pem");

    #[parameterized(
        root = { ROOT_CA },
        processor = { PROCESSOR_CA },
        leaf = { LEAF_CERT },
    )]
    fn try_from_pem(pem: &str) {
        assert!(UnverifiedCertificate::try_from(pem).is_ok());
    }

    #[test]
    fn try_from_bad_pem_errors() {
        let pem = ROOT_CA.to_string();
        let bad_pem = pem.replace("-----END CERTIFICATE-----", "");

        assert!(matches!(
            UnverifiedCertificate::try_from(bad_pem.as_str()),
            Err(Error::PemDecoding(_))
        ));
    }

    #[parameterized(
        root = { ROOT_CA },
        processor = { PROCESSOR_CA },
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
            Err(Error::DerDecoding(_))
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
        let unix_time = cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        assert_eq!(cert.verify(&key, unix_time).is_ok(), true);
    }

    #[test]
    fn verify_intermediate_certificate() {
        let root = ROOT_CA;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let (_, der_bytes) = pem_rfc7468::decode_vec(PROCESSOR_CA.as_bytes())
            .expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let unix_time = cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        assert_eq!(cert.verify(&root_cert.key, unix_time).is_ok(), true);
    }

    #[test]
    fn verify_leaf_certificate() {
        let intermediate = PROCESSOR_CA;
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.as_bytes())
            .expect("Failed to decode DER from PEM");
        let intermediate_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let leaf = LEAF_CERT;
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(leaf.as_bytes()).expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let unix_time = cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        assert_eq!(cert.verify(&intermediate_cert.key, unix_time).is_ok(), true);
    }

    #[test]
    fn verify_certificate_fails_with_wrong_key() {
        let intermediate = PROCESSOR_CA;
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.as_bytes())
            .expect("Failed to decode DER from PEM");
        let intermediate_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let unix_time = intermediate_cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        // The intermediate cert should *not* be self signed so using it's key
        // should fail verification
        let key = intermediate_cert.key;

        assert_eq!(
            intermediate_cert.verify(&key, unix_time),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn verify_certificate_succeeds_at_not_before_time() {
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let key = root_cert.key;

        let unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        assert!(root_cert.verify(&key, unix_time).is_ok());
    }

    #[test]
    fn verify_certificate_succeeds_at_not_after_time() {
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let key = root_cert.key;

        let unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        assert!(root_cert.verify(&key, unix_time).is_ok());
    }

    #[test]
    fn verify_certificate_fails_for_before_time() {
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let key = root_cert.key;

        let mut unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration();

        unix_time -= Duration::new(0, 1);

        assert_eq!(
            root_cert.verify(&key, unix_time),
            Err(Error::CertificateNotYetValid)
        );
    }

    #[test]
    fn verify_certificate_fails_for_after_time() {
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let key = root_cert.key;

        let mut unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        unix_time += Duration::new(0, 1);

        assert_eq!(
            root_cert.verify(&key, unix_time),
            Err(Error::CertificateExpired)
        );
    }

    #[test]
    fn verify_self_signed_root_ca() {
        let root_cert = UnverifiedCertificate::try_from(ROOT_CA)
            .expect("Failed to decode certificate from PEM");

        let unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        assert_eq!(root_cert.verify_self_signed(unix_time).is_ok(), true);
    }

    #[test]
    fn verify_self_signed_root_ca_fails_when_expired() {
        let root_cert = UnverifiedCertificate::try_from(ROOT_CA)
            .expect("Failed to decode certificate from PEM");

        let mut unix_time = root_cert
            .certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration();

        unix_time += Duration::new(0, 1);

        assert_eq!(
            root_cert.verify_self_signed(unix_time),
            Err(Error::CertificateExpired)
        );
    }
}
