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

    const LEAF_CERT: &str = "
        -----BEGIN CERTIFICATE-----
        MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb/spRh9U8K7AT/3MAoGCCqGSM49BAMC
        MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
        DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
        BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2
        MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
        BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
        A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        j/Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl/Ts8b0dltKUW3j
        qRd+SxnPEWJ+jUw+SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY
        PHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRz
        ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2Nh
        PXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QW
        nhmVfE31MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhN
        AQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQG
        CiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQIC
        AgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4
        TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG+E0BDQECBwIBBjAQ
        BgsqhkiG+E0BDQECCAIBADAQBgsqhkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQEC
        CgIBADAQBgsqhkiG+E0BDQECCwIBADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG
        +E0BDQECDQIBADAQBgsqhkiG+E0BDQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQ
        BgsqhkiG+E0BDQECEAIBADAQBgsqhkiG+E0BDQECEQIBCzAfBgsqhkiG+E0BDQEC
        EgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0B
        DQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA
        1XJi0ht4hw8YtC6E4rYscp9bF+7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4
        V8Zu8NFCC4vFg+cZqO6QfezEaA==
        -----END CERTIFICATE-----
        ";

    const INTERMEDIATE_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICmDCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
        MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
        b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
        CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHExIzAh
        BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl
        bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB
        MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg
        tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i
        HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww
        UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl
        cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFNDo
        qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
        AQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIQCJgTbtVqOyZ1m3jqiAXM6QYa6r5sWS
        4y/G7y8uIJGxdwIgRqPvBSKzzQagBLQq5s5A70pdoiaRJ8z/0uDz4NgV91k=
        -----END CERTIFICATE-----
        ";

    const ROOT_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
        aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
        cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
        BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
        A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
        aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
        AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
        1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
        uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
        MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
        ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
        Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
        KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
        AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
        -----END CERTIFICATE-----
        ";

    #[parameterized(
        root = { ROOT_CA },
        intermediate = { INTERMEDIATE_CA },
        leaf = { LEAF_CERT },
    )]
    fn try_from_der(pem: &str) {
        let dedent = textwrap::dedent(pem);
        let (_, der_bytes) = pem_rfc7468::decode_vec(dedent.trim().as_bytes())
            .expect("Failed to decode DER from PEM");
        assert!(UnverifiedCertificate::try_from(der_bytes.as_slice()).is_ok());
    }

    #[test]
    fn certificate_decoding_error_with_invalid_der() {
        let pem = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(pem.trim().as_bytes()).expect("Failed to decode DER from PEM");
        assert!(matches!(
            UnverifiedCertificate::try_from(&der_bytes.as_slice()[1..]),
            Err(Error::CertificateDecoding(_))
        ));
    }

    #[test]
    fn signature_decoding_error() {
        let pem = textwrap::dedent(ROOT_CA);
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(pem.trim().as_bytes()).expect("Failed to decode DER from PEM");

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
        let pem = textwrap::dedent(ROOT_CA);
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(pem.trim().as_bytes()).expect("Failed to decode DER from PEM");

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
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        // The root certificate is self-signed, ideally this key will be stored
        // by the application.
        let key = cert.key;

        assert_eq!(cert.verify(&key).is_ok(), true);
    }

    #[test]
    fn verify_intermediate_certificate() {
        let root = textwrap::dedent(ROOT_CA);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(root.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let root_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let intermediate = textwrap::dedent(INTERMEDIATE_CA);
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.trim().as_bytes())
            .expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        assert_eq!(cert.verify(&root_cert.key).is_ok(), true);
    }

    #[test]
    fn verify_leaf_certificate() {
        let intermediate = textwrap::dedent(INTERMEDIATE_CA);
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.trim().as_bytes())
            .expect("Failed to decode DER from PEM");
        let intermediate_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        let leaf = textwrap::dedent(LEAF_CERT);
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(leaf.trim().as_bytes()).expect("Failed to decode DER from PEM");
        let cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
            .expect("Failed to decode certificate from DER");

        assert_eq!(cert.verify(&intermediate_cert.key).is_ok(), true);
    }

    #[test]
    fn verify_certificate_fails_with_wrong_key() {
        let intermediate = textwrap::dedent(INTERMEDIATE_CA);
        let (_, der_bytes) = pem_rfc7468::decode_vec(intermediate.trim().as_bytes())
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
