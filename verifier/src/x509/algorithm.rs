// Copyright (c) 2023 The MobileCoin Foundation

//! Algorithm data types used in x509 certificate logic
//!
extern crate alloc;

use super::{Error, Result};
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use p256::ecdsa;
use p256::ecdsa::signature::Verifier;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::sha2::Digest;
use rsa::sha2::Sha256;
use rsa::Pkcs1v15Sign;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

const OID_PKCS1_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_PKCS1_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_SIG_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Public key used in PKI signature verification
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PublicKey {
    /// Elliptic curve public key
    Ecdsa(ecdsa::VerifyingKey),
    /// RSA public key
    Rsa(rsa::RsaPublicKey),
}

impl PublicKey {
    /// Verify the `message` and `signature` match this [`PublicKey`]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        match self {
            PublicKey::Ecdsa(key) => match signature {
                Signature::Ecdsa(sig) => key
                    .verify(message, sig)
                    .map_err(|_| Error::SignatureVerification),
                _ => Err(Error::SignatureVerification),
            },
            PublicKey::Rsa(key) => match signature {
                Signature::Rsa(sig) => {
                    let scheme = Pkcs1v15Sign::new::<Sha256>();
                    let hashed = Sha256::digest(message);
                    key.verify(scheme, &hashed, sig)
                        .map_err(|_| Error::SignatureVerification)
                }
                _ => Err(Error::SignatureVerification),
            },
        }
    }
}

/// Create a [`PublicKey`] from a [`SubjectPublicKeyInfoOwned`]
impl TryFrom<&SubjectPublicKeyInfoOwned> for PublicKey {
    type Error = Error;

    fn try_from(value: &SubjectPublicKeyInfoOwned) -> core::result::Result<Self, Self::Error> {
        let bytes = value
            .subject_public_key
            .as_bytes()
            .ok_or(Error::KeyDecoding)?;
        match value.algorithm.oid {
            OID_EC_PUBLIC_KEY => {
                let key =
                    ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::KeyDecoding)?;
                Ok(PublicKey::Ecdsa(key))
            }
            OID_PKCS1_RSA_ENCRYPTION => {
                let key =
                    rsa::RsaPublicKey::from_pkcs1_der(bytes).map_err(|_| Error::KeyDecoding)?;
                Ok(PublicKey::Rsa(key))
            }
            _ => Err(Error::KeyDecoding),
        }
    }
}

/// Signature used in PKI verification
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Signature {
    /// Elliptic curve signature
    Ecdsa(ecdsa::Signature),
    /// RSA signature
    Rsa(Vec<u8>),
}

impl Signature {
    /// Create a [`Signature`] from the `algorithm` and `signature` bytes
    pub fn try_from_algorithm_and_signature(
        algorithm: &AlgorithmIdentifierOwned,
        signature: &[u8],
    ) -> Result<Self> {
        match algorithm.oid {
            OID_SIG_ECDSA_WITH_SHA256 => {
                let sig =
                    ecdsa::Signature::from_der(signature).map_err(|_| Error::SignatureDecoding)?;
                Ok(Signature::Ecdsa(sig))
            }
            OID_PKCS1_SHA256_WITH_RSA => Ok(Signature::Rsa(signature.to_vec())),
            _ => Err(Error::SignatureDecoding),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::x509::Error::SignatureDecoding;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use x509_cert::der::asn1::BitString;
    use x509_cert::der::DecodePem;
    use x509_cert::spki::AlgorithmIdentifier;
    use yare::parameterized;

    const P256_KEY_1: &str = include_str!("../../data/tests/pub_keys/p256_key_1.pem");
    const P256_KEY_2: &str = include_str!("../../data/tests/pub_keys/p256_key_2.pem");
    const P256_KEY_3: &str = include_str!("../../data/tests/pub_keys/p256_key_3.pem");
    const RSA_KEY_1: &str = include_str!("../../data/tests/pub_keys/rsa_key_1.pem");
    const RSA_KEY_2: &str = include_str!("../../data/tests/pub_keys/rsa_key_2.pem");
    const RSA_KEY_3: &str = include_str!("../../data/tests/pub_keys/rsa_key_3.pem");

    // Warning one should not copy this size for production code without
    // understanding the security implications.
    // This size is chosen to be small so that the tests run quickly.
    const RSA_KEY_BITS: usize = 512;

    #[parameterized(
        key_1 = { P256_KEY_1 },
        key_2 = { P256_KEY_2 },
        key_3 = { P256_KEY_3 },
    )]
    fn ecdsa_key_from_subject_public_key(pem: &str) {
        let subject_public_key =
            SubjectPublicKeyInfoOwned::from_pem(pem).expect("Failed to decode key");
        let bytes = subject_public_key
            .subject_public_key
            .as_bytes()
            .expect("Failed to get bytes");
        let key = VerifyingKey::from_sec1_bytes(bytes).expect("Failed to decode key");

        assert_eq!(
            PublicKey::try_from(&subject_public_key),
            Ok(PublicKey::Ecdsa(key))
        );
    }

    #[test]
    fn ecdsa_key_with_invalid_bytes_fails() {
        let mut subject_public_key =
            SubjectPublicKeyInfoOwned::from_pem(P256_KEY_1).expect("Failed to decode key");
        let mut bytes = subject_public_key
            .subject_public_key
            .as_bytes()
            .expect("Failed to get bytes")
            .to_vec();

        // The first byte is a tag for SEC1. Changing it's value will cause a
        // decoding error.
        bytes[0] -= 1;

        subject_public_key.subject_public_key =
            BitString::from_bytes(&bytes).expect("Failed to create bit string");

        assert_eq!(
            PublicKey::try_from(&subject_public_key),
            Err(Error::KeyDecoding)
        );
    }

    #[parameterized(
        seed_1 = { 1 },
        seed_2 = { 2 },
        seed_3 = { 3 },
    )]
    fn ecdsa_verify(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key = PublicKey::Ecdsa(*verifying_key);

        let message = b"Hello, world!";

        let ecdsa_signature = signing_key.sign(message);
        let signature = Signature::Ecdsa(ecdsa_signature);

        assert_eq!(public_key.verify(message, &signature), Ok(()));
    }

    #[test]
    fn ecdsa_wrong_signature_fails() {
        let mut rng = StdRng::seed_from_u64(0);
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let public_key = PublicKey::Ecdsa(*verifying_key);

        let message = b"Hello, world!";

        let ecdsa_signature = signing_key.sign(message);
        let signature = Signature::Ecdsa(ecdsa_signature);

        // Not missing `!` at end of message
        assert_eq!(
            public_key.verify(b"Hello, world", &signature),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn ecdsa_wrong_signature_kind_fails() {
        let mut rng = StdRng::seed_from_u64(0);
        let ecdsa_key = SigningKey::random(&mut rng);
        let verifying_key = ecdsa_key.verifying_key();
        let public_key = PublicKey::Ecdsa(*verifying_key);

        let bits = RSA_KEY_BITS;
        let signing_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let message = b"Hello, world!";

        let scheme = Pkcs1v15Sign::new::<Sha256>();
        let digest = Sha256::digest(message);
        let rsa_signature = signing_key.sign(scheme, &digest).expect("failed to sign");
        let signature = Signature::Rsa(rsa_signature);

        assert_eq!(
            public_key.verify(message, &signature),
            Err(Error::SignatureVerification)
        );
    }

    #[parameterized(
    key_1 = { RSA_KEY_1 },
    key_2 = { RSA_KEY_2 },
    key_3 = { RSA_KEY_3 },
    )]
    fn rsa_key_from_subject_public_key(pem: &str) {
        let subject_public_key =
            SubjectPublicKeyInfoOwned::from_pem(pem).expect("Failed to decode key");
        let bytes = subject_public_key
            .subject_public_key
            .as_bytes()
            .expect("Failed to get bytes");
        let key = rsa::RsaPublicKey::from_pkcs1_der(bytes).expect("Failed to decode key");

        assert_eq!(
            PublicKey::try_from(&subject_public_key),
            Ok(PublicKey::Rsa(key))
        );
    }

    #[test]
    fn rsa_key_with_invalid_bytes_fails() {
        let mut subject_public_key =
            SubjectPublicKeyInfoOwned::from_pem(RSA_KEY_1).expect("Failed to decode key");
        let mut bytes = subject_public_key
            .subject_public_key
            .as_bytes()
            .expect("Failed to get bytes")
            .to_vec();

        // The first byte is a tag for DER. Changing it's value will cause a
        // decoding error.
        bytes[0] -= 1;

        subject_public_key.subject_public_key =
            BitString::from_bytes(&bytes).expect("Failed to create bit string");

        assert_eq!(
            PublicKey::try_from(&subject_public_key),
            Err(Error::KeyDecoding)
        );
    }

    #[test]
    fn key_from_unsupported_oid_fails() {
        let mut subject_public_key =
            SubjectPublicKeyInfoOwned::from_pem(RSA_KEY_1).expect("Failed to decode key");

        subject_public_key.algorithm = AlgorithmIdentifier {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.2"),
            parameters: None,
        };

        assert_eq!(
            PublicKey::try_from(&subject_public_key),
            Err(Error::KeyDecoding)
        );
    }

    #[parameterized(
        seed_1 = { 1 },
        seed_2 = { 2 },
        seed_3 = { 3 },
    )]
    fn rsa_verify(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let bits = RSA_KEY_BITS;
        let signing_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let verifying_key = RsaPublicKey::from(&signing_key);
        let public_key = PublicKey::Rsa(verifying_key);

        let message = b"Hello, world!";
        let digest = Sha256::digest(message);

        let scheme = Pkcs1v15Sign::new::<Sha256>();
        let rsa_signature = signing_key.sign(scheme, &digest).expect("failed to sign");
        let signature = Signature::Rsa(rsa_signature);

        assert_eq!(public_key.verify(message, &signature), Ok(()));
    }

    #[test]
    fn rsa_wrong_signature_fails() {
        let mut rng = StdRng::seed_from_u64(0);
        let bits = RSA_KEY_BITS;
        let signing_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let verifying_key = RsaPublicKey::from(&signing_key);
        let public_key = PublicKey::Rsa(verifying_key);

        let message = b"Hello, world!";
        let digest = Sha256::digest(message);

        let scheme = Pkcs1v15Sign::new::<Sha256>();
        let rsa_signature = signing_key.sign(scheme, &digest).expect("failed to sign");
        let signature = Signature::Rsa(rsa_signature);

        // Note the lower case 'h' in "hello, world!"
        assert_eq!(
            public_key.verify(b"hello, world!", &signature),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn rsa_wrong_signature_kind_fails() {
        let mut rng = StdRng::seed_from_u64(0);
        let bits = RSA_KEY_BITS;
        let rsa_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let verifying_key = RsaPublicKey::from(&rsa_key);
        let public_key = PublicKey::Rsa(verifying_key);

        let signing_key = SigningKey::random(&mut rng);

        let message = b"Hello, world!";

        let ecdsa_signature = signing_key.sign(message);
        let signature = Signature::Ecdsa(ecdsa_signature);

        assert_eq!(
            public_key.verify(message, &signature),
            Err(Error::SignatureVerification)
        );
    }

    #[parameterized(
        seed_1 = { 1 },
        seed_2 = { 2 },
        seed_3 = { 3 },
    )]
    fn ecdsa_signature_from_algorithm_and_bytes(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let signing_key = SigningKey::random(&mut rng);
        let message = b"Goodbye, moon!";

        let ecdsa_signature = signing_key.sign(message);
        let expected_signature = Signature::Ecdsa(ecdsa_signature);
        let der_signature = ecdsa_signature.to_der();

        let algorithm = AlgorithmIdentifierOwned {
            oid: OID_SIG_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signature =
            Signature::try_from_algorithm_and_signature(&algorithm, der_signature.as_bytes());
        assert_eq!(signature, Ok(expected_signature));
    }

    #[test]
    fn fail_to_decode_ecdsa_signature() {
        let mut rng = StdRng::seed_from_u64(1);
        let signing_key = SigningKey::random(&mut rng);
        let message = b"Goodbye, moon!";

        let ecdsa_signature: ecdsa::Signature = signing_key.sign(message);
        let der_signature = ecdsa_signature.to_der();
        let mut bytes = der_signature.as_bytes().to_vec();

        // First byte is a DER tag byte changing will cause a decoding error.
        bytes[0] += 1;

        let algorithm = AlgorithmIdentifierOwned {
            oid: OID_SIG_ECDSA_WITH_SHA256,
            parameters: None,
        };
        let signature = Signature::try_from_algorithm_and_signature(&algorithm, &bytes);
        assert_eq!(signature, Err(Error::SignatureDecoding));
    }

    #[test]
    fn signature_from_unsupported_algorithm() {
        let mut rng = StdRng::seed_from_u64(1);
        let signing_key = SigningKey::random(&mut rng);
        let message = b"Goodbye, moon!";

        let ecdsa_signature: ecdsa::Signature = signing_key.sign(message);
        let der_signature = ecdsa_signature.to_der();

        let algorithm = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1"),
            parameters: None,
        };
        let signature =
            Signature::try_from_algorithm_and_signature(&algorithm, der_signature.as_bytes());
        assert_eq!(signature, Err(SignatureDecoding));
    }

    #[parameterized(
        seed_1 = { 1 },
        seed_2 = { 2 },
        seed_3 = { 3 },
    )]
    fn rsa_signature_from_algorithm_and_bytes(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let bits = RSA_KEY_BITS;
        let signing_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let message = b"Goodbye, moon!";
        let digest = Sha256::digest(message);
        let scheme = Pkcs1v15Sign::new::<Sha256>();
        let rsa_signature = signing_key.sign(scheme, &digest).expect("failed to sign");
        let expected_signature = Signature::Rsa(rsa_signature.clone());

        let algorithm = AlgorithmIdentifierOwned {
            oid: OID_PKCS1_SHA256_WITH_RSA,
            parameters: None,
        };
        let signature =
            Signature::try_from_algorithm_and_signature(&algorithm, rsa_signature.as_slice());
        assert_eq!(signature, Ok(expected_signature));
    }
}
