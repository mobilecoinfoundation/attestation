// Copyright (c) 2026 The MobileCoin Foundation

//! DCAP certificate validation using upstream WebPKI and RustCrypto.

use crate::{CertificateChainVerifier, CertificateChainVerifierError as Error};
use ::webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExpirationPolicy,
    ExtendedKeyUsageValidator, KeyPurposeId, KeyPurposeIdIter, RevocationOptionsBuilder,
};
use alloc::vec::Vec;
use der::{DateTime, DecodePem, Encode};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    TrustAnchor, UnixTime,
};
use x509_cert::{
    crl::CertificateList,
    ext::pkix::{BasicConstraints, KeyUsage},
    Certificate,
};

/// The only certificate signature algorithm in the pinned Intel DCAP PKI.
#[derive(Debug)]
struct P256Sha256;

impl SignatureVerificationAlgorithm for P256Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = VerifyingKey::from_sec1_bytes(key).map_err(|_| InvalidSignature)?;
        let signature = Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
}

// The anyExtendedKeyUsage OID is 2.5.29.37.0.
const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// Accept absent EKU or anyExtendedKeyUsage, and parse every present purpose.
struct AttestationUsage;
impl ExtendedKeyUsageValidator for AttestationUsage {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), ::webpki::Error> {
        let mut present = Vec::new();
        let mut unrestricted = false;
        for purpose in purposes {
            let purpose = purpose?;
            unrestricted |= purpose == KeyPurposeId::new(ANY_EXTENDED_KEY_USAGE);
            present.push(purpose);
        }
        if present.is_empty() || unrestricted {
            Ok(())
        } else {
            Err(::webpki::Error::RequiredEkuNotFoundContext(
                ::webpki::RequiredEkuNotFoundContext {
                    required: ::webpki::KeyUsage::required_if_present(ANY_EXTENDED_KEY_USAGE),
                    present: present
                        .into_iter()
                        .map(|purpose| purpose.to_decoded_oid())
                        .collect(),
                },
            ))
        }
    }
}

/// A DCAP certificate verifier rooted in one explicitly pinned attestation CA.
///
/// Enabled by the `webpki` feature. Uses upstream WebPKI with RustCrypto
/// P-256/SHA-256 signatures and supports `no_std + alloc`, without a ring or
/// aws-lc backend. This is an attestation signing profile, not a TLS profile.
///
/// Verification requires an explicit time and current CRLs covering every
/// certificate below the trust anchor. Missing time, missing or unknown
/// revocation status, and expired or not-yet-valid CRLs fail verification.
/// Host-supplied time does not establish freshness against an untrusted host.
///
/// The first certificate is the leaf; remaining certificates form an unordered
/// issuer pool. Additional signing checks apply only to the validated path.
/// Supply at most one CRL per issuer on the validated path. Duplicate issuers
/// are rejected after WebPKI's path and revocation checks succeed; duplicates
/// for other issuers are ignored. Only ECDSA P-256/SHA-256 certificate and CRL
/// signatures are supported.
#[derive(Debug)]
pub struct WebPkiCertificateChainVerifier {
    anchor: TrustAnchor<'static>,
    validity: x509_cert::time::Validity,
}

impl WebPkiCertificateChainVerifier {
    /// Parse the pinned root. No system trust store or network lookup is used.
    ///
    /// # Errors
    /// Returns an error if `root` is not a PEM-encoded X.509 certificate that
    /// WebPKI can use as a trust anchor. The caller is responsible for trusting
    /// the root's public key and constraints; no system trust store is consulted.
    /// The pinned root must have BasicConstraints with `ca = true` and KeyUsage
    /// authorizing certificate and CRL signing.
    pub fn from_pem(root: &str) -> Result<Self, Error> {
        let cert = Certificate::from_pem(root).map_err(general_error)?;
        // WebPKI treats anchors as pre-validated. Require our pinned attestation
        // root to be a CA as well as authorized to sign certificates and CRLs.
        let (_, constraints) = cert
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .map_err(general_error)?
            .ok_or(Error::GeneralCertificateError)?;
        if !constraints.ca {
            return Err(Error::GeneralCertificateError);
        }
        // The pinned CA signs both certificates and the CRL covering its children.
        let (_, usage) = cert
            .tbs_certificate()
            .get_extension::<KeyUsage>()
            .map_err(general_error)?
            .ok_or(Error::GeneralCertificateError)?;
        if !usage.key_cert_sign() || !usage.crl_sign() {
            return Err(Error::GeneralCertificateError);
        }
        let der = CertificateDer::from(cert.to_der().map_err(general_error)?);
        let anchor = ::webpki::anchor_from_trusted_cert(&der)
            .map_err(map_error)?
            .to_owned();
        Ok(Self {
            anchor,
            validity: *cert.tbs_certificate().validity(),
        })
    }
}

impl CertificateChainVerifier for WebPkiCertificateChainVerifier {
    fn verify_certificate_chain<'a, 'b>(
        &self,
        certificate_chain: impl IntoIterator<Item = &'a Certificate>,
        crls: impl IntoIterator<Item = &'b CertificateList>,
        time: impl Into<Option<DateTime>>,
    ) -> Result<(), Error> {
        let time = time.into().ok_or(Error::MissingValidationTime)?;
        let certs: Vec<_> = certificate_chain.into_iter().collect();
        if certs.is_empty() {
            return Err(Error::GeneralCertificateError);
        }
        // WebPKI validates leaf/intermediate validity, but treats anchors as
        // already trusted. Apply our explicit validity policy to the pinned root.
        if time < self.validity.not_before.to_date_time() {
            return Err(Error::CertificateNotYetValid);
        }
        if time > self.validity.not_after.to_date_time() {
            return Err(Error::CertificateExpired);
        }
        let ders = certs
            .iter()
            .map(|c| c.to_der().map(CertificateDer::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(general_error)?;
        let leaf = EndEntityCert::try_from(&ders[0]).map_err(map_error)?;
        // Unrelated CRLs cannot cover any supplied certificate. Ignore them
        // before WebPKI's CRL parsing/validation.
        let mut encoded_crls = Vec::new();
        for crl in crls {
            let list = &crl.tbs_cert_list;
            if !certs
                .iter()
                .any(|cert| cert.tbs_certificate().issuer() == &list.issuer)
            {
                continue;
            }
            encoded_crls.push((crl, crl.to_der().map_err(general_error)?));
        }
        // Keep the original metadata paired with WebPKI's borrowed CRL. The
        // encoded buffers must remain separate to outlive those borrows.
        let parsed = encoded_crls
            .iter()
            .map(|(crl, der)| {
                BorrowedCertRevocationList::from_der(der)
                    .map(|parsed| (*crl, CertRevocationList::from(parsed)))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_error)?;
        let refs: Vec<_> = parsed.iter().map(|(_, crl)| crl).collect();
        let revocation = RevocationOptionsBuilder::new(&refs)
            .map_err(|_| Error::UnknownRevocationStatus)?
            .with_expiration_policy(ExpirationPolicy::Enforce)
            .build();
        // WebPKI validates BasicConstraints and authenticates revocation data
        // before invoking this callback. Check signing roles only on that path;
        // rejected candidates do not prevent it from trying another issuer path.
        let check_path = |path: &::webpki::VerifiedPath<'_>| {
            let check_usage = |selected: &::webpki::Cert<'_>, is_ca| {
                let cert = certs
                    .iter()
                    .zip(&ders)
                    .find(|(_, der)| **der == selected.der())
                    .map(|(cert, _)| *cert)
                    .ok_or(::webpki::Error::BadDer)?;
                check_key_usage(cert, is_ca)
            };
            check_usage(path.end_entity(), false)?;
            for issuer in path.intermediate_certificates() {
                check_usage(issuer, true)?;
            }
            Ok(())
        };
        let path = leaf
            .verify_for_usage(
                &[&P256Sha256],
                core::slice::from_ref(&self.anchor),
                &ders[1..],
                UnixTime::since_unix_epoch(time.unix_duration()),
                AttestationUsage,
                Some(revocation),
                Some(&check_path),
            )
            .map_err(map_error)?;
        for (crl, parsed_crl) in &parsed {
            if !core::iter::once(path.end_entity().issuer())
                .chain(path.intermediate_certificates().map(|cert| cert.issuer()))
                .any(|issuer| parsed_crl.issuer() == issuer)
            {
                continue;
            }
            // Reject ambiguous input only after path/revocation validation,
            // and only for issuers on that path. DCAP supplies one CRL per
            // issuer; overlapping or partitioned CRLs are unsupported.
            if parsed
                .iter()
                .filter(|(_, other)| other.issuer() == parsed_crl.issuer())
                .nth(1)
                .is_some()
            {
                return Err(Error::GeneralCertificateError);
            }
            // Full-path revocation succeeded and this issuer has exactly one
            // supplied CRL, so WebPKI authenticated it. Check thisUpdate now.
            if time < crl.tbs_cert_list.this_update.to_date_time() {
                return Err(Error::CrlNotYetValid);
            }
        }
        Ok(())
    }
}

fn check_key_usage(cert: &Certificate, is_ca: bool) -> Result<(), ::webpki::Error> {
    match cert
        .tbs_certificate()
        .get_extension::<KeyUsage>()
        .map_err(|_| ::webpki::Error::ExtensionValueInvalid)?
    {
        Some((_, usage))
            if (is_ca && !usage.key_cert_sign()) || (!is_ca && !usage.digital_signature()) =>
        {
            Err(::webpki::Error::ExtensionValueInvalid)
        }
        None if is_ca => Err(::webpki::Error::ExtensionValueInvalid),
        _ => Ok(()),
    }
}

fn general_error<T>(_: T) -> Error {
    Error::GeneralCertificateError
}

fn map_error(error: ::webpki::Error) -> Error {
    match error {
        ::webpki::Error::CertExpired { .. } => Error::CertificateExpired,
        ::webpki::Error::CertNotValidYet { .. } => Error::CertificateNotYetValid,
        ::webpki::Error::CertRevoked => Error::CertificateRevoked,
        ::webpki::Error::CrlExpired { .. } => Error::CrlExpired,
        ::webpki::Error::UnknownRevocationStatus => Error::UnknownRevocationStatus,
        ::webpki::Error::InvalidSignatureForPublicKey
        | ::webpki::Error::InvalidCrlSignatureForPublicKey => Error::SignatureVerification,
        _ => Error::GeneralCertificateError,
    }
}

#[cfg(test)]
mod tests;
