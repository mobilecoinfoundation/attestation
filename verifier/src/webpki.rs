// Copyright (c) 2026 The MobileCoin Foundation

//! DCAP certificate validation using upstream WebPKI and RustCrypto.

use crate::{CertificateChainVerifier, CertificateChainVerifierError as Error};
use ::webpki::{
    BorrowedCertRevocationList, CertRevocationList, EndEntityCert, ExpirationPolicy,
    ExtendedKeyUsageValidator, KeyPurposeIdIter, RevocationOptionsBuilder,
};
use alloc::vec::Vec;
use core::time::Duration;
use der::{DateTime, DecodePem, Encode};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rustls_pki_types::{
    alg_id, AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    UnixTime,
};
use x509_cert::{crl::CertificateList, ext::pkix::KeyUsage, Certificate};

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

/// DCAP certificates authenticate attestation signatures, not TLS endpoints.
struct AttestationUsage;
impl ExtendedKeyUsageValidator for AttestationUsage {
    fn validate(&self, purposes: KeyPurposeIdIter<'_, '_>) -> Result<(), ::webpki::Error> {
        // Still parse every purpose: malformed EKU encodings must fail.
        for purpose in purposes {
            purpose?;
        }
        Ok(())
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
/// Chains must be supplied leaf first, followed by issuer certificates. Only
/// ECDSA P-256/SHA-256 certificate and CRL signatures are supported.
#[derive(Debug)]
pub struct WebPkiCertificateChainVerifier {
    root: Vec<u8>,
}

impl WebPkiCertificateChainVerifier {
    /// Parse the pinned root. No system trust store or network lookup is used.
    ///
    /// # Errors
    /// Returns an error if `root` is not a valid PEM-encoded X.509 certificate.
    pub fn from_pem(root: &str) -> Result<Self, der::Error> {
        Ok(Self {
            root: Certificate::from_pem(root)?.to_der()?,
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
        let time = time.into().ok_or(Error::GeneralCertificateError)?;
        let certs: Vec<_> = certificate_chain.into_iter().collect();
        if certs.is_empty() {
            return Err(Error::GeneralCertificateError);
        }
        for (index, cert) in certs.iter().enumerate() {
            let tbs = cert.tbs_certificate();
            if time < tbs.validity().not_before.to_date_time() {
                return Err(Error::CertificateNotYetValid);
            }
            if time > tbs.validity().not_after.to_date_time() {
                return Err(Error::CertificateExpired);
            }
            // WebPKI intentionally ignores certificate KeyUsage. Enforce the DCAP
            // signing requirements here, including CA signing authorization.
            if let Some((_, usage)) = tbs
                .get_extension::<KeyUsage>()
                .map_err(|_| Error::GeneralCertificateError)?
            {
                if (index == 0 && !usage.digital_signature())
                    || (index > 0 && !usage.key_cert_sign())
                {
                    return Err(Error::GeneralCertificateError);
                }
            }
        }
        let ders = certs
            .iter()
            .map(|c| c.to_der().map(CertificateDer::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::GeneralCertificateError)?;
        let root = CertificateDer::from(self.root.as_slice());
        let anchors = [::webpki::anchor_from_trusted_cert(&root).map_err(map_error)?];
        let leaf = EndEntityCert::try_from(&ders[0]).map_err(map_error)?;
        let crls: Vec<_> = crls.into_iter().collect();
        for crl in &crls {
            let list = &crl.tbs_cert_list;
            if time < list.this_update.to_date_time()
                || list
                    .next_update
                    .is_none_or(|next| time > next.to_date_time())
            {
                return Err(Error::GeneralCertificateError);
            }
        }
        let crl_ders = crls
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::GeneralCertificateError)?;
        let parsed = crl_ders
            .iter()
            .map(|c| BorrowedCertRevocationList::from_der(c).map(CertRevocationList::from))
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_error)?;
        let refs: Vec<_> = parsed.iter().collect();
        let revocation = RevocationOptionsBuilder::new(&refs)
            .map_err(|_| Error::GeneralCertificateError)?
            .with_expiration_policy(ExpirationPolicy::Enforce)
            .build();
        leaf.verify_for_usage(
            &[&P256Sha256],
            &anchors,
            &ders[1..],
            UnixTime::since_unix_epoch(Duration::from_secs(time.unix_duration().as_secs())),
            AttestationUsage,
            Some(revocation),
            None,
        )
        .map_err(map_error)?;
        Ok(())
    }
}

fn map_error(error: ::webpki::Error) -> Error {
    match error {
        ::webpki::Error::CertExpired { .. } => Error::CertificateExpired,
        ::webpki::Error::CertNotValidYet { .. } => Error::CertificateNotYetValid,
        ::webpki::Error::CertRevoked => Error::CertificateRevoked,
        ::webpki::Error::InvalidSignatureForPublicKey => Error::SignatureVerification,
        _ => Error::GeneralCertificateError,
    }
}

#[cfg(test)]
mod tests;
