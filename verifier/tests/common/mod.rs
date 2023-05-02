// Copyright (c) 2023 The MobileCoin Foundation

use mc_attestation_verifier::x509::{CertificateChain, PublicKey, UnverifiedCrl};
use std::time::Duration;
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::Certificate as X509Certificate;

pub const TRUST_ANCHOR_ROOT_CERTIFICATE: &[u8] =
    include_bytes!("../data/pkits/certs/TrustAnchorRootCertificate.crt");
pub const GOOD_CA_CERT: &[u8] = include_bytes!("../data/pkits/certs/GoodCACert.crt");
pub const TRUST_ANCHOR_ROOT_CRL: &[u8] =
    include_bytes!("../data/pkits/crls/TrustAnchorRootCRL.crl");
pub const GOOD_CA_CRL: &[u8] = include_bytes!("../data/pkits/crls/GoodCACRL.crl");

/// Create a certificate chain and extract the key from the leaf certificate.
pub fn chain_and_leaf_key(certs: &[&[u8]]) -> (CertificateChain, PublicKey) {
    let chain = CertificateChain::try_from(certs).expect("Failed decoding certs");

    let leaf_der = certs.last().expect("Should be at least one cert");
    let leaf_cert = X509Certificate::from_der(leaf_der).expect("Failed decoding DER");
    let key = PublicKey::try_from(&leaf_cert.tbs_certificate.subject_public_key_info)
        .expect("Failed decoding key");

    (chain, key)
}

/// Create a list CRLs and extract the time from the last CRL.
///
/// The last CRL's time usually has the narrowest validity window.
pub fn crls_and_time(der_crls: &[&[u8]]) -> (Vec<UnverifiedCrl>, Duration) {
    let crls = der_crls
        .iter()
        .map(|crl| UnverifiedCrl::try_from(*crl).expect("Failed decoding CRL"))
        .collect::<Vec<_>>();

    let last_der = der_crls.last().expect("Should be at least one CRL");
    let crl = CertificateList::from_der(last_der).expect("Failed decoding DER");
    let next_update = crl
        .tbs_cert_list
        .next_update
        .expect("Next update should be valid")
        .to_unix_duration();

    let unix_time = next_update - Duration::from_nanos(1);
    (crls, unix_time)
}
