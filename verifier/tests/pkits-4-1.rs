// Copyright (c) 2023 The MobileCoin Foundation

//! Test for section 4.1 of the PKI test suite.
//! https://csrc.nist.gov/projects/pki-testing
//!
//! Tests 4.1.4 - 4.1.6 are not implemented because DSA has been deprecated, see
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C72%2C721%2Cnull%5D

use mc_attestation_verifier::x509::PublicKey;
use mc_attestation_verifier::x509::{CertificateChain, Error, UnverifiedCrl};
use std::time::Duration;
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::Certificate as X509Certificate;

const TRUST_ANCHOR_ROOT_CERTIFICATE: &[u8] =
    include_bytes!("data/pkits/certs/TrustAnchorRootCertificate.crt");
const GOOD_CA_CERT: &[u8] = include_bytes!("data/pkits/certs/GoodCACert.crt");
const VALID_CERTIFICATE_PATH_TEST_1EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidCertificatePathTest1EE.crt");
const TRUST_ANCHOR_ROOT_CRL: &[u8] = include_bytes!("data/pkits/crls/TrustAnchorRootCRL.crl");
const GOOD_CA_CRL: &[u8] = include_bytes!("data/pkits/crls/GoodCACRL.crl");
const BAD_SIGNED_CA_CERT: &[u8] = include_bytes!("data/pkits/certs/BadSignedCACert.crt");
const INVALID_CA_SIGNATURE_TEST_2EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidCASignatureTest2EE.crt");
const INVALID_EE_SIGNATURE_TEST_3EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidEESignatureTest3EE.crt");

fn chain_and_leaf_key(certs: &[&[u8]]) -> (CertificateChain, PublicKey) {
    let chain = CertificateChain::try_from(certs).expect("Failed decoding certs");

    let leaf_der = certs.last().expect("Should be at least one cert");
    let leaf_cert = X509Certificate::from_der(leaf_der).expect("Failed decoding DER");
    let key = PublicKey::try_from(&leaf_cert.tbs_certificate.subject_public_key_info)
        .expect("Failed decoding key");

    (chain, key)
}

fn crls_and_time(der_crls: &[&[u8]]) -> (Vec<UnverifiedCrl>, Duration) {
    let crls = der_crls
        .iter()
        .map(|crl| UnverifiedCrl::try_from(*crl).expect("Failed decoding CRL"))
        .collect::<Vec<_>>();

    let last_der = der_crls.last().expect("Should be at least one CRL");
    let crl = CertificateList::from_der(last_der).expect("Failed decoding DER");
    let unix_time = crl.tbs_cert_list.this_update.to_unix_duration();
    (crls, unix_time)
}

#[test]
fn valid_signatures_test_4_1_1() {
    let (chain, expected_key) = chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            VALID_CERTIFICATE_PATH_TEST_1EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed getting signing key");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn invalid_ca_signature_test_4_1_2() {
    let certs = [
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        BAD_SIGNED_CA_CERT,
        INVALID_CA_SIGNATURE_TEST_2EE,
    ];

    // Building the chain parses the signatures of each certificate. The
    // invalid signature causes a parsing error.
    assert_eq!(
        CertificateChain::try_from(certs.as_slice()),
        Err(Error::SignatureDecoding)
    );
}

#[test]
fn invalid_ee_signature_test_4_1_3() {
    let (chain, _) = chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            INVALID_EE_SIGNATURE_TEST_3EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::SignatureVerification)
    );
}
