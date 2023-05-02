// Copyright (c) 2023 The MobileCoin Foundation

//! Test for section 4.1 of the PKI test suite.
//! https://csrc.nist.gov/projects/pki-testing
//!
//! Tests 4.1.4 - 4.1.6 are not implemented because DSA has been deprecated, see
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5-draft.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C72%2C721%2Cnull%5D

mod common;

use common::{GOOD_CA_CERT, GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CERTIFICATE, TRUST_ANCHOR_ROOT_CRL};
use mc_attestation_verifier::x509::{CertificateChain, Error};

const VALID_CERTIFICATE_PATH_TEST_1EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidCertificatePathTest1EE.crt");
const BAD_SIGNED_CA_CERT: &[u8] = include_bytes!("data/pkits/certs/BadSignedCACert.crt");
const INVALID_CA_SIGNATURE_TEST_2EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidCASignatureTest2EE.crt");
const INVALID_EE_SIGNATURE_TEST_3EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidEESignatureTest3EE.crt");

#[test]
fn valid_signatures_test_4_1_1() {
    let (chain, expected_key) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            VALID_CERTIFICATE_PATH_TEST_1EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

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
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            INVALID_EE_SIGNATURE_TEST_3EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::SignatureVerification)
    );
}
