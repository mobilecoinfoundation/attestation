// Copyright (c) 2023 The MobileCoin Foundation

//! Test for section 4.2 of the PKI test suite.
//! https://csrc.nist.gov/projects/pki-testing
//!
//! Test 4.2.3 was skipped because it used 1950 as the not before date. While
//! the DER decoder used by the x509-crt will only allow dates after 1970 to
//! work with UNIX_EPOCH.

mod common;

use crate::common::{GOOD_CA_CERT, GOOD_CA_CRL};
use common::{TRUST_ANCHOR_ROOT_CERTIFICATE, TRUST_ANCHOR_ROOT_CRL};
use mc_attestation_verifier::x509::Error;

const BAD_NOT_BEFORE_DATE_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/BadnotBeforeDateCACert.crt");
const INVALID_CA_NOT_BEFORE_DATE_TEST_1EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidCAnotBeforeDateTest1EE.crt");
const INVALID_EE_NOT_BEFORE_DATE_TEST_2EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidEEnotBeforeDateTest2EE.crt");
const VALID_GENERALIZED_TIME_NOT_BEFORE_DATE_TEST_4EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidGeneralizedTimenotBeforeDateTest4EE.crt");
const INVALID_CA_NOT_AFTER_DATE_TEST_5EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidCAnotAfterDateTest5EE.crt");
const BAD_NOT_AFTER_DATE_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/BadnotAfterDateCACert.crt");
const INVALID_EE_NOT_AFTER_DATE_TEST_6EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidEEnotAfterDateTest6EE.crt");
const INVALID_PRE_2000_UTC_EE_NOT_AFTER_DATE_TEST_7EE: &[u8] =
    include_bytes!("data/pkits/certs/Invalidpre2000UTCEEnotAfterDateTest7EE.crt");
const VALID_GENERALIZED_TIME_NOT_AFTER_DATE_TEST_8EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidGeneralizedTimenotAfterDateTest8EE.crt");

const BAD_NOT_BEFORE_DATE_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/BadnotBeforeDateCACRL.crl");
const BAD_NOT_AFTER_DATE_CA_CRL: &[u8] = include_bytes!("data/pkits/crls/BadnotAfterDateCACRL.crl");

#[test]
fn invalid_ca_not_before_date_4_2_1() {
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            BAD_NOT_BEFORE_DATE_CA_CERT,
            INVALID_CA_NOT_BEFORE_DATE_TEST_1EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) =
        common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, BAD_NOT_BEFORE_DATE_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::CertificateNotYetValid)
    );
}

#[test]
fn invalid_ee_not_before_date_4_2_2() {
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            INVALID_EE_NOT_BEFORE_DATE_TEST_2EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::CertificateNotYetValid)
    );
}

#[test]
fn valid_generalizedtime_before_date_4_2_4() {
    let (chain, expected_key) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            VALID_GENERALIZED_TIME_NOT_BEFORE_DATE_TEST_4EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn invalid_ca_not_after_date_4_2_5() {
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            BAD_NOT_AFTER_DATE_CA_CERT,
            INVALID_CA_NOT_AFTER_DATE_TEST_5EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) =
        common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, BAD_NOT_AFTER_DATE_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::CertificateExpired)
    );
}

#[test]
fn invalid_ee_not_after_date_4_2_6() {
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            INVALID_EE_NOT_AFTER_DATE_TEST_6EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::CertificateExpired)
    );
}

#[test]
fn invalid_pre_2000_utc_ee_not_after_date_4_2_7() {
    let (chain, _) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            INVALID_PRE_2000_UTC_EE_NOT_AFTER_DATE_TEST_7EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::CertificateExpired)
    );
}

#[test]
fn valid_generalized_time_after_date_4_2_8() {
    let (chain, expected_key) = common::chain_and_leaf_key(
        [
            TRUST_ANCHOR_ROOT_CERTIFICATE,
            GOOD_CA_CERT,
            VALID_GENERALIZED_TIME_NOT_AFTER_DATE_TEST_8EE,
        ]
        .as_slice(),
    );
    let (crls, unix_time) = common::crls_and_time([TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL].as_slice());

    let root = chain.as_ref()[0]
        .verify_self_signed(unix_time)
        .expect("Failed verifying root");

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}
