// Copyright (c) 2023 The MobileCoin Foundation

//! Test for section 4.2 of the PKI test suite.
//! https://csrc.nist.gov/projects/pki-testing

mod common;

use crate::common::{GOOD_CA_CERT, GOOD_CA_CRL};
use chrono::NaiveDateTime;
use common::{TRUST_ANCHOR_ROOT_CERTIFICATE, TRUST_ANCHOR_ROOT_CRL};
use mc_attestation_verifier::x509::{Error, UnverifiedCertificate};
use std::str::FromStr;
use std::time::SystemTime;

const BAD_NOT_BEFORE_DATE_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/BadnotBeforeDateCACert.crt");
const INVALID_CA_NOT_BEFORE_DATE_TEST_1EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidCAnotBeforeDateTest1EE.crt");
const INVALID_EE_NOT_BEFORE_DATE_TEST_2EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidEEnotBeforeDateTest2EE.crt");
const VALID_PRE_2000_UTC_NOT_BEFORE_DATE_TEST_3EE: &[u8] =
    include_bytes!("data/pkits/certs/Validpre2000UTCnotBeforeDateTest3EE.crt");
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
fn valid_pre2000_utc_before_date_4_2_3() {
    // tl;dr - Test dates from 1970-2049
    //
    // Per https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5.1
    // The `UTCTime` format supports dates from 1950-2049. The provided
    // certificate `VALID_PRE_2000_UTC_NOT_BEFORE_DATE_TEST_3EE` uses a
    // date of 1950-01-01T00:00:00Z. The DER decoder being used will treat this
    // as 1950, but when it goes to convert this to a date, it is bound by 1970,
    // the unix epoch. To best mimic this test case we will manually test the
    // date range during decoding. Because we are modifying the certificate
    // bytes, the signature will not be valid so we will not be able to test
    // that and will only focus on the low level date conversion logic.
    // See https://obj-sys.com/asn1tutorial/node124.html
    const UTC_TIME_TAG: u8 = 23;
    // UTCTime in RFC5280 is limited to the form of "YYMMDDHHMMSSZ"
    const UTC_TIME_LENGTH: u8 = 13;
    const UTC_TIME_TAG_LENGTH: usize = 2;

    const EARLIEST_VALID_UTC_TIME: &[u8] = b"700101000000Z";
    const EARLIEST_INVALID_UTC_TIME: &[u8] = b"691231235959Z";
    const LATEST_VALID_UTC_TIME: &[u8] = b"491231235959Z";
    // Normally this would be valid, but due to the backend limiting times to
    // by the unix epoch (1970) it's not valid.
    const LATEST_INVALID_UTC_TIME: &[u8] = b"500101000000Z";

    let search_time = vec![UTC_TIME_TAG, UTC_TIME_LENGTH, '5' as u8, '0' as u8];

    let mut der_bytes = VALID_PRE_2000_UTC_NOT_BEFORE_DATE_TEST_3EE.to_vec();

    // Show that the certificate as provided will fail to parse with the DER
    // backend
    assert!(matches!(
        UnverifiedCertificate::try_from(der_bytes.as_slice()),
        Err(Error::DerDecoding(_))
    ));

    let mut not_before_offset = der_bytes
        .windows(search_time.len())
        .position(|window| window == search_time)
        .expect("Failed to find not before time");

    not_before_offset += UTC_TIME_TAG_LENGTH;
    let not_before_end = not_before_offset + UTC_TIME_LENGTH as usize;

    der_bytes[not_before_offset..not_before_end].copy_from_slice(EARLIEST_INVALID_UTC_TIME);
    assert!(matches!(
        UnverifiedCertificate::try_from(der_bytes.as_slice()),
        Err(Error::DerDecoding(_))
    ));

    der_bytes[not_before_offset..not_before_end].copy_from_slice(EARLIEST_VALID_UTC_TIME);
    let unverified_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
        .expect("Failed to decode certificate time");
    let x509_cert = unverified_cert.as_ref();
    assert_eq!(
        x509_cert
            .tbs_certificate
            .validity
            .not_before
            .to_system_time(),
        SystemTime::UNIX_EPOCH
    );

    der_bytes[not_before_offset..not_before_end].copy_from_slice(LATEST_VALID_UTC_TIME);
    let unverified_cert = UnverifiedCertificate::try_from(der_bytes.as_slice())
        .expect("Failed to decode certificate time");
    let x509_cert = unverified_cert.as_ref();
    let expected_time =
        NaiveDateTime::from_str("2049-12-31T23:59:59").expect("Failed to create date");
    let duration = x509_cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration();
    let actual_time =
        NaiveDateTime::from_timestamp_opt(duration.as_secs() as i64, duration.subsec_nanos())
            .expect("Failed to create date");
    assert_eq!(actual_time, expected_time);

    der_bytes[not_before_offset..not_before_end].copy_from_slice(LATEST_INVALID_UTC_TIME);
    assert!(matches!(
        UnverifiedCertificate::try_from(der_bytes.as_slice()),
        Err(Error::DerDecoding(_))
    ));
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
