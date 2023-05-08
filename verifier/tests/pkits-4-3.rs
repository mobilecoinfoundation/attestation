// Copyright (c) 2023 The MobileCoin Foundation

//! Test for section 4.3 of the PKI test suite.
//! https://csrc.nist.gov/projects/pki-testing

mod common;

use common::{GOOD_CA_CERT, GOOD_CA_CRL, TRUST_ANCHOR_ROOT_CERTIFICATE, TRUST_ANCHOR_ROOT_CRL};
use mc_attestation_verifier::x509::Error;

const INVALID_NAME_CHAINING_TEST_1EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidNameChainingTest1EE.crt");
const NAME_ORDERING_CA_CERT: &[u8] = include_bytes!("data/pkits/certs/NameOrderingCACert.crt");
const INVALID_NAME_CHAINING_ORDER_TEST_2EE: &[u8] =
    include_bytes!("data/pkits/certs/InvalidNameChainingOrderTest2EE.crt");
const NAME_ORDER_CA_CRL: &[u8] = include_bytes!("data/pkits/crls/NameOrderCACRL.crl");
const VALID_NAME_CHAINING_WHITESPACE_TEST_3EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidNameChainingWhitespaceTest3EE.crt");
const VALID_NAME_CHAINING_WHITESPACE_TEST_4EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidNameChainingWhitespaceTest4EE.crt");
const VALID_NAME_CHAINING_CAPITALIZATION_TEST_5EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidNameChainingCapitalizationTest5EE.crt");
const UID_CA_CERT: &[u8] = include_bytes!("data/pkits/certs/UIDCACert.crt");
const VALID_NAME_UIDS_TEST_6EE: &[u8] = include_bytes!("data/pkits/certs/ValidNameUIDsTest6EE.crt");
const UID_CA_CRL: &[u8] = include_bytes!("data/pkits/crls/UIDCACRL.crl");
const RFC3280_MANDATORY_ATTRIBUTE_TYPES_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/RFC3280MandatoryAttributeTypesCACert.crt");
const VALID_RFC3280_MANDATORY_ATTRIBUTE_TYPES_TEST_7EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidRFC3280MandatoryAttributeTypesTest7EE.crt");
const RFC3280_MANDATORY_ATTRIBUTE_TYPES_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/RFC3280MandatoryAttributeTypesCACRL.crl");
const RFC3280_OPTIONAL_ATTRIBUTE_TYPES_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/RFC3280OptionalAttributeTypesCACert.crt");
const VALID_RFC3280_OPTIONAL_ATTRIBUTE_TYPES_TEST_8EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidRFC3280OptionalAttributeTypesTest8EE.crt");
const RFC3280_OPTIONAL_ATTRIBUTE_TYPES_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/RFC3280OptionalAttributeTypesCACRL.crl");
const UTF8_STRING_ENCODED_NAMES_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/UTF8StringEncodedNamesCACert.crt");
const VALID_UTF8_STRING_ENCODED_NAMES_TEST_9EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidUTF8StringEncodedNamesTest9EE.crt");
const UTF8_STRING_ENCODED_NAMES_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/UTF8StringEncodedNamesCACRL.crl");
const ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/RolloverfromPrintableStringtoUTF8StringCACert.crt");
const VALID_ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_TEST_10EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt");
const ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/RolloverfromPrintableStringtoUTF8StringCACRL.crl");
const UTF8_STRING_CASE_INSENSITIVE_MATCH_CA_CERT: &[u8] =
    include_bytes!("data/pkits/certs/UTF8StringCaseInsensitiveMatchCACert.crt");
const VALID_UTF8_STRING_CASE_INSENSITIVE_MATCH_TEST_11EE: &[u8] =
    include_bytes!("data/pkits/certs/ValidUTF8StringCaseInsensitiveMatchTest11EE.crt");
const UTF8_STRING_CASE_INSENSITIVE_MATCH_CA_CRL: &[u8] =
    include_bytes!("data/pkits/crls/UTF8StringCaseInsensitiveMatchCACRL.crl");

#[test]
fn invalid_name_chaining_ee_4_3_1() {
    let (chain, _) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        GOOD_CA_CERT,
        INVALID_NAME_CHAINING_TEST_1EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::NameChaining)
    );
}

#[test]
fn invalid_name_chaining_order_4_3_2() {
    let (chain, _) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        NAME_ORDERING_CA_CERT,
        INVALID_NAME_CHAINING_ORDER_TEST_2EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, NAME_ORDER_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    assert_eq!(
        chain.signing_key(&root, unix_time, crls.as_slice()),
        Err(Error::NameChaining)
    );
}

#[test]
fn valid_name_chaining_whitespace_4_3_3() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        GOOD_CA_CERT,
        VALID_NAME_CHAINING_WHITESPACE_TEST_3EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_name_chaining_whitespace_4_3_4() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        GOOD_CA_CERT,
        VALID_NAME_CHAINING_WHITESPACE_TEST_4EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_name_chaining_capitalization_4_3_5() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        GOOD_CA_CERT,
        VALID_NAME_CHAINING_CAPITALIZATION_TEST_5EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, GOOD_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_name_chaining_uids_4_3_6() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        UID_CA_CERT,
        VALID_NAME_UIDS_TEST_6EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, UID_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_rfc3280_mandatory_attribute_types_4_3_7() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        RFC3280_MANDATORY_ATTRIBUTE_TYPES_CA_CERT,
        VALID_RFC3280_MANDATORY_ATTRIBUTE_TYPES_TEST_7EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[
        TRUST_ANCHOR_ROOT_CRL,
        RFC3280_MANDATORY_ATTRIBUTE_TYPES_CA_CRL,
    ]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_rfc3280_optional_attribute_types_4_3_8() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        RFC3280_OPTIONAL_ATTRIBUTE_TYPES_CA_CERT,
        VALID_RFC3280_OPTIONAL_ATTRIBUTE_TYPES_TEST_8EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[
        TRUST_ANCHOR_ROOT_CRL,
        RFC3280_OPTIONAL_ATTRIBUTE_TYPES_CA_CRL,
    ]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_utf8_string_encoded_names_4_3_9() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        UTF8_STRING_ENCODED_NAMES_CA_CERT,
        VALID_UTF8_STRING_ENCODED_NAMES_TEST_9EE,
    ]);
    let (crls, unix_time) =
        common::crls_and_time(&[TRUST_ANCHOR_ROOT_CRL, UTF8_STRING_ENCODED_NAMES_CA_CRL]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_rollover_from_printable_to_utf8_4_3_10() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_CA_CERT,
        VALID_ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_TEST_10EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[
        TRUST_ANCHOR_ROOT_CRL,
        ROLLOVER_FROM_PRINTABLE_STRING_TO_UTF8_STRING_CA_CRL,
    ]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}

#[test]
fn valid_utf8_string_case_insensitive_match_4_3_11() {
    let (chain, expected_key) = common::chain_and_leaf_key(&[
        TRUST_ANCHOR_ROOT_CERTIFICATE,
        UTF8_STRING_CASE_INSENSITIVE_MATCH_CA_CERT,
        VALID_UTF8_STRING_CASE_INSENSITIVE_MATCH_TEST_11EE,
    ]);
    let (crls, unix_time) = common::crls_and_time(&[
        TRUST_ANCHOR_ROOT_CRL,
        UTF8_STRING_CASE_INSENSITIVE_MATCH_CA_CRL,
    ]);
    let root = common::verified_root(&chain, unix_time);

    let signing_key = chain
        .signing_key(&root, unix_time, crls.as_slice())
        .expect("Failed to verify chain");

    assert_eq!(signing_key, expected_key);
}
