// Copyright (c) 2023 The MobileCoin Foundation

//! TCB measurements for an SGX enclave.
//!
//! The TCB measurements are present as OID extensions on the leaf PCK
//! certificate.
//! The OID extensions are listed at
//! <https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4cb5c8b81f126f9aa3ee921d7980a909a9bd676d/QuoteVerification/QVL/Src/AttestationParsers/src/ParserUtils.h#L57>.
//! There doesn't appear to be a more formal place where these OID extensions
//! are documented .
//!
//! These TCB measurements contain the FMSPC value which can be used to query
//! for the advisories associated with these TCB values at
//! <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
use x509_cert::der::asn1::OctetStringRef;
use x509_cert::der::Decode;
use x509_cert::Certificate;

// Per <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3>
// fmspc is limited to 12 hex characters, or 6 bytes.
const FMSPC_SIZE: usize = 6;

// Values copied from
// <https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4cb5c8b81f126f9aa3ee921d7980a909a9bd676d/QuoteVerification/QVL/Src/AttestationParsers/src/ParserUtils.h#L57>.
const SGX_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
const TCB_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
const TCB_COMPONENT_OIDS: [ObjectIdentifier; 16] = [
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.1"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.2"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.3"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.4"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.5"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.6"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.7"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.8"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.9"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.10"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.11"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.12"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.13"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.14"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.15"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.16"),
];
const PCE_SVN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.17");
const FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

#[derive(Debug, PartialEq)]
pub enum Error {
    MissingSgxExtension(String),
    Der(x509_cert::der::Error),
    FmspcSize(usize),
}

impl From<x509_cert::der::Error> for Error {
    fn from(err: x509_cert::der::Error) -> Self {
        Error::Der(err)
    }
}

// The SGX extensions aren't really documented. They aren't RFC 5280 extensions
// which are `OID` and `OCTET`. They're an `OID` and an `Any`, which is what the
// [`AttributeTypeAndValue`] is.
type SgxExtensions = Vec<AttributeTypeAndValue>;

/// The TCB info provided by the PCK(Provisioning Certification Key) leaf
/// certificate
#[derive(Debug, PartialEq)]
pub struct PckTcbInfo {
    svns: [u32; 16],
    pce_svn: u32,
    fmspc: [u8; FMSPC_SIZE],
}

impl TryFrom<&Certificate> for PckTcbInfo {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        let sgx_extensions = sgx_extensions(cert)?;

        let fmspc = fmspc(&sgx_extensions)?;

        let (pce_svn, svns) = tcb_svns(&sgx_extensions)?;

        Ok(PckTcbInfo {
            svns,
            pce_svn,
            fmspc,
        })
    }
}

/// Get the [`SgxExtensions`] from the `cert`.
///
/// # Errors
/// * `Error::MissingSgxExtension` if the `cert` does not have the SGX extension.
/// * `Error::DerDecoding` if the contained DER is invalid.
fn sgx_extensions(cert: &Certificate) -> Result<SgxExtensions, Error> {
    let extensions = &cert.tbs_certificate.extensions;
    let extension = match extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == SGX_OID)
    {
        Some(extension) => extension,
        None => return Err(Error::MissingSgxExtension(SGX_OID.to_string())),
    };

    let der_bytes = extension.extn_value.as_bytes();
    Ok(SgxExtensions::from_der(der_bytes)?)
}

/// Get the FMSPC value from the extensions
///
/// # Errors
/// * `Error::MissingSgxExtension` if the `cert` does not have the FMSPC extension.
/// * `Error::DerDecoding` if the FMSPC DER value is not an OctetString
/// * `Error::FmspcSize` if the FMSPC DER value is not exactly 6 bytes.
fn fmspc(sgx_extensions: &SgxExtensions) -> Result<[u8; FMSPC_SIZE], Error> {
    let fmspc_value = oid_value(&FMSPC_OID, sgx_extensions)?;
    let octet = fmspc_value.decode_as::<OctetStringRef>()?;
    let fmspc_bytes = octet.as_bytes();

    if fmspc_bytes.len() != FMSPC_SIZE {
        return Err(Error::FmspcSize(fmspc_bytes.len()));
    }

    let mut fmspc = [0u8; FMSPC_SIZE];
    fmspc.copy_from_slice(fmspc_bytes);
    Ok(fmspc)
}

/// Get the value for the `oid`s attribute.
///
/// # Errors
/// `Error::MissingSgxExtension` if the `oid` is not present in `extensions`.
fn oid_value(oid: &ObjectIdentifier, extensions: &SgxExtensions) -> Result<AttributeValue, Error> {
    match extensions.iter().find(|extension| &extension.oid == oid) {
        Some(extension) => Ok(extension.value.clone()),
        None => Err(Error::MissingSgxExtension(oid.to_string())),
    }
}

/// Get the SVN values from the nested `TCB_OID`
///
/// # Errors
/// * `Error::MissingSgxExtension` if any of the 1-16 component SVNs or PCE SVN is missing.
/// * `Error::DerDecoding` if the SVN values fail to decode to u32s.
fn tcb_svns(sgx_extensions: &SgxExtensions) -> Result<(u32, [u32; 16]), Error> {
    let tcb = oid_value(&TCB_OID, sgx_extensions)?;
    let components = tcb.decode_as::<SgxExtensions>()?;

    let pce_svn_value = oid_value(&PCE_SVN_OID, &components)?;
    let pce_svn = pce_svn_value.decode_as::<u32>()?;

    let mut svns = [0; 16];
    for (i, oid) in TCB_COMPONENT_OIDS.iter().enumerate() {
        let value = oid_value(oid, &components)?;
        let svn = value.decode_as::<u32>()?;
        svns[i] = svn;
    }
    Ok((pce_svn, svns))
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use core::ops::Range;
    use der::Tag::{BitString, OctetString};
    use der::{Any, Encode};
    use yare::parameterized;

    const LEAF_CERT: &str = include_str!("../../data/tests/leaf_cert.pem");

    /// Get the range of bytes for the `oid` in `der_bytes`.
    ///
    /// This range includes the tag and length bytes for the OID.
    fn oid_range(oid: &ObjectIdentifier, der_bytes: &[u8]) -> Range<usize> {
        let mut oid_bytes = vec![];
        oid.encode_to_vec(&mut oid_bytes)
            .expect("failed to encode OID");
        let oid_offset = der_bytes
            .windows(oid_bytes.len())
            .position(|window| window == oid_bytes)
            .expect("Failed to find OID");

        let oid_end = oid_offset + oid_bytes.len();
        oid_offset..oid_end
    }

    #[test]
    fn valid_pck_tcb_info() {
        let (_, der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");
        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        let tcb_info = PckTcbInfo::try_from(&certificate).expect("failed to parse TCB info");

        // These were taken by looking at `leaf_cert.pem` on an ASN1 decoder, like
        // <https://lapo.it/asn1js/#MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb_spRh9U8K7AT_3MAoGCCqGSM49BAMCMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj_Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl_Ts8b0dltKUW3jqRd-SxnPEWJ-jUw-SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11_kuSReYPHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2NhPXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QWnhmVfE31MA4GA1UdDwEB_wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhNAQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQICAgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG-E0BDQECBwIBBjAQBgsqhkiG-E0BDQECCAIBADAQBgsqhkiG-E0BDQECCQIBADAQBgsqhkiG-E0BDQECCgIBADAQBgsqhkiG-E0BDQECCwIBADAQBgsqhkiG-E0BDQECDAIBADAQBgsqhkiG-E0BDQECDQIBADAQBgsqhkiG-E0BDQECDgIBADAQBgsqhkiG-E0BDQECDwIBADAQBgsqhkiG-E0BDQECEAIBADAQBgsqhkiG-E0BDQECEQIBCzAfBgsqhkiG-E0BDQECEgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG-E0BDQEDBAIAADAUBgoqhkiG-E0BDQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA1XJi0ht4hw8YtC6E4rYscp9bF-7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4V8Zu8NFCC4vFg-cZqO6QfezEaA>
        let expected_tcb_info = PckTcbInfo {
            svns: [17, 17, 2, 4, 1, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pce_svn: 11,
            fmspc: [0, 144, 110, 213, 0, 0],
        };
        assert_eq!(tcb_info, expected_tcb_info);
    }

    #[parameterized(
        sgx = { &SGX_OID },
        fmspc = { &FMSPC_OID },
        tcb = { &TCB_OID },
        pce_svn = { &PCE_SVN_OID },
        tcb_comp_1 = { &TCB_COMPONENT_OIDS[0] },
        tcb_comp_3 = { &TCB_COMPONENT_OIDS[2] },
        tcb_comp_16 = { &TCB_COMPONENT_OIDS[15] },
    )]
    fn missing_oid(oid: &ObjectIdentifier) {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(oid, &der_bytes);

        // Corrupts the last number of the OID value,
        // i.e. 1.2.840.113741.1.13.1.2.1 -> 1.2.840.113741.1.13.1.2.2
        der_bytes[oid_range.end - 1] += 1;

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert_eq!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::MissingSgxExtension(oid.to_string()))
        );
    }

    #[test]
    fn malformed_sgx_extensions() {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(&TCB_OID, &der_bytes);

        // Corrupts the expected ObjectIdentifier tag
        der_bytes[oid_range.start] += 1;

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_fmspc() {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(&FMSPC_OID, &der_bytes);

        // Expecting OctetString tag
        der_bytes[oid_range.end] = BitString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_tcb() {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(&TCB_OID, &der_bytes);

        // Expecting Sequence tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_pce_svn() {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(&PCE_SVN_OID, &der_bytes);

        // Expecting Integer tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[parameterized(
        comp_1 = { &TCB_COMPONENT_OIDS[0] },
        comp_5 = { &TCB_COMPONENT_OIDS[4] },
        comp_16 = { &TCB_COMPONENT_OIDS[15] },
    )]
    fn malformed_tcb_component(oid: &ObjectIdentifier) {
        let (_, mut der_bytes) =
            pem_rfc7468::decode_vec(LEAF_CERT.as_bytes()).expect("Failed to decode DER from PEM");

        let oid_range = oid_range(oid, &der_bytes);

        // Expecting Integer tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            PckTcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn fmspc_from_extensions() {
        // This is done low level because changing the length of the DER FMSPC
        // would require updating *all* of the DER objects which contain this
        // one.
        // This test shows that the low level setup is correct for the
        // subsequent tests that verify the error handling of incorrect FMSPC
        // length.
        let bytes = [0u8, 1, 2, 3, 4, 5];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Ok(bytes));
    }

    #[test]
    fn fmspc_too_short() {
        let bytes = [0u8, 1, 2, 3, 4];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Err(Error::FmspcSize(5)));
    }

    #[test]
    fn fmspc_too_long() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Err(Error::FmspcSize(7)));
    }
}
