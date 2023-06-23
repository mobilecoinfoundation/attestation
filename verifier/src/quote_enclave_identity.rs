// Copyright (c) 2023 The MobileCoin Foundation

//! Handles the QE(Quoting Enclave) identity verification.
//!
//! Pre the steps documented at
//! <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
//!
//! > 1. Retrieve Enclave Identity(SGX QE, TDX QE or QVE) from PCS and verify
//! >    that it is a valid structure issued by Intel.
//! > 2. Perform the following comparison of SGX Enclave Report against the
//! >    retrieved Enclave Identity:
//! >       a. Verify if MRSIGNER field retrieved from SGX Enclave Report is
//! >          equal to the value of mrsigner field in Enclave Identity.
//! >       b. Verify if ISVPRODID field retrieved from SGX Enclave Report is
//! >          equal to the value of isvprodid field in Enclave Identity.
//! >       c. Apply miscselectMask (binary mask) from Enclave Identity to
//! >          MISCSELECT field retrieved from SGX Enclave Report. Verify if the
//! >          outcome (miscselectMask & MISCSELECT) is equal to the value of
//! >          miscselect field in Enclave Identity.
//! >       d. Apply attributesMask (binary mask) from Enclave Identity to
//! >          ATTRIBUTES field retrieved from SGX Enclave Report. Verify if the
//! >          outcome (attributesMask & ATTRIBUTES) is equal to the value of
//! >          attributes field in Enclave Identity.
//! > 3. If any of the checks above fail, the identity of the enclave does not
//! >    match Enclave Identity published by Intel.
//! > 4. Determine a TCB status of the Enclave:
//! >       a. Retrieve a collection of TCB Levels (sorted by ISVSVNs) from
//! >          tcbLevels field in Enclave Identity structure.
//! >       b. Go over the list of TCB Levels (descending order) and find the
//! >          one that has ISVSVN that is lower or equal to the ISVSVN value
//! >          from SGX Enclave Report.
//! >       c. If a TCB level is found, read its status from tcbStatus field,
//! >          otherwise your TCB Level is not supported.
//!
//! The QE identity information is provided from
//! <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>

#![allow(dead_code)]

use crate::advisories::AdvisoryStatus;
use crate::Error;
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;
use serde_json::value::RawValue;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    #[serde(with = "hex", rename = "miscselect")]
    misc_select: [u8; 4],
    #[serde(with = "hex", rename = "miscselectMask")]
    misc_select_mask: [u8; 4],
    #[serde(with = "hex")]
    attributes: [u8; 16],
    #[serde(with = "hex")]
    attributes_mask: [u8; 16],
    #[serde(with = "hex", rename = "mrsigner")]
    mr_signer: [u8; 32],
    #[serde(rename = "isvprodid")]
    isv_prod_id: u16,
    tcb_levels: Vec<TcbLevel>,
}

impl<'a> TryFrom<&SignedQeIdentity<'a>> for QeIdentity {
    type Error = Error;

    fn try_from(signed_qe_identity: &SignedQeIdentity<'a>) -> Result<Self, Self::Error> {
        let qe_identity: QeIdentity =
            serde_json::from_str(signed_qe_identity.enclave_identity.get())?;
        Ok(qe_identity)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevel {
    tcb: Tcb,
    tcb_date: String,
    tcb_status: AdvisoryStatus,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Tcb {
    #[serde(rename = "isvsvn")]
    isv_svn: u32,
}

/// Signed quoting enclave (QE) identity.
///
/// The root JSON object from
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
/// The `enclave_identity` field is kept as a raw JSON value to be able to verify the
/// signature.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedQeIdentity<'a> {
    #[serde(borrow)]
    enclave_identity: &'a RawValue,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl<'a> TryFrom<&'a str> for SignedQeIdentity<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let signed_qe_identity: SignedQeIdentity = serde_json::from_str(value)?;
        Ok(signed_qe_identity)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use assert_matches::assert_matches;

    #[test]
    fn parse_signed_id() {
        // For this test we don't care what the contents of `enclave_identity` is, just
        // that we separate the signature from the `enclave_identity` correctly.
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"signature":"abcd"}"#;
        let signed_qe_identity =
            SignedQeIdentity::try_from(raw_identity).expect("Failed to parse signed identity");
        assert_eq!(signed_qe_identity.signature, vec![171, 205]);
        assert_eq!(
            signed_qe_identity.enclave_identity.get(),
            r#"{"id":"QE","version":2,"miscselect":"00000000"}"#
        );
    }

    #[test]
    fn signed_id_two_signatures_errors() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"signature":"abcd","signature":"should not be here"}"#;
        assert_matches!(
            SignedQeIdentity::try_from(raw_identity),
            Err(Error::Serde(_))
        );
    }

    #[test]
    fn signed_id_two_enclave_identitys_errors() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"enclaveIdentity":"one too many","signature":"abcd"}"#;
        assert_matches!(
            SignedQeIdentity::try_from(raw_identity),
            Err(Error::Serde(_))
        );
    }

    #[test]
    fn signed_id_enclave_identity_inside_enclave_identity() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"enclaveIdentity":"identity inside","miscselect":"00000000"},"signature":"0102"}"#;
        let signed_qe_identity =
            SignedQeIdentity::try_from(raw_identity).expect("Failed to parse signed identity");
        assert_eq!(signed_qe_identity.signature, vec![1, 2]);
        assert_eq!(
            signed_qe_identity.enclave_identity.get(),
            r#"{"id":"QE","version":2,"enclaveIdentity":"identity inside","miscselect":"00000000"}"#
        );
    }

    #[test]
    fn parse_example_qe_identity() {
        let json = include_str!("../data/tests/example_qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let qe_identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to parse identity");
        assert_eq!(qe_identity.id, "QE");
        assert_eq!(qe_identity.version, 2);
        assert_eq!(qe_identity.issue_date, "2022-04-13T10:15:38Z");
        assert_eq!(qe_identity.next_update, "2022-05-13T10:15:38Z");
        assert_eq!(qe_identity.misc_select, [0u8, 0, 0, 0]);
        assert_eq!(qe_identity.misc_select_mask, [255u8, 255, 255, 255]);
        assert_eq!(
            qe_identity.attributes,
            [17u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.attributes_mask,
            [251u8, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.mr_signer,
            [
                140u8, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86,
                172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255
            ]
        );
        assert_eq!(qe_identity.isv_prod_id, 1);
        let first_level = &qe_identity.tcb_levels[0];
        assert_eq!(first_level.tcb.isv_svn, 6);
        assert_eq!(first_level.tcb_date, "2021-11-10T00:00:00Z");
        assert_eq!(first_level.tcb_status, AdvisoryStatus::UpToDate);
        assert!(first_level.advisory_ids.is_empty());
        let second_level = &qe_identity.tcb_levels[1];
        assert_eq!(second_level.tcb.isv_svn, 5);
        assert_eq!(second_level.tcb_date, "2020-11-11T00:00:00Z");
        assert_eq!(second_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert!(second_level.advisory_ids.is_empty());
        let last_level = &qe_identity.tcb_levels[4];
        assert_eq!(last_level.tcb.isv_svn, 1);
        assert_eq!(last_level.tcb_date, "2018-08-15T00:00:00Z");
        assert_eq!(last_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert!(last_level.advisory_ids.is_empty());
    }

    #[test]
    fn parse_qe_identity() {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let qe_identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to parse identity");
        assert_eq!(qe_identity.id, "QE");
        assert_eq!(qe_identity.version, 2);
        assert_eq!(qe_identity.issue_date, "2023-06-14T15:55:15Z");
        assert_eq!(qe_identity.next_update, "2023-07-14T15:55:15Z");
        assert_eq!(qe_identity.misc_select, [0u8, 0, 0, 0]);
        assert_eq!(qe_identity.misc_select_mask, [255u8, 255, 255, 255]);
        assert_eq!(
            qe_identity.attributes,
            [17u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.attributes_mask,
            [251u8, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.mr_signer,
            [
                140u8, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86,
                172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255
            ]
        );
        assert_eq!(qe_identity.isv_prod_id, 1);
        let first_level = &qe_identity.tcb_levels[0];
        assert_eq!(first_level.tcb.isv_svn, 8);
        assert_eq!(first_level.tcb_date, "2023-02-15T00:00:00Z");
        assert_eq!(first_level.tcb_status, AdvisoryStatus::UpToDate);
        assert!(first_level.advisory_ids.is_empty());
        let second_level = &qe_identity.tcb_levels[1];
        assert_eq!(second_level.tcb.isv_svn, 6);
        assert_eq!(second_level.tcb_date, "2021-11-10T00:00:00Z");
        assert_eq!(second_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert_eq!(second_level.advisory_ids, vec!["INTEL-SA-00615"]);
        let last_level = &qe_identity.tcb_levels[5];
        assert_eq!(last_level.tcb.isv_svn, 1);
        assert_eq!(last_level.tcb_date, "2018-08-15T00:00:00Z");
        assert_eq!(last_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert_eq!(
            last_level.advisory_ids,
            vec![
                "INTEL-SA-00202",
                "INTEL-SA-00219",
                "INTEL-SA-00293",
                "INTEL-SA-00334",
                "INTEL-SA-00477",
                "INTEL-SA-00615"
            ]
        );
    }
}
