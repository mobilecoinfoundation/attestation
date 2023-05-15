// Copyright (c) 2023 The MobileCoin Foundation

//! Verifier for TCB(Trusted Computing Base) information
//!
//! See <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>
//! for the format and usage.
//!
//! > Determining the status of a SGX TCB level for a given platform needs to be
//! > done using SGX TCB information according to the following algorithm:
//! >
//! > 1. Retrieve FMSPC value from SGX PCK Certificate assigned to a given platform.
//! > 2. Retrieve SGX TCB Info matching the FMSPC value.
//! > 3. Go over the sorted collection of TCB Levels retrieved from TCB Info
//! >    starting from the first item on the list:
//! >   a. Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK
//! >      Certificate (from 01 to 16) with the corresponding values of SVNs in
//! >      sgxtcbcomponents array of TCB Level. If all SGX TCB Comp SVNs in the
//! >      certificate are greater or equal to the corresponding values in TCB
//! >      Level, go to 3.b, otherwise move to the next item on TCB Levels list.
//! >   b. Compare PCESVN value retrieved from the SGX PCK certificate with the
//! >      corresponding value in the TCB Level. If it is greater or equal to
//! >      the value in TCB Level, read status assigned to this TCB level.
//! >      Otherwise, move to the next item on TCB Levels list.
//! > 4. If no TCB level matches your SGX PCK Certificate, your TCB Level is not
//! >    supported.
//!
//! The TCB info is retrieved by using the fsmpc available in the report body
//! and accessing <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use der::DateTime;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::value::RawValue;

/// Error parsing TCB(Trusted Computing Base) info
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Error converting from DER
    Der(der::Error),
    /// Error parsing TCB(Trusted Computing Base) json info: {0}
    Serde(serde_json::Error),
    /// Error decoding the signature in the TCB data
    SignatureDecodeError,
    /// Error verifying the signature
    SignatureVerification,
    /// TCB info not yet valid
    TcbInfoNotYetValid,
    /// TCB info expired
    TcbInfoExpired,
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Der(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

/// The `tcbInfo` member of the TCB(Trusted Computing Base) data retrieved from
/// <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
/// The schema is available at <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    pce_id: String,
    tcb_type: u32,
    tcb_evaluation_data_number: u32,
    tcb_levels: Vec<TcbLevel>,
}

impl TryFrom<&str> for TcbInfo {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let tcb_info: TcbInfo = serde_json::from_str(value)?;
        Ok(tcb_info)
    }
}

/// A single TCB level
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    tcb: Tcb,
    tcb_date: String,
    tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

/// A TCB(Trusted Computing Base) retrieved from
/// <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
#[derive(Debug, Deserialize)]
pub struct Tcb {
    #[serde(rename = "sgxtcbcomponents")]
    sgx_tcb_components: Vec<TcbComponent>,
    #[serde(rename = "pcesvn")]
    pce_svn: u32,
}

impl TryFrom<&str> for Tcb {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let tcb: Tcb = serde_json::from_str(value)?;
        Ok(tcb)
    }
}

/// A component of the TCB
#[derive(Debug, Deserialize, PartialEq)]
pub struct TcbComponent {
    svn: u32,
    category: Option<String>,
    r#type: Option<String>,
}

/// Raw unverified representation of the TCB(Trusted Computing Base) info
/// provided from
/// <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
///
/// Due to the way the TCB info is signed the contents should be provided as is.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoRaw<'a> {
    #[serde(borrow)]
    tcb_info: &'a RawValue,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl<'a> TcbInfoRaw<'a> {
    /// Verify the `tcbInfo` signature and time are valid.
    ///
    /// # Arguments
    /// - `key` - The public key to verify the `tcbInfo` signature with
    /// - `time` - The current system time
    ///   This is expected to be generated by:
    ///     ```ignore
    ///     let time = DateTime::from_system_time(SystemTime::now()).unwrap();
    ///     ```
    ///   or equivalent
    pub fn verify(self, key: &VerifyingKey, time: DateTime) -> Result<(), Error> {
        self.verify_time(time)?;
        self.verify_signature(key)?;
        Ok(())
    }

    fn verify_signature(&self, key: &VerifyingKey) -> Result<(), Error> {
        let tcb_info = self.tcb_info.get();
        let signature =
            Signature::try_from(&self.signature[..]).map_err(|_| Error::SignatureDecodeError)?;
        key.verify(tcb_info.as_bytes(), &signature)
            .map_err(|_| Error::SignatureVerification)?;
        Ok(())
    }

    fn verify_time(&self, time: DateTime) -> Result<(), Error> {
        let tcb_info = TcbInfo::try_from(self.tcb_info.get())?;
        let issue_date = tcb_info.issue_date.parse::<DateTime>()?;
        let next_update = tcb_info.next_update.parse::<DateTime>()?;
        if time < issue_date {
            Err(Error::TcbInfoNotYetValid)
        } else if time >= next_update {
            Err(Error::TcbInfoExpired)
        } else {
            Ok(())
        }
    }
}

impl<'a> TryFrom<&'a str> for TcbInfoRaw<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let tcb_info: TcbInfoRaw = serde_json::from_str(value)?;
        Ok(tcb_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p256::ecdsa::VerifyingKey;
    use serde_json::value::RawValue;
    use x509_cert::{der::DecodePem, Certificate};
    use yare::parameterized;

    fn tcb_verifying_key() -> VerifyingKey {
        let pem = include_str!("../data/tests/tcb_signer.pem");
        let certificate = Certificate::from_pem(pem).expect("failed to parse PEM");
        let key = VerifyingKey::from_sec1_bytes(
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .expect("Failed to parse public key"),
        )
        .expect("Failed to decode public key");

        key
    }

    #[test]
    fn raw_parse_info() {
        // For this test we don't care what the contents of `tcbInfo` is, just
        // that we separate the signature from the tcbInfo correctly.
        let raw_info =
            r#"{"tcbInfo":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"abcd"}"#;
        let tcb_info = TcbInfoRaw::try_from(raw_info).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.signature, vec![171, 205]);
        assert_eq!(
            tcb_info.tcb_info.get(),
            r#"{"id":"SGX","version":3,"fmspc":"00906ED50000"}"#
        );
    }

    #[test]
    fn raw_two_signatures_errors() {
        let raw_info = r#"{"tcbInfo":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"hello","signature":"abcd"}"#;
        assert!(matches!(
            TcbInfoRaw::try_from(raw_info),
            Err(Error::Serde(_))
        ));
    }

    #[test]
    fn raw_two_tcb_infos_errors() {
        let raw_info = r#"{"tcbInfo":"too many cooks","tcbInfo":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"abcd"}"#;
        assert!(matches!(
            TcbInfoRaw::try_from(raw_info),
            Err(Error::Serde(_))
        ));
    }

    #[test]
    fn raw_nested_tcb_info_still_in_parent() {
        let raw_info = r#"{"tcbInfo":{"tcbInfo":"nested","version":3,"fmspc":"00906ED50000"},"signature":"f012"}"#;
        let tcb_info = TcbInfoRaw::try_from(raw_info).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.signature, vec![240, 18]);
        assert_eq!(
            tcb_info.tcb_info.get(),
            r#"{"tcbInfo":"nested","version":3,"fmspc":"00906ED50000"}"#
        );
    }

    #[test]
    fn parse_example_tcb_info() {
        let json = include_str!("../data/tests/example_tcb.json");
        let tcb_raw = TcbInfoRaw::try_from(json).expect("Failed to parse raw TCB");
        let tcb_info = TcbInfo::try_from(tcb_raw.tcb_info.get()).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.id, "SGX");
        assert_eq!(tcb_info.version, 3);
        assert_eq!(tcb_info.issue_date, "2022-04-13T09:38:17Z");
        assert_eq!(tcb_info.next_update, "2022-05-13T09:38:17Z");
        assert_eq!(tcb_info.fmspc, "50806F000000");
        assert_eq!(tcb_info.pce_id, "0000");
        assert_eq!(tcb_info.tcb_type, 0);
        assert_eq!(tcb_info.tcb_evaluation_data_number, 12);
        assert_eq!(tcb_info.tcb_levels.len(), 2);

        let first_level = &tcb_info.tcb_levels[0];
        assert_eq!(first_level.tcb_date, "2021-11-10T00:00:00Z");
        assert_eq!(first_level.tcb_status, "UpToDate");
        let tcb = &first_level.tcb;
        assert_eq!(tcb.pce_svn, 11);

        // sub components robustly tested in the [`Tcb`] tests so just a quick
        // check here
        let first_sub_component = &tcb.sgx_tcb_components[0];
        assert_eq!(first_sub_component.svn, 1);
        assert_eq!(first_sub_component.category, Some("BIOS".into()));
        assert_eq!(
            first_sub_component.r#type,
            Some("Early Microcode Update".into())
        );

        let second_level = &tcb_info.tcb_levels[1];
        assert_eq!(second_level.tcb_date, "2018-01-04T00:00:00Z");
        assert_eq!(second_level.tcb_status, "OutOfDate");
    }

    #[test]
    fn parse_tcb_info() {
        let json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let tcb_raw = TcbInfoRaw::try_from(json).expect("Failed to parse raw TCB");
        let tcb_info = TcbInfo::try_from(tcb_raw.tcb_info.get()).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.id, "SGX");
        assert_eq!(tcb_info.version, 3);
        assert_eq!(tcb_info.issue_date, "2023-05-10T13:43:27Z");
        assert_eq!(tcb_info.next_update, "2023-06-09T13:43:27Z");
        assert_eq!(tcb_info.fmspc, "00906ED50000");
        assert_eq!(tcb_info.pce_id, "0000");
        assert_eq!(tcb_info.tcb_type, 0);
        assert_eq!(tcb_info.tcb_evaluation_data_number, 15);
        assert_eq!(tcb_info.tcb_levels.len(), 17);

        let first_level = &tcb_info.tcb_levels[0];
        assert_eq!(first_level.tcb_date, "2023-02-15T00:00:00Z");
        assert_eq!(first_level.tcb_status, "SWHardeningNeeded");
        assert_eq!(
            first_level.advisory_ids,
            vec!["INTEL-SA-00334", "INTEL-SA-00615"]
        );
        let tcb = &first_level.tcb;
        assert_eq!(tcb.pce_svn, 13);

        // sub components robustly tested in the [`Tcb`] tests so just a quick
        // check here
        let first_sub_component = &tcb.sgx_tcb_components[0];
        assert_eq!(first_sub_component.svn, 20);
        assert_eq!(first_sub_component.category, None);
        assert_eq!(first_sub_component.r#type, None);

        let second_level = &tcb_info.tcb_levels[1];
        assert_eq!(second_level.tcb_date, "2023-02-15T00:00:00Z");
        assert_eq!(second_level.tcb_status, "ConfigurationAndSWHardeningNeeded");
        assert_eq!(
            second_level.advisory_ids,
            vec![
                "INTEL-SA-00219",
                "INTEL-SA-00289",
                "INTEL-SA-00334",
                "INTEL-SA-00615"
            ]
        );

        let last_level = &tcb_info.tcb_levels[16];
        assert_eq!(last_level.tcb_date, "2018-08-15T00:00:00Z");
        assert_eq!(last_level.tcb_status, "OutOfDate");
        assert_eq!(
            last_level.advisory_ids,
            vec![
                "INTEL-SA-00203",
                "INTEL-SA-00233",
                "INTEL-SA-00220",
                "INTEL-SA-00270",
                "INTEL-SA-00293",
                "INTEL-SA-00219",
                "INTEL-SA-00161",
                "INTEL-SA-00320",
                "INTEL-SA-00329",
                "INTEL-SA-00381",
                "INTEL-SA-00389",
                "INTEL-SA-00477",
                "INTEL-SA-00614",
                "INTEL-SA-00617",
                "INTEL-SA-00289",
                "INTEL-SA-00334",
                "INTEL-SA-00615"
            ]
        );
    }
    #[test]
    fn tcb_full_option_permutation() {
        let tcb_json = r#"{
                "sgxtcbcomponents": [
                    {
                      "svn": 1
                    },
                    {
                      "svn": 2,
                      "category": "It's a category"
                    },
                    {
                      "svn": 3,
                      "type": "It's a type"
                    },
                    {
                      "svn": 4,
                      "category": "It's a category with a type",
                      "type": "It's a type to go with the category"
                    }
                ],
                "pcesvn": 5
            }"#;
        let tcb = Tcb::try_from(tcb_json).expect("Failed to parse TCB");
        assert_eq!(tcb.pce_svn, 5);
        let components = vec![
            TcbComponent {
                svn: 1,
                category: None,
                r#type: None,
            },
            TcbComponent {
                svn: 2,
                category: Some("It's a category".into()),
                r#type: None,
            },
            TcbComponent {
                svn: 3,
                category: None,
                r#type: Some("It's a type".into()),
            },
            TcbComponent {
                svn: 4,
                category: Some("It's a category with a type".into()),
                r#type: Some("It's a type to go with the category".into()),
            },
        ];
        assert_eq!(tcb.sgx_tcb_components, components);
    }

    #[parameterized(
        at_issue_date = {"2023-05-10T13:43:27Z"},
        one_secend_after_issue_date = {"2023-05-10T13:43:28Z"},
        just_before_next_update = {"2023-06-09T13:43:26Z"},
    )]
    fn tcb_verification(time: &str) {
        let key = tcb_verifying_key();
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        let time = time.parse::<DateTime>().expect("Failed to parse time");

        assert_eq!(raw_tcb.verify(&key, time).is_ok(), true);
    }

    #[test]
    fn fails_before_issue_date() {
        let key = tcb_verifying_key();
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        let time = "2023-05-10T13:43:26Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");

        assert!(matches!(
            raw_tcb.verify(&key, time),
            Err(Error::TcbInfoNotYetValid)
        ));
    }

    #[test]
    fn fails_at_next_update() {
        let key = tcb_verifying_key();
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        let time = "2023-06-09T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");

        assert!(matches!(
            raw_tcb.verify(&key, time),
            Err(Error::TcbInfoExpired)
        ));
    }

    #[test]
    fn signature_decode_error() {
        let key = tcb_verifying_key();
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let time = "2023-05-10T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let mut raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        // Note enough bytes to decode to the Signature type
        raw_tcb.signature.truncate(63);

        assert!(matches!(
            raw_tcb.verify(&key, time),
            Err(Error::SignatureDecodeError)
        ));
    }

    #[test]
    fn signature_wrong() {
        let key = tcb_verifying_key();
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let time = "2023-05-10T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let mut raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        raw_tcb.signature[0] += 1;

        assert!(matches!(
            raw_tcb.verify(&key, time),
            Err(Error::SignatureVerification)
        ));
    }

    #[test]
    fn tcb_info_fails_to_parse_when_verifying() {
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let time = "2023-05-10T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let mut raw_tcb = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse raw TCB");

        // We need valid JSON, but not valid for the TcbInfo
        let bad_tcb_info = raw_tcb.tcb_info.get().replace("pceId", "unknown_field");
        let raw_value = RawValue::from_string(bad_tcb_info).expect("Failed to create RawValue");
        raw_tcb.tcb_info = &raw_value;

        assert!(matches!(raw_tcb.verify_time(time), Err(Error::Serde(_))));
    }

    #[test]
    fn tcb_issue_time_fails_to_parse_when_verifying() {
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let time = "2023-05-10T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");

        let bad_time_json = tcb_json.replace("2023-05-10", "2023-15-10");
        let raw_tcb =
            TcbInfoRaw::try_from(bad_time_json.as_ref()).expect("Failed to parse raw TCB");

        assert!(matches!(raw_tcb.verify_time(time), Err(Error::Der(_))));
    }

    #[test]
    fn tcb_next_upate_time_fails_to_parse_when_verifying() {
        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let time = "2023-05-10T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");

        let bad_time_json = tcb_json.replace("2023-06-09", "2023-16-09");
        let raw_tcb =
            TcbInfoRaw::try_from(bad_time_json.as_ref()).expect("Failed to parse raw TCB");

        assert!(matches!(raw_tcb.verify_time(time), Err(Error::Der(_))));
    }
}
