// Copyright (c) 2023 The MobileCoin Foundation

//! Verifier for TCB information
//!
//! See <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3>
//! for the format
//!
//! The TCB info is retrieved by using the fsmpc available in the report body
//! and accessing <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>

#![allow(dead_code)]

use serde::Deserialize;
use serde_json::value::RawValue;

/// Error parsing TCB info
#[derive(Debug)]
pub enum Error {
    Serde(serde_json::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

/// Raw unverified representation of the TCB info provided from
/// <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
///
/// Due to the way the TCB info is signed the contents should be provided as is.
#[derive(Debug, Deserialize)]
pub struct TcbInfoRaw<'a> {
    tcb_info: &'a RawValue,
    signature: &'a str,
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

    #[test]
    fn parse_unverified_tcb_info() {
        // For this test we don't care what the contents of `tcb_info` is, just
        // that we separate the signature from the tcb_info correctly.
        let raw_info =
            r#"{"tcb_info":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"hello"}"#;
        let tcb_info = TcbInfoRaw::try_from(raw_info).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.signature, "hello");
        assert_eq!(
            tcb_info.tcb_info.get(),
            r#"{"id":"SGX","version":3,"fmspc":"00906ED50000"}"#
        );
    }

    #[test]
    fn two_signatures_errors() {
        let raw_info = r#"{"tcb_info":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"hello","signature":"fail"}"#;
        assert!(matches!(
            TcbInfoRaw::try_from(raw_info),
            Err(Error::Serde(_))
        ));
    }

    #[test]
    fn two_tcb_infos_errors() {
        let raw_info = r#"{"tcb_info":"too many cooks","tcb_info":{"id":"SGX","version":3,"fmspc":"00906ED50000"},"signature":"hello"}"#;
        assert!(matches!(
            TcbInfoRaw::try_from(raw_info),
            Err(Error::Serde(_))
        ));
    }

    #[test]
    fn nested_tcb_info_still_in_parent() {
        let raw_info = r#"{"tcb_info":{"tcb_info":"nested","version":3,"fmspc":"00906ED50000"},"signature":"hello"}"#;
        let tcb_info = TcbInfoRaw::try_from(raw_info).expect("Failed to parse TCB info");
        assert_eq!(tcb_info.signature, "hello");
        assert_eq!(
            tcb_info.tcb_info.get(),
            r#"{"tcb_info":"nested","version":3,"fmspc":"00906ED50000"}"#
        );
    }
}
