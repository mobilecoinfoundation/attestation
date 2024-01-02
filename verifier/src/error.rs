// Copyright (c) 2023-2024 The MobileCoin Foundation

//! Errors that can occur during verification

use alloc::string::{String, ToString};
use mc_sgx_dcap_types::TcbError;
use serde::{Deserialize, Serialize};

/// Error working with quote evidence
#[derive(displaydoc::Display, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Error {
    /// Error converting from DER {0}
    Der(String),
    /// Error parsing TCB(Trusted Computing Base) json info: {0}
    Serde(String),
    /// Error decoding the signature in the TCB data
    SignatureDecodeError,
    /// Error verifying the signature
    SignatureVerification,
    /// No public key available for signature verification
    MissingPublicKey,
    /// TCB info not yet valid
    TcbInfoNotYetValid,
    /// TCB info expired
    TcbInfoExpired,
    /// TCB info version mismatch, expecting {expected} got {actual}
    #[allow(missing_docs)]
    TcbInfoVersion { expected: u32, actual: u32 },
    /// Asking for TCB levels for a different FMSPC
    FmspcMismatch,
    /// The TCB level reported does not match an entry in the TCB info data.
    UnsupportedTcbLevel,
    /// Failure to get the TCB info from a quote {0}
    Quote3TcbInfo(TcbError),
    /// Unsupported quote certification data, should be `PckCertificateChain`
    UnsupportedQuoteCertificationData,
    /// QE identity expired
    QeIdentityExpired,
    /// QE identity not yet valid
    QeIdentityNotYetValid,
    /// QE identity version mismatch, expecting {expected} got {actual}
    #[allow(missing_docs)]
    QeIdentityVersion { expected: u32, actual: u32 },
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Der(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e.to_string())
    }
}

impl From<TcbError> for Error {
    fn from(e: TcbError) -> Self {
        Error::Quote3TcbInfo(e)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn serde_error_to_string() {
        let bad_json = "not json";
        let e = serde_json::from_str::<serde_json::Value>(bad_json).unwrap_err();
        let serde_error_message = e.to_string();
        let err = Error::from(e);
        assert_matches!(err, Error::Serde(message) if message.contains(&serde_error_message));
    }

    #[test]
    fn der_error_to_string() {
        let e = der::Error::incomplete(1u8.into());
        let der_error_message = e.to_string();
        let err = Error::from(e);
        assert_matches!(err, Error::Der(message) if message.contains(&der_error_message));
    }
}
