// Copyright (c) 2023 The MobileCoin Foundation

//! Errors that can occur during verification

use mc_sgx_dcap_types::TcbError;

pub type Result<T> = core::result::Result<T, Error>;

/// Error working with quote evidence
#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Error converting from DER {0}
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
        Error::Der(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<TcbError> for Error {
    fn from(e: TcbError) -> Self {
        Error::Quote3TcbInfo(e)
    }
}
