/// Error type for decoding and verifying certificates.
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum Error {
    /// An error occurred working with MbedTls
    MbedTls(mbedtls::Error),
    /// An error occurred decoding the signature from a certificate
    SignatureDecoding,
    /// The certification signature does not match with the verifying key
    SignatureVerification,
    /// The certificate has expired
    CertificateExpired,
    /// An error occurred decoding the DER representation
    DerDecoding(x509_cert::der::Error),
    /// The certificate is not yet valid
    CertificateNotYetValid,
    /// An error occurred decoding the key from a certificate
    KeyDecoding,
    /// The certificate revocation list has expired
    CrlExpired,
    /// The certificate revocation list is not yet valid
    CrlNotYetValid,
    /// Certificate revocation list missing next update time
    CrlMissingNextUpdate,
}

impl From<x509_cert::der::Error> for Error {
    fn from(src: x509_cert::der::Error) -> Self {
        Error::DerDecoding(src)
    }
}

impl From<mbedtls::Error> for Error {
    fn from(src: mbedtls::Error) -> Self {
        Error::MbedTls(src)
    }
}
