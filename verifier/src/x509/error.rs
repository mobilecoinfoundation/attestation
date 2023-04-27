/// Error type for decoding and verifying certificates.
#[derive(Debug, displaydoc::Display, PartialEq, Eq)]
pub enum Error {
    /// An error occurred decoding the signature from a certificate
    SignatureDecoding,
    /// The certification signature does not match with the verifying key
    SignatureVerification,
    /// The certificate has expired
    CertificateExpired,
    /// An error occurred decoding the certificate
    CertificateDecoding(x509_cert::der::Error),
    /// The certificate is not yet valid
    CertificateNotYetValid,
    /// An error occurred decoding the key from a certificate
    KeyDecoding,
}

impl From<x509_cert::der::Error> for Error {
    fn from(src: x509_cert::der::Error) -> Self {
        Error::CertificateDecoding(src)
    }
}
