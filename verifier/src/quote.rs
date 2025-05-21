// Copyright (c) 2023-2025 The MobileCoin Foundation

use crate::{Accessor, Error, VerificationMessage, VerificationOutput, Verifier};
use core::fmt::Formatter;
use mc_sgx_dcap_types::Quote3;
use p256::ecdsa::VerifyingKey;

/// Verifier for ensuring a quote was signed with the provided key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Quote3Verifier<T> {
    key: Option<VerifyingKey>,
    _phantom: core::marker::PhantomData<T>,
}

impl<T> Quote3Verifier<T> {
    /// Create a new instance.
    ///
    /// The `key` should be retrieved from the leaf certificate of the quote's
    /// [`mc-sgx-dcap-types::CertificationData`].
    pub fn new(key: Option<VerifyingKey>) -> Self {
        Self {
            key,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<T: AsRef<[u8]>, E: Accessor<Quote3<T>>> Verifier<E> for Quote3Verifier<T> {
    type Value = ();
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let is_success = self
            .key
            .map(|key| evidence.get().verify(&key).is_ok() as u8)
            .unwrap_or(0);
        VerificationOutput::new((), is_success.into())
    }
}

impl<T> VerificationMessage<()> for Quote3Verifier<T> {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<()>,
    ) -> core::fmt::Result {
        let status = crate::choice_to_status_message(result.is_success());
        write!(f, "{:pad$}{status} ", "")?;
        if result.is_success().into() {
            write!(f, "The quote was signed with the provided key")
        } else {
            match self.key {
                Some(_) => write!(f, "The quote signature did not match provided key"),
                // Formatting the `MissingPublicKey` error for symmetry with other signature style
                // verifier messages
                None => write!(
                    f,
                    "The quote signature could not be verified: {}",
                    Error::MissingPublicKey
                ),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VerificationTreeDisplay;
    use alloc::format;
    use mc_sgx_dcap_types::CertificationData;
    use x509_cert::{der::DecodePem, Certificate};

    const QUOTE_BYTES: &[u8] = include_bytes!("../data/tests/hw_quote.dat");

    fn quote_signing_key<T: AsRef<[u8]>>(quote: &Quote3<T>) -> VerifyingKey {
        let signature_data = quote.signature_data();
        let certification_data = signature_data.certification_data();
        let CertificationData::PckCertificateChain(chain) = certification_data else {
            panic!("Unexpected certification data type");
        };
        let leaf_pem = chain.into_iter().next().expect("No leaf certificate");
        let certificate =
            Certificate::from_pem(leaf_pem).expect("Failed to parse leaf certificate");

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
    fn verify_quote3() {
        let quote = Quote3::try_from(QUOTE_BYTES).expect("Failed to parse quote");
        let key = quote_signing_key(&quote);
        let verifier = Quote3Verifier::new(Some(key));
        let verification = verifier.verify(&quote);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] The quote was signed with the provided key"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn failure_to_verify_quote3() {
        let mut quote_bytes = QUOTE_BYTES.to_vec();

        // Skipping the first 4 bytes, because modifying them would prevent the
        // quote from parsing. The 5th byte (index 4) will only affect the
        // signature.
        quote_bytes[4] += 1;

        let quote = Quote3::try_from(quote_bytes.as_slice()).expect("Failed to parse quote");
        let key = quote_signing_key(&quote);
        let verifier = Quote3Verifier::new(Some(key));
        let verification = verifier.verify(&quote);

        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The quote signature did not match provided key"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn no_key_to_verify_quote3() {
        let quote = Quote3::try_from(QUOTE_BYTES).expect("Failed to parse quote");
        let verifier = Quote3Verifier::new(None);
        let verification = verifier.verify(&quote);

        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The quote signature could not be verified: No public key available for signature verification"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
