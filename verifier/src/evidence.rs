// Copyright (c) 2023 The MobileCoin Foundation

//! The full set of evidence needed for attesting a quote

use crate::{Accessor, Advisories, Error, Result, TcbInfo, TcbInfoRaw};
use der::DecodePem;
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportData,
};
use mc_sgx_dcap_types::{CertificationData, Quote3, TcbInfo as QuoteTcbInfo};
use x509_cert::Certificate;

/// The full set of evidence needed for verifying a quote
///
/// A wrapping container for a `Quote3` and a `TcbInfoRaw`. This can be used
/// with the majority of the `Verifier` implementations from this crate.
/// This allows one to compose one verifier and use an [`Evidence`] instance in
/// the `verify()` method.
///
/// Importantly this will derive the [`Advisories`] related to the provided
/// `quote` and `tcb_info_raw`, so that one can verify the allowed advisories.
#[derive(Debug)]
pub struct Evidence<'a, Q> {
    quote: Quote3<Q>,
    tcb_info_raw: TcbInfoRaw<'a>,
    advisories: Advisories,
}

impl<'a, Q: AsRef<[u8]>> Evidence<'a, Q> {
    /// Create a new instance
    pub fn new(quote: Quote3<Q>, tcb_info_raw: TcbInfoRaw<'a>) -> Result<Self> {
        let quote_tcb_info = tcb_info_try_from_quote(&quote)?;
        let tcb_info = TcbInfo::try_from(&tcb_info_raw)?;
        let advisories = tcb_info.advisories(&quote_tcb_info)?;
        Ok(Self {
            quote,
            tcb_info_raw,
            advisories,
        })
    }
}

impl<'a, Q> Accessor<TcbInfoRaw<'a>> for Evidence<'a, Q> {
    fn get(&self) -> TcbInfoRaw<'a> {
        self.tcb_info_raw.clone()
    }
}

impl<'a, Q: Clone> Accessor<Quote3<Q>> for Evidence<'a, Q> {
    fn get(&self) -> Quote3<Q> {
        self.quote.clone()
    }
}

impl<'a, Q> Accessor<Advisories> for Evidence<'a, Q> {
    fn get(&self) -> Advisories {
        self.advisories.clone()
    }
}

// TODO think this should go in tcb.rs of `mc-sgx-dcap-types`
fn tcb_info_try_from_quote<Q: AsRef<[u8]>>(quote: &Quote3<Q>) -> Result<QuoteTcbInfo> {
    let signature_data = quote.signature_data();
    let certification_data = signature_data.certification_data();
    let CertificationData::PckCertificateChain(pem_chain) = certification_data else {
        return Err(Error::UnsupportedQuoteCertificationData);
    };
    let leaf_cert = pem_chain
        .into_iter()
        .next()
        .ok_or(Error::UnsupportedQuoteCertificationData)?;
    let certificate = Certificate::from_pem(leaf_cert)?;
    Ok(QuoteTcbInfo::try_from(&certificate)?)
}

/// Macro to generate boilerplate for implementing [`Accessor`] for a field of
/// the application enclave [`ReportBody`] in the evidence's [`Quote3`]
///
/// # Arguments
/// * `field_type` - The type of the field in `ReportBody` to be accessed
/// * `accessor_method` - The method on `ReportBody` that returns the field
macro_rules! quote_application_report_body_field_accessor {
    ($($field_type:ty, $accessor_method:ident;)*) => {$(
        impl<'a, Q: AsRef<[u8]>> Accessor<$field_type> for Evidence<'a, Q> {
            fn get(&self) -> $field_type {
                self.quote.app_report_body().$accessor_method()
            }
        }
    )*}
}

quote_application_report_body_field_accessor! {
    Attributes, attributes;
    ConfigId, config_id;
    ConfigSvn, config_svn;
    CpuSvn, cpu_svn;
    ExtendedProductId, isv_extended_product_id;
    FamilyId, isv_family_id;
    IsvProductId, isv_product_id;
    IsvSvn, isv_svn;
    MiscellaneousSelect, miscellaneous_select;
    MrEnclave, mr_enclave;
    MrSigner, mr_signer;
    ReportData, report_data;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        AdvisoriesVerifier, AdvisoryStatus, And, AttributesVerifier, MrSignerVerifier,
        Quote3Verifier, TcbInfoRawVerifier, VerificationTreeDisplay, Verifier,
    };
    use alloc::format;
    use core::mem;
    use der::DateTime;
    use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t};
    use p256::ecdsa::VerifyingKey;

    fn tcb_signing_key() -> VerifyingKey {
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

    type VerifierType<T> = And<
        Quote3Verifier<T>,
        And<MrSignerVerifier, And<AttributesVerifier, And<TcbInfoRawVerifier, AdvisoriesVerifier>>>,
    >;

    // Get a common verifier used in these tests.
    //
    // The values were taking from the on test files
    // "../data/tests/hw_quote.dat" and
    // "../data/tests/fmspc_00906ED50000_2023_05_10.json"
    fn verifier<Q: AsRef<[u8]>>(product_id: IsvProductId, quote: &Quote3<Q>) -> VerifierType<Q> {
        let quote_key = quote_signing_key(quote);
        let tcb_key = tcb_signing_key();
        let mr_signer = [
            0xD4, 0x12, 0xA4, 0xF0, 0x7E, 0xF8, 0x38, 0x92, 0xA5, 0x91, 0x5F, 0xB2, 0xAB, 0x58,
            0x4B, 0xE3, 0x1E, 0x18, 0x6E, 0x5A, 0x4F, 0x95, 0xAB, 0x5F, 0x69, 0x50, 0xFD, 0x4E,
            0xB8, 0x69, 0x4D, 0x7B,
        ];
        let isv_svn = 0;
        let attributes = Attributes::default()
            .set_flags(7)
            .set_extended_features_mask(7);
        let time = "2023-06-08T13:43:27Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let allowed_advisories = Advisories::new(
            [
                "INTEL-SA-00161",
                "INTEL-SA-00219",
                "INTEL-SA-00289",
                "INTEL-SA-00334",
                "INTEL-SA-00614",
                "INTEL-SA-00615",
                "INTEL-SA-00617",
            ],
            AdvisoryStatus::OutOfDate,
        );
        let verifier = And::new(
            Quote3Verifier::new(quote_key),
            And::new(
                MrSignerVerifier::new(mr_signer.into(), product_id, isv_svn.into()),
                And::new(
                    AttributesVerifier::new(attributes),
                    And::new(
                        TcbInfoRawVerifier::new(tcb_key, time),
                        AdvisoriesVerifier::new(allowed_advisories),
                    ),
                ),
            ),
        );
        verifier
    }

    #[test]
    fn evidence_verifies_correctly() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");

        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let tcb_info_raw = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse TCB info");

        let verifier = verifier(0.into(), &quote);
        let evidence = Evidence::new(quote, tcb_info_raw).expect("Failed to create evidence");
        let verification = verifier.verify(&evidence);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] Both of the following must be true:
              - [x] The quote was signed with the provided key
              - [x] Both of the following must be true:
                - [x] MRSIGNER all of the following must be true:
                  - [x] The MRSIGNER key hash should be 0xD412_A4F0_7EF8_3892_A591_5FB2_AB58_4BE3_1E18_6E5A_4F95_AB5F_6950_FD4E_B869_4D7B
                  - [x] The ISV product ID should be 0
                  - [x] The ISV SVN should be at least 0
                - [x] Both of the following must be true:
                  - [x] The attributes should be Flags: INITTED | DEBUG | MODE64BIT Xfrm: LEGACY | AVX
                  - [x] Both of the following must be true:
                    - [x] The raw TCB info was verified for the provided key
                    - [x] The allowed advisories are IDs: {"INTEL-SA-00161", "INTEL-SA-00219", "INTEL-SA-00289", "INTEL-SA-00334", "INTEL-SA-00614", "INTEL-SA-00615", "INTEL-SA-00617"} Status: OutOfDate"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn evidence_fails_verification() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");

        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let tcb_info_raw = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse TCB info");

        let verifier = verifier(1.into(), &quote);
        let evidence = Evidence::new(quote, tcb_info_raw).expect("Failed to create evidence");
        let verification = verifier.verify(&evidence);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] Both of the following must be true:
              - [x] The quote was signed with the provided key
              - [ ] Both of the following must be true:
                - [ ] MRSIGNER all of the following must be true:
                  - [x] The MRSIGNER key hash should be 0xD412_A4F0_7EF8_3892_A591_5FB2_AB58_4BE3_1E18_6E5A_4F95_AB5F_6950_FD4E_B869_4D7B
                  - [ ] The ISV product ID should be 1, but the actual ISV product ID was 0
                  - [x] The ISV SVN should be at least 0
                - [x] Both of the following must be true:
                  - [x] The attributes should be Flags: INITTED | DEBUG | MODE64BIT Xfrm: LEGACY | AVX
                  - [x] Both of the following must be true:
                    - [x] The raw TCB info was verified for the provided key
                    - [x] The allowed advisories are IDs: {"INTEL-SA-00161", "INTEL-SA-00219", "INTEL-SA-00289", "INTEL-SA-00334", "INTEL-SA-00614", "INTEL-SA-00615", "INTEL-SA-00617"} Status: OutOfDate"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn evidence_fails_due_to_wrong_quote_certification_data() {
        let mut quote_bytes = include_bytes!("../data/tests/hw_quote.dat").to_vec();

        // The offset logic is based on
        // <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C356%2C0%5D>
        let auth_data_offset =
            mem::size_of::<sgx_quote3_t>() + mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        let auth_data_size = u16::from_le_bytes([
            quote_bytes[auth_data_offset],
            quote_bytes[auth_data_offset + 1],
        ]) as usize;

        // "2" is for the u16 for reading in the auth data size
        let cert_data_type_offset = auth_data_offset + auth_data_size + 2;

        // Not all types are supported so we set to 1
        // (PPID in plain text, CPUSVN and PCESVN)
        quote_bytes[cert_data_type_offset] = 1;

        let quote = Quote3::try_from(quote_bytes).expect("Failed to parse quote");

        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let tcb_info_raw = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse TCB info");

        assert!(matches!(
            Evidence::new(quote, tcb_info_raw),
            Err(Error::UnsupportedQuoteCertificationData)
        ));
    }

    #[test]
    fn evidence_fails_due_inability_get_advisories() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");

        let tcb_json = include_str!("../data/tests/example_tcb.json");
        let tcb_info_raw = TcbInfoRaw::try_from(tcb_json).expect("Failed to parse TCB info");

        assert!(matches!(
            Evidence::new(quote, tcb_info_raw),
            Err(Error::FmspcMismatch)
        ));
    }

    #[test]
    fn evidence_fails_due_inability_get_underlying_tcb_info() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");

        let tcb_json = include_str!("../data/tests/fmspc_00906ED50000_2023_05_10.json");
        let bad_tcb_json = tcb_json.replace("SWHardeningNeeded", "NotGonnaHappen");
        let tcb_info_raw =
            TcbInfoRaw::try_from(bad_tcb_json.as_str()).expect("Failed to parse TCB info");

        assert!(matches!(
            Evidence::new(quote, tcb_info_raw),
            Err(Error::Serde(_))
        ));
    }
}
