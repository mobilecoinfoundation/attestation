// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Verifiers which operate on the [`ReportBody`]

use crate::{
    choice_to_status_message, Accessor, EqualityVerifier, GreaterThanEqualVerifier, MaskedVerifier,
    VerificationMessage, VerificationOutput, Verifier, MESSAGE_INDENT,
};
use core::fmt::{Debug, Formatter};
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportBody, ReportData,
};
use subtle::{ConstantTimeEq, ConstantTimeGreater};

/// Macro to generate boilerplate for implementing [`Accessor`] for a field of
/// [`ReportBody`].
///
/// # Arguments
/// * `field_type` - The type of the field in `ReportBody` to be accessed
/// * `accessor_method` - The method on `ReportBody` that returns the field
macro_rules! report_body_field_accessor {
    ($($field_type:ty, $accessor_method:ident;)*) => {$(
        impl Accessor<$field_type> for ReportBody {
            fn get(&self) -> $field_type {
                self.$accessor_method()
            }
        }
    )*}
}

report_body_field_accessor! {
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

/// Verifier for ensuring [`Attributes`] values are equivalent.
pub type AttributesVerifier = MaskedVerifier<Attributes>;

/// Verifier for ensuring [`ConfigId`] values are equivalent.
pub type ConfigIdVerifier = EqualityVerifier<ConfigId>;

/// Verifier for ensuring [`ConfigSvn`] is greater than or equal to an
/// expected [`ConfigSvn`]
pub type ConfigSvnVerifier = GreaterThanEqualVerifier<ConfigSvn>;

impl<E: Accessor<ConfigSvn>> Verifier<E> for GreaterThanEqualVerifier<ConfigSvn> {
    type Value = ConfigSvn;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let expected = self.expected;
        let actual = evidence.get();

        let is_success =
            actual.as_ref().ct_gt(expected.as_ref()) | actual.as_ref().ct_eq(expected.as_ref());
        VerificationOutput::new(actual, is_success)
    }
}

/// Verifier for ensuring [`CpuSvn`] is greater than or equal to an
/// expected [`CpuSvn`]
pub type CpuSvnVerifier = GreaterThanEqualVerifier<CpuSvn>;

fn cpu_svn_to_u64s(cpu_svn: &CpuSvn) -> (u64, u64) {
    let cpu_svn_bytes: &[u8] = cpu_svn.as_ref();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&cpu_svn_bytes[0..8]);
    let high = <u64>::from_be_bytes(bytes);
    bytes.copy_from_slice(&cpu_svn_bytes[8..]);
    let low = <u64>::from_be_bytes(bytes);
    (high, low)
}

impl<E: Accessor<CpuSvn>> Verifier<E> for GreaterThanEqualVerifier<CpuSvn> {
    type Value = CpuSvn;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let expected = self.expected.clone();
        let actual = evidence.get();

        // Per the Intel docs, CPU SVN is a 16 byte BE value. Since we may not
        // support u128 on all platforms we compare the 64 bit values.
        let (actual_high, actual_low) = cpu_svn_to_u64s(&actual);
        let (expected_high, expected_low) = cpu_svn_to_u64s(&expected);
        let is_success = actual_high.ct_gt(&expected_high)
            | (actual_high.ct_eq(&expected_high)
                & (actual_low.ct_gt(&expected_low) | actual_low.ct_eq(&expected_low)));

        VerificationOutput::new(actual, is_success)
    }
}

/// Verifier for ensuring [`ExtendedProductId`] values are equivalent.
pub type ExtendedProductIdVerifier = EqualityVerifier<ExtendedProductId>;

/// Verifier for ensuring [`FamilyId`] values are equivalent.
pub type FamilyIdVerifier = EqualityVerifier<FamilyId>;

/// Verifier for ensuring [`IsvProductId`] values are equivalent.
pub type IsvProductIdVerifier = EqualityVerifier<IsvProductId>;

/// Verifier for ensuring [`IsvSvn`] is greater than or equal to an expected
/// [`IsvSvn`]
pub type IsvSvnVerifier = GreaterThanEqualVerifier<IsvSvn>;

impl<E: Accessor<IsvSvn>> Verifier<E> for GreaterThanEqualVerifier<IsvSvn> {
    type Value = IsvSvn;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let expected = self.expected;
        let actual = evidence.get();

        let is_success =
            actual.as_ref().ct_gt(expected.as_ref()) | actual.as_ref().ct_eq(expected.as_ref());
        VerificationOutput::new(actual, is_success)
    }
}

/// Verifier for ensuring [`MiscellaneousSelect`] values are equivalent.
pub type MiscellaneousSelectVerifier = MaskedVerifier<MiscellaneousSelect>;

/// Verifier for ensuring [`MrEnclave`] values are equivalent.
///
/// The Intel SDK docs refer to this as "Strict Enclave Modification Policy"
pub type MrEnclaveVerifier = EqualityVerifier<MrEnclave>;

#[derive(Clone, Debug)]
pub struct MrSignerValue {
    mr_signer_key: VerificationOutput<MrSigner>,
    product_id: VerificationOutput<IsvProductId>,
    isv_svn: VerificationOutput<IsvSvn>,
}

impl MrSignerValue {
    pub fn new(
        mr_signer_key: VerificationOutput<MrSigner>,
        product_id: VerificationOutput<IsvProductId>,
        isv_svn: VerificationOutput<IsvSvn>,
    ) -> Self {
        Self {
            mr_signer_key,
            product_id,
            isv_svn,
        }
    }
}

/// Verifier for ensuring all of the MRSIGNER inputs are sufficient.
///
/// The Intel SDK docs refer to this as "Security Enclave Modification Policy"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrSignerVerifier {
    mr_signer_key: MrSignerKeyVerifier,
    product_id: IsvProductIdVerifier,
    isv_svn: IsvSvnVerifier,
}

impl MrSignerVerifier {
    /// Create a new [`MrSignerVerifier`]
    pub fn new(mr_signer: MrSigner, product_id: IsvProductId, isv_svn: IsvSvn) -> Self {
        Self {
            mr_signer_key: MrSignerKeyVerifier::new(mr_signer),
            product_id: IsvProductIdVerifier::new(product_id),
            isv_svn: IsvSvnVerifier::new(isv_svn),
        }
    }
}

impl<E: Accessor<MrSigner> + Accessor<IsvProductId> + Accessor<IsvSvn>> Verifier<E>
    for MrSignerVerifier
{
    type Value = MrSignerValue;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let mr_signer_key = self.mr_signer_key.verify(evidence);
        let product_id = self.product_id.verify(evidence);
        let isv_svn = self.isv_svn.verify(evidence);

        let is_success =
            mr_signer_key.is_success() & product_id.is_success() & isv_svn.is_success();

        VerificationOutput::new(
            MrSignerValue::new(mr_signer_key, product_id, isv_svn),
            is_success,
        )
    }
}

impl VerificationMessage<MrSignerValue> for MrSignerVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        output: &VerificationOutput<MrSignerValue>,
    ) -> core::fmt::Result {
        let status = choice_to_status_message(output.is_success());

        write!(
            f,
            "{:pad$}{status} MRSIGNER all of the following must be true:",
            ""
        )?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f)?;
        self.mr_signer_key
            .fmt_padded(f, pad, &output.value.mr_signer_key)?;
        writeln!(f)?;
        self.product_id
            .fmt_padded(f, pad, &output.value.product_id)?;
        writeln!(f)?;
        self.isv_svn.fmt_padded(f, pad, &output.value.isv_svn)
    }
}

pub type MrSignerKeyVerifier = EqualityVerifier<MrSigner>;

/// Verifier for ensuring [`ReportData`] values are equivalent.
pub type ReportDataVerifier = MaskedVerifier<ReportData>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::{struct_name::SpacedStructName, And, VerificationTreeDisplay};
    use alloc::{format, string::ToString};
    use mc_sgx_core_sys_types::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t,
    };
    use mc_sgx_core_types::{AttributeFlags, ExtendedFeatureRequestMask};
    use yare::parameterized;
    const ALL_ATTRIBUTE_BITS: sgx_attributes_t = sgx_attributes_t {
        flags: 0xFFFF_FFFF_FFFF_FFFF,
        xfrm: 0xFFFF_FFFF_FFFF_FFFF,
    };

    const REPORT_BODY_SRC: sgx_report_body_t = sgx_report_body_t {
        cpu_svn: sgx_cpu_svn_t {
            svn: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        },
        misc_select: 17,
        reserved1: [0u8; 12],
        isv_ext_prod_id: [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        attributes: sgx_attributes_t {
            flags: 0x0102_0304_0506_0708,
            xfrm: 0x0807_0605_0403_0201,
        },
        mr_enclave: sgx_measurement_t {
            m: [
                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                38, 39, 40, 41, 42, 43, 43, 44, 45, 46, 47,
            ],
        },
        reserved2: [0u8; 32],
        mr_signer: sgx_measurement_t {
            m: [
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
                69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
            ],
        },
        reserved3: [0u8; 32],
        config_id: [
            80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
            101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
            118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
            135, 136, 137, 138, 139, 140, 141, 142, 143,
        ],
        isv_prod_id: 144,
        isv_svn: 145,
        config_svn: 146,
        reserved4: [0u8; 42],
        isv_family_id: [
            147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162,
        ],
        report_data: sgx_report_data_t {
            d: [
                163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178,
                179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
                195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
            ],
        },
    };

    #[test]
    fn report_body_succeeds() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes(), ALL_ATTRIBUTE_BITS.into()),
            ConfigIdVerifier::new(report_body.config_id()),
        );
        assert_eq!(verifier.verify(&report_body).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_attributes() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let attributes = report_body.attributes().set_flags(AttributeFlags::DEBUG);
        let verifier = And::new(
            AttributesVerifier::new(attributes, ALL_ATTRIBUTE_BITS.into()),
            ConfigIdVerifier::new(report_body.config_id()),
        );
        assert_eq!(verifier.verify(&report_body).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_config_id() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut config_id = report_body.config_id();
        config_id.as_mut()[0] = 0;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes(), ALL_ATTRIBUTE_BITS.into()),
            ConfigIdVerifier::new(config_id),
        );
        assert_eq!(verifier.verify(&report_body).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_config_security_version() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let expected_config_svn = *report_body.config_svn().as_mut() + 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes(), ALL_ATTRIBUTE_BITS.into()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                ConfigSvnVerifier::new(expected_config_svn.into()),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_mr_enclave() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut mr_enclave = report_body.mr_enclave();
        let bytes: &mut [u8] = mr_enclave.as_mut();
        bytes[0] += 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes(), ALL_ATTRIBUTE_BITS.into()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                MrEnclaveVerifier::new(mr_enclave),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_mr_signer() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut mr_signer = report_body.mr_signer();
        let bytes: &mut [u8] = mr_signer.as_mut();
        bytes[0] += 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes(), ALL_ATTRIBUTE_BITS.into()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                MrSignerVerifier::new(
                    mr_signer,
                    report_body.isv_product_id(),
                    report_body.isv_svn(),
                ),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn attributes_size() {
        // Because the verification of [`Attributes`] looks at each field, we
        // check the size to ensure no new fields have been added.
        // Both current fields, `flags` and `xfrm`, are u64s or 8 bytes each.
        assert_eq!(core::mem::size_of::<Attributes>(), 16);
    }

    #[test]
    fn attributes_success() {
        let attributes = Attributes::default()
            .set_flags(AttributeFlags::DEBUG | AttributeFlags::INITTED)
            .set_extended_features_mask(ExtendedFeatureRequestMask::AVX_512);

        let attributes_verifier = AttributesVerifier::new(attributes, ALL_ATTRIBUTE_BITS.into());
        let verification = attributes_verifier.verify(&attributes);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&attributes_verifier, verification);
        let expected = r#"
            - [x] The expected attributes is Flags: INITTED | DEBUG Xfrm: AVX | AVX_512 with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn attributes_fail_for_flags() {
        let mut attributes = Attributes::default()
            .set_flags(AttributeFlags::DEBUG | AttributeFlags::INITTED)
            .set_extended_features_mask(ExtendedFeatureRequestMask::AVX_512);
        let attributes_verifier = AttributesVerifier::new(attributes, ALL_ATTRIBUTE_BITS.into());

        attributes = attributes
            .set_flags(AttributeFlags::from_bits(0).expect("Failed to convert from bits"));

        let verification = attributes_verifier.verify(&attributes);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&attributes_verifier, verification);
        let expected = r#"
            - [ ] The expected attributes is Flags: INITTED | DEBUG Xfrm: AVX | AVX_512 with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED, but the actual attributes was Flags: (none) Xfrm: AVX | AVX_512"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn attributes_fail_for_feature_mask() {
        let mut attributes = Attributes::default()
            .set_flags(AttributeFlags::DEBUG | AttributeFlags::INITTED)
            .set_extended_features_mask(ExtendedFeatureRequestMask::AVX_512);
        let attributes_verifier = AttributesVerifier::new(attributes, ALL_ATTRIBUTE_BITS.into());
        attributes = attributes.set_extended_features_mask(
            ExtendedFeatureRequestMask::from_bits(0).expect("Failed to convert from bits"),
        );

        let verification = attributes_verifier.verify(&attributes);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&attributes_verifier, verification);
        let expected = r#"
            - [ ] The expected attributes is Flags: INITTED | DEBUG Xfrm: AVX | AVX_512 with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED, but the actual attributes was Flags: INITTED | DEBUG Xfrm: (none)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn attributes_fail_for_debug_bit_in_mask() {
        // This is a common case where the enclave is built with debug.
        // a production environment verifier should not verify a debug enclave
        // as it will leak secrets.
        let release_attributes = Attributes::default();
        let debug_attributes = Attributes::default().set_flags(AttributeFlags::DEBUG);
        let attributes_verifier = AttributesVerifier::new(release_attributes, debug_attributes);

        let verification = attributes_verifier.verify(&debug_attributes);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&attributes_verifier, verification);
        let expected = r#"
            - [ ] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: DEBUG Xfrm: (none), but the actual attributes was Flags: DEBUG Xfrm: (none)"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn attributes_succeed_when_debug_bit_not_set_in_mask() {
        let release_attributes = Attributes::default();
        let debug_attributes = Attributes::default().set_flags(AttributeFlags::DEBUG);
        let mask_all_but_debug = Attributes::from(sgx_attributes_t {
            flags: !AttributeFlags::DEBUG.bits(),
            xfrm: 0xFFFF_FFFF_FFFF_FFFF,
        });
        let attributes_verifier = AttributesVerifier::new(release_attributes, mask_all_but_debug);

        let verification = attributes_verifier.verify(&debug_attributes);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&attributes_verifier, verification);
        let expected = r#"
            - [x] The expected attributes is Flags: (none) Xfrm: (none) with mask Flags: 0xFFFF_FFFF_FFFF_FFFD Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn config_id_success() {
        let config_id = ConfigId::from(REPORT_BODY_SRC.config_id);
        let verifier = ConfigIdVerifier::new(config_id.clone());

        assert_eq!(verifier.verify(&config_id).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn config_id_fail() {
        let mut config_id = ConfigId::from(REPORT_BODY_SRC.config_id);
        let verifier = ConfigIdVerifier::new(config_id.clone());
        config_id.as_mut()[0] = 2;

        assert_eq!(verifier.verify(&config_id).is_failure().unwrap_u8(), 1);
    }

    #[parameterized(
        equal = { 10, 10 },
        greater = { 12, 11 },
        much_greater = { 20, 1 },
    )]
    fn config_svn_succeeds(actual: u16, expected: u16) {
        let verifier = ConfigSvnVerifier::new(expected.into());
        let config_svn = ConfigSvn::from(actual);

        assert_eq!(verifier.verify(&config_svn).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn config_svn_fails_less_than_expected() {
        let verifier = ConfigSvnVerifier::new(10.into());
        let config_svn = ConfigSvn::from(9);

        assert_eq!(verifier.verify(&config_svn).is_failure().unwrap_u8(), 1);
    }

    #[parameterized(
        equal = { 25, 25 },
        greater = { 17, 16 },
        much_greater = { 100, 50 },
    )]
    fn isv_svn_succeeds(actual: u16, expected: u16) {
        let verifier = IsvSvnVerifier::new(expected.into());
        let isv_svn = IsvSvn::from(actual);

        assert_eq!(verifier.verify(&isv_svn).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn isv_svn_fails_less_than_expected() {
        let verifier = IsvSvnVerifier::new(10.into());
        let isv_svn = IsvSvn::from(9);

        assert_eq!(verifier.verify(&isv_svn).is_failure().unwrap_u8(), 1);
    }

    #[parameterized(
        empty_mask = { 0x5555_5555, 0x5555_5555, 0 },
        last_bit_masked = { 0xFFFF_FFFF, 0x0000_0001, 0x0000_0001 },
        upper_bit_masked = { 0x8000_0000, 0xFFFF_FFFF, 0x8000_0000 },
        last_nybble_masked = { 0x5555_5555, 0xAAAA_5555, 0x0000_FFFF },
        upper_nybble_masked = { 0xAAAA_AAAA, 0xAAAA_5555, 0xFFFF_0000 },
    )]
    fn miscellaneous_select_success(actual: u32, expected: u32, mask: u32) {
        let miscellaneous_select = MiscellaneousSelect::from(expected);
        let verifier = MiscellaneousSelectVerifier::new(actual.into(), mask.into());

        assert_eq!(
            verifier
                .verify(&miscellaneous_select)
                .is_success()
                .unwrap_u8(),
            1
        );
    }

    #[test]
    fn miscellaneous_select_fails() {
        let mut miscellaneous_select = MiscellaneousSelect::from(0xFFFF_FFFF);
        let verifier =
            MiscellaneousSelectVerifier::new(miscellaneous_select.clone(), 0xFFFF_FFFF.into());
        *miscellaneous_select.as_mut() = 0xFFFF_FFFE;

        assert_eq!(
            verifier
                .verify(&miscellaneous_select)
                .is_failure()
                .unwrap_u8(),
            1
        );
    }

    #[test]
    fn mr_encalve_success() {
        let mr_enclave = MrEnclave::from(REPORT_BODY_SRC.mr_enclave);
        let verifier = MrEnclaveVerifier::new(mr_enclave.clone());

        assert_eq!(verifier.verify(&mr_enclave).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn mr_enclave_fails() {
        let mut mr_enclave = MrEnclave::from(REPORT_BODY_SRC.mr_enclave);
        let verifier = MrEnclaveVerifier::new(mr_enclave.clone());
        let bytes: &mut [u8] = mr_enclave.as_mut();
        bytes[0] = 0;

        assert_eq!(verifier.verify(&mr_enclave).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_key_success() {
        let mr_signer = MrSigner::from(REPORT_BODY_SRC.mr_signer);
        let verifier = MrSignerKeyVerifier::new(mr_signer.clone());

        assert_eq!(verifier.verify(&mr_signer).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_key_fails() {
        let mut mr_signer = MrSigner::from(REPORT_BODY_SRC.mr_signer);
        let verifier = MrSignerKeyVerifier::new(mr_signer.clone());
        let bytes: &mut [u8] = mr_signer.as_mut();
        bytes[0] = 1;

        assert_eq!(verifier.verify(&mr_signer).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_success() {
        let report_data = ReportData::from(REPORT_BODY_SRC.report_data);
        let report_data_verifier =
            ReportDataVerifier::new(report_data.clone(), [0b1111_1111; ReportData::SIZE].into());
        let verification = report_data_verifier.verify(&report_data);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&report_data_verifier, verification);
        assert_eq!(format!("{displayable}"), "- [x] The expected report data is 0xA3A4_A5A6_A7A8_A9AA_ABAC_ADAE_AFB0_B1B2_B3B4_B5B6_B7B8_B9BA_BBBC_BDBE_BFC0_C1C2_C3C4_C5C6_C7C8_C9CA_CBCC_CDCE_CFD0_D1D2_D3D4_D5D6_D7D8_D9DA_DBDC_DDDE_DFE0_E1E2 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF");
    }

    #[test]
    fn report_data_fails() {
        let mut report_data = ReportData::from(REPORT_BODY_SRC.report_data);
        let report_data_verifier =
            ReportDataVerifier::new(report_data.clone(), [0b1111_1111; ReportData::SIZE].into());

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 1;

        let verification = report_data_verifier.verify(&report_data);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&report_data_verifier, verification);
        assert_eq!(format!("{displayable}"), "- [ ] The expected report data is 0xA3A4_A5A6_A7A8_A9AA_ABAC_ADAE_AFB0_B1B2_B3B4_B5B6_B7B8_B9BA_BBBC_BDBE_BFC0_C1C2_C3C4_C5C6_C7C8_C9CA_CBCC_CDCE_CFD0_D1D2_D3D4_D5D6_D7D8_D9DA_DBDC_DDDE_DFE0_E1E2 with mask 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF, but the actual report data was 0x01A4_A5A6_A7A8_A9AA_ABAC_ADAE_AFB0_B1B2_B3B4_B5B6_B7B8_B9BA_BBBC_BDBE_BFC0_C1C2_C3C4_C5C6_C7C8_C9CA_CBCC_CDCE_CFD0_D1D2_D3D4_D5D6_D7D8_D9DA_DBDC_DDDE_DFE0_E1E2");
    }

    #[test]
    fn report_data_ignores_masked_off_bits() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[0] = 0b0000_0000;
        let verifier = ReportDataVerifier::new(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 0b1111_0000;

        assert_eq!(verifier.verify(&report_data).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_fails_when_non_masked_bits_differ() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[0] = 0b0000_0000;
        let verifier = ReportDataVerifier::new(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 0b1111_0000;
        bytes[1] = 0b1111_0000; // Not masked off so should fail

        assert_eq!(verifier.verify(&report_data).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_ignores_masked_off_bit_at_end() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[mask_bytes.len() - 1] = 0b1111_1110;
        let verifier = ReportDataVerifier::new(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[bytes.len() - 1] = 0b1010_1011; // Note: the last bit is different

        assert_eq!(verifier.verify(&report_data).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_fails_when_non_masked_bit_differs() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let verifier = ReportDataVerifier::new(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[bytes.len() - 1] = 0b1010_1011; // Note: the last bit is different

        assert_eq!(verifier.verify(&report_data).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_succeeds() {
        let cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        assert_eq!(verifier.verify(&cpu_svn).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_on_high_u64() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_on_low_u64() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[15] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_succeeds_when_high_u64_greater() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] += 1;

        // Making this less, to show how the high 64 takes precedence
        bytes[15] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_when_high_u64_less_but_low_greater() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] -= 1;

        // Making this greater, to show how the high 64 takes precedence
        bytes[15] += 1;

        assert_eq!(verifier.verify(&cpu_svn).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn extended_product_id_succeeds() {
        let extended_product_id = ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id);
        let verifier = ExtendedProductIdVerifier::new(extended_product_id.clone());

        assert_eq!(
            verifier
                .verify(&extended_product_id)
                .is_success()
                .unwrap_u8(),
            1
        );
    }

    #[test]
    fn extended_product_id_fails() {
        let mut extended_product_id = ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id);
        let verifier = ExtendedProductIdVerifier::new(extended_product_id.clone());

        let bytes: &mut [u8] = extended_product_id.as_mut();
        bytes[0] += 1;

        assert_eq!(
            verifier
                .verify(&extended_product_id)
                .is_failure()
                .unwrap_u8(),
            1
        );
    }

    #[test]
    fn family_id_succeeds() {
        let family_id = FamilyId::from(REPORT_BODY_SRC.isv_family_id);
        let verifier = FamilyIdVerifier::new(family_id.clone());

        assert_eq!(verifier.verify(&family_id).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn family_id_fails() {
        let mut family_id = FamilyId::from(REPORT_BODY_SRC.isv_family_id);
        let verifier = FamilyIdVerifier::new(family_id.clone());

        let bytes: &mut [u8] = family_id.as_mut();
        bytes[0] += 1;

        assert_eq!(verifier.verify(&family_id).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn isv_product_id_succeeds() {
        let isv_product_id = IsvProductId::from(REPORT_BODY_SRC.isv_prod_id);
        let verifier = IsvProductIdVerifier::new(isv_product_id.clone());

        assert_eq!(verifier.verify(&isv_product_id).is_success().unwrap_u8(), 1);
    }

    #[test]
    fn isv_product_id_fails() {
        let mut isv_product_id = IsvProductId::from(REPORT_BODY_SRC.isv_prod_id);
        let verifier = IsvProductIdVerifier::new(isv_product_id.clone());

        *isv_product_id.as_mut() += 1;

        assert_eq!(verifier.verify(&isv_product_id).is_failure().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_succeeds() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let product_id = report_body.isv_product_id();
        let isv_svn = report_body.isv_svn();

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);
        let verification = mr_signer_verifier.verify(&report_body);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&mr_signer_verifier, verification);
        let expected = r#"
            - [x] MRSIGNER all of the following must be true:
              - [x] The MRSIGNER key hash should be 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
              - [x] The ISV product ID should be 144
              - [x] The ISV SVN should be at least 145"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn mr_signer_fails_due_to_mr_signer_key() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mut mr_signer = report_body.mr_signer();
        let product_id = report_body.isv_product_id();
        let isv_svn = report_body.isv_svn();

        let bytes: &mut [u8] = mr_signer.as_mut();
        bytes[0] += 1;

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);
        let verification = mr_signer_verifier.verify(&report_body);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&mr_signer_verifier, verification);
        let expected = r#"
            - [ ] MRSIGNER all of the following must be true:
              - [ ] The MRSIGNER key hash should be 313132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f, but the actual MRSIGNER key hash was 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
              - [x] The ISV product ID should be 144
              - [x] The ISV SVN should be at least 145"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn mr_signer_fails_due_to_product_id() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let mut product_id = report_body.isv_product_id();
        let isv_svn = report_body.isv_svn();

        *product_id.as_mut() += 1;

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);
        let verification = mr_signer_verifier.verify(&report_body);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&mr_signer_verifier, verification);
        let expected = r#"
            - [ ] MRSIGNER all of the following must be true:
              - [x] The MRSIGNER key hash should be 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
              - [ ] The ISV product ID should be 145, but the actual ISV product ID was 144
              - [x] The ISV SVN should be at least 145"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn mr_signer_fails_due_to_isv_svn() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let product_id = report_body.isv_product_id();
        let mut isv_svn = report_body.isv_svn();

        *isv_svn.as_mut() += 1;

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);
        let verification = mr_signer_verifier.verify(&report_body);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&mr_signer_verifier, verification);
        let expected = r#"
            - [ ] MRSIGNER all of the following must be true:
              - [x] The MRSIGNER key hash should be 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
              - [x] The ISV product ID should be 144
              - [ ] The ISV SVN should be at least 146, but the actual ISV SVN was 145"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn attributes_verifier_display() {
        let inner = Attributes::from(REPORT_BODY_SRC.attributes);
        let verifier = AttributesVerifier::new(inner, ALL_ATTRIBUTE_BITS.into());

        assert_eq!(verifier.to_string(), "The expected attributes is Flags: 0x0102_0304_0506_0708 Xfrm: 0x0807_0605_0403_0201 with mask Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | RESERVED");
    }

    #[test]
    fn config_id_verifier_display() {
        let inner = ConfigId::from(REPORT_BODY_SRC.config_id);
        let verifier = ConfigIdVerifier::new(inner.clone());

        let expected = format!("The {} should be {inner}", ConfigId::spaced_struct_name());

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn config_svn_verifier_display() {
        let inner = ConfigSvn::from(REPORT_BODY_SRC.config_svn);
        let verifier = ConfigSvnVerifier::new(inner.clone());

        let expected = format!(
            "The {} should be at least {inner}",
            ConfigSvn::spaced_struct_name()
        );

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn cpu_svn_verifier_display() {
        let inner = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(inner.clone());

        let expected = format!(
            "The {} should be at least {inner}",
            CpuSvn::spaced_struct_name()
        );

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn extended_product_id_verifier_display() {
        let inner = ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id);
        let verifier = ExtendedProductIdVerifier::new(inner.clone());

        let expected = format!(
            "The {} should be {inner}",
            ExtendedProductId::spaced_struct_name()
        );

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn family_id_verifier_display() {
        let inner = FamilyId::from(REPORT_BODY_SRC.isv_family_id);
        let verifier = FamilyIdVerifier::new(inner.clone());

        let expected = format!("The {} should be {inner}", FamilyId::spaced_struct_name());

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn isv_product_id_verifier_display() {
        let inner = IsvProductId::from(REPORT_BODY_SRC.isv_prod_id);
        let verifier = IsvProductIdVerifier::new(inner.clone());

        let expected = format!(
            "The {} should be {inner}",
            IsvProductId::spaced_struct_name()
        );

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn isv_svn_verifier_display() {
        let inner = IsvSvn::from(REPORT_BODY_SRC.isv_svn);
        let verifier = IsvSvnVerifier::new(inner.clone());

        let expected = format!(
            "The {} should be at least {inner}",
            IsvSvn::spaced_struct_name()
        );

        assert_eq!(verifier.to_string(), expected)
    }

    #[test]
    fn miscellaneous_select_verifier_display() {
        let inner = MiscellaneousSelect::from(REPORT_BODY_SRC.misc_select);
        let verifier = MiscellaneousSelectVerifier::new(inner.clone(), 0xFFFFFFFF.into());

        assert_eq!(
            verifier.to_string(),
            "The expected miscellaneous select is 0x0000_0011 with mask 0xFFFF_FFFF"
        )
    }

    #[test]
    fn mr_enclave_verifier_display() {
        let inner = MrEnclave::from(REPORT_BODY_SRC.mr_enclave);
        let verifier = MrEnclaveVerifier::new(inner.clone());

        let expected = format!("The {} should be {inner}", MrEnclave::spaced_struct_name());

        assert_eq!(verifier.to_string(), expected)
    }
}
