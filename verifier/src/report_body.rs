// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Verifiers which operate on the [`ReportBody`]

use crate::{VerificationResult, VerificationResultMetadata, Verifier};
use core::fmt::Debug;
use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportBody, ReportData,
};
use subtle::{ConstantTimeEq, ConstantTimeGreater};

/// Trait for getting access to the type `T` that needs to be verified.
///
/// The intent is to implement this for a higher level type that contains the
/// `T`
///
/// ```ignore
/// use mc_attestation_verifier::ConfigIdVerifier;
/// impl Accessor<Contained> for Container {
///     fn get(&self) -> Contained {
///         self.some_method()
///     }
/// }
/// ```
pub trait Accessor<T>: Debug {
    fn get(&self) -> T;
}

/// [`Accessor`] for returning Self, i.e. T -> T
impl<T: Clone + Debug> Accessor<T> for T {
    fn get(&self) -> T {
        self.clone()
    }
}

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

trait IntoVerificationMetadata {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata;
}

/// Common implementation for [`Verifier`]s that test for equality between
/// an expected and actual value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EqualityVerifier<T> {
    expected: T,
}

impl<T> EqualityVerifier<T> {
    pub fn new(expected: T) -> Self {
        Self { expected }
    }
}

impl<T, E> Verifier<E> for EqualityVerifier<T>
where
    T: Debug + Clone + PartialEq + IntoVerificationMetadata,
    E: Accessor<T>,
{
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let expected = self.expected.clone();
        let actual = evidence.get();
        // TODO - This should be a constant time comparison.
        let is_ok = if expected == actual { 1 } else { 0 };
        VerificationResult::new(
            T::into_verification_metadata(expected, actual),
            is_ok.into(),
        )
    }
}

/// Common implementation for [`Verifier`]s that test for an actual value being
/// greater than or equal to an expected value
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GreaterThanEqualVerifier<T> {
    expected: T,
}

impl<T> GreaterThanEqualVerifier<T> {
    pub fn new(expected: T) -> Self {
        Self { expected }
    }
}

/// Verifier for ensuring [`Attributes`] values are equivalent.
pub type AttributesVerifier = EqualityVerifier<Attributes>;
impl IntoVerificationMetadata for Attributes {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::Attributes { expected, actual }
    }
}

/// Verifier for ensuring [`ConfigId`] values are equivalent.
pub type ConfigIdVerifier = EqualityVerifier<ConfigId>;
impl IntoVerificationMetadata for ConfigId {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::ConfigId { expected, actual }
    }
}

/// Verifier for ensuring [`ConfigSvn`] is greater than or equal to an
/// expected [`ConfigSvn`]
pub type ConfigSvnVerifier = GreaterThanEqualVerifier<ConfigSvn>;
impl IntoVerificationMetadata for ConfigSvn {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::ConfigSvn { expected, actual }
    }
}

impl<E: Accessor<ConfigSvn>> Verifier<E> for GreaterThanEqualVerifier<ConfigSvn> {
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let expected = self.expected;
        let actual = evidence.get();

        let actual_value = actual.as_ref();
        let expected_value = expected.as_ref();
        let is_ok = actual_value.ct_gt(expected_value) | actual_value.ct_eq(expected_value);
        VerificationResult::new(
            ConfigSvn::into_verification_metadata(expected, actual),
            is_ok,
        )
    }
}

/// Verifier for ensuring [`CpuSvn`] is greater than or equal to an
/// expected [`CpuSvn`]
pub type CpuSvnVerifier = GreaterThanEqualVerifier<CpuSvn>;
impl IntoVerificationMetadata for CpuSvn {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::CpuSvn { expected, actual }
    }
}

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
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let expected = self.expected.clone();
        let actual = evidence.get();

        // Per the Intel docs, CPU SVN is a 16 byte BE value. Since we may not
        // support u128 on all platforms we compare the 64 bit values.
        let (actual_high, actual_low) = cpu_svn_to_u64s(&actual);
        let (expected_high, expected_low) = cpu_svn_to_u64s(&expected);

        let high_order_greater = actual_high.ct_gt(&expected_high);
        let high_order_equal = actual_high.ct_eq(&expected_high);
        let low_order_greater_equal =
            actual_low.ct_gt(&expected_low) | actual_low.ct_eq(&expected_low);
        let is_ok = high_order_greater | (high_order_equal & low_order_greater_equal);

        VerificationResult::new(CpuSvn::into_verification_metadata(expected, actual), is_ok)
    }
}

/// Verifier for ensuring [`ExtendedProductId`] values are equivalent.
pub type ExtendedProductIdVerifier = EqualityVerifier<ExtendedProductId>;
impl IntoVerificationMetadata for ExtendedProductId {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::ExtendedProductId { expected, actual }
    }
}

/// Verifier for ensuring [`FamilyId`] values are equivalent.
pub type FamilyIdVerifier = EqualityVerifier<FamilyId>;
impl IntoVerificationMetadata for FamilyId {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::FamilyId { expected, actual }
    }
}

/// Verifier for ensuring [`IsvProductId`] values are equivalent.
pub type IsvProductIdVerifier = EqualityVerifier<IsvProductId>;
impl IntoVerificationMetadata for IsvProductId {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::IsvProductId { expected, actual }
    }
}

/// Verifier for ensuring [`IsvSvn`] is greater than or equal to an expected
/// [`IsvSvn`]
pub type IsvSvnVerifier = GreaterThanEqualVerifier<IsvSvn>;
impl IntoVerificationMetadata for IsvSvn {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::IsvSvn { expected, actual }
    }
}

impl<E: Accessor<IsvSvn>> Verifier<E> for GreaterThanEqualVerifier<IsvSvn> {
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let expected = self.expected;
        let actual = evidence.get();

        let actual_value = actual.as_ref();
        let expected_value = expected.as_ref();
        let is_ok = actual_value.ct_gt(expected_value) | actual_value.ct_eq(expected_value);
        VerificationResult::new(IsvSvn::into_verification_metadata(expected, actual), is_ok)
    }
}

/// Verifier for ensuring [`MiscellaneousSelect`] values are equivalent.
pub type MiscellaneousSelectVerifier = EqualityVerifier<MiscellaneousSelect>;
impl IntoVerificationMetadata for MiscellaneousSelect {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::MiscellaneousSelect { expected, actual }
    }
}

/// Verifier for ensuring [`MrEnclave`] values are equivalent.
///
/// The Intel SDK docs refer to this as "Strict Enclave Modification Policy"
pub type MrEnclaveVerifier = EqualityVerifier<MrEnclave>;
impl IntoVerificationMetadata for MrEnclave {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::MrEnclave { expected, actual }
    }
}

/// Verifier for ensuring all of the MRSIGNER inputs are sufficient.
///
/// The Intel SDK docs refer to this as "Security Enclave Modification Policy"
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrSignerVerifier {
    mr_signer: MrSignerKeyVerifier,
    product_id: IsvProductIdVerifier,
    isv_svn: IsvSvnVerifier,
}

impl MrSignerVerifier {
    /// Create a new [`MrSignerVerifier`]
    pub fn new(mr_signer: MrSigner, product_id: IsvProductId, isv_svn: IsvSvn) -> Self {
        Self {
            mr_signer: MrSignerKeyVerifier::new(mr_signer),
            product_id: IsvProductIdVerifier::new(product_id),
            isv_svn: IsvSvnVerifier::new(isv_svn),
        }
    }
}

impl<E: Accessor<MrSigner> + Accessor<IsvProductId> + Accessor<IsvSvn>> Verifier<E>
    for MrSignerVerifier
{
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let mr_signer_key = self.mr_signer.verify(evidence);
        let product_id = self.product_id.verify(evidence);
        let isv_svn = self.isv_svn.verify(evidence);

        let is_ok = mr_signer_key.is_ok() & product_id.is_ok() & isv_svn.is_ok();

        VerificationResult::new(VerificationResultMetadata::General, is_ok)
    }
}
/// Verifier for ensuring [`MrSigner`] key values are equivalent.
type MrSignerKeyVerifier = EqualityVerifier<MrSigner>;
impl IntoVerificationMetadata for MrSigner {
    fn into_verification_metadata(expected: Self, actual: Self) -> VerificationResultMetadata {
        VerificationResultMetadata::MrSignerKey { expected, actual }
    }
}

/// Verifier for ensuring [`ReportData`] values are equivalent.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ReportDataVerifier {
    expected: ReportData,
    mask: ReportData,
}
impl ReportDataVerifier {
    /// Create a new [`ReportDataVerifier`] where all bits will be compared
    pub fn new(expected: ReportData) -> Self {
        let mask = ReportData::from([0xff; ReportData::SIZE]);
        Self::new_with_mask(expected, mask)
    }

    /// Create a new [`ReportDataVerifier`] where only bits set in the mask will
    /// compared
    pub fn new_with_mask(expected: ReportData, mask: ReportData) -> Self {
        Self { expected, mask }
    }
}

impl<E: Accessor<ReportData>> Verifier<E> for ReportDataVerifier {
    type ResultMetadata = VerificationResultMetadata;
    fn verify(&self, evidence: &E) -> VerificationResult<Self::ResultMetadata> {
        let mask = self.mask.clone();
        let expected = &self.expected & &mask;
        let actual = &evidence.get() & &mask;
        // TODO - This should be a constant time comparison.
        let is_some = if expected == actual { 1 } else { 0 };
        VerificationResult::new(
            VerificationResultMetadata::ReportData {
                expected,
                actual,
                mask,
            },
            is_some.into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::And;
    use mc_sgx_core_sys_types::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t,
    };
    use yare::parameterized;

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
            AttributesVerifier::new(report_body.attributes()),
            ConfigIdVerifier::new(report_body.config_id()),
        );
        assert_eq!(verifier.verify(&report_body).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_attributes() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let attributes = report_body.attributes().set_flags(0);
        let verifier = And::new(
            AttributesVerifier::new(attributes),
            ConfigIdVerifier::new(report_body.config_id()),
        );
        assert_eq!(verifier.verify(&report_body).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_config_id() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut config_id = report_body.config_id();
        config_id.as_mut()[0] = 0;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes()),
            ConfigIdVerifier::new(config_id),
        );
        assert_eq!(verifier.verify(&report_body).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_config_security_version() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let expected_config_svn = *report_body.config_svn().as_mut() + 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                ConfigSvnVerifier::new(expected_config_svn.into()),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_mr_enclave() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut mr_enclave = report_body.mr_enclave();
        let bytes: &mut [u8] = mr_enclave.as_mut();
        bytes[0] += 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                MrEnclaveVerifier::new(mr_enclave),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_mr_signer() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut mr_signer = report_body.mr_signer();
        let bytes: &mut [u8] = mr_signer.as_mut();
        bytes[0] += 1;
        let verifier = And::new(
            AttributesVerifier::new(report_body.attributes()),
            And::new(
                ConfigIdVerifier::new(report_body.config_id()),
                MrSignerVerifier::new(
                    mr_signer,
                    report_body.isv_product_id(),
                    report_body.isv_svn(),
                ),
            ),
        );
        assert_eq!(verifier.verify(&report_body).is_err().unwrap_u8(), 1);
    }
    #[test]
    fn attributes_success() {
        let attributes = Attributes::from(REPORT_BODY_SRC.attributes);
        let verifier = AttributesVerifier::new(attributes);

        assert_eq!(verifier.verify(&attributes).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn attributes_fail() {
        let mut attributes = Attributes::from(REPORT_BODY_SRC.attributes);
        let verifier = AttributesVerifier::new(attributes);
        attributes = attributes.set_flags(0);

        assert_eq!(verifier.verify(&attributes).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn config_id_success() {
        let config_id = ConfigId::from(REPORT_BODY_SRC.config_id);
        let verifier = ConfigIdVerifier::new(config_id.clone());

        assert_eq!(verifier.verify(&config_id).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn config_id_fail() {
        let mut config_id = ConfigId::from(REPORT_BODY_SRC.config_id);
        let verifier = ConfigIdVerifier::new(config_id.clone());
        config_id.as_mut()[0] = 2;

        assert_eq!(verifier.verify(&config_id).is_err().unwrap_u8(), 1);
    }

    #[parameterized(
        equal = { 10, 10 },
        greater = { 12, 11 },
        much_greater = { 20, 1 },
    )]
    fn config_svn_succeeds(actual: u16, expected: u16) {
        let verifier = ConfigSvnVerifier::new(expected.into());
        let config_svn = ConfigSvn::from(actual);

        assert_eq!(verifier.verify(&config_svn).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn config_svn_fails_less_than_expected() {
        let verifier = ConfigSvnVerifier::new(10.into());
        let config_svn = ConfigSvn::from(9);

        assert_eq!(verifier.verify(&config_svn).is_err().unwrap_u8(), 1);
    }

    #[parameterized(
    equal = { 25, 25 },
    greater = { 17, 16 },
    much_greater = { 100, 50 },
    )]
    fn isv_svn_succeeds(actual: u16, expected: u16) {
        let verifier = IsvSvnVerifier::new(expected.into());
        let isv_svn = IsvSvn::from(actual);

        assert_eq!(verifier.verify(&isv_svn).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn isv_svn_fails_less_than_expected() {
        let verifier = IsvSvnVerifier::new(10.into());
        let isv_svn = IsvSvn::from(9);

        assert_eq!(verifier.verify(&isv_svn).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn miscellaneous_select_success() {
        let miscellaneous_select = MiscellaneousSelect::from(REPORT_BODY_SRC.misc_select);
        let verifier = MiscellaneousSelectVerifier::new(miscellaneous_select.clone());

        assert_eq!(
            verifier.verify(&miscellaneous_select).is_ok().unwrap_u8(),
            1
        );
    }

    #[test]
    fn miscellaneous_select_fails() {
        let mut miscellaneous_select = MiscellaneousSelect::from(REPORT_BODY_SRC.misc_select);
        let verifier = MiscellaneousSelectVerifier::new(miscellaneous_select.clone());
        *miscellaneous_select.as_mut() = 0;

        assert_eq!(
            verifier.verify(&miscellaneous_select).is_err().unwrap_u8(),
            1
        );
    }

    #[test]
    fn mr_encalve_success() {
        let mr_enclave = MrEnclave::from(REPORT_BODY_SRC.mr_enclave);
        let verifier = MrEnclaveVerifier::new(mr_enclave.clone());

        assert_eq!(verifier.verify(&mr_enclave).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn mr_enclave_fails() {
        let mut mr_enclave = MrEnclave::from(REPORT_BODY_SRC.mr_enclave);
        let verifier = MrEnclaveVerifier::new(mr_enclave.clone());
        let bytes: &mut [u8] = mr_enclave.as_mut();
        bytes[0] = 0;

        assert_eq!(verifier.verify(&mr_enclave).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_key_success() {
        let mr_signer = MrSigner::from(REPORT_BODY_SRC.mr_signer);
        let verifier = MrSignerKeyVerifier::new(mr_signer.clone());

        assert_eq!(verifier.verify(&mr_signer).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_key_fails() {
        let mut mr_signer = MrSigner::from(REPORT_BODY_SRC.mr_signer);
        let verifier = MrSignerKeyVerifier::new(mr_signer.clone());
        let bytes: &mut [u8] = mr_signer.as_mut();
        bytes[0] = 1;

        assert_eq!(verifier.verify(&mr_signer).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_success() {
        let report_data = ReportData::from(REPORT_BODY_SRC.report_data);
        let verifier = ReportDataVerifier::new(report_data.clone());

        assert_eq!(verifier.verify(&report_data).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_fails() {
        let mut report_data = ReportData::from(REPORT_BODY_SRC.report_data);
        let verifier = ReportDataVerifier::new(report_data.clone());
        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 1;

        assert_eq!(verifier.verify(&report_data).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_ignores_masked_off_bits() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[0] = 0b0000_0000;
        let verifier = ReportDataVerifier::new_with_mask(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 0b1111_0000;

        assert_eq!(verifier.verify(&report_data).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_fails_when_non_masked_bits_differ() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[0] = 0b0000_0000;
        let verifier = ReportDataVerifier::new_with_mask(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[0] = 0b1111_0000;
        bytes[1] = 0b1111_0000; // Not masked off so should fail

        assert_eq!(verifier.verify(&report_data).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_ignores_masked_off_bit_at_end() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mut mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let mask_bytes: &mut [u8] = mask.as_mut();
        mask_bytes[mask_bytes.len() - 1] = 0b1111_1110;
        let verifier = ReportDataVerifier::new_with_mask(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[bytes.len() - 1] = 0b1010_1011; // Note: the last bit is different

        assert_eq!(verifier.verify(&report_data).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn report_data_fails_when_non_masked_bit_differs() {
        let mut report_data = ReportData::from([0b1010_1010; ReportData::SIZE]);
        let mask = ReportData::from([0b1111_1111; ReportData::SIZE]);
        let verifier = ReportDataVerifier::new_with_mask(report_data.clone(), mask);

        let bytes: &mut [u8] = report_data.as_mut();
        bytes[bytes.len() - 1] = 0b1010_1011; // Note: the last bit is different

        assert_eq!(verifier.verify(&report_data).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_succeeds() {
        let cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        assert_eq!(verifier.verify(&cpu_svn).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_on_high_u64() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_on_low_u64() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[15] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_succeeds_when_high_u64_greater() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] += 1;

        // Making this less, to show how the high 64 takes precedence
        bytes[15] -= 1;

        assert_eq!(verifier.verify(&cpu_svn).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn cpu_svn_fails_when_high_u64_less_but_low_greater() {
        let mut cpu_svn = CpuSvn::from(REPORT_BODY_SRC.cpu_svn);
        let verifier = CpuSvnVerifier::new(cpu_svn.clone());

        let bytes: &mut [u8] = cpu_svn.as_mut();
        bytes[7] -= 1;

        // Making this greater, to show how the high 64 takes precedence
        bytes[15] += 1;

        assert_eq!(verifier.verify(&cpu_svn).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn extended_product_id_succeeds() {
        let extended_product_id = ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id);
        let verifier = ExtendedProductIdVerifier::new(extended_product_id.clone());

        assert_eq!(verifier.verify(&extended_product_id).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn extended_product_id_fails() {
        let mut extended_product_id = ExtendedProductId::from(REPORT_BODY_SRC.isv_ext_prod_id);
        let verifier = ExtendedProductIdVerifier::new(extended_product_id.clone());

        let bytes: &mut [u8] = extended_product_id.as_mut();
        bytes[0] += 1;

        assert_eq!(
            verifier.verify(&extended_product_id).is_err().unwrap_u8(),
            1
        );
    }

    #[test]
    fn family_id_succeeds() {
        let family_id = FamilyId::from(REPORT_BODY_SRC.isv_family_id);
        let verifier = FamilyIdVerifier::new(family_id.clone());

        assert_eq!(verifier.verify(&family_id).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn family_id_fails() {
        let mut family_id = FamilyId::from(REPORT_BODY_SRC.isv_family_id);
        let verifier = FamilyIdVerifier::new(family_id.clone());

        let bytes: &mut [u8] = family_id.as_mut();
        bytes[0] += 1;

        assert_eq!(verifier.verify(&family_id).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn isv_product_id_succeeds() {
        let isv_product_id = IsvProductId::from(REPORT_BODY_SRC.isv_prod_id);
        let verifier = IsvProductIdVerifier::new(isv_product_id.clone());

        assert_eq!(verifier.verify(&isv_product_id).is_ok().unwrap_u8(), 1);
    }

    #[test]
    fn isv_product_id_fails() {
        let mut isv_product_id = IsvProductId::from(REPORT_BODY_SRC.isv_prod_id);
        let verifier = IsvProductIdVerifier::new(isv_product_id.clone());

        *isv_product_id.as_mut() += 1;

        assert_eq!(verifier.verify(&isv_product_id).is_err().unwrap_u8(), 1);
    }

    #[test]
    fn mr_signer_succeeds() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let product_id = report_body.isv_product_id();
        let isv_svn = report_body.isv_svn();

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);

        assert_eq!(
            mr_signer_verifier.verify(&report_body).is_ok().unwrap_u8(),
            1
        );
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

        assert_eq!(
            mr_signer_verifier.verify(&report_body).is_err().unwrap_u8(),
            1
        );
    }

    #[test]
    fn mr_signer_fails_due_to_product_id() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let mut product_id = report_body.isv_product_id();
        let isv_svn = report_body.isv_svn();

        *product_id.as_mut() += 1;

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);

        assert_eq!(
            mr_signer_verifier.verify(&report_body).is_err().unwrap_u8(),
            1
        );
    }

    #[test]
    fn mr_signer_fails_due_to_isv_svn() {
        let report_body = ReportBody::from(REPORT_BODY_SRC);
        let mr_signer = report_body.mr_signer();
        let product_id = report_body.isv_product_id();
        let mut isv_svn = report_body.isv_svn();

        *isv_svn.as_mut() += 1;

        let mr_signer_verifier = MrSignerVerifier::new(mr_signer, product_id, isv_svn);

        assert_eq!(
            mr_signer_verifier.verify(&report_body).is_err().unwrap_u8(),
            1
        );
    }
}
