// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Verifiers which operate on the [`ReportBody`]

use crate::{AlwaysTrue, AndError, VerificationError, Verifier};
use mc_sgx_core_types::{Attributes, ConfigId, ReportBody};
use subtle::CtOption;

/// Verify the report body is as expected.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Default)]
pub struct ReportBodyVerifier {
    attributes_verifier: ReportBodyVerifierKind,
    config_id_verifier: ReportBodyVerifierKind,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ReportBodyVerifierKind {
    AttributesVerifier(AttributesVerifier),
    ConfigIdVerifier(ConfigIdVerifier),
    AlwaysTrue(AlwaysTrue),
}

impl Verifier<ReportBody> for ReportBodyVerifierKind {
    type Error = VerificationError;

    fn verify(&self, evidence: &ReportBody) -> CtOption<Self::Error> {
        match self {
            Self::AttributesVerifier(verifier) => verifier.verify(evidence),
            Self::ConfigIdVerifier(verifier) => verifier.verify(evidence),
            Self::AlwaysTrue(verifier) => verifier.verify(evidence),
        }
    }
}

impl Default for ReportBodyVerifierKind {
    fn default() -> Self {
        Self::AlwaysTrue(AlwaysTrue::default())
    }
}

impl ReportBodyVerifier {
    /// Verify the report body against the provided Attributes
    pub fn with_attributes(mut self, attributes: Attributes) -> Self {
        self.attributes_verifier =
            ReportBodyVerifierKind::AttributesVerifier(AttributesVerifier::new(attributes));
        self
    }

    /// Verify the report body against the provided ConfigId
    pub fn with_config_id(mut self, config_id: ConfigId) -> Self {
        self.config_id_verifier =
            ReportBodyVerifierKind::ConfigIdVerifier(ConfigIdVerifier::new(config_id));
        self
    }
}

impl Verifier<ReportBody> for ReportBodyVerifier {
    type Error = AndError<VerificationError, VerificationError>;

    fn verify(&self, evidence: &ReportBody) -> CtOption<Self::Error> {
        let verifier = self
            .attributes_verifier
            .clone()
            .and(self.config_id_verifier.clone());
        verifier.verify(evidence)
    }
}

/// Verify the attributes are as expected.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AttributesVerifier {
    expected_attributes: Attributes,
}

impl AttributesVerifier {
    /// Create a new [`AttributesVerifier`] instance.
    ///
    /// # Arguments:
    /// * `expected_attributes` - The expected attributes.
    /// * `report_body` - The report body containing attributes that conforms
    ///    to the `expected_attributes`.
    pub fn new(expected_attributes: Attributes) -> Self {
        Self {
            expected_attributes,
        }
    }
}

impl Verifier<ReportBody> for AttributesVerifier {
    type Error = VerificationError;
    fn verify(&self, evidence: &ReportBody) -> CtOption<Self::Error> {
        let expected = self.expected_attributes;
        let actual = evidence.attributes();
        // TODO - This should be a constant time comparison.
        let is_some = if expected == actual { 0 } else { 1 };
        CtOption::new(
            VerificationError::AttributeMismatch { expected, actual },
            is_some.into(),
        )
    }
}

/// Verify the [`ConfigId`] is as expected.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConfigIdVerifier {
    expected_id: ConfigId,
}

impl ConfigIdVerifier {
    /// Create a new [`ConfigIdVerifier`] instance.
    ///
    /// # Arguments:
    /// * `expected_id` - The expected id.
    /// * `report_body` - The report body containing config id that conforms
    ///    to the `expected_id`.
    pub fn new(expected_id: ConfigId) -> Self {
        Self { expected_id }
    }
}
impl Verifier<ReportBody> for ConfigIdVerifier {
    type Error = VerificationError;
    fn verify(&self, evidence: &ReportBody) -> CtOption<Self::Error> {
        let expected = self.expected_id.clone();
        let actual = evidence.config_id();
        // TODO - This should be a constant time comparison.
        let is_some = if expected == actual { 0 } else { 1 };
        CtOption::new(
            VerificationError::ConfigIdMismatch { expected, actual },
            is_some.into(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_core_sys_types::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t,
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
        let verifier = ReportBodyVerifier::default()
            .with_attributes(REPORT_BODY_SRC.attributes.into())
            .with_config_id(REPORT_BODY_SRC.config_id.into());
        assert_eq!(verifier.verify(&report_body).is_none().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_attributes() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut report_body_src = REPORT_BODY_SRC;
        report_body_src.attributes.flags = 0;
        let report_body_src: ReportBody = report_body_src.into();
        let verifier = ReportBodyVerifier::default()
            .with_attributes(report_body_src.attributes())
            .with_config_id(report_body_src.config_id());
        assert_eq!(verifier.verify(&report_body).is_some().unwrap_u8(), 1);
    }

    #[test]
    fn report_body_fails_due_to_config_id() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut report_body_src = REPORT_BODY_SRC;
        report_body_src.config_id[0] = 0;
        let report_body_src: ReportBody = report_body_src.into();
        let verifier = ReportBodyVerifier::default()
            .with_attributes(report_body_src.attributes())
            .with_config_id(report_body_src.config_id());
        assert_eq!(verifier.verify(&report_body).is_some().unwrap_u8(), 1);
    }

    #[test]
    fn attributes_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = AttributesVerifier::new(REPORT_BODY_SRC.attributes.into());

        assert_eq!(verifier.verify(&report_body).is_none().unwrap_u8(), 1);
    }

    #[test]
    fn attributes_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut attributes: Attributes = REPORT_BODY_SRC.attributes.into();
        attributes = attributes.set_flags(0);
        let verifier = AttributesVerifier::new(attributes);

        assert_eq!(verifier.verify(&report_body).is_some().unwrap_u8(), 1);
    }

    #[test]
    fn config_id_success() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let verifier = ConfigIdVerifier::new(REPORT_BODY_SRC.config_id.into());

        assert_eq!(verifier.verify(&report_body).is_none().unwrap_u8(), 1);
    }

    #[test]
    fn config_id_fail() {
        let report_body = ReportBody::from(&REPORT_BODY_SRC);
        let mut config_id: ConfigId = REPORT_BODY_SRC.config_id.into();
        config_id.as_mut()[0] = 0;
        let verifier = ConfigIdVerifier::new(config_id);

        assert_eq!(verifier.verify(&report_body).is_some().unwrap_u8(), 1);
    }
}
