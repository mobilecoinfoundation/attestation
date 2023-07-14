// Copyright (c) 2023 The MobileCoin Foundation

//! Handles the QE(Quoting Enclave) identity verification.
//!
//! Step one from the steps documented at
//! <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
//!
//! > 1. Retrieve Enclave Identity(SGX QE, TDX QE or QVE) from PCS and verify
//! >    that it is a valid structure issued by Intel.
//! > 2. Perform the following comparison of SGX Enclave Report against the
//! >    retrieved Enclave Identity:
//! >       a. Verify if MRSIGNER field retrieved from SGX Enclave Report is
//! >          equal to the value of mrsigner field in Enclave Identity.
//! >       b. Verify if ISVPRODID field retrieved from SGX Enclave Report is
//! >          equal to the value of isvprodid field in Enclave Identity.
//! >       c. Apply miscselectMask (binary mask) from Enclave Identity to
//! >          MISCSELECT field retrieved from SGX Enclave Report. Verify if the
//! >          outcome (miscselectMask & MISCSELECT) is equal to the value of
//! >          miscselect field in Enclave Identity.
//! >       d. Apply attributesMask (binary mask) from Enclave Identity to
//! >          ATTRIBUTES field retrieved from SGX Enclave Report. Verify if the
//! >          outcome (attributesMask & ATTRIBUTES) is equal to the value of
//! >          attributes field in Enclave Identity.
//! > 3. If any of the checks above fail, the identity of the enclave does not
//! >    match Enclave Identity published by Intel.
//! > 4. Determine a TCB status of the Enclave:
//! >       a. Retrieve a collection of TCB Levels (sorted by ISVSVNs) from
//! >          tcbLevels field in Enclave Identity structure.
//! >       b. Go over the list of TCB Levels (descending order) and find the
//! >          one that has ISVSVN that is lower or equal to the ISVSVN value
//! >          from SGX Enclave Report.
//! >       c. If a TCB level is found, read its status from tcbStatus field,
//! >          otherwise your TCB Level is not supported.
//!
//! The QE identity information is provided from
//! <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>

#![allow(dead_code)]

use crate::{
    advisories::AdvisoryStatus, Accessor, Advisories, Error, VerificationMessage,
    VerificationOutput, Verifier,
};
use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Formatter;
use der::DateTime;
use mc_sgx_core_sys_types::sgx_attributes_t;
use mc_sgx_core_types::{Attributes, IsvProductId, IsvSvn, MiscellaneousSelect, MrSigner};
use p256::ecdsa::{signature::Verifier as SignatureVerifier, Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::value::RawValue;

const QE_IDENTITY_VERSION: u32 = 2;
const UNIX_TIME_STR: &str = "1970-01-01T00:00:00Z";

/// QE(quoting enclave) identity information.
///
/// This is derived from JSON data formatted according to,
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>.
///
/// The identity can be retrieved from,
/// <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct QeIdentity {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    #[serde(with = "hex", rename = "miscselect")]
    misc_select: [u8; 4],
    #[serde(with = "hex", rename = "miscselectMask")]
    misc_select_mask: [u8; 4],
    #[serde(with = "hex")]
    attributes: [u8; 16],
    #[serde(with = "hex")]
    attributes_mask: [u8; 16],
    #[serde(with = "hex", rename = "mrsigner")]
    mr_signer: [u8; 32],
    #[serde(rename = "isvprodid")]
    isv_prod_id: u16,
    tcb_levels: Vec<TcbLevel>,
}

impl QeIdentity {
    /// The MRSIGNER key value of the QE.
    pub fn mr_signer(&self) -> MrSigner {
        MrSigner::from(self.mr_signer)
    }

    /// The ISV product ID of the QE.
    pub fn isv_prod_id(&self) -> IsvProductId {
        self.isv_prod_id.into()
    }

    /// The list of current and former TCB levels of the QE.
    pub fn tcb_levels(&self) -> &[TcbLevel] {
        &self.tcb_levels
    }

    /// The expected [`MiscellaneousSelect`] bits of the QE report body.
    pub fn miscellaneous_select(&self) -> MiscellaneousSelect {
        let miscellaneous_select = u32::from_le_bytes(self.misc_select);
        miscellaneous_select.into()
    }

    /// The [`MiscellaneousSelect`] mask to use when comparing the
    /// [`MiscellaneousSelect`] bits of the QE report body.
    pub fn miscellaneous_select_mask(&self) -> MiscellaneousSelect {
        let mask = u32::from_le_bytes(self.misc_select_mask);
        mask.into()
    }

    /// The expected [`Attributes`] of the QE report body.
    pub fn attributes(&self) -> Attributes {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.attributes[..8]);
        let flags = u64::from_le_bytes(bytes);
        bytes.copy_from_slice(&self.attributes[8..]);
        let xfrm = u64::from_le_bytes(bytes);
        sgx_attributes_t { flags, xfrm }.into()
    }

    /// The [`Attributes`] mask to use when comparing the
    /// [`Attributes`] of the QE report body.
    pub fn attributes_mask(&self) -> Attributes {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.attributes_mask[..8]);
        let flags = u64::from_le_bytes(bytes);
        bytes.copy_from_slice(&self.attributes_mask[8..]);
        let xfrm = u64::from_le_bytes(bytes);
        sgx_attributes_t { flags, xfrm }.into()
    }

    fn verify(&self, time: DateTime) -> Result<(), Error> {
        self.verify_version()?.verify_time(time)?;
        Ok(())
    }

    fn verify_time(&self, time: DateTime) -> Result<&Self, Error> {
        let issue_date = self.issue_date.parse::<DateTime>()?;
        let next_update = self.next_update.parse::<DateTime>()?;
        if time < issue_date {
            Err(Error::QeIdentityNotYetValid)
        } else if time >= next_update {
            Err(Error::QeIdentityExpired)
        } else {
            Ok(self)
        }
    }

    fn verify_version(&self) -> Result<&Self, Error> {
        if self.version != QE_IDENTITY_VERSION {
            Err(Error::QeIdentityVersion {
                expected: QE_IDENTITY_VERSION,
                actual: self.version,
            })
        } else {
            Ok(self)
        }
    }
}

impl TryFrom<&SignedQeIdentity> for QeIdentity {
    type Error = Error;

    fn try_from(signed_qe_identity: &SignedQeIdentity) -> Result<Self, Self::Error> {
        let qe_identity: QeIdentity =
            serde_json::from_str(signed_qe_identity.enclave_identity.as_ref().get())?;
        Ok(qe_identity)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    tcb: Tcb,
    tcb_date: String,
    tcb_status: AdvisoryStatus,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

impl TcbLevel {
    pub fn new<'a, I, E>(tcb: Tcb, tcb_status: AdvisoryStatus, advisory_ids: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        Self {
            tcb,
            tcb_date: UNIX_TIME_STR.to_string(),
            tcb_status,
            advisory_ids: advisory_ids.into_iter().map(ToString::to_string).collect(),
        }
    }

    pub fn isv_svn(&self) -> IsvSvn {
        self.tcb.isv_svn.into()
    }

    pub fn advisories(&self) -> Advisories {
        Advisories::new(&self.advisory_ids, self.tcb_status)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Tcb {
    #[serde(rename = "isvsvn")]
    isv_svn: u16,
}

impl Tcb {
    pub fn new<I: Into<IsvSvn>>(isv_svn: I) -> Self {
        Self {
            isv_svn: isv_svn.into().into(),
        }
    }
}

/// Signed quoting enclave (QE) identity.
///
/// The root JSON object from
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
/// The `enclave_identity` field is kept as a raw JSON value to be able to verify the
/// signature.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignedQeIdentity {
    enclave_identity: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl SignedQeIdentity {
    /// Verify the `enclaveIdentity` signature and time are valid.
    ///
    /// # Arguments
    /// - `key` - The public key to verify the `enclaveIdentity` signature with. When the key is
    ///   `None` the verification will always fail.
    /// - `time` - The current system time
    ///   This is expected to be generated by:
    ///     ```ignore
    ///     let time = DateTime::from_system_time(SystemTime::now()).unwrap();
    ///     ```
    ///   or equivalent
    pub fn verify(self, key: Option<&VerifyingKey>, time: DateTime) -> Result<(), Error> {
        self.verify_signature(key)?;
        let qe_identity = QeIdentity::try_from(&self)?;
        qe_identity.verify(time)?;
        Ok(())
    }

    fn verify_signature(&self, key: Option<&VerifyingKey>) -> Result<(), Error> {
        let key = key.ok_or(Error::MissingPublicKey)?;
        let qe_identity = self.enclave_identity.get();
        let signature =
            Signature::try_from(&self.signature[..]).map_err(|_| Error::SignatureDecodeError)?;
        key.verify(qe_identity.as_ref().get().as_bytes(), &signature)
            .map_err(|_| Error::SignatureVerification)?;
        Ok(())
    }
}

impl TryFrom<&str> for SignedQeIdentity {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let signed_qe_identity: SignedQeIdentity = serde_json::from_str(value)?;
        Ok(signed_qe_identity)
    }
}

/// Verifier for ensuring a QE(Quoting Enclave) identity was signed with the
/// provided key
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedQeIdentityVerifier {
    key: Option<VerifyingKey>,
    time: DateTime,
}

impl SignedQeIdentityVerifier {
    /// Create a new instance.
    ///
    /// The `SignedQeIdentityVerifier::verify()` will fail if the signature doesn't
    /// match for the `key` or if the `time` is outside the `issueDate` and
    /// `nextUpdate` times in the `enclaveIdentity`.
    ///
    /// # Arguments
    /// - `key` - The public key to verify the `enclaveIdentity` signature with
    ///   This should be retrieved from the x509 certificate provided in the
    ///   QE identity request from
    ///   <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>
    ///   When this is `None` verification will always fail.
    /// - `time` - The current system time
    ///   This is expected to be generated by:
    ///     ```ignore
    ///     let time = DateTime::from_system_time(SystemTime::now()).unwrap();
    ///     ```
    ///   or equivalent
    pub fn new(key: Option<VerifyingKey>, time: DateTime) -> Self {
        Self { key, time }
    }
}

impl<E: Accessor<SignedQeIdentity>> Verifier<E> for SignedQeIdentityVerifier {
    type Value = Option<Error>;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let signed_qe_identity = evidence.get();
        let result = signed_qe_identity.verify(self.key.as_ref(), self.time);
        let is_success = result.is_ok() as u8;

        VerificationOutput::new(result.err(), is_success.into())
    }
}

impl VerificationMessage<Option<Error>> for SignedQeIdentityVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        result: &VerificationOutput<Option<Error>>,
    ) -> core::fmt::Result {
        let is_success = result.is_success();
        let status = crate::choice_to_status_message(is_success);
        write!(f, "{:pad$}{status} ", "")?;

        if is_success.into() {
            write!(f, "The QE identity was verified for the provided key")
        } else {
            let error = result
                .value()
                .as_ref()
                .expect("Should have an error if not successful");
            write!(
                f,
                "The QE identity signature could not be verified: {error}"
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VerificationTreeDisplay;
    use alloc::{format, vec};
    use assert_matches::assert_matches;
    use der::DateTime;
    use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
    use x509_cert::{der::DecodePem, Certificate};
    use yare::parameterized;

    fn qe_verifying_key() -> VerifyingKey {
        // The QE identity and TCB happen to use the same signer
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

    /// Takes the test `qe_identity.json` file and will replace all instances of `from` with `to`.
    ///
    /// Returns the altered `SignedQeIdentity` and the `VerifyingKey` that was used to sign it.
    fn alter_signed_qe_identity(from: &str, to: &str) -> (SignedQeIdentity, VerifyingKey) {
        let json = include_str!("../data/tests/qe_identity.json");

        let bad_json = json.replace(from, to);

        let mut signed_qe_identity =
            SignedQeIdentity::try_from(bad_json.as_ref()).expect("Failed to parse signed identity");

        // Since the signature is based on the original contents we must re-sign
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::random(&mut rng);
        let (signature, _) = signing_key.sign(
            signed_qe_identity
                .enclave_identity
                .as_ref()
                .get()
                .as_bytes(),
        );
        signed_qe_identity.signature = signature.to_bytes().to_vec();

        let key = signing_key.verifying_key().clone();

        (signed_qe_identity, key)
    }

    #[test]
    fn parse_signed_id() {
        // For this test we don't care what the contents of `enclave_identity` is, just
        // that we separate the signature from the `enclave_identity` correctly.
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"signature":"abcd"}"#;
        let signed_qe_identity =
            SignedQeIdentity::try_from(raw_identity).expect("Failed to parse signed identity");
        assert_eq!(signed_qe_identity.signature, vec![171, 205]);
        assert_eq!(
            signed_qe_identity.enclave_identity.as_ref().get(),
            r#"{"id":"QE","version":2,"miscselect":"00000000"}"#
        );
    }

    #[test]
    fn signed_id_two_signatures_errors() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"signature":"abcd","signature":"should not be here"}"#;
        assert_matches!(
            SignedQeIdentity::try_from(raw_identity),
            Err(Error::Serde(_))
        );
    }

    #[test]
    fn signed_id_two_enclave_identitys_errors() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"miscselect":"00000000"},"enclaveIdentity":"one too many","signature":"abcd"}"#;
        assert_matches!(
            SignedQeIdentity::try_from(raw_identity),
            Err(Error::Serde(_))
        );
    }

    #[test]
    fn signed_id_enclave_identity_inside_enclave_identity() {
        let raw_identity = r#"{"enclaveIdentity":{"id":"QE","version":2,"enclaveIdentity":"identity inside","miscselect":"00000000"},"signature":"0102"}"#;
        let signed_qe_identity =
            SignedQeIdentity::try_from(raw_identity).expect("Failed to parse signed identity");
        assert_eq!(signed_qe_identity.signature, vec![1, 2]);
        assert_eq!(
            signed_qe_identity.enclave_identity.as_ref().get(),
            r#"{"id":"QE","version":2,"enclaveIdentity":"identity inside","miscselect":"00000000"}"#
        );
    }

    #[test]
    fn parse_example_qe_identity() {
        let json = include_str!("../data/tests/example_qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let qe_identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to parse identity");
        assert_eq!(qe_identity.id, "QE");
        assert_eq!(qe_identity.version, 2);
        assert_eq!(qe_identity.issue_date, "2022-04-13T10:15:38Z");
        assert_eq!(qe_identity.next_update, "2022-05-13T10:15:38Z");
        assert_eq!(qe_identity.misc_select, [0u8, 0, 0, 0]);
        assert_eq!(qe_identity.misc_select_mask, [255u8, 255, 255, 255]);
        assert_eq!(
            qe_identity.attributes,
            [17u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.attributes_mask,
            [251u8, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.mr_signer,
            [
                140u8, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86,
                172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255
            ]
        );
        assert_eq!(qe_identity.isv_prod_id, 1);
        let first_level = &qe_identity.tcb_levels[0];
        assert_eq!(first_level.tcb.isv_svn, 6);
        assert_eq!(first_level.tcb_date, "2021-11-10T00:00:00Z");
        assert_eq!(first_level.tcb_status, AdvisoryStatus::UpToDate);
        assert!(first_level.advisory_ids.is_empty());
        let second_level = &qe_identity.tcb_levels[1];
        assert_eq!(second_level.tcb.isv_svn, 5);
        assert_eq!(second_level.tcb_date, "2020-11-11T00:00:00Z");
        assert_eq!(second_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert!(second_level.advisory_ids.is_empty());
        let last_level = &qe_identity.tcb_levels[4];
        assert_eq!(last_level.tcb.isv_svn, 1);
        assert_eq!(last_level.tcb_date, "2018-08-15T00:00:00Z");
        assert_eq!(last_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert!(last_level.advisory_ids.is_empty());
    }

    #[test]
    fn parse_qe_identity() {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let qe_identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to parse identity");
        assert_eq!(qe_identity.id, "QE");
        assert_eq!(qe_identity.version, 2);
        assert_eq!(qe_identity.issue_date, "2023-07-12T20:48:25Z");
        assert_eq!(qe_identity.next_update, "2023-08-11T20:48:25Z");
        assert_eq!(qe_identity.misc_select, [0u8, 0, 0, 0]);
        assert_eq!(qe_identity.misc_select_mask, [255u8, 255, 255, 255]);
        assert_eq!(
            qe_identity.attributes,
            [17u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.attributes_mask,
            [251u8, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            qe_identity.mr_signer,
            [
                140u8, 79, 87, 117, 215, 150, 80, 62, 150, 19, 127, 119, 198, 138, 130, 154, 0, 86,
                172, 141, 237, 112, 20, 11, 8, 27, 9, 68, 144, 197, 123, 255
            ]
        );
        assert_eq!(qe_identity.isv_prod_id, 1);
        let first_level = &qe_identity.tcb_levels[0];
        assert_eq!(first_level.tcb.isv_svn, 8);
        assert_eq!(first_level.tcb_date, "2023-02-15T00:00:00Z");
        assert_eq!(first_level.tcb_status, AdvisoryStatus::UpToDate);
        assert!(first_level.advisory_ids.is_empty());
        let second_level = &qe_identity.tcb_levels[1];
        assert_eq!(second_level.tcb.isv_svn, 6);
        assert_eq!(second_level.tcb_date, "2021-11-10T00:00:00Z");
        assert_eq!(second_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert_eq!(second_level.advisory_ids, vec!["INTEL-SA-00615"]);
        let last_level = &qe_identity.tcb_levels[5];
        assert_eq!(last_level.tcb.isv_svn, 1);
        assert_eq!(last_level.tcb_date, "2018-08-15T00:00:00Z");
        assert_eq!(last_level.tcb_status, AdvisoryStatus::OutOfDate);
        assert_eq!(
            last_level.advisory_ids,
            vec![
                "INTEL-SA-00202",
                "INTEL-SA-00219",
                "INTEL-SA-00293",
                "INTEL-SA-00334",
                "INTEL-SA-00477",
                "INTEL-SA-00615"
            ]
        );
    }

    #[parameterized(
        at_issue_date = {"2023-07-12T20:48:25Z"},
        one_secend_after_issue_date = {"2023-07-12T20:48:26Z"},
        one_second_before_next_update = {"2023-08-11T20:48:24Z"},
    )]
    fn verify_signature_of_qe_identity(time: &str) {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let key = qe_verifying_key();
        let time = time.parse::<DateTime>().expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] The QE identity was verified for the provided key"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn qe_identity_verifier_fails_at_next_update() {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let key = qe_verifying_key();
        let time = "2023-08-11T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        // Only this verifier test verifies the failed error message as error
        // messages are often fragile to verify, so trying to minimize any
        // future churn to this one test.
        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The QE identity signature could not be verified: QE identity expired"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn qe_identity_verifier_fails_before_issue_date() {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let key = qe_verifying_key();
        let time = "2023-06-14T15:55:14Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(
            verification.value.expect("Expecting error"),
            Error::QeIdentityNotYetValid
        );
    }

    #[test]
    fn qe_identity_fails_to_parse_issue_date() {
        let (signed_qe_identity, key) = alter_signed_qe_identity("2023-07-12", "2023-17-12");
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(verification.value.expect("Expecting error"), Error::Der(_));
    }

    #[test]
    fn qe_identity_fails_to_parse_next_update() {
        let (signed_qe_identity, key) = alter_signed_qe_identity("2023-08-11", "2023-18-11");
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(verification.value.expect("Expecting error"), Error::Der(_));
    }

    #[test]
    fn verify_fails_to_parse_qe_identity() {
        let (signed_qe_identity, key) = alter_signed_qe_identity("mrsigner", "signerjr");
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(
            verification.value.expect("Expecting error"),
            Error::Serde(_)
        );
    }

    #[test]
    fn qe_identity_verifier_wrong_signature() {
        let json = include_str!("../data/tests/qe_identity.json");
        let mut signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");

        signed_qe_identity.signature[0] += 1;

        let key = qe_verifying_key();
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(
            verification.value.expect("Expecting error"),
            Error::SignatureVerification
        );
    }

    #[test]
    fn qe_identity_verifier_fails_to_decode_signature() {
        let json = include_str!("../data/tests/qe_identity.json");
        let mut signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");

        // Note enough bytes to decode to the Signature type
        signed_qe_identity.signature.truncate(63);

        let key = qe_verifying_key();
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(
            verification.value.expect("Expecting error"),
            Error::SignatureDecodeError
        );
    }

    #[parameterized(
        version_1 = { 1 },
        version_3 = { 3 },
    )]
    fn qe_identity_fails_to_verify_different_version(version: u32) {
        let (signed_qe_identity, key) =
            alter_signed_qe_identity("\"version\":2", &format!("\"version\":{version}"));
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(Some(key), time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_failure().unwrap_u8(), 1);
        assert_matches!(
            verification.value.expect("Expecting error"),
            Error::QeIdentityVersion{expected: QE_IDENTITY_VERSION, actual} if actual == version
        );
    }

    #[test]
    fn qe_identity_fails_to_verify_when_no_key() {
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let time = "2023-07-12T20:48:25Z"
            .parse::<DateTime>()
            .expect("Failed to parse time");
        let verifier = SignedQeIdentityVerifier::new(None, time);

        let verification = verifier.verify(&signed_qe_identity);

        assert_eq!(verification.is_success().unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The QE identity signature could not be verified: No public key available for signature verification"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
