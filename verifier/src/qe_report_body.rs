// Copyright (c) 2023-2024 The MobileCoin Foundation

//! Verification of a QE(Quoting Enclave) report body.

use crate::{
    choice_to_status_message,
    qe_identity::{QeIdentity, TcbLevel},
    report_body::MrSignerKeyVerifier,
    struct_name::SpacedStructName,
    Accessor, Advisories, AdvisoriesVerifier, AdvisoryStatus, AttributesVerifier,
    IsvProductIdVerifier, MiscellaneousSelectVerifier, VerificationMessage, VerificationOutput,
    Verifier, MESSAGE_INDENT,
};
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use mc_sgx_core_types::{
    Attributes, IsvProductId, IsvSvn, MiscellaneousSelect, MrSigner, ReportBody,
};
use mc_sgx_dcap_types::Quote3;

/// QE(quoting enclave) report body
///
/// The QE report body is provided via the
/// [`SignatureData`](`mc_sgx_dcap_types::SignatureData`) of a
/// [`Quote3`](`mc_sgx_dcap_types::Quote3`).
#[derive(Clone, Debug)]
pub struct QeReportBody(ReportBody);

impl QeReportBody {
    /// Create a new instance.
    pub fn new(report_body: ReportBody) -> Self {
        Self(report_body)
    }
}

impl<T: AsRef<[u8]>> From<&Quote3<T>> for QeReportBody {
    fn from(quote: &Quote3<T>) -> Self {
        let signature_data = quote.signature_data();
        let report_body = signature_data.qe_report_body();
        Self::new(report_body.clone())
    }
}

/// Verifier for ensuring a QE(quoting enclave) matches the provided identity
///
///
/// The verifier will perform steps 2-4 documented at
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
///
/// > 1. Retrieve Enclave Identity(SGX QE, TDX QE or QVE) from PCS and verify
/// >    that it is a valid structure issued by Intel.
/// > 2. Perform the following comparison of SGX Enclave Report against the
/// >    retrieved Enclave Identity:
/// >       a. Verify if MRSIGNER field retrieved from SGX Enclave Report is
/// >          equal to the value of mrsigner field in Enclave Identity.
/// >       b. Verify if ISVPRODID field retrieved from SGX Enclave Report is
/// >          equal to the value of isvprodid field in Enclave Identity.
/// >       c. Apply miscselectMask (binary mask) from Enclave Identity to
/// >          MISCSELECT field retrieved from SGX Enclave Report. Verify if the
/// >          outcome (miscselectMask & MISCSELECT) is equal to the value of
/// >          miscselect field in Enclave Identity.
/// >       d. Apply attributesMask (binary mask) from Enclave Identity to
/// >          ATTRIBUTES field retrieved from SGX Enclave Report. Verify if the
/// >          outcome (attributesMask & ATTRIBUTES) is equal to the value of
/// >          attributes field in Enclave Identity.
/// > 3. If any of the checks above fail, the identity of the enclave does not
/// >    match Enclave Identity published by Intel.
/// > 4. Determine a TCB status of the Enclave:
/// >       a. Retrieve a collection of TCB Levels (sorted by ISVSVNs) from
/// >          tcbLevels field in Enclave Identity structure.
/// >       b. Go over the list of TCB Levels (descending order) and find the
/// >          one that has ISVSVN that is lower or equal to the ISVSVN value
/// >          from SGX Enclave Report.
/// >       c. If a TCB level is found, read its status from tcbStatus field,
/// >          otherwise your TCB Level is not supported.
#[derive(Clone, Debug)]
pub struct QeReportBodyVerifier {
    attributes: AttributesVerifier,
    mr_signer: MrSignerKeyVerifier,
    isv_prod_id: IsvProductIdVerifier,
    isv_svn: QeIsvSvnVerifier,
    miscellaneous_select: MiscellaneousSelectVerifier,
}

impl QeReportBodyVerifier {
    /// Create a new instance.
    ///
    /// The `identity` should be retrieved from
    /// <https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity?update=standard>
    /// and verified to be signed.
    pub fn new(identity: QeIdentity) -> Self {
        let mr_signer = MrSignerKeyVerifier::new(identity.mr_signer());
        let isv_prod_id = IsvProductIdVerifier::new(identity.isv_prod_id());
        let miscellaneous_select = MiscellaneousSelectVerifier::new(
            identity.miscellaneous_select(),
            identity.miscellaneous_select_mask(),
        );
        let attributes = AttributesVerifier::new(identity.attributes(), identity.attributes_mask());
        let isv_svn = QeIsvSvnVerifier::new(identity.tcb_levels());
        Self {
            attributes,
            mr_signer,
            isv_prod_id,
            isv_svn,
            miscellaneous_select,
        }
    }
}

/// The output from verifying a QE(quoting enclave) report body
#[derive(Debug, Clone)]
pub struct QeReportBodyValue {
    mr_signer: VerificationOutput<MrSigner>,
    isv_prod_id: VerificationOutput<IsvProductId>,
    miscellaneous_select: VerificationOutput<MiscellaneousSelect>,
    attributes: VerificationOutput<Attributes>,
    isv_svn: VerificationOutput<(IsvSvn, Option<TcbLevel>)>,
}

impl<E: Accessor<QeReportBody>> Verifier<E> for QeReportBodyVerifier {
    type Value = QeReportBodyValue;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let qe_report_body = evidence.get();
        let mr_signer = self.mr_signer.verify(&qe_report_body.0);
        let isv_prod_id = self.isv_prod_id.verify(&qe_report_body.0);
        let miscellaneous_select = self.miscellaneous_select.verify(&qe_report_body.0);
        let attributes = self.attributes.verify(&qe_report_body.0);
        let isv_svn = self.isv_svn.verify(&qe_report_body.0);
        let status = mr_signer.is_success()
            & isv_prod_id.is_success()
            & miscellaneous_select.is_success()
            & attributes.is_success()
            & isv_svn.is_success();
        VerificationOutput::new(
            QeReportBodyValue {
                mr_signer,
                isv_prod_id,
                miscellaneous_select,
                attributes,
                isv_svn,
            },
            status,
        )
    }
}

impl VerificationMessage<QeReportBodyValue> for QeReportBodyVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        output: &VerificationOutput<QeReportBodyValue>,
    ) -> core::fmt::Result {
        let status = choice_to_status_message(output.is_success());

        write!(
            f,
            "{:pad$}{status} QE Report Body all of the following must be true:",
            ""
        )?;
        let pad = pad + MESSAGE_INDENT;
        writeln!(f)?;
        self.mr_signer.fmt_padded(f, pad, &output.value.mr_signer)?;
        writeln!(f)?;
        self.isv_prod_id
            .fmt_padded(f, pad, &output.value.isv_prod_id)?;
        writeln!(f)?;
        self.miscellaneous_select
            .fmt_padded(f, pad, &output.value.miscellaneous_select)?;
        writeln!(f)?;
        self.attributes
            .fmt_padded(f, pad, &output.value.attributes)?;
        writeln!(f)?;
        self.isv_svn.fmt_padded(f, pad, &output.value.isv_svn)
    }
}

/// Verifier for ensuring a QE(quoting enclave) ISV SVN falls within the
/// provided [`TcbLevel`]s.
///
/// Preforms step 4 of
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
///
/// > 4. Determine a TCB status of the Enclave:
/// >       a. Retrieve a collection of TCB Levels (sorted by ISVSVNs) from
/// >          tcbLevels field in Enclave Identity structure.
/// >       b. Go over the list of TCB Levels (descending order) and find the
/// >          one that has ISVSVN that is lower or equal to the ISVSVN value
/// >          from SGX Enclave Report.
/// >       c. If a TCB level is found, read its status from tcbStatus field,
/// >          otherwise your TCB Level is not supported.
#[derive(Debug, Clone)]
struct QeIsvSvnVerifier {
    tcb_levels: Vec<TcbLevel>,
}

impl QeIsvSvnVerifier {
    fn new<'a, I>(tcb_levels: I) -> Self
    where
        I: IntoIterator<Item = &'a TcbLevel>,
    {
        Self {
            tcb_levels: tcb_levels.into_iter().cloned().collect(),
        }
    }
}

impl<E: Accessor<IsvSvn>> Verifier<E> for QeIsvSvnVerifier {
    type Value = (IsvSvn, Option<TcbLevel>);
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let isv_svn = evidence.get();
        let mut tcb_levels = self.tcb_levels.clone();

        // The tcb levels seem to be pre-sorted in the qe_identity, but the step 4 of determining
        // ISV SVN says "sorted by ISVSVNs" which further stresses teh need so we sort here for
        // robustness. This sorting is descending order.
        tcb_levels.sort_by(|a, b| b.isv_svn().as_ref().cmp(a.isv_svn().as_ref()));

        let tcb_level = tcb_levels.iter().find_map(|tcb_level| {
            if tcb_level.isv_svn().as_ref() <= isv_svn.as_ref() {
                Some(tcb_level.clone())
            } else {
                None
            }
        });

        let mut is_success = 0.into();
        if let Some(tcb_level) = &tcb_level {
            let up_to_date_with_no_advisories =
                Advisories::new([] as [&str; 0], AdvisoryStatus::UpToDate);
            let advisories_verifier = AdvisoriesVerifier::new(up_to_date_with_no_advisories);
            let result = advisories_verifier.verify(&tcb_level.advisories());
            is_success = result.is_success();
        }

        VerificationOutput::new((isv_svn, tcb_level), is_success)
    }
}

impl Display for QeIsvSvnVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "The {} should correspond to an `UpToDate` level with no advisories, from: {:?}",
            IsvSvn::spaced_struct_name(),
            self.tcb_levels
        )
    }
}

impl VerificationMessage<(IsvSvn, Option<TcbLevel>)> for QeIsvSvnVerifier {
    fn fmt_padded(
        &self,
        f: &mut Formatter<'_>,
        pad: usize,
        output: &VerificationOutput<(IsvSvn, Option<TcbLevel>)>,
    ) -> core::fmt::Result {
        let is_success = output.is_success();
        let status = choice_to_status_message(is_success);
        write!(f, "{:pad$}{status} {self}", "")?;
        if (!is_success).into() {
            let name = IsvSvn::spaced_struct_name();
            let actual = &output.value;

            write!(
                f,
                ", but the {name} of {} corresponds to {:?}",
                actual.0, actual.1
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qe_identity::{SignedQeIdentity, Tcb},
        VerificationTreeDisplay,
    };
    use alloc::{format, string::ToString};
    use mc_sgx_core_sys_types::sgx_report_body_t;
    use mc_sgx_core_types::AttributeFlags;
    use mc_sgx_dcap_types::Quote3;

    #[test]
    fn no_tcb_levels_for_qe_isv_svn_fails() {
        let isv_svn = IsvSvn::from(1);
        let verifier = QeIsvSvnVerifier::new(&[]);
        let verification = verifier.verify(&isv_svn);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        assert_eq!(
            displayable.to_string(),
            r#"- [ ] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [], but the ISV SVN of 1 corresponds to None"#
        );
    }

    #[test]
    fn tcb_level_at_isv_svn_succeeds() {
        let isv_svn = IsvSvn::from(1);
        let tcb_levels = [TcbLevel::new(
            Tcb::new(1),
            AdvisoryStatus::UpToDate,
            [] as [&str; 0],
        )];
        let verifier = QeIsvSvnVerifier::new(&tcb_levels);
        let verification = verifier.verify(&isv_svn);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        assert_eq!(
            displayable.to_string(),
            r#"- [x] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }]"#
        );
    }

    #[test]
    fn tcb_level_above_isv_svn_fails() {
        let isv_svn = IsvSvn::from(1);
        let tcb_levels = [TcbLevel::new(
            Tcb::new(2),
            AdvisoryStatus::UpToDate,
            [] as [&str; 0],
        )];
        let verifier = QeIsvSvnVerifier::new(&tcb_levels);
        let verification = verifier.verify(&isv_svn);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        assert_eq!(
            displayable.to_string(),
            r#"- [ ] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 2 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }], but the ISV SVN of 1 corresponds to None"#
        );
    }

    #[test]
    fn tcb_level_not_up_to_date_fails() {
        let isv_svn = IsvSvn::from(1);
        let tcb_levels = [TcbLevel::new(
            Tcb::new(1),
            AdvisoryStatus::SWHardeningNeeded,
            [] as [&str; 0],
        )];
        let verifier = QeIsvSvnVerifier::new(&tcb_levels);
        let verification = verifier.verify(&isv_svn);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        assert_eq!(
            displayable.to_string(),
            r#"- [ ] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: SWHardeningNeeded, advisory_ids: [] }], but the ISV SVN of 1 corresponds to Some(TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: SWHardeningNeeded, advisory_ids: [] })"#
        );
    }

    #[test]
    fn tcb_level_with_advisories_fails() {
        let isv_svn = IsvSvn::from(1);
        let tcb_levels = [TcbLevel::new(
            Tcb::new(1),
            AdvisoryStatus::UpToDate,
            ["an id"],
        )];
        let verifier = QeIsvSvnVerifier::new(&tcb_levels);
        let verification = verifier.verify(&isv_svn);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        assert_eq!(
            displayable.to_string(),
            r#"- [ ] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: UpToDate, advisory_ids: ["an id"] }], but the ISV SVN of 1 corresponds to Some(TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "1970-01-01T00:00:00Z", tcb_status: UpToDate, advisory_ids: ["an id"] })"#
        );
    }

    #[test]
    fn correct_tcb_level_is_used_from_multiple_levels() {
        // Order is important here and must be descending
        let mut tcb_levels = [6, 5, 2, 1]
            .iter()
            .map(|isv_svn| {
                TcbLevel::new(
                    Tcb::new(*isv_svn),
                    AdvisoryStatus::SWHardeningNeeded,
                    [] as [&str; 0],
                )
            })
            .collect::<Vec<_>>();
        tcb_levels.insert(
            2,
            TcbLevel::new(Tcb::new(3), AdvisoryStatus::UpToDate, [] as [&str; 0]),
        );
        let verifier = QeIsvSvnVerifier::new(&tcb_levels);

        assert_eq!(
            verifier.verify(&IsvSvn::from(1)).is_failure().unwrap_u8(),
            1
        );
        assert_eq!(
            verifier.verify(&IsvSvn::from(1)).is_failure().unwrap_u8(),
            1
        );
        // Note 3 and 4 should be success. 3 is exactly equal to the 3 inserted
        // above while 4 is greater than it.
        assert_eq!(
            verifier.verify(&IsvSvn::from(3)).is_success().unwrap_u8(),
            1
        );
        assert_eq!(
            verifier.verify(&IsvSvn::from(4)).is_success().unwrap_u8(),
            1
        );

        // This is unlikely to happen that newer ISV SVN values are invalid if
        // previous values were valid, but it shows that the logic stops at the
        // first entry which is less than or equal to the ISV SVN.
        assert_eq!(
            verifier.verify(&IsvSvn::from(5)).is_failure().unwrap_u8(),
            1
        );
        assert_eq!(
            verifier.verify(&IsvSvn::from(6)).is_failure().unwrap_u8(),
            1
        );
    }

    #[test]
    fn qe_report_body_succeeds() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let qe_report_body = QeReportBody::from(&quote);
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] QE Report Body all of the following must be true:
              - [x] The MRSIGNER key hash should be 8c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff
              - [x] The ISV product ID should be 1
              - [x] The expected miscellaneous select is 0x0000_0000 with mask 0xFFFF_FFFF
              - [x] The expected attributes is Flags: INITTED | PROVISION_KEY Xfrm: (none) with mask Flags: 0xFFFF_FFFF_FFFF_FFFB Xfrm: (none)
              - [x] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 8 }, tcb_date: "2023-02-15T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }, TcbLevel { tcb: Tcb { isv_svn: 6 }, tcb_date: "2021-11-10T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 5 }, tcb_date: "2020-11-11T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 4 }, tcb_date: "2019-11-13T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 2 }, tcb_date: "2019-05-15T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00219", "INTEL-SA-00293", "INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "2018-08-15T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00202", "INTEL-SA-00219", "INTEL-SA-00293", "INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }]"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn qe_report_body_fails_for_mr_signer_key() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let mut sgx_report_body: sgx_report_body_t = QeReportBody::from(&quote).0.into();
        sgx_report_body.mr_signer.m[0] += 1;
        let qe_report_body = QeReportBody::new(ReportBody::from(sgx_report_body));

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 0);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] QE Report Body all of the following must be true:
              - [ ] The MRSIGNER key hash should be 8c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff, but the actual MRSIGNER key hash was 8d4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff
              - [x] The ISV product ID should be 1
              - [x] The expected miscellaneous select is 0x0000_0000 with mask 0xFFFF_FFFF
              - [x] The expected attributes is Flags: INITTED | PROVISION_KEY Xfrm: (none) with mask Flags: 0xFFFF_FFFF_FFFF_FFFB Xfrm: (none)
              - [x] The ISV SVN should correspond to an `UpToDate` level with no advisories, from: [TcbLevel { tcb: Tcb { isv_svn: 8 }, tcb_date: "2023-02-15T00:00:00Z", tcb_status: UpToDate, advisory_ids: [] }, TcbLevel { tcb: Tcb { isv_svn: 6 }, tcb_date: "2021-11-10T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 5 }, tcb_date: "2020-11-11T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 4 }, tcb_date: "2019-11-13T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 2 }, tcb_date: "2019-05-15T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00219", "INTEL-SA-00293", "INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }, TcbLevel { tcb: Tcb { isv_svn: 1 }, tcb_date: "2018-08-15T00:00:00Z", tcb_status: OutOfDate, advisory_ids: ["INTEL-SA-00202", "INTEL-SA-00219", "INTEL-SA-00293", "INTEL-SA-00334", "INTEL-SA-00477", "INTEL-SA-00615"] }]"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn qe_report_body_fails_for_isv_prod_id() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let mut sgx_report_body: sgx_report_body_t = QeReportBody::from(&quote).0.into();
        sgx_report_body.isv_prod_id += 1;
        let qe_report_body = QeReportBody::new(ReportBody::from(sgx_report_body));

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 0);
    }

    #[test]
    fn qe_report_body_fails_for_isv_svn() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let mut sgx_report_body: sgx_report_body_t = QeReportBody::from(&quote).0.into();
        // The isv svn in the identity is 8, can be seen by looking at the json file
        sgx_report_body.isv_svn = 7;
        let qe_report_body = QeReportBody::new(ReportBody::from(sgx_report_body));

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 0);
    }

    #[test]
    fn qe_report_body_fails_for_miscellaneous_select() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let mut sgx_report_body: sgx_report_body_t = QeReportBody::from(&quote).0.into();
        // Current mask is 0xFFFF_FFFF so any change will fail
        sgx_report_body.misc_select += 1;
        let qe_report_body = QeReportBody::new(ReportBody::from(sgx_report_body));

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 0);
    }

    #[test]
    fn qe_report_body_fails_for_attributes() {
        let quote_bytes = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(quote_bytes.as_ref()).expect("Failed to parse quote");
        let json = include_str!("../data/tests/qe_identity.json");
        let signed_qe_identity =
            SignedQeIdentity::try_from(json).expect("Failed to parse signed identity");
        let identity =
            QeIdentity::try_from(&signed_qe_identity).expect("Failed to verify identity");
        let verifier = QeReportBodyVerifier::new(identity);

        let mut sgx_report_body: sgx_report_body_t = QeReportBody::from(&quote).0.into();
        sgx_report_body.attributes.flags |= AttributeFlags::DEBUG.bits();
        let qe_report_body = QeReportBody::new(ReportBody::from(sgx_report_body));

        let verification = verifier.verify(&qe_report_body);
        assert_eq!(verification.succeeded.unwrap_u8(), 0);
    }
}
