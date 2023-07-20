// Copyright (c) 2023 The MobileCoin Foundation

use crate::{Accessor, SpacedStructName, VerificationOutput, Verifier};
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
};
use core::fmt::{Display, Formatter};
use serde::{Deserialize, Serialize};

/// The status of a set of advisories
///
/// The variants are defined in the schema at
/// <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3>
///
/// The variant order is important here, the higher the index the better the
/// status. For example: `UpToDate` is a better status than `SWHardeningNeeded`.
/// ```
/// use mc_attestation_verifier::AdvisoryStatus;
/// assert!(AdvisoryStatus::UpToDate > AdvisoryStatus::SWHardeningNeeded);
/// ```
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AdvisoryStatus {
    /// TCB level of SGX platform is revoked. The platform is not trustworthy.
    Revoked,
    /// TCB level of SGX platform is outdated and additional configuration of
    /// SGX platform may be needed.
    OutOfDateConfigurationNeeded,
    /// TCB level of SGX platform is outdated.
    OutOfDate,
    /// TCB level of the SGX platform is up-to-date but additional configuration
    /// for the platform and SW Hardening in the attesting SGX enclaves may be
    /// needed.
    ConfigurationAndSWHardeningNeeded,
    /// TCB level of the SGX platform is up-to-date but additional configuration
    /// of SGX platform may be needed.
    ConfigurationNeeded,
    /// TCB level of the SGX platform is up-to-date but due to certain issues
    /// affecting the platform, additional SW Hardening in the attesting SGX
    /// enclaves may be needed.
    SWHardeningNeeded,
    /// TCB level of the SGX platform is up-to-date.
    #[default]
    UpToDate,
}

/// The advisories pertaining to a TCB(Trusted Computing Base).
#[derive(Debug, Default, Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Advisories {
    ids: BTreeSet<String>,
    status: AdvisoryStatus,
}

impl Advisories {
    /// Create a new instance.
    ///
    /// # Arguments:
    /// * ids - The IDs, these are of the form "INTEL-SA-12345". They should be
    ///   all caps.
    /// * status - The status of the advisories specified in `ids`.
    pub fn new<'a, I, E>(ids: I, status: AdvisoryStatus) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        let ids = ids.into_iter().map(ToString::to_string).collect();
        Self { ids, status }
    }

    /// Returns `true` if `self` is a superset of `other`.
    ///
    /// This means that `self` contains at all the advisories in `other`
    /// and the `status` on `other` is as good or better than `status` on self.
    fn is_superset(&self, other: &Self) -> bool {
        if self.status > other.status {
            return false;
        }
        self.ids.is_superset(&other.ids)
    }
}

impl Display for Advisories {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "IDs: ")?;
        let ids = &self.ids;
        if ids.is_empty() {
            write!(f, "(none)")?
        } else {
            write!(f, "{ids:?}")?
        }
        write!(f, " Status: {:?}", self.status)
    }
}

impl SpacedStructName for Advisories {
    fn spaced_struct_name() -> &'static str {
        "advisories"
    }
}

/// Verifier for ensuring the expected [`Advisories`] are the only advisories
/// present and that they have a status that is at least as good as the
/// expected.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AdvisoriesVerifier {
    expected: Advisories,
}

impl AdvisoriesVerifier {
    /// Create a new instance.
    ///
    /// The `expected` advisories are treated as a superset of the allowed
    /// advisories.
    /// For example if the expected advisories contain the entry
    /// "INTEL-SA-12345", not having this entry in the actual advisories is a
    /// verification success. However having an advisory, "INTEL-SA-98765",
    /// which is not in the `expected` advisories is a verification failure.
    pub fn new(expected: Advisories) -> Self {
        Self { expected }
    }
}

impl<E: Accessor<Advisories>> Verifier<E> for AdvisoriesVerifier {
    type Value = Advisories;
    fn verify(&self, evidence: &E) -> VerificationOutput<Self::Value> {
        let expected = self.expected.clone();
        let actual = evidence.get();

        let is_success = expected.is_superset(&actual) as u8;

        VerificationOutput::new(actual, is_success.into())
    }
}

impl Display for AdvisoriesVerifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let expected = &self.expected;
        write!(f, "The allowed advisories are {expected}")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::VerificationTreeDisplay;
    use alloc::format;

    #[test]
    fn verifying_advisories_the_same() {
        let advisories = Advisories::new(
            ["123".into(), "345".into()],
            AdvisoryStatus::SWHardeningNeeded,
        );
        let verifier = AdvisoriesVerifier::new(advisories.clone());
        let verification = verifier.verify(&advisories);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] The allowed advisories are IDs: {"123", "345"} Status: SWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn advisories_have_one_more_when_verifying() {
        let mut advisories = Advisories::new(
            ["123".into(), "345".into()],
            AdvisoryStatus::SWHardeningNeeded,
        );
        let verifier = AdvisoriesVerifier::new(advisories.clone());

        advisories.ids.insert("678".into());

        let verification = verifier.verify(&advisories);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The allowed advisories are IDs: {"123", "345"} Status: SWHardeningNeeded, but the actual advisories was IDs: {"123", "345", "678"} Status: SWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn advisories_have_one_less_when_verifying() {
        let mut advisories = Advisories::new(["123", "345"], AdvisoryStatus::ConfigurationNeeded);
        let verifier = AdvisoriesVerifier::new(advisories.clone());

        advisories.ids.remove("123");

        let verification = verifier.verify(&advisories);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] The allowed advisories are IDs: {"123", "345"} Status: ConfigurationNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn advisories_have_lower_status_when_verifying() {
        let mut advisories = Advisories::new(["123", "345"], AdvisoryStatus::UpToDate);
        let verifier = AdvisoriesVerifier::new(advisories.clone());

        advisories.status = AdvisoryStatus::SWHardeningNeeded;

        let verification = verifier.verify(&advisories);
        assert_eq!(verification.is_failure().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [ ] The allowed advisories are IDs: {"123", "345"} Status: UpToDate, but the actual advisories was IDs: {"123", "345"} Status: SWHardeningNeeded"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }

    #[test]
    fn verifying_when_no_advisories_allowed() {
        let advisories = Advisories::new::<[&str; 0], str>([], AdvisoryStatus::UpToDate);
        let verifier = AdvisoriesVerifier::new(advisories.clone());

        let verification = verifier.verify(&advisories);
        assert_eq!(verification.is_success().unwrap_u8(), 1);

        let displayable = VerificationTreeDisplay::new(&verifier, verification);
        let expected = r#"
            - [x] The allowed advisories are IDs: (none) Status: UpToDate"#;
        assert_eq!(format!("\n{displayable}"), textwrap::dedent(expected));
    }
}
