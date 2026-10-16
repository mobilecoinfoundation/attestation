// Copyright (c) 2026 The MobileCoin Foundation

use super::*;
use alloc::vec;
use der::{Decode, EncodePem};
use p256::ecdsa::{signature::Signer, SigningKey};
use x509_cert::{
    builder::{Builder, CertificateBuilder, CrlBuilder},
    crl::RevokedCert,
    ext::{
        pkix::{AuthorityKeyIdentifier, CrlNumber, KeyUsages, SubjectKeyIdentifier},
        ToExtension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfo,
    time::Validity,
};

mod certificates;
use certificates::TestProfile;

const ROOT: &str = include_str!("../../data/tests/root_ca.pem");
const PROCESSOR: &str = include_str!("../../data/tests/processor_ca.pem");
const LEAF: &str = include_str!("../../data/tests/leaf_cert.pem");
const TCB: &str = include_str!("../../data/tests/tcb_signer.pem");
const ROOT_CRL: &[u8] = include_bytes!("../../data/tests/root_crl.der");
const PROCESSOR_CRL: &[u8] = include_bytes!("../../data/tests/processor_crl.der");

fn date(s: &str) -> DateTime {
    s.parse().unwrap()
}
fn now() -> DateTime {
    date("2023-07-12T20:48:25Z")
}
fn cert(s: &str) -> Certificate {
    Certificate::from_pem(s).unwrap()
}
fn crl(b: &[u8]) -> CertificateList {
    CertificateList::from_der(b).unwrap()
}

#[test]
fn real_intel_certificate_chains() {
    let verifier = WebPkiCertificateChainVerifier::from_pem(ROOT).unwrap();
    let chain = [cert(LEAF), cert(PROCESSOR), cert(ROOT)];
    let crls = [crl(ROOT_CRL), crl(PROCESSOR_CRL)];
    verifier
        .verify_certificate_chain(&chain, &crls, date("2023-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls, now()),
        Err(Error::CrlExpired)
    );
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls, date("2030-01-01T00:00:00Z")),
        Err(Error::CertificateExpired)
    );
    let chain = [cert(TCB), cert(ROOT)];
    verifier
        .verify_certificate_chain(&chain, &crls[..1], now())
        .unwrap();
}

#[test]
fn current_intel_certificate_chains_and_signed_collateral() {
    use crate::{
        SignedQeIdentity, SignedQeIdentityVerifier, SignedTcbInfo, SignedTcbInfoVerifier,
        Verifier as _,
    };
    let time = date("2026-10-16T21:00:00Z");
    let verifier = WebPkiCertificateChainVerifier::from_pem(ROOT).unwrap();
    let crls = [
        crl(include_bytes!("../../data/tests/current_root_crl.der")),
        crl(include_bytes!("../../data/tests/current_processor_crl.der")),
    ];
    verifier
        .verify_certificate_chain(&[cert(LEAF), cert(PROCESSOR), cert(ROOT)], &crls, time)
        .unwrap();
    let tcb_signer = cert(include_str!("../../data/tests/current_tcb_signer.pem"));
    let qe_signer = cert(include_str!("../../data/tests/current_qe_signer.pem"));
    for signer in [&tcb_signer, &qe_signer] {
        verifier
            .verify_certificate_chain([signer, &cert(ROOT)], &crls[..1], time)
            .unwrap();
    }
    let tcb =
        SignedTcbInfo::try_from(include_str!("../../data/tests/current_tcb_info.json")).unwrap();
    assert!(bool::from(
        SignedTcbInfoVerifier::new(
            crate::evidence::key_from_certificate(&tcb_signer),
            Some(time)
        )
        .verify(&tcb)
        .is_success()
    ));
    let qe = SignedQeIdentity::try_from(include_str!("../../data/tests/current_qe_identity.json"))
        .unwrap();
    assert!(bool::from(
        SignedQeIdentityVerifier::new(crate::evidence::key_from_certificate(&qe_signer), time)
            .verify(&qe)
            .is_success()
    ));
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_slice(&[n; 32]).unwrap()
}
fn issued(
    subject: &str,
    issuer: &str,
    subject_key: &SigningKey,
    issuer_key: &SigningKey,
    serial: u8,
    ca: bool,
    path_len_constraint: Option<u8>,
) -> Certificate {
    let profile = TestProfile {
        subject: subject.parse::<Name>().unwrap(),
        issuer: issuer.parse().unwrap(),
        is_ca: Some(ca),
        path_len_constraint,
        extensions: vec![],
        key_usage: Some(KeyUsage(if ca {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        } else {
            KeyUsages::DigitalSignature.into()
        })),
    };
    // Anchors outlive the issued certificates so expiry tests reach WebPKI's
    // leaf/intermediate checks rather than our explicit anchor-validity check.
    let validity = if ca && subject == issuer {
        Validity::new(
            date("2020-01-01T00:00:00Z").into(),
            date("2030-01-01T00:00:00Z").into(),
        )
    } else {
        Validity::new(
            date("2023-01-01T00:00:00Z").into(),
            date("2024-01-01T00:00:00Z").into(),
        )
    };
    certificate(profile, serial, subject_key, issuer_key, validity)
}

fn certificate(
    profile: TestProfile,
    serial: u8,
    subject_key: &SigningKey,
    issuer_key: &SigningKey,
    validity: Validity,
) -> Certificate {
    CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        validity,
        SubjectPublicKeyInfo::from_key(subject_key.verifying_key()).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(issuer_key)
    .unwrap()
}

fn issued_crl(
    issuer: &Certificate,
    issuer_key: &SigningKey,
    revoked: Option<u8>,
) -> CertificateList {
    let mut crl = CrlBuilder::new_with_this_update(
        issuer,
        CrlNumber::try_from(1u8).unwrap(),
        date("2023-01-01T00:00:00Z").into(),
    )
    .unwrap()
    .with_next_update(Some(date("2024-01-01T00:00:00Z").into()))
    .with_certificates(revoked.into_iter().map(|serial| RevokedCert {
        serial_number: SerialNumber::from(serial),
        revocation_date: date("2023-01-01T00:00:00Z").into(),
        crl_entry_extensions: None,
    }))
    .build::<_, p256::ecdsa::DerSignature>(issuer_key)
    .unwrap();
    // x509-cert 0.3 copies the certificate's AKI (its parent's key ID).
    // Correct it to this issuer's SKI while preserving cRLNumber and any other
    // builder extensions. WebPKI currently selects CRLs independently of AKI.
    let ski = issuer
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let aki = AuthorityKeyIdentifier {
        key_identifier: Some(ski.0),
        ..Default::default()
    };
    let extension = aki.to_extension(&crl.tbs_cert_list.issuer, &[]).unwrap();
    let existing = crl
        .tbs_cert_list
        .crl_extensions
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|existing| existing.extn_id == extension.extn_id)
        .unwrap();
    *existing = extension;
    resign_crl(&mut crl, issuer_key);
    crl
}

fn resign_crl(crl: &mut CertificateList, issuer_key: &SigningKey) {
    let signature: p256::ecdsa::DerSignature =
        issuer_key.sign(&crl.tbs_cert_list.to_der().unwrap());
    crl.signature = der::asn1::BitString::from_bytes(signature.as_bytes()).unwrap();
}

#[test]
fn rejects_invalid_paths_revocation_and_times() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false, None);
    let chain = [leaf.clone(), issuer.clone(), root.clone()];
    let crls = [
        issued_crl(&root, &key(1), None),
        issued_crl(&issuer, &key(2), None),
    ];
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    verifier
        .verify_certificate_chain(&chain, &crls, now())
        .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls, None),
        Err(Error::MissingValidationTime)
    );
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls, date("2022-01-01T00:00:00Z")),
        Err(Error::CertificateNotYetValid)
    );
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls, date("2025-01-01T00:00:00Z")),
        Err(Error::CertificateExpired)
    );
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &[] as &[CertificateList], now()),
        Err(Error::UnknownRevocationStatus)
    );
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &crls[..1], now()),
        Err(Error::UnknownRevocationStatus)
    );
    assert_eq!(
        verifier.verify_certificate_chain([&leaf, &root], &crls, now()),
        Err(Error::GeneralCertificateError)
    );
    let revoked_leaf = [crls[0].clone(), issued_crl(&issuer, &key(2), Some(3))];
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &revoked_leaf, now()),
        Err(Error::CertificateRevoked)
    );
    let revoked_ca = [issued_crl(&root, &key(1), Some(2)), crls[1].clone()];
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &revoked_ca, now()),
        Err(Error::CertificateRevoked)
    );
    let bad_issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, false, None);
    assert_eq!(
        verifier.verify_certificate_chain([&leaf, &bad_issuer, &root], &crls, now()),
        Err(Error::GeneralCertificateError)
    );
    let other = issued("CN=Other", "CN=Other", &key(4), &key(4), 4, true, Some(0));
    let wrong_root =
        WebPkiCertificateChainVerifier::from_pem(&other.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    assert_eq!(
        wrong_root.verify_certificate_chain(&chain, &crls, now()),
        Err(Error::GeneralCertificateError)
    );
    let mut bad_crls = crls.clone();
    let mut sig = bad_crls[1].signature.as_bytes().unwrap().to_vec();
    *sig.last_mut().unwrap() ^= 1;
    bad_crls[1].signature = der::asn1::BitString::from_bytes(&sig).unwrap();
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &bad_crls, now()),
        Err(Error::SignatureVerification)
    );
    let mut stale = crls.clone();
    stale[1].tbs_cert_list.next_update = Some(date("2023-01-02T00:00:00Z").into());
    resign_crl(&mut stale[1], &key(2));
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &stale, now()),
        Err(Error::CrlExpired)
    );
    let mut corrupt = leaf.to_der().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    let corrupt = Certificate::from_der(&corrupt).unwrap();
    assert_eq!(
        verifier.verify_certificate_chain([&corrupt, &issuer, &root], &crls, now()),
        Err(Error::SignatureVerification)
    );

    // The issuer allows no subordinate CAs (pathLenConstraint=0).
    let sub_ca = issued("CN=SubCA", "CN=Issuer", &key(4), &key(2), 4, true, Some(0));
    let sub_leaf = issued("CN=SubLeaf", "CN=SubCA", &key(5), &key(4), 5, false, None);
    let sub_crls = [
        crls[0].clone(),
        crls[1].clone(),
        issued_crl(&sub_ca, &key(4), None),
    ];
    assert_eq!(
        verifier.verify_certificate_chain([&sub_leaf, &sub_ca, &issuer, &root], &sub_crls, now()),
        Err(Error::GeneralCertificateError)
    );

    let mut future = crls.clone();
    future[1].tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    resign_crl(&mut future[1], &key(2));
    assert_eq!(
        verifier.verify_certificate_chain(&chain, &future, now()),
        Err(Error::CrlNotYetValid)
    );
    assert!(matches!(
        WebPkiCertificateChainVerifier::from_pem("garbage"),
        Err(Error::GeneralCertificateError)
    ));
}

// A synthetic PCK hierarchy and re-signed collateral let the complete verifier
// succeed at a common historical time without accepting an outdated platform.
#[test]
fn evidence_verifier_succeeds_with_generated_signing_hierarchy() {
    use crate::{
        Evidence, EvidenceVerifier, TrustedMrEnclaveIdentity, VerificationTreeDisplay, Verifier,
    };
    use mc_sgx_dcap_types::Quote3;

    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let original_quote =
        Quote3::try_from(include_bytes!("../../data/tests/hw_quote.dat").as_slice()).unwrap();
    let signature_data = original_quote.signature_data();
    let mc_sgx_dcap_types::CertificationData::PckCertificateChain(original_chain) =
        signature_data.certification_data()
    else {
        panic!("Expected PCK chain")
    };
    let intel_leaf = Certificate::from_pem(original_chain.into_iter().next().unwrap()).unwrap();
    let sgx_extension = intel_leaf
        .tbs_certificate()
        .extensions()
        .as_ref()
        .unwrap()
        .iter()
        .find(|ext| ext.extn_id == "1.2.840.113741.1.13.1".parse().unwrap())
        .unwrap()
        .clone();
    let profile = TestProfile {
        subject: "CN=PCK".parse().unwrap(),
        issuer: "CN=Issuer".parse().unwrap(),
        is_ca: Some(false),
        path_len_constraint: None,
        extensions: vec![sgx_extension],
        key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
    };
    let pck = CertificateBuilder::new(
        profile,
        SerialNumber::from(3u8),
        Validity::new(
            date("2023-01-01T00:00:00Z").into(),
            date("2024-01-01T00:00:00Z").into(),
        ),
        SubjectPublicKeyInfo::from_key(key(3).verifying_key()).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&key(2))
    .unwrap();
    let signer = issued("CN=Signer", "CN=Root", &key(4), &key(1), 4, false, None);
    let root_pem = root.to_pem(der::pem::LineEnding::LF).unwrap();
    let signer_pem = signer.to_pem(der::pem::LineEnding::LF).unwrap();
    let chain = [pck, issuer.clone(), root.clone()]
        .iter()
        .map(|cert| cert.to_pem(der::pem::LineEnding::LF).unwrap())
        .collect::<Vec<_>>()
        .concat();

    // Preserve the application quote and attestation-key binding. Re-sign the QE
    // report with the synthetic PCK key and replace its certification chain.
    let mut quote_bytes = include_bytes!("../../data/tests/hw_quote.dat").to_vec();
    let qe_signature: p256::ecdsa::Signature = key(3).sign(&quote_bytes[564..948]);
    quote_bytes[948..1012].copy_from_slice(&qe_signature.to_bytes());
    let auth_len = u16::from_le_bytes(quote_bytes[1012..1014].try_into().unwrap()) as usize;
    let cert_header = 1014 + auth_len;
    quote_bytes.truncate(cert_header + 2); // retain certification type (PCK chain)
    quote_bytes.extend_from_slice(&(chain.len() as u32).to_le_bytes());
    quote_bytes.extend_from_slice(chain.as_bytes());
    let signature_len = (quote_bytes.len() - 436) as u32;
    quote_bytes[432..436].copy_from_slice(&signature_len.to_le_bytes());
    let quote = Quote3::try_from(quote_bytes).unwrap();

    let sign_json = |input: &str, field: &str| {
        let mut value: serde_json::Value = serde_json::from_str(input).unwrap();
        let body = serde_json::to_string(&value[field]).unwrap();
        let signature: p256::ecdsa::Signature = key(4).sign(body.as_bytes());
        value["signature"] = hex::encode(signature.to_bytes()).into();
        serde_json::to_string(&value).unwrap()
    };
    let tcb = sign_json(
        include_str!("../../data/tests/fmspc_00906ED50000_2023_07_12.json"),
        "tcbInfo",
    );
    let qe = sign_json(
        include_str!("../../data/tests/qe_identity.json"),
        "enclaveIdentity",
    );
    let collateral = crate::evidence::test::collateral_with_certificates(
        &tcb,
        &qe,
        &signer_pem,
        &signer_pem,
        [&issuer.to_pem(der::pem::LineEnding::LF).unwrap(), &root_pem],
        &issued_crl(&root, &key(1), None).to_der().unwrap(),
        &issued_crl(&issuer, &key(2), None).to_der().unwrap(),
    );
    let identity = TrustedMrEnclaveIdentity::new(
        quote.app_report_body().mr_enclave(),
        [] as [&str; 0],
        ["INTEL-SA-00334", "INTEL-SA-00615"],
    );
    assert_eq!(collateral.pck_crl_issuer_chain(), &[issuer, root]);
    let evidence = Evidence::new(quote, collateral).unwrap();
    let verifier = EvidenceVerifier::new(
        WebPkiCertificateChainVerifier::from_pem(&root_pem).unwrap(),
        [identity],
        now(),
    );
    let result = verifier.verify(&evidence);
    assert!(
        bool::from(result.is_success()),
        "{}",
        VerificationTreeDisplay::new(&verifier, result)
    );
}

#[test]
fn constructor_rejects_an_unusable_anchor() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    // x509-cert can decode a certificate with duplicate extensions, but WebPKI
    // cannot use it as an anchor. Reject it now, before any evidence is verified.
    let profile = TestProfile {
        subject: "CN=Root".parse().unwrap(),
        issuer: "CN=Root".parse().unwrap(),
        is_ca: Some(true),
        path_len_constraint: Some(1),
        extensions: vec![root
            .tbs_certificate()
            .extensions()
            .unwrap()
            .iter()
            .find(|ext| ext.extn_id == "2.5.29.19".parse().unwrap())
            .unwrap()
            .clone()],
        key_usage: Some(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
    };
    let unusable = CertificateBuilder::new(
        profile,
        SerialNumber::from(1u8),
        *root.tbs_certificate().validity(),
        SubjectPublicKeyInfo::from_key(key(1).verifying_key()).unwrap(),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&key(1))
    .unwrap();
    let pem = unusable.to_pem(der::pem::LineEnding::LF).unwrap();
    Certificate::from_pem(&pem).unwrap();
    assert!(matches!(
        WebPkiCertificateChainVerifier::from_pem(&pem),
        Err(Error::GeneralCertificateError)
    ));
}

#[test]
fn crl_next_update_boundary_and_missing_next_update_fail() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let leaf = issued("CN=Leaf", "CN=Root", &key(2), &key(1), 2, false, None);
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    let crl = issued_crl(&root, &key(1), None);
    let chain = [&leaf]; // The pinned anchor need not be repeated in the chain.
    verifier
        .verify_certificate_chain(chain, [&crl], date("2023-12-31T23:59:59Z"))
        .unwrap();
    // WebPKI requires time < nextUpdate, even though certificate notAfter is inclusive.
    assert_eq!(
        verifier.verify_certificate_chain(chain, [&crl], date("2024-01-01T00:00:00Z")),
        Err(Error::CrlExpired)
    );
    assert_eq!(
        verifier.verify_certificate_chain(chain, [&crl], date("2024-01-01T00:00:01Z")),
        Err(Error::CertificateExpired)
    );
    let mut missing_next_update = crl;
    missing_next_update.tbs_cert_list.next_update = None;
    resign_crl(&mut missing_next_update, &key(1));
    assert_eq!(
        verifier.verify_certificate_chain(chain, [&missing_next_update], now()),
        Err(Error::GeneralCertificateError)
    );
}

#[test]
fn requires_key_usage_for_ca_certificate_and_crl_signing() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false, None);
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    let crls = [
        issued_crl(&root, &key(1), None),
        issued_crl(&issuer, &key(2), None),
    ];
    verifier
        .verify_certificate_chain([&leaf, &issuer], &crls, now())
        .unwrap();

    // Missing KeyUsage, missing keyCertSign, and missing cRLSign each fail.
    for key_usage in [
        None,
        Some(KeyUsage(KeyUsages::CRLSign.into())),
        Some(KeyUsage(KeyUsages::KeyCertSign.into())),
    ] {
        let profile = TestProfile {
            issuer: "CN=Root".parse().unwrap(),
            subject: "CN=Issuer".parse().unwrap(),
            is_ca: Some(true),
            path_len_constraint: Some(0),
            extensions: vec![],
            key_usage,
        };
        let unauthorized_issuer = certificate(
            profile,
            2,
            &key(2),
            &key(1),
            *issuer.tbs_certificate().validity(),
        );
        assert_eq!(
            verifier.verify_certificate_chain([&leaf, &unauthorized_issuer], &crls, now()),
            Err(Error::GeneralCertificateError)
        );

        let profile = TestProfile {
            issuer: "CN=Root".parse().unwrap(),
            subject: "CN=Root".parse().unwrap(),
            is_ca: Some(true),
            path_len_constraint: Some(1),
            extensions: vec![],
            key_usage,
        };
        let unauthorized_root = certificate(
            profile,
            1,
            &key(1),
            &key(1),
            *root.tbs_certificate().validity(),
        );
        assert!(matches!(
            WebPkiCertificateChainVerifier::from_pem(
                &unauthorized_root.to_pem(der::pem::LineEnding::LF).unwrap()
            ),
            Err(Error::GeneralCertificateError)
        ));
    }

    // This profile permits an absent leaf KeyUsage, but rejects a present one
    // that does not authorize digital signatures.
    for (key_usage, expected) in [
        (None, Ok(())),
        (
            Some(KeyUsage(KeyUsages::KeyEncipherment.into())),
            Err(Error::GeneralCertificateError),
        ),
    ] {
        let profile = TestProfile {
            issuer: "CN=Issuer".parse().unwrap(),
            subject: "CN=Leaf".parse().unwrap(),
            is_ca: Some(false),
            path_len_constraint: None,
            extensions: vec![],
            key_usage,
        };
        let leaf = certificate(
            profile,
            3,
            &key(3),
            &key(2),
            *leaf.tbs_certificate().validity(),
        );
        assert_eq!(
            verifier.verify_certificate_chain([&leaf, &issuer], &crls, now()),
            expected
        );
    }
}

#[test]
fn ignores_unrelated_future_crls_but_rejects_relevant_ones() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let leaf = issued("CN=Leaf", "CN=Root", &key(2), &key(1), 2, false, None);
    let other = issued("CN=Other", "CN=Other", &key(3), &key(3), 3, true, Some(0));
    let crl = issued_crl(&root, &key(1), None);
    let mut unrelated = issued_crl(&other, &key(3), None);
    unrelated.tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    resign_crl(&mut unrelated, &key(3));
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    // The root is intentionally omitted from the supplied chain.
    verifier
        .verify_certificate_chain([&leaf], [&unrelated, &crl], now())
        .unwrap();
    verifier
        .verify_certificate_chain([&leaf], [&crl, &unrelated], now())
        .unwrap();
    let mut future = crl;
    future.tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    resign_crl(&mut future, &key(1));
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&unrelated, &future], now()),
        Err(Error::CrlNotYetValid)
    );
}

#[test]
fn maps_leaf_validity_errors_with_valid_anchor_and_crl() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let crl = issued_crl(&root, &key(1), None);
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    for (not_before, not_after, expected) in [
        (
            "2023-08-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            Error::CertificateNotYetValid,
        ),
        (
            "2023-01-01T00:00:00Z",
            "2023-07-01T00:00:00Z",
            Error::CertificateExpired,
        ),
    ] {
        let profile = TestProfile {
            issuer: "CN=Root".parse().unwrap(),
            subject: "CN=Leaf".parse().unwrap(),
            is_ca: Some(false),
            path_len_constraint: None,
            extensions: vec![],
            key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
        };
        let leaf = certificate(
            profile,
            2,
            &key(2),
            &key(1),
            Validity::new(date(not_before).into(), date(not_after).into()),
        );
        assert_eq!(
            verifier.verify_certificate_chain([&leaf], [&crl], now()),
            Err(expected)
        );
    }
}

#[test]
fn pinned_root_requires_ca_basic_constraints() {
    for is_ca in [None, Some(false), Some(true)] {
        let profile = TestProfile {
            issuer: "CN=Root".parse().unwrap(),
            subject: "CN=Root".parse().unwrap(),
            is_ca,
            path_len_constraint: None,
            extensions: vec![],
            key_usage: Some(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
        };
        let root = certificate(
            profile,
            1,
            &key(1),
            &key(1),
            Validity::new(
                date("2020-01-01T00:00:00Z").into(),
                date("2030-01-01T00:00:00Z").into(),
            ),
        );
        let pem = root.to_pem(der::pem::LineEnding::LF).unwrap();
        Certificate::from_pem(&pem).unwrap();
        let result = WebPkiCertificateChainVerifier::from_pem(&pem);
        if is_ca == Some(true) {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::GeneralCertificateError)));
        }
    }
}

#[test]
fn crl_fixture_preserves_number_and_identifies_its_signer() {
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let crl = issued_crl(&issuer, &key(2), None);
    let extensions = crl.tbs_cert_list.crl_extensions.as_ref().unwrap();
    let number_extension = extensions
        .iter()
        .find(|extension| extension.extn_id == "2.5.29.20".parse().unwrap())
        .unwrap();
    let number = CrlNumber::from_der(number_extension.extn_value.as_bytes()).unwrap();
    assert_eq!(number, CrlNumber::try_from(1u8).unwrap());
    let aki_extension = extensions
        .iter()
        .find(|extension| extension.extn_id == "2.5.29.35".parse().unwrap())
        .unwrap();
    let aki = AuthorityKeyIdentifier::from_der(aki_extension.extn_value.as_bytes()).unwrap();
    let ski = issuer
        .tbs_certificate()
        .get_extension::<SubjectKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    let parent_key = issuer
        .tbs_certificate()
        .get_extension::<AuthorityKeyIdentifier>()
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(aki.key_identifier, Some(ski.0));
    assert_ne!(aki.key_identifier, parent_key.key_identifier);
}

#[test]
fn eku_must_be_absent_or_include_any_extended_key_usage() {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false, None);
    let crls = [
        issued_crl(&root, &key(1), None),
        issued_crl(&issuer, &key(2), None),
    ];
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    // These OIDs are anyExtendedKeyUsage, serverAuth, and codeSigning.
    for (purposes, allowed) in [
        (None, true),
        (Some(vec!["2.5.29.37.0"]), true),
        (Some(vec!["1.3.6.1.5.5.7.3.1", "2.5.29.37.0"]), true),
        (Some(vec!["1.3.6.1.5.5.7.3.1"]), false),
        (Some(vec!["1.3.6.1.5.5.7.3.3"]), false),
        (Some(vec![]), false),
    ] {
        for is_ca in [false, true] {
            let (subject, parent, subject_key, parent_key, serial) = if is_ca {
                ("CN=Issuer", "CN=Root", key(2), key(1), 2)
            } else {
                ("CN=Leaf", "CN=Issuer", key(3), key(2), 3)
            };
            let subject: Name = subject.parse().unwrap();
            let extensions = purposes
                .as_ref()
                .map(|purposes| {
                    vec![ExtendedKeyUsage(
                        purposes.iter().map(|oid| oid.parse().unwrap()).collect(),
                    )
                    .to_extension(&subject, &[])
                    .unwrap()]
                })
                .unwrap_or_default();
            let profile = TestProfile {
                subject,
                issuer: parent.parse().unwrap(),
                is_ca: Some(is_ca),
                path_len_constraint: is_ca.then_some(0),
                extensions,
                key_usage: Some(KeyUsage(if is_ca {
                    KeyUsages::KeyCertSign | KeyUsages::CRLSign
                } else {
                    KeyUsages::DigitalSignature.into()
                })),
            };
            let cert = certificate(
                profile,
                serial,
                &subject_key,
                &parent_key,
                *leaf.tbs_certificate().validity(),
            );
            let chain = if is_ca {
                [&leaf, &cert]
            } else {
                [&cert, &issuer]
            };
            let result = verifier.verify_certificate_chain(chain, &crls, now());
            assert_eq!(
                result,
                if allowed {
                    Ok(())
                } else {
                    Err(Error::GeneralCertificateError)
                }
            );
        }
    }
}

#[test]
fn malformed_eku_after_any_usage_is_rejected() {
    use x509_cert::ext::Extension;
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(0));
    let crl = issued_crl(&root, &key(1), None);
    let profile = TestProfile {
        subject: "CN=Leaf".parse().unwrap(),
        issuer: "CN=Root".parse().unwrap(),
        is_ca: Some(false),
        path_len_constraint: None,
        key_usage: Some(KeyUsage(KeyUsages::DigitalSignature.into())),
        extensions: vec![Extension {
            extn_id: "2.5.29.37".parse().unwrap(),
            critical: false,
            // SEQUENCE { anyExtendedKeyUsage OID, NULL }: parse the whole EKU.
            extn_value: der::asn1::OctetString::new([0x30, 8, 6, 4, 0x55, 0x1d, 0x25, 0, 5, 0])
                .unwrap(),
        }],
    };
    let leaf = certificate(
        profile,
        2,
        &key(2),
        &key(1),
        Validity::new(
            date("2023-01-01T00:00:00Z").into(),
            date("2024-01-01T00:00:00Z").into(),
        ),
    );
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&crl], now()),
        Err(Error::GeneralCertificateError)
    );
}

#[test]
fn crl_authentication_precedes_this_update_check() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Root", &key(2), &key(1), 2, false, None);
    let mut crl = issued_crl(&root, &key(1), None);
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    crl.tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&crl], now()),
        Err(Error::SignatureVerification)
    );
    resign_crl(&mut crl, &key(1));
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&crl], now()),
        Err(Error::CrlNotYetValid)
    );
}

#[test]
fn validated_path_ignores_unused_certificates_and_crls() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false, None);
    let unused_profile = TestProfile {
        subject: "CN=UnusedCA".parse().unwrap(),
        issuer: "CN=Root".parse().unwrap(),
        is_ca: Some(true),
        path_len_constraint: Some(0),
        extensions: vec![],
        key_usage: None,
    };
    let unused_ca = certificate(
        unused_profile,
        4,
        &key(4),
        &key(1),
        *issuer.tbs_certificate().validity(),
    );
    let unused_leaf = issued(
        "CN=UnusedLeaf",
        "CN=UnusedCA",
        &key(5),
        &key(4),
        5,
        false,
        None,
    );
    let mut unused_crl = issued_crl(&unused_ca, &key(4), None);
    unused_crl.tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    resign_crl(&mut unused_crl, &key(4));
    let crls = [
        issued_crl(&root, &key(1), None),
        issued_crl(&issuer, &key(2), None),
        unused_crl.clone(),
        unused_crl,
    ];
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    // The unused leaf makes the duplicate CRLs relevant to the pool, but not
    // the selected path. Neither their ambiguity nor future time should fail it.
    for pool in [
        [&leaf, &unused_leaf, &unused_ca, &root, &issuer],
        [&leaf, &root, &issuer, &unused_ca, &unused_leaf],
    ] {
        verifier
            .verify_certificate_chain(pool, &crls, now())
            .unwrap();
    }
    // The same duplicates are also ignored when their issuer is not in the pool.
    verifier
        .verify_certificate_chain([&leaf, &issuer], &crls, now())
        .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain([&issuer, &leaf], &crls, now()),
        Err(Error::GeneralCertificateError)
    );
}

#[test]
fn tries_another_issuer_path_after_key_usage_rejection() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(1));
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false, None);
    let missing_usage = certificate(
        TestProfile {
            subject: "CN=Issuer".parse().unwrap(),
            issuer: "CN=Root".parse().unwrap(),
            is_ca: Some(true),
            path_len_constraint: Some(0),
            extensions: vec![],
            key_usage: None,
        },
        4,
        &key(2),
        &key(1),
        *issuer.tbs_certificate().validity(),
    );
    let crls = [
        issued_crl(&root, &key(1), None),
        issued_crl(&issuer, &key(2), None),
    ];
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain([&leaf, &missing_usage], &crls, now()),
        Err(Error::GeneralCertificateError)
    );
    verifier
        .verify_certificate_chain([&leaf, &missing_usage, &issuer], &crls, now())
        .unwrap();
}

#[test]
fn path_and_revocation_errors_precede_duplicate_crl_rejection() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true, Some(0));
    let leaf = issued("CN=Leaf", "CN=Root", &key(2), &key(1), 2, false, None);
    let fresh = issued_crl(&root, &key(1), None);
    let mut stale = fresh.clone();
    stale.tbs_cert_list.next_update = Some(date("2023-01-02T00:00:00Z").into());
    resign_crl(&mut stale, &key(1));
    let revoked = issued_crl(&root, &key(1), Some(2));
    let forged = issued_crl(&root, &key(3), None);
    let verifier =
        WebPkiCertificateChainVerifier::from_pem(&root.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    verifier
        .verify_certificate_chain([&leaf], [&fresh], now())
        .unwrap();
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&fresh, &fresh], date("2022-01-01T00:00:00Z")),
        Err(Error::CertificateNotYetValid)
    );
    assert_eq!(
        verifier.verify_certificate_chain([&leaf], [&stale], now()),
        Err(Error::CrlExpired)
    );
    // WebPKI authenticates/checks its first matching CRL before the backend
    // rejects duplicates for an otherwise valid path. Invalid duplicates never
    // turn a more specific WebPKI error into the generic ambiguity error.
    for (crls, expected) in [
        ([&stale, &fresh], Error::CrlExpired),
        ([&fresh, &stale], Error::GeneralCertificateError),
        ([&fresh, &fresh], Error::GeneralCertificateError),
        ([&revoked, &forged], Error::CertificateRevoked),
        ([&forged, &revoked], Error::SignatureVerification),
        ([&fresh, &forged], Error::GeneralCertificateError),
    ] {
        assert_eq!(
            verifier.verify_certificate_chain([&leaf], crls, now()),
            Err(expected)
        );
    }
}
