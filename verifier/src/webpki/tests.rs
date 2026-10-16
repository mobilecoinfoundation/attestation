// Copyright (c) 2026 The MobileCoin Foundation

extern crate std;

use super::*;
use alloc::vec;
use der::{Decode, EncodePem};
use p256::ecdsa::{signature::Signer, SigningKey};
use x509_cert::{
    builder::{Builder, CertificateBuilder, CrlBuilder},
    crl::RevokedCert,
    ext::{
        pkix::{AuthorityKeyIdentifier, CrlNumber, SubjectKeyIdentifier},
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
    assert!(verifier
        .verify_certificate_chain(&chain, &crls, now())
        .is_err());
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
    let public_key = |cert: &Certificate| {
        VerifyingKey::from_sec1_bytes(
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .as_bytes()
                .unwrap(),
        )
        .unwrap()
    };
    let tcb =
        SignedTcbInfo::try_from(include_str!("../../data/tests/current_tcb_info.json")).unwrap();
    assert!(bool::from(
        SignedTcbInfoVerifier::new(Some(public_key(&tcb_signer)), Some(time))
            .verify(&tcb)
            .is_success()
    ));
    let qe = SignedQeIdentity::try_from(include_str!("../../data/tests/current_qe_identity.json"))
        .unwrap();
    assert!(bool::from(
        SignedQeIdentityVerifier::new(Some(public_key(&qe_signer)), time)
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
) -> Certificate {
    let profile = TestProfile {
        subject: subject.parse::<Name>().unwrap(),
        issuer: issuer.parse().unwrap(),
        is_ca: ca,
        extensions: vec![],
    };
    CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        Validity::new(
            date("2023-01-01T00:00:00Z").into(),
            date("2024-01-01T00:00:00Z").into(),
        ),
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
    // CrlBuilder currently copies the issuer cert's AKI. A CRL instead identifies
    // the issuer's own signing key, i.e. the certificate's SKI.
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
    crl.tbs_cert_list.crl_extensions = Some(vec![aki
        .to_extension(&crl.tbs_cert_list.issuer, &[])
        .unwrap()]);
    let sig: p256::ecdsa::DerSignature = issuer_key.sign(&crl.tbs_cert_list.to_der().unwrap());
    crl.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    crl
}

#[test]
fn rejects_invalid_paths_revocation_and_times() {
    let root = issued("CN=Root", "CN=Root", &key(1), &key(1), 1, true);
    let issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, true);
    let leaf = issued("CN=Leaf", "CN=Issuer", &key(3), &key(2), 3, false);
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
    assert!(verifier
        .verify_certificate_chain(&chain, &crls, None)
        .is_err());
    assert!(verifier
        .verify_certificate_chain(&chain, &crls, date("2022-01-01T00:00:00Z"))
        .is_err());
    assert!(verifier
        .verify_certificate_chain(&chain, &crls, date("2025-01-01T00:00:00Z"))
        .is_err());
    assert!(verifier
        .verify_certificate_chain(&chain, &[] as &[CertificateList], now())
        .is_err());
    assert!(verifier
        .verify_certificate_chain(&chain, &crls[..1], now())
        .is_err());
    assert!(verifier
        .verify_certificate_chain([&leaf, &root], &crls, now())
        .is_err());
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
    let bad_issuer = issued("CN=Issuer", "CN=Root", &key(2), &key(1), 2, false);
    assert!(verifier
        .verify_certificate_chain([&leaf, &bad_issuer, &root], &crls, now())
        .is_err());
    let other = issued("CN=Other", "CN=Other", &key(4), &key(4), 4, true);
    let wrong_root =
        WebPkiCertificateChainVerifier::from_pem(&other.to_pem(der::pem::LineEnding::LF).unwrap())
            .unwrap();
    assert!(wrong_root
        .verify_certificate_chain(&chain, &crls, now())
        .is_err());
    let mut bad_crls = crls.clone();
    let mut sig = bad_crls[1].signature.as_bytes().unwrap().to_vec();
    *sig.last_mut().unwrap() ^= 1;
    bad_crls[1].signature = der::asn1::BitString::from_bytes(&sig).unwrap();
    assert!(verifier
        .verify_certificate_chain(&chain, &bad_crls, now())
        .is_err());
    let mut stale = crls.clone();
    stale[1].tbs_cert_list.next_update = Some(date("2023-01-02T00:00:00Z").into());
    let sig: p256::ecdsa::DerSignature = key(2).sign(&stale[1].tbs_cert_list.to_der().unwrap());
    stale[1].signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    assert!(verifier
        .verify_certificate_chain(&chain, &stale, now())
        .is_err());
    let mut corrupt = leaf.to_der().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    let corrupt = Certificate::from_der(&corrupt).unwrap();
    assert!(verifier
        .verify_certificate_chain([&corrupt, &issuer, &root], &crls, now())
        .is_err());

    // The issuer allows no subordinate CAs (pathLenConstraint=0).
    let sub_ca = issued("CN=SubCA", "CN=Issuer", &key(4), &key(2), 4, true);
    let sub_leaf = issued("CN=SubLeaf", "CN=SubCA", &key(5), &key(4), 5, false);
    let sub_crls = [
        crls[0].clone(),
        crls[1].clone(),
        issued_crl(&sub_ca, &key(4), None),
    ];
    assert!(verifier
        .verify_certificate_chain([&sub_leaf, &sub_ca, &issuer, &root], &sub_crls, now())
        .is_err());

    let mut future = crls.clone();
    future[1].tbs_cert_list.this_update = date("2023-08-01T00:00:00Z").into();
    let sig: p256::ecdsa::DerSignature = key(2).sign(&future[1].tbs_cert_list.to_der().unwrap());
    future[1].signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
    assert!(verifier
        .verify_certificate_chain(&chain, &future, now())
        .is_err());
    assert!(WebPkiCertificateChainVerifier::from_pem("garbage").is_err());
}
