// Copyright (c) 2026 The MobileCoin Foundation

use alloc::vec::Vec;
use x509_cert::{
    builder::profile::BuilderProfile,
    certificate::TbsCertificate,
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        Extension, ToExtension,
    },
    name::Name,
    spki::SubjectPublicKeyInfoRef,
};
#[derive(Debug)]
pub struct TestProfile {
    pub issuer: Name,
    pub subject: Name,
    pub is_ca: bool,
    pub extensions: Vec<Extension>,
}

impl BuilderProfile for TestProfile {
    fn get_issuer(&self, _: &Name) -> Name {
        self.issuer.clone()
    }
    fn get_subject(&self) -> Name {
        self.subject.clone()
    }
    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let mut extensions = self.extensions.clone();
        let basic = BasicConstraints {
            ca: self.is_ca,
            path_len_constraint: if self.is_ca { Some(0) } else { None },
        };
        extensions.push(basic.to_extension(&self.subject, &extensions)?);
        let usage = if self.is_ca {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        } else {
            KeyUsages::DigitalSignature | KeyUsages::NonRepudiation
        };
        extensions.push(KeyUsage(usage).to_extension(&self.subject, &extensions)?);
        extensions
            .push(SubjectKeyIdentifier::try_from(spk)?.to_extension(&self.subject, &extensions)?);
        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(SubjectKeyIdentifier::try_from(issuer_spk)?.0),
            ..Default::default()
        };
        extensions.push(aki.to_extension(&self.subject, &extensions)?);
        Ok(extensions)
    }
}
