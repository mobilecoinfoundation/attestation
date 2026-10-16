// Copyright (c) 2026 The MobileCoin Foundation

use alloc::vec::Vec;
use x509_cert::{
    builder::profile::BuilderProfile,
    certificate::TbsCertificate,
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        Extension, ToExtension,
    },
    name::Name,
    spki::SubjectPublicKeyInfoRef,
};
#[derive(Debug)]
pub struct TestProfile {
    pub issuer: Name,
    pub subject: Name,
    /// None omits BasicConstraints entirely.
    pub is_ca: Option<bool>,
    pub path_len_constraint: Option<u8>,
    pub extensions: Vec<Extension>,
    pub key_usage: Option<KeyUsage>,
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
        if let Some(is_ca) = self.is_ca {
            let basic = BasicConstraints {
                ca: is_ca,
                path_len_constraint: self.path_len_constraint,
            };
            extensions.push(basic.to_extension(&self.subject, &extensions)?);
        }
        if let Some(usage) = &self.key_usage {
            extensions.push(usage.to_extension(&self.subject, &extensions)?);
        }
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
