// Copyright (c) 2023 The MobileCoin Foundation

//! X509 distinguished name as defined in sections
//! [4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4) and
//! [4.1.2.6](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6) of
//! [RFC5280](https://datatracker.ietf.org/doc/html/rfc5280)
//!
//! Issuer and subject structure from
//! [4.1.2.4](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4):
//!
//! ```ignore
//!     Name ::= RDNSequence
//!     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//!     RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
//!     AttributeTypeAndValue ::= SEQUENCE {
//!         AttributeType,
//!         AttributeValue
//!     }
//!     AttributeType ::= OBJECT IDENTIFIER
//!     AttributeValue ::= DirectoryString
//!
//!     DirectoryString ::= CHOICE {
//!         TeletexString (Unsupported in this implementation).
//!         PrintableString
//!         UniversalString (Unsupported in this implementation)
//!         UTF8String
//!         BMPString (Unsupported in this implementation)
//!         IA5String (See note below)
//!     }
//! ```
//!
//! Note: IA5String is is not called out in the BNF explanation of
//!   [4.1.2.4](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4), but if
//!   one reads X they will see:
//!
//! > In addition, implementations of this specification MUST be prepared
//! > to receive the domainComponent attribute, as defined in
//! > [RFC4519](https://www.rfc-editor.org/rfc/rfc4519).
//!
//! [RFC4519](https://www.rfc-editor.org/rfc/rfc4519) says says that `Ia5String`
//! will be used for the domain component.
//!
//! The [`DistinguishedName`] corresponds to the `Name` in the above hierarchy.
//! RFC5280 calls this distinguished name when used as the issuer or subject of
//! a certificate.
//!
//! The [`DirectoryString`] corresponds to the `DirectoryString` in the above
//! hierarchy.

use super::rfc4518::Rfc4518String;
use x509_cert::attr::AttributeValue;
use x509_cert::der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};
use x509_cert::der::ErrorKind::TagUnknown;
use x509_cert::der::{Length, Tag, Tagged};
use x509_cert::name::Name;

#[derive(Debug)]
pub struct DistinguishedName<'a>(&'a Name);

impl<'a> From<&'a Name> for DistinguishedName<'a> {
    fn from(name: &'a Name) -> Self {
        Self(name)
    }
}

/// Does `DistinguishedName` comparison as defined in
/// https://tools.ietf.org/html/rfc5280#section-7.1
impl<'a> PartialEq for DistinguishedName<'a> {
    fn eq(&self, other: &Self) -> bool {
        let name_1 = self.0;
        let name_2 = other.0;

        if name_1.0.len() != name_2.0.len() {
            return false;
        }
        for (rdn_1, rdn_2) in name_1.0.iter().zip(name_2.0.iter()) {
            if rdn_1.0.len() != rdn_2.0.len() {
                return false;
            }
            for (attr_1, attr_2) in rdn_1.0.iter().zip(rdn_2.0.iter()) {
                if attr_1.oid != attr_2.oid {
                    return false;
                }

                let value_1 = match DirectoryString::try_from(&attr_1.value) {
                    Ok(value) => value,
                    Err(_) => return false,
                };
                let value_2 = match DirectoryString::try_from(&attr_2.value) {
                    Ok(value) => value,
                    Err(_) => return false,
                };

                if value_1 != value_2 {
                    return false;
                }
            }
        }
        true
    }
}

#[derive(Debug)]
enum DirectoryString<'a> {
    Printable(PrintableStringRef<'a>),
    Utf8(Utf8StringRef<'a>),
    Ia5(Ia5StringRef<'a>),
}

/// Compares a `DirectoryString` as defined in
/// https://tools.ietf.org/html/rfc5280#section-7.1
impl<'a> PartialEq for DirectoryString<'a> {
    fn eq(&self, other: &Self) -> bool {
        let string_1 = Rfc4518String::from(self);
        let string_2 = Rfc4518String::from(other);

        let fold_1 = caseless::default_case_fold_str((&string_1).into());
        let fold_2 = caseless::default_case_fold_str((&string_2).into());

        fold_1 == fold_2
    }
}

impl<'a> TryFrom<&'a AttributeValue> for DirectoryString<'a> {
    type Error = x509_cert::der::Error;

    fn try_from(value: &'a AttributeValue) -> Result<Self, Self::Error> {
        match value.tag() {
            Tag::PrintableString => Ok(DirectoryString::Printable(PrintableStringRef::try_from(
                value,
            )?)),
            Tag::Utf8String => Ok(DirectoryString::Utf8(Utf8StringRef::try_from(value)?)),
            Tag::Ia5String => Ok(DirectoryString::Ia5(Ia5StringRef::try_from(value)?)),
            tag => Err(Self::Error::new(
                TagUnknown { byte: tag.octet() },
                Length::from(0u8),
            )),
        }
    }
}

impl<'a> From<&DirectoryString<'a>> for &'a str {
    fn from(value: &DirectoryString<'a>) -> &'a str {
        match value {
            DirectoryString::Printable(s) => s.as_str(),
            DirectoryString::Utf8(s) => s.as_str(),
            DirectoryString::Ia5(s) => s.as_str(),
        }
    }
}

impl<'a> From<&DirectoryString<'a>> for Rfc4518String {
    fn from(value: &DirectoryString<'a>) -> Rfc4518String {
        let string: &str = value.into();
        Rfc4518String::from(string)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use const_oid::db::rfc4519::ORGANIZATION_NAME;
    use core::str::FromStr;
    use rsa::pkcs8::der::asn1::SetOfVec;
    use x509_cert::attr::AttributeTypeAndValue;
    use x509_cert::der::asn1::TeletexStringRef;
    use x509_cert::name::RelativeDistinguishedName;
    use yare::parameterized;

    #[parameterized(
        same_1 = {"Hello", "Hello"},
        same_2 = {"World", "World"},
        case_ignore_first = {"Title", "title"},
        case_ignore_all = {"ALL UPPER", "all upper"},
        space_compression = {"Hello World", "Hello  World"},
    )]
    fn compare_printable_strings(str_1: &str, str_2: &str) {
        let string_1 = PrintableStringRef::new(str_1).expect("Failed to create PrintableStringRef");
        let value_1 = AttributeValue::from(string_1);
        let directory_string_1 =
            DirectoryString::try_from(&value_1).expect("Failed to convert to directory string");

        let string_2 = PrintableStringRef::new(str_2).expect("Failed to create PrintableStringRef");
        let value_2 = AttributeValue::from(string_2);
        let directory_string_2 =
            DirectoryString::try_from(&value_2).expect("Failed to convert to directory string");

        assert_eq!(directory_string_1, directory_string_2);
    }

    // Code points for case folding taken from
    // https://unicode.org/Public/UNIDATA/CaseFolding.txt
    // A good reference for seeing the characters is
    // https://www.compart.com/en/unicode/U+03A1
    // Change the `U+03A1` as appropriate in the url
    #[parameterized(
        same = {"Sure", "Sure"},
        case_fold_micro = {"Μ","µ"}, // U+039C, U+00B5
        case_fold_rho = {"Ρ", "ρ"}, // U+03A1, U+03C1
        case_fold_adlam_sha = {"\u{1E921}", "\u{1E943}"}, // not visible in most IDEs
    )]
    fn compare_utf8_strings(str_1: &str, str_2: &str) {
        let string_1 = Utf8StringRef::new(str_1).expect("Failed to create Utf8StringRef");
        let value_1 = AttributeValue::from(string_1);
        let directory_string_1 =
            DirectoryString::try_from(&value_1).expect("Failed to convert to directory string");

        let string_2 = Utf8StringRef::new(str_2).expect("Failed to create Utf8StringRef");
        let value_2 = AttributeValue::from(string_2);
        let directory_string_2 =
            DirectoryString::try_from(&value_2).expect("Failed to convert to directory string");

        assert_eq!(directory_string_1, directory_string_2);
    }

    #[parameterized(
        same = {"string with @", "string with @"},
        case_fold = {"Capitalized Ampersand &", "capitalized ampersand &"},
        space_compression = {"A          big        distance   from     @", "A big distance from @"},
    )]
    fn compare_ia5_strings(str_1: &str, str_2: &str) {
        let string_1 = Ia5StringRef::new(str_1).expect("Failed to create Ia5StringRef");
        let value_1 = AttributeValue::from(string_1);
        let directory_string_1 =
            DirectoryString::try_from(&value_1).expect("Failed to convert to directory string");

        let string_2 = Ia5StringRef::new(str_2).expect("Failed to create Ia5StringRef");
        let value_2 = AttributeValue::from(string_2);
        let directory_string_2 =
            DirectoryString::try_from(&value_2).expect("Failed to convert to directory string");

        assert_eq!(directory_string_1, directory_string_2);
    }

    #[test]
    fn unsupported_directory_string_type() {
        let teletex_string =
            TeletexStringRef::new("Hello").expect("Failed to create TeletexStringRef");
        let attribute_value = AttributeValue::from(teletex_string);
        let byte = Tag::TeletexString.octet();
        assert_eq!(
            DirectoryString::try_from(&attribute_value),
            Err(x509_cert::der::Error::new(
                TagUnknown { byte },
                Length::from(0u8)
            ))
        );
    }

    #[parameterized(
    name_1 = {"C=US,O=Test Certificates 2011,CN=Trust Anchor"},
    name_2 = {"C=US,O=Test Certificates 2011,CN=Good CA"},
    name_3 = {"C=US,O=Test Certificates 2011,CN=Valid EE Certificate Test1"},
    multiple_first_rdns = {"C=US+C=CA+C=UK,O=Test Certificates 2011,CN=Trust Anchor"},
    multiple_middle_rdns = {"C=US,O=Test Certificates 2011+O=More Stuff,CN=Trust Anchor"},
    multiple_last_rdns = {"C=US,O=Test Certificates 2011,CN=Trust Anchor+CN=You Know It"},
    )]
    fn matched_distinguished_names(name: &str) {
        let name_1 = Name::from_str(name).expect("Failed to parse name");
        let name_2 = name_1.clone();
        assert_eq!(
            DistinguishedName::from(&name_1),
            DistinguishedName::from(&name_2)
        );
    }

    #[parameterized(
    first = {"C=US,O=Test Certificates 2011,CN=Trust Anchor", "C=IS,O=Test Certificates 2011,CN=Trust Anchor"},
    middle = {"C=US,O=Test Certificates 2011,CN=Good CA", "C=US,O=Test Certificate 2011,CN=Good CA"},
    last = {"C=US,O=Test Certificates 2011,CN=Valid EE Certificate Test1", "C=US,O=Test Certificates 2011,CN=Invalid EE Certificate Test1"},
    different_lengths = {"C=US,O=Test Certificates 2011", "C=US,O=Test Certificates 2011,CN=Valid EE Certificate Test1"},
    different_rdn_lengths = {"C=US+C=CA+C=UK", "C=US+C=CA"},
    different_oids = {"C=US", "CN=US"},
    )]
    fn mismatched_distinguished_names(name_1: &str, name_2: &str) {
        let name_1 = Name::from_str(name_1).expect("Failed to parse name");
        let name_2 = Name::from_str(name_2).expect("Failed to parse name");
        assert_ne!(
            DistinguishedName::from(&name_1),
            DistinguishedName::from(&name_2)
        );
    }

    #[test]
    fn distinguished_name_build_up() {
        // This test builds up a `DistinguishedName` type manually and compares
        // to show that subsequent test cases fail due to unsupported string
        // types and not a failure to build up the `DistinguishedName`.
        let common_message = "Hello";
        let oid = ORGANIZATION_NAME;

        let string_1 =
            PrintableStringRef::new(common_message).expect("Failed to create PrintableStringRef");
        let attribute_type_value_1 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_1),
        };
        let rdn_1 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_1])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_1 = Name::from(vec![rdn_1]);

        let string_2 =
            PrintableStringRef::new(common_message).expect("Failed to create PrintableStringRef");
        let attribute_type_value_2 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_2),
        };
        let rdn_2 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_2])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_2 = Name::from(vec![rdn_2]);
        assert_eq!(
            DistinguishedName::from(&name_1),
            DistinguishedName::from(&name_2)
        );
    }

    #[test]
    fn teletxstring_as_first_distinguished_name_fails() {
        let common_message = "Hello";
        let oid = ORGANIZATION_NAME;

        let string_1 =
            TeletexStringRef::new(common_message).expect("Failed to create TeletexStringRef");
        let attribute_type_value_1 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_1),
        };
        let rdn_1 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_1])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_1 = Name::from(vec![rdn_1]);

        let string_2 =
            PrintableStringRef::new(common_message).expect("Failed to create PrintableStringRef");
        let attribute_type_value_2 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_2),
        };
        let rdn_2 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_2])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_2 = Name::from(vec![rdn_2]);
        assert_ne!(
            DistinguishedName::from(&name_1),
            DistinguishedName::from(&name_2)
        );
    }

    #[test]
    fn teletxstring_as_second_distinguished_name_fails() {
        let common_message = "Hello";
        let oid = ORGANIZATION_NAME;

        let string_1 =
            PrintableStringRef::new(common_message).expect("Failed to create PrintableStringRef");
        let attribute_type_value_1 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_1),
        };
        let rdn_1 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_1])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_1 = Name::from(vec![rdn_1]);

        let string_2 =
            TeletexStringRef::new(common_message).expect("Failed to create TeletexStringRef");
        let attribute_type_value_2 = AttributeTypeAndValue {
            oid,
            value: AttributeValue::from(string_2),
        };
        let rdn_2 = RelativeDistinguishedName::from(
            SetOfVec::try_from([attribute_type_value_2])
                .expect("Failed to build `RelativeDistinguishedName`"),
        );
        let name_2 = Name::from(vec![rdn_2]);
        assert_ne!(
            DistinguishedName::from(&name_1),
            DistinguishedName::from(&name_2)
        );
    }
}
