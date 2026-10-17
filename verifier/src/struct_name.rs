// Copyright (c) 2023-2025 The MobileCoin Foundation

//! Provides a trait that provides a textual friendly version of a struct name.
//! The names are all lowercase and use spaces between the words.

use mc_sgx_core_types::{
    Attributes, ConfigId, ConfigSvn, CpuSvn, ExtendedProductId, FamilyId, IsvProductId, IsvSvn,
    MiscellaneousSelect, MrEnclave, MrSigner, ReportData,
};

macro_rules! spaced_struct_name {
    ($($item:ident, $name:literal;)*) => {$(
        impl SpacedStructName for $item {
            fn spaced_struct_name() -> &'static str {
                $name
            }
        }
    )*}
}

/// A textual name of a struct to be used in explanatory text.
///
/// Instead of the common pascal case names used in rust, a lowercase space
/// separated name is used. Words or acronyms that are capitalized will still be
/// capitalized.
pub trait SpacedStructName {
    fn spaced_struct_name() -> &'static str;
}

spaced_struct_name! {
    Attributes, "attributes";
    CpuSvn, "CPU SVN";
    MiscellaneousSelect, "miscellaneous select";
    ExtendedProductId, "extended product ID";
    MrEnclave, "MRENCLAVE";
    MrSigner, "MRSIGNER key hash";
    ConfigId, "config ID";
    IsvProductId, "ISV product ID";
    IsvSvn, "ISV SVN";
    ConfigSvn, "config SVN";
    FamilyId, "family ID";
    ReportData, "report data";
    u8, "Unsigned byte";

}
