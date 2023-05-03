// Copyright (c) 2023 The MobileCoin Foundation

//! An implementation of https://www.rfc-editor.org/rfc/rfc4518 string preparation.
//!
//! A good document on normal forms, https://unicode.org/reports/tr15/#Norm_Forms
extern crate alloc;

use alloc::string::String;
use unicode_normalization::UnicodeNormalization;

/// An RFC4518 prepared String
#[derive(Debug, PartialEq)]
pub struct Rfc4518String {
    inner: String,
}

impl From<&str> for Rfc4518String {
    fn from(string: &str) -> Self {
        let normalized = string
            .chars()
            .filter_map(rfc_4518_filter_map)
            .nfkc()
            .collect::<String>();
        let inner = space_compression(&normalized);
        Self { inner }
    }
}

impl<'a> From<&'a Rfc4518String> for &'a str {
    fn from(value: &'a Rfc4518String) -> &'a str {
        &value.inner
    }
}

/// Perform step 2 of the string preparation,
/// https://www.rfc-editor.org/rfc/rfc4518#section-2.2
///
/// Note RFC4518 calls this step map, but it also _filters_ out certain
/// characters, thus the name deviation.
fn rfc_4518_filter_map(c: char) -> Option<char> {
    // per https://doc.rust-lang.org/std/primitive.char.html#method.is_whitespace
    // uses to the same values in
    // https://www.rfc-editor.org/rfc/rfc4518#section-2.2 that map to space.
    if c.is_whitespace() {
        Some(' ')
    } else {
        rfc_4518_filter(c)
    }
}

/// Filter out characters from
/// https://www.rfc-editor.org/rfc/rfc4518#section-2.2 that map to nothing.
///
/// Note it says:
///
///   VARIATION SELECTORs (U+180B-180D, FF00-FE0F)
///
/// However that should be `FE00-FE0F` as per
/// https://www.rfc-editor.org/rfc/rfc3454#appendix-B.1
///
fn rfc_4518_filter(c: char) -> Option<char> {
    match c {
        '\u{0000}'..='\u{0008}'
        | '\u{000E}'..='\u{001F}'
        | '\u{007F}'..='\u{0084}'
        | '\u{0086}'..='\u{009F}'
        | '\u{00AD}'
        | '\u{034F}'
        | '\u{06DD}'
        | '\u{070F}'
        | '\u{1806}'
        | '\u{180B}'..='\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2063}'
        | '\u{206A}'..='\u{206F}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFC}'
        | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}'
        | '\u{E0020}'..='\u{E0074}' => None,
        c => Some(c),
    }
}

/// Compress spaces as defined in https://www.rfc-editor.org/rfc/rfc4518#section-2.6.1
///
/// The resultant string will have:
/// - One leading space
/// - One trailing space.
/// - Any consecutive intermediate spaces will be converted to two spaces. i.e.
///   4 consecutive spaces will be 2, but also 1 lone space will be converted
///   to 2 spaces.
fn space_compression(s: &str) -> String {
    // Strings are either empty => <space><space>
    // or they have a leading space so always start with a space
    let mut result = String::from(" ");

    let mut last_char = ' ';

    for c in s.trim_end().chars() {
        if c == ' ' {
            if last_char == ' ' {
                continue;
            } else {
                // An extra space for the two spaces specified in
                // https://www.rfc-editor.org/rfc/rfc4518#section-2.6.1
                result.push(' ');
            }
        }
        result.push(c);
        last_char = c;
    }

    // Strings are either empty => <space><space>
    // or they have a trailing space so always end with a space
    result.push(' ');
    result
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
        empty = {"", "  "},
        mulitple_spaces = {"      ", "  "},
        leading_and_trailing_space = {"Hello", " Hello "},
        intermediate_space = {"Hello world", " Hello  world "},
        foo_space_bar_space_space = {"foo bar  ", " foo  bar "},
        so_many_spaces = {"       What     it      is?      ", " What  it  is? "},
    )]
    fn insignificant_space_handling(input: &str, expected: &str) {
        let result = space_compression(input);
        assert_eq!(&result, expected);
    }

    #[parameterized(
        empty = {"", "  "},
        ignored_control_character_0000 = {"Hello \u{0000}world", " Hello  world "},
        ignored_control_character_0704 = {"Hello\u{070F}world", " Helloworld "},
        whitespace_is_the_same_as_space = {"\n\t\n\tHello\nworld\n\t\n\t\n", " Hello  world "},
        normalizing_nfkc_fi = {"ﬁ", " fi "}, // U+FB01, U+0066 U+0069
        normalizing_nfkc_25 = {"2⁵", " 25 "}, // U+0032 U+2075, U+0032 U+0035
        normalizing_nfkc_tel = {"℡", " TEL "}, // U+2121, U+0054 U+0045 U+004C
    )]
    fn to_rfc4518_string(input: &str, expected: &str) {
        let result = Rfc4518String::from(input);
        assert_eq!(&result.inner, expected);
    }
}
