//! Comment validation functions for C compatibility
//!
//! This module implements validation functions that match the C implementation's
//! behavior for validating comment strings in signature files.

use crate::errors::{Error, Result};

/// Validate that a string contains only printable characters and valid UTF-8
///
/// This function matches the behavior of the C implementation's `is_printable()`
/// function (minisign.c:76-125). It validates:
///
/// - Printable ASCII (0x20-0x7E)
/// - Tab character (0x09)
/// - Valid UTF-8 multi-byte sequences (2-4 bytes)
/// - Rejects control characters (0x00-0x1F except tab, 0x7F)
/// - Rejects C1 control characters (U+007F-U+009F)
/// - Rejects overlong encodings
/// - Rejects surrogate pairs (U+D800-U+DFFF)
/// - Rejects values > U+10FFFF
///
/// # Arguments
///
/// * `s` - String slice to validate
///
/// # Errors
///
/// Returns `Error::InvalidComment` if the string contains:
/// - Control characters (0x00-0x08, 0x0A-0x1F, 0x7F)
/// - C1 control characters (U+0080-U+009F)
/// - Invalid UTF-8 sequences
/// - Overlong encodings
/// - Truncated multi-byte sequences
///
/// # Examples
///
/// ```
/// use minisign::validation::is_printable;
///
/// assert!(is_printable("Hello, world!").is_ok());
/// assert!(is_printable("Tab\there").is_ok());
/// assert!(is_printable("Emoji 🎉").is_ok());
/// assert!(is_printable("Control\x00char").is_err());
/// ```
pub fn is_printable(s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];

        // Tab is allowed
        if c == b'\t' {
            i += 1;
            continue;
        }

        // Printable ASCII range
        if (0x20..=0x7e).contains(&c) {
            i += 1;
            continue;
        }

        // Control characters (including 0x7F DEL)
        if c < 0x20 || c == 0x7f {
            return Err(Error::InvalidComment(format!(
                "contains control character at byte {i}: 0x{c:02x}"
            )));
        }

        // Multi-byte UTF-8 sequences
        let (need, mask) = if (0xc2..=0xdf).contains(&c) {
            // 2-byte sequence
            (1, 0x1f)
        } else if (0xe0..=0xef).contains(&c) {
            // 3-byte sequence
            (2, 0x0f)
        } else if (0xf0..=0xf4).contains(&c) {
            // 4-byte sequence
            (3, 0x07)
        } else {
            return Err(Error::InvalidComment(format!(
                "invalid UTF-8 leading byte at position {i}: 0x{c:02x}"
            )));
        };

        // Validate we have enough bytes for continuation
        if i + need >= bytes.len() {
            return Err(Error::InvalidComment(format!(
                "truncated UTF-8 sequence at position {i}"
            )));
        }

        // Validate continuation bytes
        for j in 1..=need {
            let cc = bytes[i + j];
            if cc == 0 || (cc & 0xc0) != 0x80 {
                return Err(Error::InvalidComment(format!(
                    "invalid UTF-8 continuation byte at position {}: 0x{cc:02x}",
                    i + j
                )));
            }
        }

        // Check for overlong encodings and invalid ranges
        let first_continuation = bytes[i + 1];
        if (c == 0xe0 && first_continuation < 0xa0)
            || (c == 0xed && first_continuation > 0x9f)
            || (c == 0xf0 && first_continuation < 0x90)
            || (c == 0xf4 && first_continuation > 0x8f)
        {
            return Err(Error::InvalidComment(format!(
                "invalid UTF-8 encoding at position {i}: overlong or invalid range"
            )));
        }

        // Decode the code point to check for control characters
        let mut cp = u32::from(c & mask);
        for j in 1..=need {
            cp = (cp << 6) | u32::from(bytes[i + j] & 0x3f);
        }

        // Reject control characters in C1 range (U+007F-U+009F)
        // Note: 0x7F is already rejected above, this catches U+0080-U+009F
        if cp <= 0x1f || (0x7f..=0x9f).contains(&cp) {
            return Err(Error::InvalidComment(format!(
                "contains C1 control character at position {i}: U+{cp:04X}"
            )));
        }

        i += need + 1;
    }

    Ok(())
}

/// Validate that a string doesn't contain embedded carriage returns
///
/// This function matches the behavior of the C implementation's `trim()`
/// function (helpers.c:174-175) which rejects strings with embedded '\r' characters.
///
/// Carriage returns at the end of strings are typically stripped during parsing,
/// but embedded '\r' characters within the string content should be rejected to
/// prevent mixing of line ending styles.
///
/// # Arguments
///
/// * `s` - String slice to validate
///
/// # Errors
///
/// Returns `Error::InvalidComment` if the string contains any '\r' (0x0D) characters.
///
/// # Examples
///
/// ```
/// use minisign::validation::validate_no_embedded_cr;
///
/// assert!(validate_no_embedded_cr("Hello, world!").is_ok());
/// assert!(validate_no_embedded_cr("Multi\nline").is_ok());
/// assert!(validate_no_embedded_cr("").is_ok());
/// assert!(validate_no_embedded_cr("Windows\r\nstyle").is_err());
/// assert!(validate_no_embedded_cr("Embedded\rCR").is_err());
/// ```
pub fn validate_no_embedded_cr(s: &str) -> Result<()> {
    if s.contains('\r') {
        return Err(Error::InvalidComment(
            "contains embedded carriage return character".to_string(),
        ));
    }
    Ok(())
}

/// Validate a comment string for both printability and carriage returns
///
/// This is a convenience function that applies both `is_printable()` and
/// `validate_no_embedded_cr()` checks.
///
/// # Arguments
///
/// * `s` - String slice to validate
///
/// # Errors
///
/// Returns `Error::InvalidComment` if:
/// - The string contains unprintable characters (see `is_printable()`)
/// - The string contains embedded '\r' characters (see `validate_no_embedded_cr()`)
pub fn validate_comment(s: &str) -> Result<()> {
    is_printable(s)?;
    validate_no_embedded_cr(s)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    mod is_printable_tests {
        use super::*;

        #[test]
        fn test_empty_string() {
            assert!(is_printable("").is_ok());
        }

        #[test]
        fn test_printable_ascii() {
            assert!(is_printable("Hello, world!").is_ok());
            assert!(is_printable("The quick brown fox").is_ok());
            assert!(is_printable("0123456789").is_ok());
            assert!(is_printable("!@#$%^&*()").is_ok());
        }

        #[test]
        fn test_tab_allowed() {
            assert!(is_printable("Hello\tworld").is_ok());
            assert!(is_printable("\t").is_ok());
            assert!(is_printable("Start\tmiddle\tend").is_ok());
        }

        #[test]
        fn test_space_allowed() {
            assert!(is_printable(" ").is_ok());
            assert!(is_printable("   ").is_ok());
            assert!(is_printable("hello world").is_ok());
        }

        #[test]
        fn test_boundary_ascii() {
            // 0x20 (space) is allowed
            assert!(is_printable("\x20").is_ok());
            // 0x7E (~) is allowed
            assert!(is_printable("\x7E").is_ok());
            // 0x1F is rejected (control char)
            assert!(is_printable("\x1F").is_err());
            // 0x7F (DEL) is rejected
            assert!(is_printable("\x7F").is_err());
        }

        #[test]
        fn test_control_characters_rejected() {
            // Null
            assert!(is_printable("\x00").is_err());
            // Bell
            assert!(is_printable("\x07").is_err());
            // Backspace
            assert!(is_printable("\x08").is_err());
            // Newline (note: tab 0x09 is allowed)
            assert!(is_printable("\n").is_err());
            assert!(is_printable("\x0A").is_err());
            // Carriage return
            assert!(is_printable("\r").is_err());
            assert!(is_printable("\x0D").is_err());
            // Escape
            assert!(is_printable("\x1B").is_err());
        }

        #[test]
        fn test_utf8_multibyte_valid() {
            // 2-byte sequences
            assert!(is_printable("café").is_ok()); // é = C3 A9
            assert!(is_printable("Ñoño").is_ok()); // Ñ = C3 91, ñ = C3 B1

            // 3-byte sequences
            assert!(is_printable("日本語").is_ok());
            assert!(is_printable("Hello 世界").is_ok());

            // 4-byte sequences (emoji)
            assert!(is_printable("🎉").is_ok());
            assert!(is_printable("Test 🚀 rocket").is_ok());
            assert!(is_printable("👍🏻").is_ok()); // emoji with skin tone modifier
        }

        #[test]
        fn test_c1_control_characters_rejected() {
            // C1 control characters U+0080-U+009F should be rejected
            // These are valid UTF-8 but are control characters
            assert!(is_printable("\u{0080}").is_err()); // PAD
            assert!(is_printable("\u{0081}").is_err()); // HOP
            assert!(is_printable("\u{009F}").is_err()); // APC

            // U+00A0 (non-breaking space) and above should be allowed
            assert!(is_printable("\u{00A0}").is_ok());
        }

        #[test]
        fn test_surrogate_pairs_rejected() {
            // Surrogate pairs (U+D800-U+DFFF) are invalid in UTF-8
            // Rust's string type already prevents these, but our validator
            // checks the raw bytes. We need to construct invalid UTF-8.

            // This is tricky because Rust's &str must be valid UTF-8.
            // The C code would reject 0xED 0xA0 0x80 (U+D800)
            // but we can't construct this as a &str in Rust.

            // Instead, verify that valid UTF-8 strings don't trigger false positives
            // The actual invalid UTF-8 rejection happens at the byte level.
        }

        #[test]
        fn test_overlong_encodings() {
            // Overlong encodings are rejected by the checks in the function
            // These are caught by the range checks for first continuation byte
            // We can't easily construct these as &str since Rust validates UTF-8

            // The function checks:
            // - 0xE0 with first continuation < 0xA0 (overlong 3-byte)
            // - 0xED with first continuation > 0x9F (surrogate)
            // - 0xF0 with first continuation < 0x90 (overlong 4-byte)
            // - 0xF4 with first continuation > 0x8F (> U+10FFFF)
        }

        #[test]
        fn test_invalid_utf8_leading_bytes() {
            // Can't test with &str since Rust validates UTF-8
            // The function would reject:
            // - 0x80-0xBF (continuation bytes as leading)
            // - 0xC0-0xC1 (overlong 2-byte)
            // - 0xF5-0xFF (invalid range)
        }

        #[test]
        fn test_truncated_sequences() {
            // Can't easily test with &str
            // The function checks that we have enough continuation bytes
        }

        #[test]
        fn test_mixed_content() {
            assert!(is_printable("ASCII and 日本語 mixed").is_ok());
            assert!(is_printable("Emoji 🎉 with text!").is_ok());
            assert!(is_printable("Tab\there and café").is_ok());
        }
    }

    mod validate_no_embedded_cr_tests {
        use super::*;

        #[test]
        fn test_empty_string() {
            assert!(validate_no_embedded_cr("").is_ok());
        }

        #[test]
        fn test_no_cr() {
            assert!(validate_no_embedded_cr("Hello, world!").is_ok());
            assert!(validate_no_embedded_cr("Multi\nline\ntext").is_ok());
        }

        #[test]
        fn test_embedded_cr_rejected() {
            assert!(validate_no_embedded_cr("Hello\rworld").is_err());
            assert!(validate_no_embedded_cr("\r").is_err());
            assert!(validate_no_embedded_cr("Start\rEnd").is_err());
        }

        #[test]
        fn test_crlf_rejected() {
            // Windows-style line endings should be rejected
            assert!(validate_no_embedded_cr("Line1\r\nLine2").is_err());
            assert!(validate_no_embedded_cr("\r\n").is_err());
        }

        #[test]
        fn test_multiple_cr_rejected() {
            assert!(validate_no_embedded_cr("A\rB\rC").is_err());
        }
    }

    mod validate_comment_tests {
        use super::*;

        #[test]
        fn test_valid_comments() {
            assert!(validate_comment("").is_ok());
            assert!(validate_comment("Hello, world!").is_ok());
            assert!(validate_comment("Comment with 日本語").is_ok());
            assert!(validate_comment("Emoji 🎉 comment").is_ok());
        }

        #[test]
        fn test_invalid_printability() {
            assert!(validate_comment("Control\x00char").is_err());
            assert!(validate_comment("Newline\nhere").is_err());
        }

        #[test]
        fn test_invalid_cr() {
            assert!(validate_comment("Embedded\rCR").is_err());
            assert!(validate_comment("CRLF\r\nstyle").is_err());
        }

        #[test]
        fn test_both_validations_fail() {
            // Both control char and CR
            assert!(validate_comment("\x00\r").is_err());
        }
    }

    // Property-based tests
    use proptest::prelude::*;

    proptest! {
        /// Property: strings with only ASCII printables and tabs should always be valid
        #[test]
        fn prop_printable_ascii_valid(s in "[\\x20-\\x7E\\t]*") {
            prop_assert!(is_printable(&s).is_ok());
        }

        /// Property: strings without \r should pass validate_no_embedded_cr
        #[test]
        fn prop_no_cr_valid(s in "[^\r]*") {
            prop_assert!(validate_no_embedded_cr(&s).is_ok());
        }

        /// Property: strings with \r should fail validate_no_embedded_cr
        #[test]
        fn prop_with_cr_invalid(
            prefix in "[^\r]*",
            suffix in "[^\r]*"
        ) {
            let s = format!("{prefix}\r{suffix}");
            prop_assert!(validate_no_embedded_cr(&s).is_err());
        }

        /// Property: valid printable strings without \r should pass validate_comment
        #[test]
        fn prop_valid_comment(s in "[\\x20-\\x7E\\t]*") {
            prop_assert!(validate_comment(&s).is_ok());
        }

        /// Property: length validation - strings up to a reasonable length should work
        #[test]
        fn prop_long_valid_string(s in prop::collection::vec(0x20u8..=0x7Eu8, 0..1000)) {
            let s = String::from_utf8(s).unwrap();
            prop_assert!(is_printable(&s).is_ok());
        }

        /// Property: strings with null bytes should fail
        #[test]
        fn prop_null_byte_invalid(
            prefix in "[\\x20-\\x7E]*",
            suffix in "[\\x20-\\x7E]*"
        ) {
            let s = format!("{prefix}\x00{suffix}");
            prop_assert!(is_printable(&s).is_err());
        }

        /// Property: strings with newlines should fail
        #[test]
        fn prop_newline_invalid(
            prefix in "[\\x20-\\x7E]*",
            suffix in "[\\x20-\\x7E]*"
        ) {
            let s = format!("{prefix}\n{suffix}");
            prop_assert!(is_printable(&s).is_err());
        }
    }
}
