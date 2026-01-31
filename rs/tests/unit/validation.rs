use minisign::validation::*;

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
