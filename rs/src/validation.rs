//! Comment validation functions for C compatibility
//!
//! This module implements validation functions that match the C implementation's
//! behavior for validating comment strings in signature files.
//!
//! # Implementation Note: Inline Constants
//!
//! The UTF-8 validation code uses inline hex constants (e.g., `0x20`, `0x7e`, `0xc2`)
//! rather than extracted named constants. This is intentional:
//!
//! - These are standard UTF-8 specification values, not arbitrary magic numbers
//! - They're used only within the UTF-8 validation algorithm
//! - Keeping them inline makes the algorithm more readable in context
//! - Range expressions like `(0x20..=0x7e)` clearly communicate "printable ASCII"
//! - Extracting them would scatter the algorithm across multiple definitions

use crate::errors::{Error, Result};

/// Validate that a string contains only printable characters
///
/// This function matches the behavior of the C implementation's `is_printable()`
/// function (minisign.c:76-125), but simplified for Rust's UTF-8 guarantees.
///
/// Since Rust's `&str` type guarantees valid UTF-8 (no overlong encodings,
/// no surrogate pairs, no invalid code points), we only need to check for
/// control characters.
///
/// Validates:
/// - Printable ASCII (0x20-0x7E)
/// - Tab character (0x09)
/// - Non-control Unicode characters (> U+009F)
/// - Rejects control characters (0x00-0x1F except tab, 0x7F)
/// - Rejects C1 control characters (U+0080-U+009F)
///
/// # Arguments
///
/// * `s` - String slice to validate (already guaranteed to be valid UTF-8)
///
/// # Errors
///
/// Returns `Error::InvalidComment` if the string contains:
/// - Control characters (0x00-0x08, 0x0A-0x1F, 0x7F)
/// - C1 control characters (U+0080-U+009F)
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
    // Since &str guarantees valid UTF-8, we can use .chars() which handles
    // all UTF-8 decoding for us. We only need to check for control characters.
    for c in s.chars() {
        // Tab is explicitly allowed (despite being a control character)
        if c == '\t' {
            continue;
        }

        // Reject ASCII control characters (0x00-0x1F and 0x7F)
        // and C1 control characters (U+0080-U+009F)
        if c.is_control() || c == '\x7f' {
            return Err(Error::InvalidComment(format!(
                "contains control character: U+{:04X}",
                c as u32
            )));
        }
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
