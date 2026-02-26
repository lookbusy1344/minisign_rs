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

/// Validate a comment string for printability
///
/// This is a thin wrapper around `is_printable()`. Carriage returns (`\r`, U+000D)
/// are rejected here as control characters — the separate `validate_no_embedded_cr()`
/// call that previously followed was redundant because `is_printable()` already rejects
/// `\r` before the CR-specific check could fire.
///
/// # Arguments
///
/// * `s` - String slice to validate
///
/// # Errors
///
/// Returns `Error::InvalidComment` if the string contains unprintable characters
/// (see `is_printable()`).
pub fn validate_comment(s: &str) -> Result<()> {
    is_printable(s)
}

/// Validate a comment string with optional length limit
///
/// This function centralizes all comment validation logic:
/// - Printability check (via `is_printable()`)
/// - Carriage return check (via `validate_no_embedded_cr()`)
/// - Optional length check
///
/// # Arguments
///
/// * `s` - String slice to validate
/// * `max_length` - Optional maximum length in bytes. If provided, the comment must be
///   strictly less than this value to allow for format prefixes (e.g., "untrusted comment: ")
/// * `comment_type` - Description for error messages (e.g., "untrusted", "trusted")
///
/// # Errors
///
/// Returns `Error::InvalidComment` if:
/// - The string contains unprintable characters
/// - The string contains embedded '\r' characters
/// - The string length exceeds `max_length` (if provided)
///
/// # Examples
///
/// ```
/// use minisign::validation::validate_comment_with_length;
///
/// // Basic validation without length check
/// assert!(validate_comment_with_length("Hello", None, "test").is_ok());
///
/// // With length limit
/// assert!(validate_comment_with_length("Hello", Some(10), "test").is_ok());
/// assert!(validate_comment_with_length("Very long text", Some(5), "test").is_err());
/// ```
pub fn validate_comment_with_length(
    s: &str,
    max_length: Option<usize>,
    comment_type: &str,
) -> Result<()> {
    // First validate content (printability and carriage returns)
    validate_comment(s)?;

    // Then validate length if provided
    if let Some(max_len) = max_length
        && s.len() > max_len
    {
        return Err(Error::InvalidComment(format!(
            "{comment_type} comment too long: {} bytes (limit: {} bytes)",
            s.len(),
            max_len
        )));
    }

    Ok(())
}

/// Validate that a path doesn't use Windows reserved names
///
/// Windows reserves certain device names that cannot be used as filenames,
/// even with extensions. This function checks if the filename (without directory path)
/// matches any of these reserved names.
///
/// Reserved names (case-insensitive):
/// - CON, PRN, AUX, NUL
/// - COM1-COM9, LPT1-LPT9
///
/// These names are reserved both with and without extensions:
/// - "NUL", "NUL.txt", "nul", "nul.minisig" are all reserved
///
/// # Arguments
///
/// * `path` - Path to validate
///
/// # Errors
///
/// Returns `Error::InvalidPath` if the filename is a Windows reserved name.
///
/// # Examples
///
/// ```
/// use minisign::validation::validate_windows_path;
/// use std::path::Path;
///
/// # #[cfg(windows)]
/// # {
/// // These should fail on Windows
/// assert!(validate_windows_path(Path::new("NUL")).is_err());
/// assert!(validate_windows_path(Path::new("CON.txt")).is_err());
/// assert!(validate_windows_path(Path::new("COM1.minisig")).is_err());
///
/// // These should succeed
/// assert!(validate_windows_path(Path::new("file.txt")).is_ok());
/// assert!(validate_windows_path(Path::new("nuclear.txt")).is_ok());
/// # }
/// ```
#[cfg(windows)]
pub fn validate_windows_path(path: &std::path::Path) -> Result<()> {
    use std::path::Path;

    const SIMPLE_RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL"];

    // Extract just the filename (not the full path)
    let filename = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| Error::InvalidPath(path.to_path_buf()))?;

    // Strip extension if present to check the base name
    let base_name = Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(filename);

    // Convert to uppercase for case-insensitive comparison
    let base_upper = base_name.to_uppercase();

    // Check simple reserved names
    if SIMPLE_RESERVED.contains(&base_upper.as_str()) {
        return Err(Error::InvalidPath(path.to_path_buf()));
    }

    // Check COM1-COM9 (COM0 is not a reserved Windows device name)
    if base_upper.starts_with("COM")
        && base_upper.len() == 4
        && base_upper
            .chars()
            .nth(3)
            .is_some_and(|c| matches!(c, '1'..='9'))
    {
        return Err(Error::InvalidPath(path.to_path_buf()));
    }

    // Check LPT1-LPT9 (LPT0 is not a reserved Windows device name)
    if base_upper.starts_with("LPT")
        && base_upper.len() == 4
        && base_upper
            .chars()
            .nth(3)
            .is_some_and(|c| matches!(c, '1'..='9'))
    {
        return Err(Error::InvalidPath(path.to_path_buf()));
    }

    Ok(())
}

/// No-op validation for non-Windows platforms
///
/// This function always succeeds on non-Windows platforms since
/// Windows reserved names are not an issue on Unix-like systems.
///
/// # Errors
///
/// This function never returns an error on non-Windows platforms.
#[cfg(not(windows))]
#[inline]
pub fn validate_windows_path(_path: &std::path::Path) -> Result<()> {
    Ok(())
}
