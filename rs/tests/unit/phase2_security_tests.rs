// Phase 2: Security Hardening - Test Suite
//
// Tests for findings H5, M1, M6 from 2026-02-06 code review

use minisign::{
    crypto::{calculate_kdf_params, KeyNum, KEYNUM_BYTES},
    ops::sign::create_signature,
    signature::TRUSTEDCOMMENTMAXBYTES,
    Error,
};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

// ============================================================================
// H5: KeyNum comparison should use constant-time comparison
// ============================================================================

#[test]
fn h5_keynum_comparison_security() {
    // This test documents that KeyNum comparison is security-relevant
    // KeyNums appear in plaintext in signature files, but we should still
    // use constant-time comparison in the verification path

    let keynum1 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let keynum2 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let keynum3 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 9]);

    // Should support constant-time equality check - convert Choice to bool
    let equal: bool = keynum1.ct_eq(&keynum2).into();
    let not_equal: bool = keynum1.ct_eq(&keynum3).into();

    assert!(equal);
    assert!(!not_equal);
}

#[test]
fn h5_keynum_constant_time_eq_implementation() {
    // Verify that KeyNum implements ConstantTimeEq trait
    let keynum = KeyNum::from_bytes([0u8; KEYNUM_BYTES]);
    let same = KeyNum::from_bytes([0u8; KEYNUM_BYTES]);
    let different = KeyNum::from_bytes([1u8; KEYNUM_BYTES]);

    // ct_eq returns Choice, convert to bool with .into()
    let result1: bool = keynum.ct_eq(&same).into();
    let result2: bool = keynum.ct_eq(&different).into();

    assert!(result1, "Identical keynums should be equal");
    assert!(!result2, "Different keynums should not be equal");
}

// ============================================================================
// M1: calculate_kdf_params() must bounds-check log_n and use checked arithmetic
// ============================================================================

#[test]
fn m1_calculate_kdf_params_rejects_excessive_log_n() {
    // log_n values >= 64 cause undefined behavior (1u64 << log_n wraps/panics)
    // Test that we reject them

    let result = calculate_kdf_params(64, false);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );

    let result = calculate_kdf_params(100, false);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );

    let result = calculate_kdf_params(255, false);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );
}

#[test]
fn m1_calculate_kdf_params_handles_overflow_safely() {
    // For large but valid log_n values (32-63), the subsequent multiplications
    // (n * r * MULTIPLIER) can overflow without checked arithmetic
    // Test that we handle this safely

    // log_n = 50 gives n = 2^50 = 1,125,899,906,842,624
    // n * r * MULTIPLIER could overflow u64
    let result = calculate_kdf_params(50, false);

    // Should either succeed with valid params or return overflow error
    match result {
        Ok((opslimit, memlimit)) => {
            // Verify results are reasonable and didn't wrap
            assert!(opslimit > 0, "opslimit should be non-zero");
            assert!(memlimit > 0, "memlimit should be non-zero");
        }
        Err(e) => {
            // Overflow error is acceptable
            assert!(
                e.to_string().contains("overflow") || e.to_string().contains("ScryptParamError"),
                "Should return overflow error: {e}"
            );
        }
    }
}

#[test]
fn m1_calculate_kdf_params_valid_range() {
    // Test that normal production range works (log_n = 14-20)
    for log_n in 14..=20 {
        let result = calculate_kdf_params(log_n, false);
        assert!(
            result.is_ok(),
            "calculate_kdf_params should succeed for log_n={log_n}"
        );
    }
}

// ============================================================================
// M6: Validation should happen before crypto operations in create_signature()
// ============================================================================

#[test]
fn m6_create_signature_validates_before_crypto() {
    // This test verifies that comment validation happens before file I/O or crypto
    // We use a nonexistent file - if validation happens first, we'll get InvalidComment
    // instead of a file error

    let (secret_key, _, keynum) = minisign::crypto::generate_keypair().unwrap();

    // Use invalid characters (newline) which always causes error
    // (oversized untrusted comment only warns, per C compatibility)
    let invalid_comment = "comment\nwith\nnewlines";

    // Use nonexistent file path - if validation happens first, we won't reach file I/O
    let nonexistent_path = PathBuf::from("/nonexistent/path/file.txt");

    let result = create_signature(
        &secret_key,
        keynum,
        &nonexistent_path,
        false,
        None,
        Some(invalid_comment),
    );

    // Should fail with InvalidComment (from validation), NOT FileRead (from I/O)
    assert!(result.is_err(), "Should reject invalid comment");
    match result.unwrap_err() {
        Error::InvalidComment(_) => {
            // Good! Validation happened before file I/O
        }
        e => panic!("Expected InvalidComment, got: {e}"),
    }
}

#[test]
fn m6_create_signature_rejects_invalid_chars_early() {
    // Verify that comment character validation happens before file I/O or crypto
    let (secret_key, _, keynum) = minisign::crypto::generate_keypair().unwrap();

    // Use nonexistent file - if validation is first, we won't reach file I/O
    let nonexistent_path = PathBuf::from("/nonexistent/invalid.txt");

    // Comment with newline should be rejected before any file I/O or crypto
    let result = create_signature(
        &secret_key,
        keynum,
        &nonexistent_path,
        false,
        None,
        Some("invalid\ncomment"),
    );

    assert!(result.is_err(), "Should reject invalid comment");
    match result.unwrap_err() {
        Error::InvalidComment(_) => {
            // Good! Validation happened before file I/O
        }
        e => panic!("Expected InvalidComment, got: {e}"),
    }
}

#[test]
fn m6_trusted_comment_validation_before_crypto() {
    let (secret_key, _, keynum) = minisign::crypto::generate_keypair().unwrap();

    // Use nonexistent file
    let nonexistent_path = PathBuf::from("/nonexistent/test.txt");

    // Oversized trusted comment
    let oversized_trusted = "x".repeat(TRUSTEDCOMMENTMAXBYTES + 1);

    let result = create_signature(
        &secret_key,
        keynum,
        &nonexistent_path,
        false,
        Some(&oversized_trusted),
        None,
    );

    assert!(result.is_err(), "Should reject oversized trusted comment");
    match result.unwrap_err() {
        Error::InvalidComment(_) => {
            // Good! Validation happened before file I/O
        }
        e => panic!("Expected InvalidComment, got: {e}"),
    }
}

#[test]
fn m6_validation_with_valid_comments_proceeds_to_file_io() {
    // This test verifies that with valid comments, we DO proceed to file I/O
    // (and get a file error for nonexistent file)
    let (secret_key, _, keynum) = minisign::crypto::generate_keypair().unwrap();

    let nonexistent_path = PathBuf::from("/nonexistent/file.txt");

    let result = create_signature(
        &secret_key,
        keynum,
        &nonexistent_path,
        false,
        Some("valid trusted"),
        Some("valid untrusted"),
    );

    // With valid comments, we should reach file I/O and get FileRead error
    assert!(result.is_err());
    match result.unwrap_err() {
        Error::FileRead { .. } => {
            // Good! Validation passed, and we reached file I/O
        }
        e => panic!("Expected FileRead error after validation, got: {e}"),
    }
}
