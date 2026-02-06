// Phase 2: Security Hardening - Test Suite
//
// Tests for findings H5, M1, M6 from 2026-02-06 code review

use minisign::{
    crypto::{calculate_kdf_params, KeyNum, KEYNUM_BYTES},
    ops::sign::create_signature,
    Error,
};
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
#[ignore = "M1 not yet implemented"]
fn m1_calculate_kdf_params_rejects_excessive_log_n() {
    // log_n values >= 64 cause undefined behavior (1u64 << log_n wraps/panics)
    // Test that we reject them

    let result = calculate_kdf_params(64);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );

    let result = calculate_kdf_params(100);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );

    let result = calculate_kdf_params(255);
    assert!(
        result.is_err(),
        "calculate_kdf_params should reject log_n >= 64"
    );
}

#[test]
#[ignore = "M1 not yet implemented"]
fn m1_calculate_kdf_params_handles_overflow_safely() {
    // For large but valid log_n values (32-63), the subsequent multiplications
    // (n * r * MULTIPLIER) can overflow without checked arithmetic
    // Test that we handle this safely

    // log_n = 50 gives n = 2^50 = 1,125,899,906,842,624
    // n * r * MULTIPLIER could overflow u64
    let result = calculate_kdf_params(50);

    // Should either succeed with valid params or return overflow error
    match result {
        Ok((log_n, opslimit, memlimit)) => {
            assert_eq!(log_n, 50);
            // Verify results are reasonable and didn't wrap
            assert!(opslimit > 0, "opslimit should be non-zero");
            assert!(memlimit > 0, "memlimit should be non-zero");
        }
        Err(e) => {
            // Overflow error is acceptable
            assert!(
                e.to_string().contains("overflow") || e.to_string().contains("ScryptParamError"),
                "Should return overflow error: {}",
                e
            );
        }
    }
}

#[test]
#[ignore = "M1 not yet implemented"]
fn m1_calculate_kdf_params_valid_range() {
    // Test that normal production range works (log_n = 14-20)
    for log_n in 14..=20 {
        let result = calculate_kdf_params(log_n);
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
#[ignore = "M6 not yet implemented"]
fn m6_create_signature_validates_before_crypto() {
    // This test verifies that comment validation happens before signing
    // We'll test with invalid comments that should be rejected before any crypto work

    use minisign::signature::COMMENTMAXBYTES;
    use std::path::PathBuf;

    let (secret_key, _, _) = minisign::crypto::generate_keypair().unwrap();

    // Create an oversized untrusted comment (should fail validation)
    let oversized_comment = "x".repeat(COMMENTMAXBYTES + 1);
    let message_path = PathBuf::from("/tmp/nonexistent.txt");

    let result = create_signature(
        &secret_key,
        &message_path,
        Some(oversized_comment),
        None,
        false,
    );

    // Should fail with InvalidComment, not a crypto or file error
    assert!(result.is_err(), "Should reject oversized comment");
    assert!(
        matches!(result.unwrap_err(), Error::InvalidComment(_)),
        "Should fail with InvalidComment before attempting crypto"
    );
}

#[test]
#[ignore = "M6 not yet implemented"]
fn m6_create_signature_rejects_invalid_chars_early() {
    // Verify that comment character validation happens before crypto
    use std::path::PathBuf;

    let (secret_key, _, _) = minisign::crypto::generate_keypair().unwrap();
    let message_path = PathBuf::from("/tmp/test.txt");

    // Comment with newline should be rejected before any file I/O or crypto
    let result = create_signature(
        &secret_key,
        &message_path,
        Some("invalid\ncomment".to_string()),
        None,
        false,
    );

    assert!(result.is_err(), "Should reject invalid comment");
    assert!(
        matches!(result.unwrap_err(), Error::InvalidComment(_)),
        "Should fail with InvalidComment"
    );
}

#[test]
#[ignore = "M6 not yet implemented"]
fn m6_trusted_comment_validation_before_crypto() {
    use minisign::signature::TRUSTEDCOMMENTMAXBYTES;
    use std::path::PathBuf;

    let (secret_key, _, _) = minisign::crypto::generate_keypair().unwrap();
    let message_path = PathBuf::from("/tmp/test.txt");

    // Oversized trusted comment
    let oversized_trusted = "x".repeat(TRUSTEDCOMMENTMAXBYTES + 1);

    let result = create_signature(
        &secret_key,
        &message_path,
        None,
        Some(oversized_trusted),
        false,
    );

    assert!(result.is_err(), "Should reject oversized trusted comment");
    assert!(
        matches!(result.unwrap_err(), Error::InvalidComment(_)),
        "Should fail with InvalidComment before crypto"
    );
}
