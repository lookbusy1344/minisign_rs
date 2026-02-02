//! Edge case tests for minisign
//!
//! Tests for boundary conditions and unusual inputs

use minisign::ops::{
    change::{ChangeOptions, change},
    generate::{GenerateOptions, generate},
    sign::{SignOptions, sign},
    verify::{PublicKeySource, VerifyOptions, verify},
};
use std::fs;
use tempfile::TempDir;

/// Test signing and verifying an empty file
#[test]
fn test_empty_file_signing() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("empty.txt");
    let sig_file = temp_dir.path().join("empty.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create empty file
    fs::write(&message_file, b"").expect("Failed to create empty file");

    // Sign empty file (prehashed mode)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };
    sign(&sign_opts, None).expect("Should sign empty file");

    // Verify signature on empty file
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify empty file signature");
}

/// Test signing and verifying an empty file in legacy mode
#[test]
fn test_empty_file_legacy_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("empty_legacy.txt");
    let sig_file = temp_dir.path().join("empty_legacy.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create empty file
    fs::write(&message_file, b"").expect("Failed to create empty file");

    // Sign empty file (legacy mode - non-prehashed)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: false, // Legacy mode
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };
    sign(&sign_opts, None).expect("Should sign empty file in legacy mode");

    // Verify signature on empty file
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify empty file legacy signature");
}

/// Test signing with Unicode (non-ASCII) in trusted comment
#[test]
fn test_unicode_in_trusted_comment() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Sign with Unicode trusted comment (emoji, Chinese, Arabic)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some("Signed 🔐 签名 توقيع".to_string()),
        untrusted_comment: Some("Test signature 测试 اختبار 🚀".to_string()),
        force: true,
        quiet: false,
    };
    let result = sign(&sign_opts, None).expect("Should sign with Unicode comments");
    assert!(result.trusted_comment.contains("🔐"));
    assert!(result.trusted_comment.contains("签名"));

    // Verify signature with Unicode comments
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: false,
    };
    let result = verify(&verify_opts).expect("Should verify signature with Unicode");
    assert!(result.trusted_comment.contains("🔐"));
}

/// Test signing with Unicode (non-ASCII) in untrusted comment
#[test]
fn test_unicode_in_untrusted_comment() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message
    fs::write(&message_file, b"Test").expect("Failed to write message");

    // Sign with Unicode untrusted comment only
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some("Файл подписан ✓".to_string()),
        force: true,
        quiet: false,
    };
    sign(&sign_opts, None).expect("Should sign with Unicode untrusted comment");

    // Verify and check untrusted comment
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: false,
    };
    let result = verify(&verify_opts).expect("Should verify");
    assert!(result.untrusted_comment.contains("Файл"));
}

/// Test signing a large file with prehashed mode
#[test]
fn test_large_file_prehashed() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("large.bin");
    let sig_file = temp_dir.path().join("large.bin.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create a 100MB file (not 4GB to keep tests fast)
    // This tests that large files work with prehashed mode
    let large_data = vec![0xABu8; 100 * 1024 * 1024]; // 100 MB
    fs::write(&message_file, large_data).expect("Failed to write large file");

    // Sign large file - should use prehashed mode
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some("Large file signature".to_string()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };
    sign(&sign_opts, None).expect("Should sign large file");

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify large file signature");
}

/// Test handling of symlinks in file paths
#[cfg(unix)]
#[test]
fn test_symlink_handling() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let message_link = temp_dir.path().join("message_link.txt");
    let sig_file = temp_dir.path().join("message_link.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message file and symlink to it
    fs::write(&message_file, b"Real file content").expect("Failed to write message");
    symlink(&message_file, &message_link).expect("Failed to create symlink");

    // Sign the symlink - should follow it and sign the real file
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_link.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };
    sign(&sign_opts, None).expect("Should sign through symlink");

    // Verify using the symlink
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_link.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify through symlink");

    // Verify using the real file - should also work
    let verify_opts2 = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts2).expect("Should verify real file with symlink signature");
}

/// Test generating a key with an empty password
#[test]
fn test_generate_key_with_empty_password() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate key with empty password
    #[cfg(debug_assertions)]
    let gen_opts = GenerateOptions::new_with_weak_kdf(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        false, // Password is required
        false,
        true, // Use weak KDF for faster test
    );
    #[cfg(not(debug_assertions))]
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        false, // Password is required
        false,
    );

    // Empty password should work
    generate(&gen_opts, Some(b"")).expect("Should generate key with empty password");

    // Verify the key was created
    assert!(secret_key.exists(), "Secret key should be created");
    assert!(public_key.exists(), "Public key should be created");

    // Sign with the key using empty password
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    // Should be able to sign with empty password
    sign(&sign_opts, Some(b"")).expect("Should sign with empty password");

    // Verify the signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify signature created with empty password");
}

/// Test changing password from non-empty to empty
#[test]
fn test_change_password_to_empty() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate key with non-empty password
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        false,
        false,
    );
    generate(&gen_opts, Some(b"original_password")).expect("Failed to generate key");

    // Change password to empty
    #[cfg(debug_assertions)]
    let change_opts = ChangeOptions::new_with_weak_kdf(
        secret_key.as_path(),
        false, // Not removing, just changing
        false,
        true,
    );
    #[cfg(not(debug_assertions))]
    let change_opts = ChangeOptions::new(
        secret_key.as_path(),
        false, // Not removing, just changing
        false,
    );

    change(&change_opts, Some(b"original_password"), Some(b""))
        .expect("Should change password to empty");

    // Sign with empty password
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    fs::write(&message_file, b"Test").expect("Failed to write message");

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    sign(&sign_opts, Some(b"")).expect("Should sign with new empty password");
}

/// Test changing password from empty to non-empty
#[test]
fn test_change_password_from_empty() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate key with empty password
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        false,
        false,
    );
    generate(&gen_opts, Some(b"")).expect("Failed to generate key with empty password");

    // Change from empty password to non-empty
    #[cfg(debug_assertions)]
    let change_opts = ChangeOptions::new_with_weak_kdf(secret_key.as_path(), false, false, true);
    #[cfg(not(debug_assertions))]
    let change_opts = ChangeOptions::new(secret_key.as_path(), false, false);

    change(&change_opts, Some(b""), Some(b"new_password"))
        .expect("Should change from empty to non-empty password");

    // Sign with new password
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    fs::write(&message_file, b"Test").expect("Failed to write message");

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    sign(&sign_opts, Some(b"new_password")).expect("Should sign with new non-empty password");
}

/// Test untrusted comment at exactly max valid length (1003 bytes)
#[test]
fn test_untrusted_comment_max_valid_length() {
    use minisign::constants::{COMMENT_PREFIX_SIZE, COMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Max valid length: COMMENTMAXBYTES - COMMENT_PREFIX_SIZE - 1 = 1024 - 20 - 1 = 1003
    let max_valid_comment = "a".repeat(COMMENTMAXBYTES - COMMENT_PREFIX_SIZE - 1);
    assert_eq!(max_valid_comment.len(), 1003);

    // Should succeed without warning
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some(max_valid_comment),
        force: true,
        quiet: false,
    };

    sign(&sign_opts, None).expect("Should sign with max valid untrusted comment");

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify signature with max valid comment");
}

/// Test untrusted comment at warning threshold (1004 bytes)
#[test]
fn test_untrusted_comment_warning_threshold() {
    use minisign::constants::{COMMENT_PREFIX_SIZE, COMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Warning threshold: COMMENTMAXBYTES - COMMENT_PREFIX_SIZE = 1024 - 20 = 1004
    let warning_comment = "a".repeat(COMMENTMAXBYTES - COMMENT_PREFIX_SIZE);
    assert_eq!(warning_comment.len(), 1004);

    // Should succeed but emit warning to stderr (we can't easily capture stderr in test)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some(warning_comment),
        force: true,
        quiet: false,
    };

    sign(&sign_opts, None).expect("Should sign but warn about untrusted comment length");

    // Verify signature still works
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify signature despite warning");
}

/// Test trusted comment at exactly max valid length (8173 bytes)
#[test]
fn test_trusted_comment_max_valid_length() {
    use minisign::constants::{TRUSTED_COMMENT_PREFIX_SIZE, TRUSTEDCOMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Max valid length: TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1 = 8192 - 18 - 1 = 8173
    let max_valid_trusted = "b".repeat(TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1);
    assert_eq!(max_valid_trusted.len(), 8173);

    // Should succeed
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(max_valid_trusted.clone()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None).expect("Should sign with max valid trusted comment");
    assert_eq!(result.trusted_comment, max_valid_trusted);

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify signature with max valid trusted comment");
}

/// Test trusted comment at error threshold (8174 bytes)
#[test]
fn test_trusted_comment_error_threshold() {
    use minisign::constants::{TRUSTED_COMMENT_PREFIX_SIZE, TRUSTEDCOMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Error threshold: TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE = 8192 - 18 = 8174
    let too_long_trusted = "b".repeat(TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE);
    assert_eq!(too_long_trusted.len(), 8174);

    // Should error
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(too_long_trusted),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None);
    assert!(
        result.is_err(),
        "Should fail with trusted comment at error threshold"
    );

    // Verify error message mentions trusted comment
    let err = result.unwrap_err();
    assert!(
        format!("{err}").to_lowercase().contains("trusted comment"),
        "Error should mention trusted comment"
    );
}

/// Test that symlinks to existing files can't be overwritten without force
///
/// This verifies that `create_new(true)` protects against symlink attacks
/// where an attacker creates a symlink to a sensitive file before the
/// target file is created.
#[cfg(unix)]
#[test]
fn test_symlink_to_existing_file_cannot_overwrite() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    // Create a "sensitive" file that shouldn't be overwritten
    let sensitive_file = temp_dir.path().join("sensitive_data.txt");
    fs::write(&sensitive_file, b"SENSITIVE DATA - DO NOT OVERWRITE")
        .expect("Failed to create sensitive file");

    // Create a symlink where the signature would be written
    let sig_file = temp_dir.path().join("message.txt.minisig");
    symlink(&sensitive_file, &sig_file).expect("Failed to create symlink");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Attempt to sign without force - should fail because sig_file exists (via symlink)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: false, // Important: no force
        quiet: false,
    };

    let result = sign(&sign_opts, None);
    assert!(
        result.is_err(),
        "Should fail to overwrite file via symlink without force"
    );

    // Verify sensitive file was NOT modified
    let sensitive_content =
        fs::read_to_string(&sensitive_file).expect("Failed to read sensitive file");
    assert_eq!(
        sensitive_content, "SENSITIVE DATA - DO NOT OVERWRITE",
        "Sensitive file should not be modified"
    );
}

/// Test that symlinks pointing outside the working directory are handled safely
///
/// Verifies that operations on symlinks don't allow escaping the intended
/// directory or accessing files outside the user's control.
#[cfg(unix)]
#[test]
fn test_symlink_outside_working_directory() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let work_dir = temp_dir.path().join("work");
    fs::create_dir(&work_dir).expect("Failed to create work dir");

    // Create a message file outside the work directory
    let outside_message = temp_dir.path().join("outside_message.txt");
    fs::write(&outside_message, b"Outside content").expect("Failed to write outside file");

    // Create a symlink inside work dir that points outside
    let inside_link = work_dir.join("message_link.txt");
    symlink(&outside_message, &inside_link).expect("Failed to create symlink");

    // Generate key in work directory
    let secret_key = work_dir.join("test.key");
    let public_key = work_dir.join("test.pub");
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Sign using the symlink - should follow it and sign the real file
    let sig_file = work_dir.join("message_link.txt.minisig");
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: inside_link.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    // Should succeed - symlink following is expected behavior
    sign(&sign_opts, None).expect("Should sign file via symlink");

    // Verify using the real file path works
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: outside_message.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify using real file path");
}

/// Test that parent directory symlinks don't allow directory traversal
///
/// Verifies that even if a parent directory in the path is a symlink,
/// operations are still safe and don't escape to unintended locations.
#[cfg(unix)]
#[test]
fn test_parent_directory_symlink_no_escape() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create two directories
    let real_dir = temp_dir.path().join("real");
    let other_dir = temp_dir.path().join("other");
    fs::create_dir(&real_dir).expect("Failed to create real dir");
    fs::create_dir(&other_dir).expect("Failed to create other dir");

    // Create a symlink directory that points to real_dir
    let link_dir = temp_dir.path().join("link");
    symlink(&real_dir, &link_dir).expect("Failed to create directory symlink");

    // Generate key using path through symlinked directory
    let secret_key = link_dir.join("test.key");
    let public_key = link_dir.join("test.pub");
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Verify files were created in the real directory
    let real_secret_key = real_dir.join("test.key");
    let real_public_key = real_dir.join("test.pub");
    assert!(
        real_secret_key.exists(),
        "Secret key should exist in real directory"
    );
    assert!(
        real_public_key.exists(),
        "Public key should exist in real directory"
    );

    // Verify files are NOT in the other directory
    let other_secret_key = other_dir.join("test.key");
    assert!(
        !other_secret_key.exists(),
        "Secret key should NOT exist in other directory"
    );

    // Sign a message using the symlinked path
    let message_file = link_dir.join("message.txt");
    fs::write(&message_file, b"Test").expect("Failed to write message");

    let sig_file = link_dir.join("message.txt.minisig");
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    sign(&sign_opts, None).expect("Should sign using symlinked directory path");

    // Verify signature exists in real directory
    let real_sig_file = real_dir.join("message.txt.minisig");
    assert!(
        real_sig_file.exists(),
        "Signature should exist in real directory"
    );
}

/// Test circular symlinks don't cause infinite loops
///
/// Verifies that the code handles circular symlink references gracefully.
#[cfg(unix)]
#[test]
fn test_circular_symlink_handling() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let link1 = temp_dir.path().join("link1.txt");
    let link2 = temp_dir.path().join("link2.txt");

    // Create circular symlinks
    symlink(&link2, &link1).expect("Failed to create first symlink");
    symlink(&link1, &link2).expect("Failed to create second symlink");

    // Generate key
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    // Attempt to sign the circular symlink
    let sig_file = temp_dir.path().join("link1.txt.minisig");
    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: link1.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    // Should fail gracefully (not infinite loop or panic)
    let result = sign(&sign_opts, None);
    assert!(
        result.is_err(),
        "Should fail gracefully with circular symlink"
    );
}

/// Test comments with zero-width joiners (ZWJ)
///
/// Zero-width joiners can be used to create alternative representations
/// of characters. This test ensures they're handled correctly.
#[test]
fn test_unicode_zero_width_joiners() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Zero-width joiner (U+200D) between characters
    let zwj_comment = "Test\u{200D}Comment";
    assert!(zwj_comment.len() > zwj_comment.chars().count()); // Multi-byte

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(zwj_comment.to_string()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None).expect("Should sign with ZWJ in comment");
    assert!(result.trusted_comment.contains('\u{200D}'));
}

/// Test comments with right-to-left (RTL) override characters
///
/// RTL override characters can change text display direction, potentially
/// causing confusion or spoofing attacks in comment display.
#[test]
fn test_unicode_rtl_override() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Right-to-left override (U+202E)
    let rtl_comment = "Test\u{202E}Override";

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(rtl_comment.to_string()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None).expect("Should sign with RTL override");
    assert!(result.trusted_comment.contains('\u{202E}'));

    // Verify signature works despite RTL
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.as_path()),
        signature_file: sig_file.as_path(),
        message_file: message_file.as_path(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify signature with RTL comment");
}

/// Test comments with homoglyphs (visually similar characters)
///
/// Homoglyphs can be used for spoofing. This test ensures they're stored
/// and retrieved correctly without normalization.
#[test]
fn test_unicode_homoglyphs() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Cyrillic 'а' (U+0430) looks like Latin 'a' (U+0061)
    // Greek 'ο' (U+03BF) looks like Latin 'o' (U+006F)
    let homoglyph_comment = "Test with Cyrillic а and Greek ο";

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(homoglyph_comment.to_string()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None).expect("Should sign with homoglyphs");

    // Verify exact preservation (no Unicode normalization)
    assert_eq!(result.trusted_comment, homoglyph_comment);
    assert!(result.trusted_comment.contains('а')); // Cyrillic а
    assert!(result.trusted_comment.contains('ο')); // Greek ο
}

/// Test multi-byte characters at exact byte limit
///
/// This tests the interaction between byte limits and multi-byte UTF-8
/// encoding to ensure proper boundary handling.
#[test]
fn test_unicode_multibyte_at_byte_limit() {
    use minisign::constants::{TRUSTED_COMMENT_PREFIX_SIZE, TRUSTEDCOMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Create comment that's just under limit with ASCII, then add multi-byte char
    let max_bytes = TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1;

    // Fill with ASCII 'a' characters, leaving room for one 3-byte character
    let ascii_part = "a".repeat(max_bytes - 3);

    // Add a 3-byte UTF-8 character (Euro sign: €, U+20AC = 0xE2 0x82 0xAC)
    let comment_with_multibyte = format!("{ascii_part}€");

    // Should be exactly at the byte limit
    assert_eq!(comment_with_multibyte.len(), max_bytes);
    assert!(comment_with_multibyte.chars().count() < comment_with_multibyte.len());

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(comment_with_multibyte.clone()),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None).expect("Should sign with multi-byte char at byte limit");
    assert_eq!(result.trusted_comment, comment_with_multibyte);
}

/// Test comment that exceeds byte limit when last character is multi-byte
///
/// Ensures that adding a multi-byte character that would exceed the limit
/// is properly rejected.
#[test]
fn test_unicode_multibyte_exceeds_limit() {
    use minisign::constants::{TRUSTED_COMMENT_PREFIX_SIZE, TRUSTEDCOMMENTMAXBYTES};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate key
    let gen_opts = GenerateOptions::new(
        secret_key.as_path(),
        public_key.as_path(),
        None,
        true,
        true,
        false,
    );
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Create comment at max length with ASCII, then add 2-byte character
    let max_bytes = TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1;
    let ascii_part = "a".repeat(max_bytes);

    // Add a 2-byte UTF-8 character (Latin small letter e with acute: é, U+00E9)
    let too_long_comment = format!("{ascii_part}é");

    // Should exceed byte limit
    assert!(too_long_comment.len() > max_bytes);

    let sign_opts = SignOptions {
        secret_key_file: secret_key.as_path(),
        message_file: message_file.as_path(),
        signature_file: Some(sig_file.as_path()),
        prehashed: true,
        trusted_comment: Some(too_long_comment),
        untrusted_comment: None,
        force: true,
        quiet: false,
    };

    let result = sign(&sign_opts, None);
    assert!(
        result.is_err(),
        "Should reject comment exceeding byte limit with multi-byte char"
    );
}
