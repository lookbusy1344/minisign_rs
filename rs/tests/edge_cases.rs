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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create empty file
    fs::write(&message_file, b"").expect("Failed to create empty file");

    // Sign empty file (prehashed mode)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("Should sign empty file");

    // Verify signature on empty file
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create empty file
    fs::write(&message_file, b"").expect("Failed to create empty file");

    // Sign empty file (legacy mode - non-prehashed)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: false, // Legacy mode
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("Should sign empty file in legacy mode");

    // Verify signature on empty file
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Sign with Unicode trusted comment (emoji, Chinese, Arabic)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: Some("Signed 🔐 签名 توقيع".to_string()),
        untrusted_comment: Some("Test signature 测试 اختبار 🚀".to_string()),
        force: true,
    };
    let result = sign(&sign_opts, None).expect("Should sign with Unicode comments");
    assert!(result.trusted_comment.contains("🔐"));
    assert!(result.trusted_comment.contains("签名"));

    // Verify signature with Unicode comments
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message
    fs::write(&message_file, b"Test").expect("Failed to write message");

    // Sign with Unicode untrusted comment only
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some("Файл подписан ✓".to_string()),
        force: true,
    };
    sign(&sign_opts, None).expect("Should sign with Unicode untrusted comment");

    // Verify and check untrusted comment
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create a 100MB file (not 4GB to keep tests fast)
    // This tests that large files work with prehashed mode
    let large_data = vec![0xABu8; 100 * 1024 * 1024]; // 100 MB
    fs::write(&message_file, large_data).expect("Failed to write large file");

    // Sign large file - should use prehashed mode
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: Some("Large file signature".to_string()),
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("Should sign large file");

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create message file and symlink to it
    fs::write(&message_file, b"Real file content").expect("Failed to write message");
    symlink(&message_file, &message_link).expect("Failed to create symlink");

    // Sign the symlink - should follow it and sign the real file
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_link.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("Should sign through symlink");

    // Verify using the symlink
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_link.to_str().unwrap().to_string(),
        output: false,
        quiet: true,
    };
    verify(&verify_opts).expect("Should verify through symlink");

    // Verify using the real file - should also work
    let verify_opts2 = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: false, // Password is required
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: true, // Use weak KDF for faster test
    };

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
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };

    // Should be able to sign with empty password
    sign(&sign_opts, Some(b"")).expect("Should sign with empty password");

    // Verify the signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: false,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: true,
    };
    generate(&gen_opts, Some(b"original_password")).expect("Failed to generate key");

    // Change password to empty
    let change_opts = ChangeOptions {
        secret_key_file: secret_key.clone(),
        remove_password: false, // Not removing, just changing
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: true,
    };

    change(&change_opts, Some(b"original_password"), Some(b""))
        .expect("Should change password to empty");

    // Sign with empty password
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    fs::write(&message_file, b"Test").expect("Failed to write message");

    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: false,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: true,
    };
    generate(&gen_opts, Some(b"")).expect("Failed to generate key with empty password");

    // Change from empty password to non-empty
    let change_opts = ChangeOptions {
        secret_key_file: secret_key.clone(),
        remove_password: false,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: true,
    };

    change(&change_opts, Some(b""), Some(b"new_password"))
        .expect("Should change from empty to non-empty password");

    // Sign with new password
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    fs::write(&message_file, b"Test").expect("Failed to write message");

    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Max valid length: COMMENTMAXBYTES - COMMENT_PREFIX_SIZE - 1 = 1024 - 20 - 1 = 1003
    let max_valid_comment = "a".repeat(COMMENTMAXBYTES - COMMENT_PREFIX_SIZE - 1);
    assert_eq!(max_valid_comment.len(), 1003);

    // Should succeed without warning
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some(max_valid_comment),
        force: true,
    };

    sign(&sign_opts, None).expect("Should sign with max valid untrusted comment");

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Warning threshold: COMMENTMAXBYTES - COMMENT_PREFIX_SIZE = 1024 - 20 = 1004
    let warning_comment = "a".repeat(COMMENTMAXBYTES - COMMENT_PREFIX_SIZE);
    assert_eq!(warning_comment.len(), 1004);

    // Should succeed but emit warning to stderr (we can't easily capture stderr in test)
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: Some(warning_comment),
        force: true,
    };

    sign(&sign_opts, None).expect("Should sign but warn about untrusted comment length");

    // Verify signature still works
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Max valid length: TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1 = 8192 - 18 - 1 = 8173
    let max_valid_trusted = "b".repeat(TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE - 1);
    assert_eq!(max_valid_trusted.len(), 8173);

    // Should succeed
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: Some(max_valid_trusted.clone()),
        untrusted_comment: None,
        force: true,
    };

    let result = sign(&sign_opts, None).expect("Should sign with max valid trusted comment");
    assert_eq!(result.trusted_comment, max_valid_trusted);

    // Verify signature
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(public_key.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
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
    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Error threshold: TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE = 8192 - 18 = 8174
    let too_long_trusted = "b".repeat(TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE);
    assert_eq!(too_long_trusted.len(), 8174);

    // Should error
    let sign_opts = SignOptions {
        secret_key_file: secret_key.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: Some(too_long_trusted),
        untrusted_comment: None,
        force: true,
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
