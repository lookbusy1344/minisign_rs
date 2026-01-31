use minisign::constants::*;

#[test]
fn test_cryptographic_sizes() {
    // Verify Ed25519 sizes
    assert_eq!(SIGNATURE_BYTES, 64);
    assert_eq!(PUBLIC_KEY_BYTES, 32);
    assert_eq!(SECRET_KEY_BYTES, 64);
    assert_eq!(KEYNUM_BYTES, 8);

    // Verify hash/KDF sizes
    assert_eq!(KDF_SALT_BYTES, 32);
    assert_eq!(CHECKSUM_BYTES, 32);
}

#[test]
fn test_scrypt_parameters() {
    // Verify production parameters (SENSITIVE level)
    assert_eq!(SCRYPT_LOG_N, 20); // N = 2^20 = 1,048,576
    assert_eq!(SCRYPT_R, 8);
    assert_eq!(SCRYPT_P, 1);

    // Verify minimum thresholds
    assert_eq!(SCRYPT_OPSLIMIT_MIN, 32_768);
    assert_eq!(SCRYPT_MEMLIMIT_MIN, 16_777_216); // 16 MB
}

#[test]
fn test_comment_sizes() {
    // Verify comment limits (matching C implementation)
    assert_eq!(COMMENTMAXBYTES, 1024);
    assert_eq!(TRUSTEDCOMMENTMAXBYTES, 8192);

    // Verify prefix sizes (include null terminator in C)
    assert_eq!(COMMENT_PREFIX_SIZE, 20); // "untrusted comment: \0"
    assert_eq!(TRUSTED_COMMENT_PREFIX_SIZE, 18); // "trusted comment: \0"
}

#[test]
fn test_structure_sizes() {
    // Signature structure: sig_alg(2) + keynum(8) + signature(64)
    assert_eq!(SIG_STRUCT_SIZE, 74);
    assert_eq!(SIG_STRUCT_SIZE, 2 + KEYNUM_BYTES + SIGNATURE_BYTES);

    // Public key structure: sig_alg(2) + keynum(8) + public_key(32)
    assert_eq!(PUBKEY_STRUCT_SIZE, 42);
    assert_eq!(PUBKEY_STRUCT_SIZE, 2 + KEYNUM_BYTES + PUBLIC_KEY_BYTES);

    // Secret key structure: sig_alg(2) + kdf_alg(2) + chk_alg(2) +
    //   salt(32) + opslimit(8) + memlimit(8) + keynum(8) + secret(64) + checksum(32)
    assert_eq!(SECKEY_STRUCT_SIZE, 158);
    assert_eq!(
        SECKEY_STRUCT_SIZE,
        2 + 2 + 2 + KDF_SALT_BYTES + 8 + 8 + KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES
    );

    // Encrypted blob: keynum(8) + secret_key(64) + checksum(32)
    assert_eq!(ENCRYPTED_BLOB_SIZE, 104);
    assert_eq!(
        ENCRYPTED_BLOB_SIZE,
        KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES
    );
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_all_constants_are_nonzero() {
    // Sanity check: all size constants should be > 0
    assert!(SIGNATURE_BYTES > 0);
    assert!(PUBLIC_KEY_BYTES > 0);
    assert!(SECRET_KEY_BYTES > 0);
    assert!(KEYNUM_BYTES > 0);
    assert!(KDF_SALT_BYTES > 0);
    assert!(CHECKSUM_BYTES > 0);
    assert!(SCRYPT_LOG_N > 0);
    assert!(SCRYPT_R > 0);
    assert!(SCRYPT_P > 0);
    assert!(SCRYPT_OPSLIMIT_MIN > 0);
    assert!(SCRYPT_MEMLIMIT_MIN > 0);
    assert!(COMMENTMAXBYTES > 0);
    assert!(TRUSTEDCOMMENTMAXBYTES > 0);
    assert!(COMMENT_PREFIX_SIZE > 0);
    assert!(TRUSTED_COMMENT_PREFIX_SIZE > 0);
    assert!(SIG_STRUCT_SIZE > 0);
    assert!(PUBKEY_STRUCT_SIZE > 0);
    assert!(SECKEY_STRUCT_SIZE > 0);
    assert!(ENCRYPTED_BLOB_SIZE > 0);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_comment_size_relationships() {
    // Trusted comments can be larger than untrusted
    assert!(TRUSTEDCOMMENTMAXBYTES > COMMENTMAXBYTES);

    // Prefixes should be smaller than max sizes
    assert!(COMMENT_PREFIX_SIZE < COMMENTMAXBYTES);
    assert!(TRUSTED_COMMENT_PREFIX_SIZE < TRUSTEDCOMMENTMAXBYTES);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_structure_composition() {
    // Secret key should be larger than public key
    assert!(SECKEY_STRUCT_SIZE > PUBKEY_STRUCT_SIZE);

    // Signature structure size consistency
    assert!(SIG_STRUCT_SIZE < SECKEY_STRUCT_SIZE);
    assert!(SIG_STRUCT_SIZE > PUBKEY_STRUCT_SIZE);

    // Encrypted blob consistency
    assert!(ENCRYPTED_BLOB_SIZE < SECKEY_STRUCT_SIZE);
    assert!(ENCRYPTED_BLOB_SIZE > SECRET_KEY_BYTES);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn test_max_message_size() {
    // 1 GB limit
    assert_eq!(MAX_MESSAGE_SIZE_BYTES, 1024 * 1024 * 1024);
    assert_eq!(MAX_MESSAGE_SIZE_BYTES, 1_073_741_824);

    // Should be reasonable for CLI tool
    assert!(MAX_MESSAGE_SIZE_BYTES > 1_000_000); // > 1 MB
    assert!(MAX_MESSAGE_SIZE_BYTES <= 10 * 1024 * 1024 * 1024); // <= 10 GB
}
