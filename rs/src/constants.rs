//! Centralized constants for minisign
//!
//! This module provides a single reference point for all constants used throughout
//! the minisign implementation. These constants match the C implementation exactly
//! to ensure byte-level compatibility.
//!
//! ## Organization
//!
//! Constants are organized by category:
//! - **Cryptographic sizes**: Key, signature, and hash sizes
//! - **Scrypt parameters**: Key derivation function settings
//! - **Signature format**: Comment and structure sizes
//! - **File format**: Binary structure sizes
//!
//! ## C Implementation Cross-Reference
//!
//! | Constant | Rust Value | C Reference | Notes |
//! |----------|-----------|-------------|-------|
//! | `SIGNATURE_BYTES` | 64 | `crypto_sign_BYTES` | Ed25519 signature size |
//! | `PUBLIC_KEY_BYTES` | 32 | `crypto_sign_PUBLICKEYBYTES` | Ed25519 public key |
//! | `SECRET_KEY_BYTES` | 64 | `crypto_sign_SECRETKEYBYTES` | Ed25519 secret key |
//! | `KEYNUM_BYTES` | 8 | `KEYNUMBYTES` | Key number/ID size |
//! | `KDF_SALT_BYTES` | 32 | `crypto_pwhash_scryptsalsa208sha256_SALTBYTES` | Scrypt salt |
//! | `CHECKSUM_BYTES` | 32 | `crypto_generichash_BYTES` | Blake2b-256 hash |
//! | `SCRYPT_LOG_N` | 20 | N=2^20 | SENSITIVE level work factor |
//! | `SCRYPT_R` | 8 | r=8 | Block size parameter |
//! | `SCRYPT_P` | 1 | p=1 | Parallelization |
//! | `LIBSODIUM_OPSLIMIT_MULTIPLIER` | 4 | - | libsodium formula constant |
//! | `LIBSODIUM_MEMLIMIT_MULTIPLIER` | 128 | - | libsodium formula constant |
//! | `COMMENTMAXBYTES` | 1024 | `COMMENTMAXBYTES` | Max untrusted comment |
//! | `TRUSTEDCOMMENTMAXBYTES` | 8192 | `TRUSTEDCOMMENTMAXBYTES` | Max trusted comment |
//! | `SIG_STRUCT_SIZE` | 74 | 2+8+64 | Signature structure |
//! | `PUBKEY_STRUCT_SIZE` | 42 | 2+8+32 | Public key structure |
//! | `SECKEY_STRUCT_SIZE` | 158 | 2+2+2+32+8+8+8+64+32 | Secret key structure |

// Re-export cryptographic constants from crypto module
pub use crate::crypto::{
    CHECKSUM_BYTES, KDF_SALT_BYTES, KEYNUM_BYTES, LIBSODIUM_MEMLIMIT_MULTIPLIER,
    LIBSODIUM_OPSLIMIT_MULTIPLIER, PUBLIC_KEY_BYTES, SCRYPT_LOG_N, SCRYPT_MEMLIMIT_MIN,
    SCRYPT_OPSLIMIT_MIN, SCRYPT_P, SCRYPT_R, SECRET_KEY_BYTES, SIGNATURE_BYTES,
};

// Re-export signature format constants from signature module
pub use crate::signature::{
    COMMENT_PREFIX_SIZE, COMMENTMAXBYTES, SIG_STRUCT_SIZE, TRUSTED_COMMENT_PREFIX_SIZE,
    TRUSTEDCOMMENTMAXBYTES,
};

// Re-export file format constants from keys module
pub use crate::keys::{ENCRYPTED_BLOB_SIZE, PUBKEY_STRUCT_SIZE, SECKEY_STRUCT_SIZE};

/// Maximum file size for non-prehashed signing/verification (1 GB)
///
/// This limit prevents resource exhaustion from maliciously large files.
/// Files larger than this should use prehashed mode, which streams the
/// file through Blake2b-512 without loading it entirely into memory.
///
/// ## Rationale
///
/// - Ed25519 requires the full message in memory for non-prehashed signatures
/// - 1 GB is large enough for most reasonable use cases
/// - Larger files should use prehashed mode (already supports streaming)
/// - Matches industry best practices (e.g., similar to git object size limits)
pub const MAX_MESSAGE_SIZE_BYTES: u64 = 1024 * 1024 * 1024; // 1 GB

/// All constants in one place for easy reference
///
/// This module provides no additional functionality beyond re-exporting
/// constants from their respective modules. Use this when you need a
/// quick reference or want to import multiple constants at once:
///
/// ```
/// use minisign::constants::{SIGNATURE_BYTES, PUBLIC_KEY_BYTES, KEYNUM_BYTES};
/// ```
///
/// Alternatively, you can use a wildcard import for test code:
///
/// ```
/// use minisign::constants::*;
/// ```
#[cfg(test)]
mod tests {
    use super::*;

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
}
