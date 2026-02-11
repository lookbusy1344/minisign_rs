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

/// Production-strength scrypt opslimit (N=2^20, r=8, p=1)
///
/// Computed as `LIBSODIUM_OPSLIMIT_MULTIPLIER * N * r = 4 * 1_048_576 * 8`.
/// Keys created with a lower opslimit were generated with reduced security
/// (see KDF fallback mechanism).
pub const PRODUCTION_OPSLIMIT: u64 = 33_554_432;

/// Production-strength scrypt memlimit (N=2^20, r=8, p=1)
///
/// Computed as `LIBSODIUM_MEMLIMIT_MULTIPLIER * N * r = 128 * 1_048_576 * 8` (1 GiB).
/// Keys created with a lower memlimit were generated with reduced security
/// (see KDF fallback mechanism).
pub const PRODUCTION_MEMLIMIT: u64 = 1_073_741_824;

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

/// Placeholder key ID displayed for encrypted keys before decryption
///
/// When a secret key is encrypted, its keynum is also encrypted. Before
/// decryption, the key ID is displayed as "0000000000000000" to indicate
/// that the real key ID is not yet available without the password.
pub const ENCRYPTED_KEYNUM_PLACEHOLDER: &str = "0000000000000000";

/// Hardware slot version number
///
/// This version field allows future format evolution without breaking existing
/// HW-encrypted keys. Current version is 1.
pub const HW_SLOT_VERSION: u16 = 1;

/// Hardware slot fixed size (excluding variable-length label)
///
/// Layout:
/// - 0-1: `hw_version` (u16, 2 bytes)
/// - 2-34: `ephemeral_pubkey` (33 bytes, compressed P-256)
/// - 35-46: `nonce` (12 bytes, AES-256-GCM)
/// - 47-150: `ciphertext` (104 bytes, encrypted blob)
/// - 151-166: `tag` (16 bytes, AES-256-GCM auth tag)
/// - 167+: `hw_key_label` (variable length UTF-8)
pub const HW_SLOT_FIXED_SIZE: usize = 167;

/// Maximum hardware key label size in bytes
///
/// Labels are UTF-8 strings (e.g., "minisign:a1b2c3d4e5f6g7h8").
/// This limit prevents resource exhaustion from maliciously large labels.
pub const HW_KEY_LABEL_MAX_BYTES: usize = 64;
