//! Key file inspection operations
//!
//! This module provides functionality to inspect minisign key files
//! and display their security parameters and KDF configuration.

use crate::constants::{PRODUCTION_MEMLIMIT, PRODUCTION_OPSLIMIT};
use crate::errors::{Error, Result};
use crate::keys::{PubkeyStruct, SeckeyStruct};
use crate::signature::SignatureAlgorithm;
use std::fs;
use std::path::Path;

/// Security level classification for encrypted keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Production-strength parameters (N=2^20, 1024 MB)
    High,
    /// Reduced parameters after 1-2 fallbacks (512-256 MB)
    Medium,
    /// Weak parameters after 3+ fallbacks or minimum (<=128 MB)
    Low,
    /// Unencrypted key (no KDF protection)
    None,
}

impl SecurityLevel {
    /// Classify security level from KDF parameters
    ///
    /// # Arguments
    ///
    /// * `memlimit` - Memory limit for the KDF
    /// * `is_fallback` - Whether the parameters indicate a fallback from production strength
    ///
    /// # Returns
    ///
    /// The appropriate security level based on the parameters
    #[must_use]
    pub fn from_kdf_params(memlimit: u64, is_fallback: bool) -> Self {
        if !is_fallback {
            Self::High
        } else if memlimit >= 256_000_000 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Options for inspecting a key file
#[derive(Debug, Clone)]
pub struct InspectOptions<'a> {
    /// Path to the key file (can be secret or public key)
    key_file: &'a std::path::Path,
}

impl<'a> InspectOptions<'a> {
    /// Create new inspect options
    ///
    /// # Arguments
    ///
    /// * `key_file` - Path to the key file (can be secret or public key)
    #[must_use]
    pub const fn new(key_file: &'a std::path::Path) -> Self {
        Self { key_file }
    }

    /// Get the key file path
    #[must_use]
    pub const fn key_file(&self) -> &std::path::Path {
        self.key_file
    }
}

/// Options for inspecting an encrypted private key (with decryption)
#[derive(Debug, Clone)]
pub struct InspectPrivateOptions<'a> {
    /// Path to the secret key file
    key_file: &'a std::path::Path,
}

impl<'a> InspectPrivateOptions<'a> {
    /// Create new inspect private options
    ///
    /// # Arguments
    ///
    /// * `key_file` - Path to the secret key file
    #[must_use]
    pub const fn new(key_file: &'a std::path::Path) -> Self {
        Self { key_file }
    }

    /// Get the key file path
    #[must_use]
    pub const fn key_file(&self) -> &std::path::Path {
        self.key_file
    }
}

/// Result of inspecting a key file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectResult {
    /// Key ID in base64 format
    pub key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    pub key_id_words: String,
    /// Whether this is a secret or public key
    pub key_type: KeyType,
    /// Security level (for secret keys)
    pub security_level: Option<SecurityLevel>,
    /// KDF information (for encrypted secret keys)
    pub kdf_info: Option<KdfInfo>,
    /// Whether a password is saved in the OS credential store for this key
    pub password_saved: bool,
}

/// Type of key being inspected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    SecretEncrypted,
    SecretUnencrypted,
    Public,
}

/// KDF parameter information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfInfo {
    pub opslimit: u64,
    pub memlimit: u64,
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
    pub is_fallback: bool,
    pub weakness_multiplier: Option<u64>,
}

/// Inspect a key file and return detailed information
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file format is invalid
/// - The key structure cannot be parsed
pub fn inspect(options: &InspectOptions<'_>) -> Result<InspectResult> {
    let contents = fs::read_to_string(options.key_file())
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))?;

    // Try to parse as secret key first
    if let Ok(seckey) = SeckeyStruct::from_file_contents(&contents) {
        return inspect_secret_key(&seckey);
    }

    // Try to parse as public key
    if let Ok(pubkey) = PubkeyStruct::from_file_contents(&contents) {
        return Ok(inspect_public_key(&pubkey));
    }

    Err(Error::InvalidKeyFormat(
        "File is not a valid minisign key".to_string(),
    ))
}

/// Inspect a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded. For encrypted keys, shows the encrypted keynum
/// placeholder. Use `inspect_private_with_key` to decrypt and show the real keynum.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
///
/// # Returns
///
/// An `InspectResult` containing key information
///
/// # Errors
///
/// Returns an error if the KDF parameters cannot be parsed
pub fn inspect_with_key(seckey: &SeckeyStruct) -> Result<InspectResult> {
    inspect_secret_key(seckey)
}

/// Inspect a pre-loaded secret key by decrypting it first (if encrypted)
///
/// This variant accepts a pre-loaded `SeckeyStruct` and decrypts it to retrieve
/// the real key ID. For unencrypted keys, it behaves identically to `inspect_with_key`.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
/// * `password` - Password to decrypt the key (if encrypted)
///
/// # Returns
///
/// An `InspectResult` containing key information with real keynum
///
/// # Errors
///
/// Returns an error if:
/// - For encrypted keys: password is incorrect or decryption fails
pub fn inspect_private_with_key(
    seckey: &SeckeyStruct,
    password: &[u8],
) -> Result<InspectResult> {
    if !seckey.is_encrypted() {
        // Unencrypted secret key - behave like regular inspect
        return inspect_secret_key(seckey);
    }

    // Encrypted - decrypt to get the real keynum
    let (_secret_key, decrypted_keynum) = seckey.decrypt(password)?;

    // Get the base inspection result
    let mut result = inspect_secret_key(seckey)?;

    // Update with the real keynum
    result.key_id = decrypted_keynum.to_key_id();
    result.key_id_words = crate::wordlist::keynum_to_words(&decrypted_keynum);

    Ok(result)
}

/// Inspect a public key from base64 string
///
/// # Errors
///
/// Returns an error if:
/// - The base64 string cannot be decoded
/// - The decoded data is not a valid public key
pub fn inspect_base64(base64_str: &str) -> Result<InspectResult> {
    let pubkey = PubkeyStruct::from_base64(base64_str)?;
    Ok(inspect_public_key(&pubkey))
}

/// Inspect a private key by decrypting it first (if encrypted)
///
/// This function works like `inspect()` but decrypts encrypted private keys
/// to retrieve the real key ID. For unencrypted keys and public keys, it
/// behaves identically to `inspect()`.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file is not a valid key
/// - For encrypted keys: password is incorrect or decryption fails
pub fn inspect_private(
    options: &InspectPrivateOptions<'_>,
    password: &[u8],
) -> Result<InspectResult> {
    let contents = fs::read_to_string(options.key_file())
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))?;

    // Try to parse as secret key first
    if let Ok(seckey) = SeckeyStruct::from_file_contents(&contents) {
        if !seckey.is_encrypted() {
            // Unencrypted secret key - behave like regular inspect
            return inspect_secret_key(&seckey);
        }

        // Encrypted - decrypt to get the real keynum
        let (_secret_key, decrypted_keynum) = seckey.decrypt(password)?;

        // Get KDF info for security analysis
        let opslimit = seckey.kdf_opslimit();
        let memlimit = seckey.kdf_memlimit();
        let (log_n, r, p) = opslimit_memlimit_to_params(opslimit, memlimit)?;

        let is_fallback = opslimit < PRODUCTION_OPSLIMIT || memlimit < PRODUCTION_MEMLIMIT;
        let weakness_multiplier = if is_fallback {
            Some(PRODUCTION_MEMLIMIT / memlimit)
        } else {
            None
        };

        let security_level = SecurityLevel::from_kdf_params(memlimit, is_fallback);

        let key_id = decrypted_keynum.to_key_id();
        let credential_id = seckey.credential_id();
        let password_saved = crate::credential_store::has_password(&credential_id);

        return Ok(InspectResult {
            key_id,
            key_id_words: crate::wordlist::keynum_to_words(&decrypted_keynum),
            key_type: KeyType::SecretEncrypted,
            security_level: Some(security_level),
            kdf_info: Some(KdfInfo {
                opslimit,
                memlimit,
                log_n,
                r,
                p,
                is_fallback,
                weakness_multiplier,
            }),
            password_saved,
        });
    }

    // Try to parse as public key
    if let Ok(pubkey) = PubkeyStruct::from_file_contents(&contents) {
        return Ok(inspect_public_key(&pubkey));
    }

    Err(Error::InvalidKeyFormat(
        "File is not a valid minisign key".to_string(),
    ))
}

/// Inspect a secret key structure
fn inspect_secret_key(seckey: &SeckeyStruct) -> Result<InspectResult> {
    let key_id = seckey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(seckey.keynum());
    let credential_id = seckey.credential_id();

    if !seckey.is_encrypted() {
        // Unencrypted key
        let password_saved = crate::credential_store::has_password(&credential_id);
        return Ok(InspectResult {
            key_id,
            key_id_words,
            key_type: KeyType::SecretUnencrypted,
            security_level: Some(SecurityLevel::None),
            kdf_info: None,
            password_saved,
        });
    }

    // Encrypted key - analyze KDF parameters
    let opslimit = seckey.kdf_opslimit();
    let memlimit = seckey.kdf_memlimit();

    // Convert to scrypt parameters
    let (log_n, r, p) = opslimit_memlimit_to_params(opslimit, memlimit)?;

    // Determine if this is a fallback key

    let is_fallback = opslimit < PRODUCTION_OPSLIMIT || memlimit < PRODUCTION_MEMLIMIT;

    // Calculate weakness multiplier if fallback
    let weakness_multiplier = if is_fallback {
        Some(PRODUCTION_MEMLIMIT / memlimit)
    } else {
        None
    };

    // Classify security level
    let security_level = SecurityLevel::from_kdf_params(memlimit, is_fallback);

    let password_saved = crate::credential_store::has_password(&credential_id);

    Ok(InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::SecretEncrypted,
        security_level: Some(security_level),
        kdf_info: Some(KdfInfo {
            opslimit,
            memlimit,
            log_n,
            r,
            p,
            is_fallback,
            weakness_multiplier,
        }),
        password_saved,
    })
}

/// Inspect a public key structure
fn inspect_public_key(pubkey: &PubkeyStruct) -> InspectResult {
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::Public,
        security_level: None,
        kdf_info: None,
        password_saved: false, // Public keys don't have passwords
    }
}

/// Result of inspecting a signature file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInspectResult {
    /// Key ID in hex format
    pub key_id: String,
    /// Key ID in PGP Word List format
    pub key_id_words: String,
    /// Signature algorithm type
    pub algorithm: SignatureAlgorithm,
}

/// Inspect a signature file and return key ID information
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file format is invalid
pub fn inspect_signature(signature_file: &Path) -> Result<SignatureInspectResult> {
    use crate::signature::SignatureBox;

    let contents = std::fs::read_to_string(signature_file)
        .map_err(|e| Error::Io(format!("Failed to read signature file: {e}")))?;

    let sig_box = SignatureBox::from_file_contents(&contents)?;

    let keynum = sig_box.sig_struct().keynum();
    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(keynum);
    let algorithm = sig_box.sig_struct().algorithm();

    Ok(SignatureInspectResult {
        key_id,
        key_id_words,
        algorithm,
    })
}

/// Convert opslimit/memlimit to scrypt parameters (`log_n`, r, p)
///
/// Delegates to the shared implementation in [`crate::crypto::opslimit_memlimit_to_params`].
fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
    crate::crypto::opslimit_memlimit_to_params(opslimit, memlimit)
}
