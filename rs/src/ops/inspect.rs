//! Key file inspection operations
//!
//! This module provides functionality to inspect minisign key files
//! and display their security parameters and KDF configuration.

use crate::constants::{PRODUCTION_MEMLIMIT, PRODUCTION_OPSLIMIT};
use crate::errors::{Error, Result};
use crate::hw_keystore::HardwareKeyStore;
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

/// Options for inspecting a key file with hardware key store
pub struct InspectOptionsWithHw<'a> {
    /// Path to the key file
    key_file: &'a std::path::Path,
    /// Hardware key store for checking HW key availability
    hw_store: &'a dyn HardwareKeyStore,
}

impl<'a> InspectOptionsWithHw<'a> {
    /// Create new inspect options with hardware key store
    ///
    /// # Arguments
    ///
    /// * `key_file` - Path to the key file
    /// * `hw_store` - Hardware key store for checking HW key availability
    #[must_use]
    pub const fn new(key_file: &'a std::path::Path, hw_store: &'a dyn HardwareKeyStore) -> Self {
        Self { key_file, hw_store }
    }

    /// Get the key file path
    #[must_use]
    pub const fn key_file(&self) -> &std::path::Path {
        self.key_file
    }

    /// Get the hardware key store
    #[must_use]
    pub const fn hw_store(&self) -> &dyn HardwareKeyStore {
        self.hw_store
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
    /// Whether hardware key protection is enrolled
    pub hw_enrolled: bool,
    /// Hardware key label (if enrolled)
    pub hw_label: Option<String>,
    /// Hardware backend name (if enrolled and backend is available/unavailable)
    pub hw_backend_name: Option<&'static str>,
    /// Whether the hardware key is available (None if backend unavailable)
    pub hw_key_available: Option<bool>,
    /// Whether to show a warning that HW is enrolled but unavailable
    pub hw_unavailable_warning: bool,
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

        return Ok(InspectResult {
            key_id: decrypted_keynum.to_key_id(),
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
            hw_enrolled: false,
            hw_label: None,
            hw_backend_name: None,
            hw_key_available: None,
            hw_unavailable_warning: false,
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

    if !seckey.is_encrypted() {
        // Unencrypted key
        return Ok(InspectResult {
            key_id,
            key_id_words,
            key_type: KeyType::SecretUnencrypted,
            security_level: Some(SecurityLevel::None),
            kdf_info: None,
            hw_enrolled: false,
            hw_label: None,
            hw_backend_name: None,
            hw_key_available: None,
            hw_unavailable_warning: false,
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
        hw_enrolled: false,
        hw_label: None,
        hw_backend_name: None,
        hw_key_available: None,
        hw_unavailable_warning: false,
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
        hw_enrolled: false,
        hw_label: None,
        hw_backend_name: None,
        hw_key_available: None,
        hw_unavailable_warning: false,
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

/// Inspect a key file with hardware key store information
///
/// This function loads the key file and checks for hardware key enrollment.
/// If a hardware key slot is present, it checks whether the hardware backend
/// is available and whether the key exists in the hardware.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file format is invalid
/// - The key structure cannot be parsed
pub fn inspect_with_hw(options: &InspectOptionsWithHw<'_>) -> Result<InspectResult> {
    use crate::ops::file_utils::load_secret_key;

    let contents = fs::read_to_string(options.key_file())
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))?;

    // Try to parse as secret key first
    if let Ok((seckey, hw_slot)) = load_secret_key(options.key_file()) {
        let mut result = inspect_secret_key(&seckey)?;

        // Check for HW enrollment
        if let Some(slot) = hw_slot {
            result.hw_enrolled = true;
            result.hw_label = Some(slot.hw_key_label.clone());

            // Check hardware backend availability
            let hw_store = options.hw_store();
            if hw_store.is_available() {
                result.hw_backend_name = Some(hw_store.display_name());
                // Check if the key exists in hardware
                result.hw_key_available = Some(hw_store.key_exists(&slot.hw_key_label)?);
                result.hw_unavailable_warning = false;
            } else {
                // Hardware backend not available
                result.hw_backend_name = Some(hw_store.display_name());
                result.hw_key_available = None;
                result.hw_unavailable_warning = true;
            }
        }

        return Ok(result);
    }

    // Try to parse as public key
    if let Ok(pubkey) = PubkeyStruct::from_file_contents(&contents) {
        return Ok(inspect_public_key(&pubkey));
    }

    Err(Error::InvalidKeyFormat(
        "File is not a valid minisign key".to_string(),
    ))
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
