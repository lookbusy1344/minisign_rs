//! Key file inspection operations
//!
//! This module provides functionality to inspect minisign key files
//! and display their security parameters and KDF configuration.

use crate::errors::{Error, Result};
use crate::keys::{PubkeyStruct, SeckeyStruct};
use std::fs;

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

/// Options for inspecting a key file
#[derive(Debug, Clone)]
pub struct InspectOptions {
    /// Path to the key file (can be secret or public key)
    pub key_file: String,
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
pub fn inspect(options: &InspectOptions) -> Result<InspectResult> {
    let contents = fs::read_to_string(&options.key_file)
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

// Production-strength KDF parameters (N=2^20, r=8, p=1)
const PRODUCTION_OPSLIMIT: u64 = 33_554_432;
const PRODUCTION_MEMLIMIT: u64 = 1_073_741_824;

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
    let security_level = if !is_fallback {
        SecurityLevel::High
    } else if memlimit >= 256_000_000 {
        // >=256 MB: 1-2 fallbacks (2-4x weaker)
        SecurityLevel::Medium
    } else {
        // <256 MB: 3+ fallbacks (8x+ weaker)
        SecurityLevel::Low
    };

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
    }
}

/// Convert opslimit/memlimit to scrypt parameters
///
/// This is a copy of the logic from `SeckeyStruct::opslimit_memlimit_to_params`
/// but made available for inspection purposes.
fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
    const SCRYPT_R_STANDARD: u32 = 8;
    const SCRYPT_P_STANDARD: u32 = 1;
    const LIBSODIUM_OPSLIMIT_MULTIPLIER: u64 = 4;
    const LIBSODIUM_MEMLIMIT_MULTIPLIER: u64 = 128;

    let r = SCRYPT_R_STANDARD;
    let p = SCRYPT_P_STANDARD;

    let divisor = LIBSODIUM_MEMLIMIT_MULTIPLIER
        .checked_mul(u64::from(r))
        .ok_or_else(|| Error::ScryptParamError("overflow calculating divisor".into()))?;

    let n = memlimit
        .checked_div(divisor)
        .ok_or_else(|| Error::ScryptParamError("division by zero".into()))?;

    if n == 0 {
        return Err(Error::ScryptParamError("N cannot be zero".into()));
    }

    let log_n = n
        .checked_ilog2()
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| Error::ScryptParamError("log_n out of valid range".into()))?;

    let expected_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER
        .checked_mul(n)
        .and_then(|v| v.checked_mul(u64::from(r)))
        .ok_or_else(|| Error::ScryptParamError("overflow calculating expected opslimit".into()))?;

    if expected_opslimit != opslimit {
        let derived_r = opslimit
            .checked_div(
                LIBSODIUM_OPSLIMIT_MULTIPLIER
                    .checked_mul(n)
                    .ok_or_else(|| {
                        Error::ScryptParamError("overflow calculating derived r".into())
                    })?,
            )
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(r);
        return Ok((log_n, derived_r, p));
    }

    Ok((log_n, r, p))
}
