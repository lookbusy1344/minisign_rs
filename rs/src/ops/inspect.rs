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
    let key_id = format!(
        "RW{}",
        crate::formats::encode_base64(seckey.keynum().as_bytes())
    );

    if !seckey.is_encrypted() {
        // Unencrypted key
        return Ok(InspectResult {
            key_id,
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
    let key_id = format!(
        "RW{}",
        crate::formats::encode_base64(pubkey.keynum().as_bytes())
    );

    InspectResult {
        key_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use rand::Rng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper to create a temporary key file
    fn create_temp_key_file(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("Failed to create temp file");
        file.write_all(contents.as_bytes())
            .expect("Failed to write temp file");
        file.flush().expect("Failed to flush temp file");
        file
    }

    #[test]
    fn test_inspect_production_strength_encrypted_key() {
        // Create a production-strength encrypted key
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let password = b"test_password";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill(&mut kdf_salt);

        // Production parameters: N=2^20
        let kdf_opslimit = 33_554_432;
        let kdf_memlimit = 1_073_741_824;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false,
        )
        .unwrap();

        let file_contents = seckey.to_file_contents("test key");
        let temp_file = create_temp_key_file(&file_contents);

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options).unwrap();

        // Verify results
        assert_eq!(result.key_type, KeyType::SecretEncrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::High));
        assert!(result.kdf_info.is_some());

        let kdf_info = result.kdf_info.unwrap();
        assert_eq!(kdf_info.opslimit, 33_554_432);
        assert_eq!(kdf_info.memlimit, 1_073_741_824);
        assert_eq!(kdf_info.log_n, 20);
        assert_eq!(kdf_info.r, 8);
        assert_eq!(kdf_info.p, 1);
        assert!(!kdf_info.is_fallback);
        assert_eq!(kdf_info.weakness_multiplier, None);
    }

    #[test]
    fn test_inspect_medium_strength_fallback_key() {
        // Create a key with 1 fallback (N=2^19, 512 MB)
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let password = b"test_password";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill(&mut kdf_salt);

        let kdf_opslimit = 16_777_216; // 1 fallback
        let kdf_memlimit = 536_870_912; // 512 MB

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false,
        )
        .unwrap();

        let file_contents = seckey.to_file_contents("test key");
        let temp_file = create_temp_key_file(&file_contents);

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options).unwrap();

        assert_eq!(result.key_type, KeyType::SecretEncrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::Medium));

        let kdf_info = result.kdf_info.unwrap();
        assert_eq!(kdf_info.opslimit, 16_777_216);
        assert_eq!(kdf_info.memlimit, 536_870_912);
        assert_eq!(kdf_info.log_n, 19);
        assert!(kdf_info.is_fallback);
        assert_eq!(kdf_info.weakness_multiplier, Some(2));
    }

    #[test]
    fn test_inspect_low_strength_fallback_key() {
        // Create a key with 3 fallbacks (N=2^17, 128 MB)
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let password = b"test_password";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill(&mut kdf_salt);

        let kdf_opslimit = 4_194_304; // 3 fallbacks (8x weaker)
        let kdf_memlimit = 134_217_728; // 128 MB

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false,
        )
        .unwrap();

        let file_contents = seckey.to_file_contents("test key");
        let temp_file = create_temp_key_file(&file_contents);

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options).unwrap();

        assert_eq!(result.key_type, KeyType::SecretEncrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::Low));

        let kdf_info = result.kdf_info.unwrap();
        assert_eq!(kdf_info.opslimit, 4_194_304);
        assert_eq!(kdf_info.memlimit, 134_217_728);
        assert_eq!(kdf_info.log_n, 17);
        assert!(kdf_info.is_fallback);
        assert_eq!(kdf_info.weakness_multiplier, Some(8));
    }

    #[test]
    fn test_inspect_unencrypted_secret_key() {
        // Create an unencrypted secret key
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let file_contents = seckey.to_file_contents("unencrypted test key");
        let temp_file = create_temp_key_file(&file_contents);

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options).unwrap();

        assert_eq!(result.key_type, KeyType::SecretUnencrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::None));
        assert!(result.kdf_info.is_none());
    }

    #[test]
    fn test_inspect_public_key() {
        // Load a real public key from fixtures
        let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
            .expect("Failed to read test.pub fixture");

        let temp_file = create_temp_key_file(&contents);

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options).unwrap();

        assert_eq!(result.key_type, KeyType::Public);
        assert_eq!(result.security_level, None);
        assert!(result.kdf_info.is_none());
        assert!(!result.key_id.is_empty());
    }

    #[test]
    fn test_inspect_invalid_file() {
        let temp_file = create_temp_key_file("not a valid key file\n");

        let options = InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        };

        let result = inspect(&options);
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_missing_file() {
        let options = InspectOptions {
            key_file: "/nonexistent/path/to/key.file".to_string(),
        };

        let result = inspect(&options);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_level_classification() {
        // Test the security level boundaries

        // High: Production strength (N=2^20)
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let password = b"test";
        let mut salt = [0u8; 32];
        rand::thread_rng().fill(&mut salt);

        let high_key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            salt,
            33_554_432,
            1_073_741_824,
            false,
        )
        .unwrap();

        let high_contents = high_key.to_file_contents("high");
        let high_file = create_temp_key_file(&high_contents);
        let result = inspect(&InspectOptions {
            key_file: high_file.path().to_string_lossy().to_string(),
        })
        .unwrap();
        assert_eq!(result.security_level, Some(SecurityLevel::High));

        // Medium: After 1 fallback (N=2^19, 512 MB)
        rand::thread_rng().fill(&mut salt);
        let medium_key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            salt,
            16_777_216,
            536_870_912,
            false,
        )
        .unwrap();

        let medium_contents = medium_key.to_file_contents("medium");
        let medium_file = create_temp_key_file(&medium_contents);
        let result = inspect(&InspectOptions {
            key_file: medium_file.path().to_string_lossy().to_string(),
        })
        .unwrap();
        assert_eq!(result.security_level, Some(SecurityLevel::Medium));

        // Low: After 3 fallbacks (N=2^17, 128 MB)
        rand::thread_rng().fill(&mut salt);
        let low_key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            salt,
            4_194_304,
            134_217_728,
            false,
        )
        .unwrap();

        let low_contents = low_key.to_file_contents("low");
        let low_file = create_temp_key_file(&low_contents);
        let result = inspect(&InspectOptions {
            key_file: low_file.path().to_string_lossy().to_string(),
        })
        .unwrap();
        assert_eq!(result.security_level, Some(SecurityLevel::Low));
    }

    #[test]
    fn test_weakness_multiplier_calculation() {
        // Test the weakness multiplier calculation for different fallback levels
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let password = b"test";

        // Test cases: (memlimit, expected_multiplier)
        let test_cases = vec![
            (1_073_741_824, None),  // Production: no weakness
            (536_870_912, Some(2)), // 1 fallback: 2x weaker
            (268_435_456, Some(4)), // 2 fallbacks: 4x weaker
            (134_217_728, Some(8)), // 3 fallbacks: 8x weaker
            (67_108_864, Some(16)), // 4 fallbacks: 16x weaker
            (33_554_432, Some(32)), // 5 fallbacks: 32x weaker
            (16_777_216, Some(64)), // 6 fallbacks (minimum): 64x weaker
        ];

        for (memlimit, expected_multiplier) in test_cases {
            let mut salt = [0u8; 32];
            rand::thread_rng().fill(&mut salt);

            // Calculate corresponding opslimit
            let n = memlimit / 1024; // memlimit = 128 * N * r, so N = memlimit / (128 * 8)
            let opslimit = n * 32; // opslimit = 4 * N * r = 4 * N * 8

            let key = SeckeyStruct::new_encrypted(
                keynum,
                &secret_key,
                password,
                salt,
                opslimit,
                memlimit,
                false,
            )
            .unwrap();

            let contents = key.to_file_contents("test");
            let file = create_temp_key_file(&contents);

            let result = inspect(&InspectOptions {
                key_file: file.path().to_string_lossy().to_string(),
            })
            .unwrap();

            let kdf_info = result.kdf_info.unwrap();
            assert_eq!(
                kdf_info.weakness_multiplier, expected_multiplier,
                "Failed for memlimit={memlimit}"
            );
        }
    }

    #[test]
    fn test_inspect_c_generated_production_key() {
        // Test inspecting a real C-generated key with production parameters
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        let temp_file = create_temp_key_file(&contents);

        let result = inspect(&InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        })
        .unwrap();

        // C-generated test key should be production strength
        assert_eq!(result.key_type, KeyType::SecretEncrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::High));

        let kdf_info = result.kdf_info.unwrap();
        assert_eq!(kdf_info.opslimit, 33_554_432);
        assert_eq!(kdf_info.memlimit, 1_073_741_824);
        assert!(!kdf_info.is_fallback);
    }

    #[test]
    fn test_inspect_c_generated_unencrypted_key() {
        // Test inspecting a C-generated unencrypted key
        let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
            .expect("Failed to read unencrypted.key fixture");

        let temp_file = create_temp_key_file(&contents);

        let result = inspect(&InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        })
        .unwrap();

        assert_eq!(result.key_type, KeyType::SecretUnencrypted);
        assert_eq!(result.security_level, Some(SecurityLevel::None));
        assert!(result.kdf_info.is_none());
    }

    #[test]
    fn test_inspect_c_generated_public_key() {
        // Test inspecting a C-generated public key
        let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
            .expect("Failed to read test.pub fixture");

        let temp_file = create_temp_key_file(&contents);

        let result = inspect(&InspectOptions {
            key_file: temp_file.path().to_string_lossy().to_string(),
        })
        .unwrap();

        assert_eq!(result.key_type, KeyType::Public);
        assert_eq!(result.security_level, None);
        assert!(result.kdf_info.is_none());
    }

    #[test]
    fn test_inspect_base64_public_key() {
        // Test inspecting a public key from base64 string
        let base64 = "RWTa4nmE9BYWyPMkgjyqrmh+smzESa8GEX0SnJzS2MIWbR1lL79TJ/8b";

        let result = super::inspect_base64(base64).unwrap();

        assert_eq!(result.key_type, KeyType::Public);
        assert_eq!(result.security_level, None);
        assert!(result.kdf_info.is_none());
        assert!(!result.key_id.is_empty());
        assert!(result.key_id.starts_with("RW"));
    }

    #[test]
    fn test_inspect_base64_invalid() {
        // Test that invalid base64 returns an error
        let invalid_base64 = "not-valid-base64!!!";
        let result = super::inspect_base64(invalid_base64);
        assert!(result.is_err());
    }

    #[test]
    fn test_inspect_base64_wrong_format() {
        // Test that valid base64 but wrong format returns an error
        let wrong_format = "SGVsbG8gV29ybGQh"; // "Hello World!" in base64
        let result = super::inspect_base64(wrong_format);
        assert!(result.is_err());
    }
}
