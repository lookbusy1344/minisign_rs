//! Key generation operations
//!
//! This module implements keypair generation for minisign.

use super::file_utils::{write_public_key_file, write_secret_key_file};
use crate::{
    Result,
    constants::{
        LIBSODIUM_MEMLIMIT_MULTIPLIER, LIBSODIUM_OPSLIMIT_MULTIPLIER, SCRYPT_LOG_N, SCRYPT_R,
    },
    crypto::generate_keypair,
    errors::Error,
    formats::encode_base64,
    keys::{PubkeyStruct, SeckeyStruct},
};
use std::path::{Path, PathBuf};

/// Options for key generation
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct GenerateOptions {
    /// Path to write the secret key file
    pub secret_key_file: PathBuf,
    /// Path to write the public key file
    pub public_key_file: PathBuf,
    /// Comment for the key files
    pub comment: Option<String>,
    /// Force overwrite existing files
    pub force: bool,
    /// Create unencrypted key (no password)
    pub no_password: bool,
    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    pub allow_kdf_fallback: bool,
    /// Force weak KDF parameters for testing (DEBUG ONLY)
    #[cfg(debug_assertions)]
    pub force_weak_kdf: bool,
}

/// Result of key generation
#[derive(Debug, Clone)]
pub struct GenerateResult {
    /// Path where the secret key was written
    pub secret_key_file: PathBuf,
    /// Path where the public key was written
    pub public_key_file: PathBuf,
    /// The keynum in hexadecimal format
    pub keynum_hex: String,
    /// The full public key in base64 format (for -P flag)
    pub public_key_base64: String,
}

/// Generate a new keypair
///
/// # Arguments
///
/// * `options` - Generation options including file paths and encryption settings
/// * `password` - Password to encrypt the secret key (required unless `no_password` is true)
///
/// # Returns
///
/// A `GenerateResult` containing the paths and keynum
///
/// # Errors
///
/// Returns an error if:
/// - Files already exist (unless force is true)
/// - Password is required but not provided
/// - File I/O operations fail
/// - Parent directories cannot be created
///
/// # Panics
///
/// Will not panic. The function uses `?` operator for all fallible operations.
pub fn generate(options: &GenerateOptions, password: Option<&[u8]>) -> Result<GenerateResult> {
    generate_with_log_n(options, password, SCRYPT_LOG_N)
}

/// Internal implementation of generate with custom scrypt `log_n` parameter
///
/// This allows both the production function and tests to share the same logic
/// while using different scrypt parameters.
fn generate_with_log_n(
    options: &GenerateOptions,
    password: Option<&[u8]>,
    log_n: u8,
) -> Result<GenerateResult> {
    // Ensure password is provided if encryption is requested
    if !options.no_password && password.is_none() {
        return Err(Error::PasswordRequired);
    }

    // Generate the keypair
    let (secret_key, public_key, keynum) = generate_keypair()?;

    // Create the secret key structure
    let seckey = if options.no_password {
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        let pwd = password.ok_or(Error::PasswordRequired)?;

        // Generate random salt (cryptographically secure)
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).map_err(|e| Error::RngError(e.to_string()))?;

        // Calculate KDF parameters using libsodium formula
        #[cfg(debug_assertions)]
        let (kdf_opslimit, kdf_memlimit) = if options.force_weak_kdf {
            // DEBUG ONLY: Force weak parameters (N=2^17, 8x weaker than production)
            eprintln!("\n*** DEBUG WARNING: INTENTIONALLY INSECURE KEY ***");
            eprintln!("--force-weak-kdf creates keys that are 8x easier to brute-force.");
            eprintln!("NEVER use in production. For testing purposes only.\n");
            (4_194_304_u64, 134_217_728_u64) // N=2^17, r=8
        } else {
            let n = 1u64 << log_n;
            let r = u64::from(SCRYPT_R);
            (
                LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r,
                LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r,
            )
        };

        #[cfg(not(debug_assertions))]
        let (kdf_opslimit, kdf_memlimit) = {
            let n = 1u64 << log_n;
            let r = u64::from(SCRYPT_R);
            (
                LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r,
                LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r,
            )
        };

        SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            pwd,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            options.allow_kdf_fallback,
        )?
    };

    // Create the public key structure
    let pubkey = PubkeyStruct::new(keynum, public_key);

    // Generate comments
    let keynum_hex = keynum.to_hex();
    let comment = options
        .comment
        .clone()
        .unwrap_or_else(|| format!("minisign public key {keynum_hex}"));

    // Ensure parent directories exist
    ensure_parent_directory(&options.secret_key_file)?;
    ensure_parent_directory(&options.public_key_file)?;

    // Write the secret key file with appropriate comment
    let seckey_comment = if options.no_password {
        "minisign secret key"
    } else {
        "minisign encrypted secret key"
    };
    let seckey_contents = seckey.to_file_contents(seckey_comment);
    write_secret_key_file(&options.secret_key_file, &seckey_contents, options.force)?;

    // Write the public key file
    let pubkey_contents = pubkey.to_file_contents(&comment);
    write_public_key_file(&options.public_key_file, &pubkey_contents, options.force)?;

    // Encode the public key for command-line usage
    let public_key_base64 = encode_base64(pubkey.to_bytes());

    Ok(GenerateResult {
        secret_key_file: options.secret_key_file.clone(),
        public_key_file: options.public_key_file.clone(),
        keynum_hex,
        public_key_base64,
    })
}

/// Ensure the parent directory exists
fn ensure_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.exists()) {
        std::fs::create_dir_all(parent).map_err(|e| Error::file_write(parent, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SeckeyStruct;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    #[ignore = "slow test due to scrypt SENSITIVE parameters (N=2^20, ~1-5 seconds)"]
    fn test_generate_encrypted_key() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: Some("Test key".to_string()),
            force: false,
            no_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let password = b"testpassword";
        let result = generate(&options, Some(password)).expect("generation should succeed");

        // Check files were created
        assert!(sk_path.exists());
        assert!(pk_path.exists());

        // Check keynum format
        assert_eq!(result.keynum_hex.len(), 16); // 8 bytes = 16 hex chars

        // Verify secret key can be loaded and decrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(seckey.is_encrypted());
        let (_secret_key, _keynum) = seckey
            .decrypt(password)
            .expect("should decrypt with correct password");

        // Verify wrong password fails
        let wrong_result = seckey.decrypt(b"wrongpassword");
        assert!(wrong_result.is_err());
    }

    #[test]
    fn test_generate_encrypted_key_fast() {
        // Fast variant using N=2^14 (~50ms) instead of N=2^20 (~1-5s)
        // Tests the same logic with weaker security parameters
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test_fast.key");
        let pk_path = temp_dir.path().join("test_fast.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: Some("Fast test key".to_string()),
            force: false,
            no_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let password = b"testpassword";
        let result =
            generate_with_log_n(&options, Some(password), 14).expect("generation should succeed");

        // Check files were created
        assert!(sk_path.exists());
        assert!(pk_path.exists());

        // Check keynum format
        assert_eq!(result.keynum_hex.len(), 16);

        // Verify secret key can be loaded and decrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(seckey.is_encrypted());
        let (_secret_key, _keynum) = seckey
            .decrypt(password)
            .expect("should decrypt with correct password");

        // Verify wrong password fails
        let wrong_result = seckey.decrypt(b"wrongpassword");
        assert!(wrong_result.is_err());
    }

    #[test]
    fn test_generate_unencrypted_key() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = generate(&options, None).expect("generation should succeed");

        assert!(sk_path.exists());
        assert!(pk_path.exists());

        // Verify secret key is unencrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(!seckey.is_encrypted());

        // Check public key comment contains keynum
        let pk_contents = fs::read_to_string(&pk_path).unwrap();
        assert!(pk_contents.contains(&result.keynum_hex));
    }

    #[test]
    fn test_generate_without_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
            no_password: false, // Password required
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = generate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
    }

    #[test]
    fn test_generate_file_exists_without_force() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        // Create existing files
        fs::write(&sk_path, "existing").unwrap();
        fs::write(&pk_path, "existing").unwrap();

        let options = GenerateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = generate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
    }

    #[test]
    fn test_generate_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        // Create existing files
        fs::write(&sk_path, "existing").unwrap();
        fs::write(&pk_path, "existing").unwrap();

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: None,
            force: true,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        generate(&options, None).expect("should overwrite with force=true");

        // Verify files were overwritten
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        assert!(sk_contents.starts_with("untrusted comment:"));
    }

    #[test]
    fn test_generate_creates_parent_directories() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("nested").join("dirs");
        let sk_path = nested_dir.join("test.key");
        let pk_path = nested_dir.join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        generate(&options, None).expect("should create parent directories");

        assert!(sk_path.exists());
        assert!(pk_path.exists());
        assert!(nested_dir.exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_secret_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path,
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        generate(&options, None).expect("generation should succeed");

        // Check secret key has mode 0600
        let metadata = fs::metadata(&sk_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    fn test_ensure_parent_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir
            .path()
            .join("a")
            .join("b")
            .join("c")
            .join("file.txt");

        ensure_parent_directory(&nested_path).expect("should create parent dirs");

        let parent = nested_path.parent().unwrap();
        assert!(parent.exists());
        assert!(parent.is_dir());
    }

    #[test]
    fn test_roundtrip_generated_keys() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: Some("Roundtrip test".to_string()),
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = generate(&options, None).expect("generation should succeed");

        // Load and verify the keys
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

        let pk_contents = fs::read_to_string(&pk_path).unwrap();
        let pubkey = PubkeyStruct::from_file_contents(&pk_contents).unwrap();

        // Verify keynums match
        assert_eq!(seckey.keynum(), pubkey.keynum());
        assert_eq!(seckey.keynum().to_hex(), result.keynum_hex);
    }

    #[test]
    fn test_atomic_file_creation_prevents_race() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        // Create existing secret key file
        fs::write(&sk_path, "existing secret key").unwrap();

        let options = GenerateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path,
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        // Should fail due to existing file (atomic check)
        let result = generate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

        // Verify original content unchanged
        let contents = fs::read_to_string(&sk_path).unwrap();
        assert_eq!(contents, "existing secret key");
    }

    #[test]
    fn test_atomic_file_creation_pubkey_prevents_race() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        // Create existing public key file
        fs::write(&pk_path, "existing public key").unwrap();

        let options = GenerateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path.clone(),
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        // Should fail due to existing file (atomic check)
        let result = generate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

        // Verify original content unchanged
        let contents = fs::read_to_string(&pk_path).unwrap();
        assert_eq!(contents, "existing public key");
    }

    #[test]
    fn test_atomic_file_creation_both_files_check() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");
        let pk_path = temp_dir.path().join("test.pub");

        // Create both files
        fs::write(&sk_path, "existing sk").unwrap();
        fs::write(&pk_path, "existing pk").unwrap();

        let options = GenerateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        // Should fail (doesn't matter which file is checked first)
        let result = generate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
    }

    #[test]
    fn test_write_secret_key_file_atomic_creation() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("new.key");

        // Should succeed when file doesn't exist
        write_secret_key_file(&sk_path, "secret key content", false)
            .expect("should create new file");

        // Verify content
        let contents = fs::read_to_string(&sk_path).unwrap();
        assert_eq!(contents, "secret key content");
    }

    #[test]
    fn test_write_secret_key_file_prevents_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("existing.key");

        // Create initial file
        fs::write(&sk_path, "original content").unwrap();

        // Try to write without force - should fail
        let result = write_secret_key_file(&sk_path, "new content", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

        // Verify original content unchanged
        let contents = fs::read_to_string(&sk_path).unwrap();
        assert_eq!(contents, "original content");
    }

    #[test]
    fn test_write_secret_key_file_force_overwrites() {
        let temp_dir = TempDir::new().unwrap();
        let sk_path = temp_dir.path().join("test.key");

        // Create initial file
        fs::write(&sk_path, "original content").unwrap();

        // Write with force - should succeed
        write_secret_key_file(&sk_path, "overwritten content", true)
            .expect("should overwrite with force");

        // Verify content was overwritten
        let contents = fs::read_to_string(&sk_path).unwrap();
        assert_eq!(contents, "overwritten content");
    }

    #[test]
    fn test_write_public_key_file_atomic_creation() {
        let temp_dir = TempDir::new().unwrap();
        let pk_path = temp_dir.path().join("new.pub");

        // Should succeed when file doesn't exist
        write_public_key_file(&pk_path, "public key content", false)
            .expect("should create new file");

        // Verify content
        let contents = fs::read_to_string(&pk_path).unwrap();
        assert_eq!(contents, "public key content");
    }

    #[test]
    fn test_write_public_key_file_prevents_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let pk_path = temp_dir.path().join("existing.pub");

        // Create initial file
        fs::write(&pk_path, "original content").unwrap();

        // Try to write without force - should fail
        let result = write_public_key_file(&pk_path, "new content", false);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

        // Verify original content unchanged
        let contents = fs::read_to_string(&pk_path).unwrap();
        assert_eq!(contents, "original content");
    }

    #[test]
    fn test_write_public_key_file_force_overwrites() {
        let temp_dir = TempDir::new().unwrap();
        let pk_path = temp_dir.path().join("test.pub");

        // Create initial file
        fs::write(&pk_path, "original content").unwrap();

        // Write with force - should succeed
        write_public_key_file(&pk_path, "overwritten content", true)
            .expect("should overwrite with force");

        // Verify content was overwritten
        let contents = fs::read_to_string(&pk_path).unwrap();
        assert_eq!(contents, "overwritten content");
    }
}
