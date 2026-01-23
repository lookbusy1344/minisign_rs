//! Key generation operations
//!
//! This module implements keypair generation for minisign.

use crate::{
    crypto::generate_keypair,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
    Result,
};
use rand::RngCore;
use std::path::{Path, PathBuf};

// Scrypt parameters matching libsodium SENSITIVE level
const SCRYPT_LOG_N: u8 = 20; // N = 2^20 = 1,048,576
const SCRYPT_R: u32 = 8;

// Libsodium formula constants
const LIBSODIUM_OPSLIMIT_MULTIPLIER: u64 = 4;
const LIBSODIUM_MEMLIMIT_MULTIPLIER: u64 = 128;

/// Options for key generation
#[derive(Debug, Clone)]
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
}

/// Generate a new keypair
///
/// # Arguments
///
/// * `options` - Generation options including file paths and encryption settings
/// * `password` - Password to encrypt the secret key (required unless no_password is true)
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
pub fn generate(options: &GenerateOptions, password: Option<&[u8]>) -> Result<GenerateResult> {
    // Check if files already exist (unless force is set)
    if !options.force {
        if options.secret_key_file.exists() {
            return Err(Error::FileExists(options.secret_key_file.clone()));
        }
        if options.public_key_file.exists() {
            return Err(Error::FileExists(options.public_key_file.clone()));
        }
    }

    // Ensure password is provided if encryption is requested
    if !options.no_password && password.is_none() {
        return Err(Error::PasswordRequired);
    }

    // Generate the keypair
    let (secret_key, public_key, keynum) = generate_keypair();

    // Create the secret key structure
    let seckey = if options.no_password {
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        let pwd = password.unwrap(); // Safe because we checked above

        // Generate random salt
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kdf_salt);

        // Calculate KDF parameters using libsodium formula
        let n = 1u64 << SCRYPT_LOG_N;
        let r = u64::from(SCRYPT_R);
        let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
        let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

        SeckeyStruct::new_encrypted(keynum, &secret_key, pwd, kdf_salt, kdf_opslimit, kdf_memlimit)?
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

    // Write the secret key file
    let seckey_contents = seckey.to_file_contents("minisign encrypted secret key");
    write_secret_key_file(&options.secret_key_file, &seckey_contents)?;

    // Write the public key file
    let pubkey_contents = pubkey.to_file_contents(&comment);
    std::fs::write(&options.public_key_file, pubkey_contents)
        .map_err(|e| Error::file_write(&options.public_key_file, e))?;

    Ok(GenerateResult {
        secret_key_file: options.secret_key_file.clone(),
        public_key_file: options.public_key_file.clone(),
        keynum_hex,
    })
}

/// Ensure the parent directory exists
fn ensure_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::file_write(parent, e))?;
        }
    }
    Ok(())
}

/// Write a secret key file with appropriate permissions
fn write_secret_key_file(path: &Path, contents: &str) -> Result<()> {
    // Write the file
    std::fs::write(path, contents).map_err(|e| Error::file_write(path, e))?;

    // Set restrictive permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|e| Error::file_read(path, e))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(path, permissions).map_err(|e| Error::file_write(path, e))?;
    }

    Ok(())
}

/// Generate a keypair with custom scrypt parameters (for testing)
///
/// This is exposed for testing purposes to allow fast tests with weaker parameters.
#[cfg(test)]
fn generate_with_custom_params(
    options: &GenerateOptions,
    password: Option<&[u8]>,
    log_n: u8,
) -> Result<GenerateResult> {
    // Check if files already exist (unless force is set)
    if !options.force {
        if options.secret_key_file.exists() {
            return Err(Error::FileExists(options.secret_key_file.clone()));
        }
        if options.public_key_file.exists() {
            return Err(Error::FileExists(options.public_key_file.clone()));
        }
    }

    // Ensure password is provided if encryption is requested
    if !options.no_password && password.is_none() {
        return Err(Error::PasswordRequired);
    }

    // Generate the keypair
    let (secret_key, public_key, keynum) = generate_keypair();

    // Create the secret key structure
    let seckey = if options.no_password {
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        let pwd = password.unwrap();

        // Generate random salt
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kdf_salt);

        // Calculate KDF parameters using libsodium formula with custom N
        let n = 1u64 << log_n;
        let r = u64::from(SCRYPT_R);
        let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
        let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

        SeckeyStruct::new_encrypted(keynum, &secret_key, pwd, kdf_salt, kdf_opslimit, kdf_memlimit)?
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

    // Write the secret key file
    let seckey_contents = seckey.to_file_contents("minisign encrypted secret key");
    write_secret_key_file(&options.secret_key_file, &seckey_contents)?;

    // Write the public key file
    let pubkey_contents = pubkey.to_file_contents(&comment);
    std::fs::write(&options.public_key_file, pubkey_contents)
        .map_err(|e| Error::file_write(&options.public_key_file, e))?;

    Ok(GenerateResult {
        secret_key_file: options.secret_key_file.clone(),
        public_key_file: options.public_key_file.clone(),
        keynum_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SeckeyStruct;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    #[ignore] // Slow test due to scrypt SENSITIVE parameters (N=2^20, ~1-5 seconds)
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
        seckey.decrypt(password).expect("should decrypt with correct password");

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
        };

        let password = b"testpassword";
        let result = generate_with_custom_params(&options, Some(password), 14)
            .expect("generation should succeed");

        // Check files were created
        assert!(sk_path.exists());
        assert!(pk_path.exists());

        // Check keynum format
        assert_eq!(result.keynum_hex.len(), 16);

        // Verify secret key can be loaded and decrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(seckey.is_encrypted());
        seckey.decrypt(password).expect("should decrypt with correct password");

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
        let nested_path = temp_dir.path().join("a").join("b").join("c").join("file.txt");

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
}
