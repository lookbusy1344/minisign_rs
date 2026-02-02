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
pub struct GenerateOptions<'a> {
    /// Path to write the secret key file
    secret_key_file: &'a Path,
    /// Path to write the public key file
    public_key_file: &'a Path,
    /// Comment for the key files
    comment: Option<String>,
    /// Force overwrite existing files
    force: bool,
    /// Create unencrypted key (no password)
    no_password: bool,
    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    allow_kdf_fallback: bool,
    /// Force weak KDF parameters for testing (DEBUG ONLY, must be false in release)
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    force_weak_kdf: bool,
}

impl<'a> GenerateOptions<'a> {
    /// Create new generate options
    ///
    /// # Arguments
    ///
    /// * `secret_key_file` - Path to write the secret key file
    /// * `public_key_file` - Path to write the public key file
    /// * `comment` - Optional comment for the key files
    /// * `force` - Force overwrite existing files
    /// * `no_password` - Create unencrypted key (no password)
    /// * `allow_kdf_fallback` - Allow KDF parameter fallback (LESS SECURE, opt-in only)
    /// * `force_weak_kdf` - Force weak KDF parameters for testing (DEBUG ONLY, ignored in release builds)
    #[allow(clippy::fn_params_excessive_bools)]
    #[must_use]
    pub fn new(
        secret_key_file: &'a Path,
        public_key_file: &'a Path,
        comment: Option<String>,
        force: bool,
        no_password: bool,
        allow_kdf_fallback: bool,
        force_weak_kdf: bool,
    ) -> Self {
        // In release builds, force_weak_kdf must always be false
        #[cfg(not(debug_assertions))]
        assert!(
            !force_weak_kdf,
            "force_weak_kdf must be false in release builds"
        );

        Self {
            secret_key_file,
            public_key_file,
            comment,
            force,
            no_password,
            allow_kdf_fallback,
            force_weak_kdf,
        }
    }
}

/// Result of key generation
#[derive(Debug, Clone)]
pub struct GenerateResult {
    /// Path where the secret key was written
    secret_key_file: PathBuf,
    /// Path where the public key was written
    public_key_file: PathBuf,
    /// The keynum in hexadecimal format
    keynum_hex: String,
    /// The full public key in base64 format (for -P flag)
    public_key_base64: String,
}

impl GenerateResult {
    /// Get the path where the secret key was written
    #[must_use]
    pub fn secret_key_file(&self) -> &Path {
        &self.secret_key_file
    }

    /// Get the path where the public key was written
    #[must_use]
    pub fn public_key_file(&self) -> &Path {
        &self.public_key_file
    }

    /// Get the keynum in hexadecimal format
    #[must_use]
    pub fn keynum_hex(&self) -> &str {
        &self.keynum_hex
    }

    /// Get the full public key in base64 format (for -P flag)
    #[must_use]
    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }
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
pub fn generate(options: &GenerateOptions<'_>, password: Option<&[u8]>) -> Result<GenerateResult> {
    generate_with_log_n(options, password, SCRYPT_LOG_N)
}

/// Internal implementation of generate with custom scrypt `log_n` parameter
///
/// This allows both the production function and tests to share the same logic
/// while using different scrypt parameters.
///
/// # Errors
///
/// Returns an error if:
/// - Password is required but not provided
/// - RNG fails to generate random values
/// - File I/O operations fail
/// - Parent directories cannot be created
/// - Files already exist (unless force is true)
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn generate_with_log_n(
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
    let keynum_hex = keynum.to_key_id();
    let default_comment = format!("minisign public key {keynum_hex}");
    let comment = options.comment.as_deref().unwrap_or(&default_comment);

    // Ensure parent directories exist
    ensure_parent_directory(options.secret_key_file)?;
    ensure_parent_directory(options.public_key_file)?;

    // Write the secret key file with appropriate comment
    let seckey_comment = if options.no_password {
        "minisign secret key"
    } else {
        "minisign encrypted secret key"
    };
    let seckey_contents = seckey.to_file_contents(seckey_comment);
    write_secret_key_file(options.secret_key_file, &seckey_contents, options.force)?;

    // Write the public key file
    let pubkey_contents = pubkey.to_file_contents(comment);
    write_public_key_file(options.public_key_file, &pubkey_contents, options.force)?;

    // Encode the public key for command-line usage
    let public_key_base64 = encode_base64(pubkey.to_bytes());

    Ok(GenerateResult {
        secret_key_file: options.secret_key_file.to_path_buf(),
        public_key_file: options.public_key_file.to_path_buf(),
        keynum_hex,
        public_key_base64,
    })
}

/// Ensure the parent directory exists
///
/// # Errors
///
/// Returns an error if the directory cannot be created.
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn ensure_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.exists()) {
        std::fs::create_dir_all(parent).map_err(|e| Error::file_write(parent, e))?;
    }
    Ok(())
}
