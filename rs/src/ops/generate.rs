//! Key generation operations
//!
//! This module implements keypair generation for minisign.

use super::file_utils::{write_public_key_file, write_secret_key_file};
use crate::{
    Result,
    constants::SCRYPT_LOG_N,
    crypto::{calculate_kdf_params, generate_keypair},
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
    comment: Option<&'a str>,
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

/// Builder for `GenerateOptions`
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct GenerateOptionsBuilder<'a> {
    secret_key_file: &'a Path,
    public_key_file: &'a Path,
    comment: Option<&'a str>,
    force: bool,
    no_password: bool,
    allow_kdf_fallback: bool,
    force_weak_kdf: bool,
}

impl<'a> GenerateOptionsBuilder<'a> {
    /// Create a new builder with required fields
    #[must_use]
    pub const fn new(secret_key_file: &'a Path, public_key_file: &'a Path) -> Self {
        Self {
            secret_key_file,
            public_key_file,
            comment: None,
            force: false,
            no_password: false,
            allow_kdf_fallback: false,
            force_weak_kdf: false,
        }
    }

    /// Set the comment for the key files
    #[must_use]
    pub const fn comment(mut self, comment: &'a str) -> Self {
        self.comment = Some(comment);
        self
    }

    /// Enable force mode (overwrite existing files)
    #[must_use]
    pub const fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    /// Create unencrypted key (no password)
    #[must_use]
    pub const fn no_password(mut self, no_password: bool) -> Self {
        self.no_password = no_password;
        self
    }

    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    #[must_use]
    pub const fn allow_kdf_fallback(mut self, allow: bool) -> Self {
        self.allow_kdf_fallback = allow;
        self
    }

    /// Force weak KDF parameters for testing (DEBUG ONLY)
    #[must_use]
    pub const fn force_weak_kdf(mut self, force: bool) -> Self {
        self.force_weak_kdf = force;
        self
    }

    /// Build the `GenerateOptions`
    #[must_use]
    pub const fn build(self) -> GenerateOptions<'a> {
        // In release builds, force_weak_kdf must always be false
        #[cfg(not(debug_assertions))]
        assert!(
            !self.force_weak_kdf,
            "force_weak_kdf must be false in release builds"
        );

        GenerateOptions {
            secret_key_file: self.secret_key_file,
            public_key_file: self.public_key_file,
            comment: self.comment,
            force: self.force,
            no_password: self.no_password,
            allow_kdf_fallback: self.allow_kdf_fallback,
            force_weak_kdf: self.force_weak_kdf,
        }
    }
}

impl<'a> GenerateOptions<'a> {
    /// Create a builder for `GenerateOptions`
    #[must_use]
    pub const fn builder(
        secret_key_file: &'a Path,
        public_key_file: &'a Path,
    ) -> GenerateOptionsBuilder<'a> {
        GenerateOptionsBuilder::new(secret_key_file, public_key_file)
    }

    /// Create new generate options (deprecated, use `builder()` instead)
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
    #[deprecated(
        since = "1.3.0",
        note = "use `builder()` instead to avoid excessive booleans"
    )]
    #[allow(clippy::fn_params_excessive_bools)]
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        secret_key_file: &'a Path,
        public_key_file: &'a Path,
        comment: Option<&'a str>,
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
/// # Examples
///
/// ```no_run
/// use minisign::ops::{generate, GenerateOptions};
/// use std::path::Path;
///
/// let secret_key_path = Path::new("~/.minisign/minisign.key");
/// let public_key_path = Path::new("~/.minisign/minisign.pub");
/// let password = Some(b"my_secure_password".as_ref());
///
/// let options = GenerateOptions::new(
///     secret_key_path,
///     public_key_path,
///     None,   // comment
///     false,  // force
///     false,  // no_password
///     false,  // allow_kdf_fallback
///     false,  // force_weak_kdf
/// );
///
/// let result = generate(&options, password)?;
/// println!("Key pair generated successfully");
/// println!("Secret key: {}", result.secret_key_file().display());
/// println!("Public key: {}", result.public_key_file().display());
/// # Ok::<(), minisign::Error>(())
/// ```
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
        let (kdf_opslimit, kdf_memlimit) = calculate_kdf_params(log_n, options.force_weak_kdf)?;

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
    let comment = options.comment.unwrap_or(&default_comment);

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
