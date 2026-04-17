//! Key generation operations
//!
//! This module implements keypair generation for minisign.

use super::file_utils::{write_public_key_file, write_secret_key_file};
use super::{EncryptionMode, OverwritePolicy};
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
pub struct GenerateOptions<'a> {
    /// Path to write the secret key file
    secret_key_file: &'a Path,
    /// Path to write the public key file
    public_key_file: &'a Path,
    /// Comment for the key files
    comment: Option<&'a str>,
    /// Whether to overwrite existing files
    overwrite: OverwritePolicy,
    /// Whether to encrypt the secret key with a password
    encryption: EncryptionMode,
    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    allow_kdf_fallback: bool,
    /// Force weak KDF parameters for testing (DEBUG ONLY, must be false in release)
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    force_weak_kdf: bool,
}

impl<'a> GenerateOptions<'a> {
    #[must_use]
    pub const fn builder(secret_key_file: &'a Path, public_key_file: &'a Path) -> Self {
        Self {
            secret_key_file,
            public_key_file,
            comment: None,
            overwrite: OverwritePolicy::Preserve,
            encryption: EncryptionMode::Protected,
            allow_kdf_fallback: false,
            force_weak_kdf: false,
        }
    }

    #[must_use]
    pub const fn build(self) -> Self {
        self
    }

    #[must_use]
    pub const fn comment(mut self, comment: &'a str) -> Self {
        self.comment = Some(comment);
        self
    }

    #[must_use]
    pub const fn force(mut self, force: bool) -> Self {
        self.overwrite = if force {
            OverwritePolicy::Overwrite
        } else {
            OverwritePolicy::Preserve
        };
        self
    }

    #[must_use]
    pub const fn no_password(mut self, no_password: bool) -> Self {
        self.encryption = if no_password {
            EncryptionMode::Unprotected
        } else {
            EncryptionMode::Protected
        };
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
        #[cfg(not(debug_assertions))]
        assert!(!force, "force_weak_kdf must be false in release builds");
        self.force_weak_kdf = force;
        self
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
    /// The keynum in PGP Word List format (human-readable)
    keynum_words: String,
    /// The full public key in base64 format (for -P flag)
    public_key_base64: String,
    /// Credential store lookup key (for --save-password)
    credential_id: String,
}

impl GenerateResult {
    #[must_use]
    pub fn secret_key_file(&self) -> &Path {
        &self.secret_key_file
    }

    #[must_use]
    pub fn public_key_file(&self) -> &Path {
        &self.public_key_file
    }

    #[must_use]
    pub fn keynum_hex(&self) -> &str {
        &self.keynum_hex
    }

    #[must_use]
    pub fn keynum_words(&self) -> &str {
        &self.keynum_words
    }

    /// Full public key in base64 (for `-P` flag)
    #[must_use]
    pub fn public_key_base64(&self) -> &str {
        &self.public_key_base64
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
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
/// let options = GenerateOptions::builder(secret_key_path, public_key_path)
///     .build();
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
    if options.encryption == EncryptionMode::Protected && password.is_none() {
        return Err(Error::PasswordRequired);
    }

    // Generate the keypair
    let (secret_key, public_key, keynum) = generate_keypair()?;

    // Create the secret key structure
    let seckey = if options.encryption == EncryptionMode::Unprotected {
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        use rand_core::{OsRng, RngCore};

        let pwd = password.ok_or(Error::PasswordRequired)?;

        // Generate random salt (cryptographically secure)
        let mut kdf_salt = [0u8; 32];
        OsRng.fill_bytes(&mut kdf_salt);

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

    // Capture credential ID for credential store
    let credential_id = seckey.credential_id();

    // Generate key ID display formats
    let keynum_hex = keynum.to_key_id();
    let keynum_words = crate::wordlist::keynum_to_words(&keynum);
    let default_comment = format!("minisign public key {keynum_hex}");
    let comment = options.comment.unwrap_or(&default_comment);

    // Ensure parent directories exist
    ensure_parent_directory(options.secret_key_file)?;
    ensure_parent_directory(options.public_key_file)?;

    // Write the secret key file with appropriate comment
    let seckey_comment = if options.encryption == EncryptionMode::Unprotected {
        "minisign secret key"
    } else {
        "minisign encrypted secret key"
    };
    let force = options.overwrite == OverwritePolicy::Overwrite;

    // Windows has no atomic rename + O_NOFOLLOW equivalent implemented yet.
    // Truncate-then-write risks key corruption on crash; refuse until properly implemented.
    #[cfg(not(unix))]
    if force && options.secret_key_file.exists() {
        return Err(Error::Other(
            "Overwriting an existing secret key (--force) is not yet supported on Windows. \
             Delete the key file manually and retry without --force."
                .into(),
        ));
    }

    let seckey_contents = seckey.to_file_contents(seckey_comment);
    write_secret_key_file(options.secret_key_file, &seckey_contents, force)?;

    // Write the public key file. On failure, clean up only if we created the secret
    // key fresh (non-force mode). In force mode the pre-existing secret key was
    // already overwritten and cannot be recovered — deleting it here would cause
    // irrecoverable key loss.
    let pubkey_contents = pubkey.to_file_contents(comment);
    if let Err(e) = write_public_key_file(options.public_key_file, &pubkey_contents, force) {
        if !force {
            let _ = std::fs::remove_file(options.secret_key_file);
        }
        return Err(e);
    }

    // Encode the public key for command-line usage
    let public_key_base64 = encode_base64(pubkey.to_bytes());

    Ok(GenerateResult {
        secret_key_file: options.secret_key_file.to_path_buf(),
        public_key_file: options.public_key_file.to_path_buf(),
        keynum_hex,
        keynum_words,
        public_key_base64,
        credential_id,
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
