//! Password change operations
//!
//! This module implements changing or removing the password on a secret key.

use super::file_utils::{load_secret_key, write_secret_key_file};
use crate::{
    Result, constants::SCRYPT_LOG_N, crypto::calculate_kdf_params, errors::Error,
    keys::SeckeyStruct,
};
use std::path::{Path, PathBuf};

/// Options for changing secret key password
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChangeOptions<'a> {
    /// Path to the secret key file
    secret_key_file: &'a Path,
    /// Remove password (make unencrypted)
    remove_password: bool,
    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    allow_kdf_fallback: bool,
    /// Force weak KDF parameters for testing (DEBUG ONLY, must be false in release)
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    force_weak_kdf: bool,
}

impl<'a> ChangeOptions<'a> {
    #[must_use]
    pub const fn builder(secret_key_file: &'a Path) -> Self {
        Self {
            secret_key_file,
            remove_password: false,
            allow_kdf_fallback: false,
            force_weak_kdf: false,
        }
    }

    #[must_use]
    pub const fn build(self) -> Self {
        self
    }

    #[must_use]
    pub const fn remove_password(mut self, remove: bool) -> Self {
        self.remove_password = remove;
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

/// Result of password change operation
#[derive(Debug, Clone)]
pub struct ChangeResult {
    /// Path to the secret key file that was modified
    secret_key_file: PathBuf,
    /// Whether the key is now encrypted
    encrypted: bool,
    /// New credential store lookup key (after password change)
    credential_id: String,
}

impl ChangeResult {
    #[must_use]
    pub fn secret_key_file(&self) -> &Path {
        &self.secret_key_file
    }

    #[must_use]
    pub const fn encrypted(&self) -> bool {
        self.encrypted
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }
}

/// Change or remove the password on a secret key
///
/// # Arguments
///
/// * `options` - Change options including the file path
/// * `old_password` - Current password (if encrypted)
/// * `new_password` - New password (if not removing encryption)
///
/// # Returns
///
/// A `ChangeResult` containing the file path and encryption status
///
/// # Errors
///
/// Returns an error if:
/// - The secret key file cannot be loaded
/// - The old password is incorrect
/// - The new password is not provided when encryption is requested
/// - File I/O operations fail
pub fn change(
    options: &ChangeOptions<'_>,
    old_password: Option<&[u8]>,
    new_password: Option<&[u8]>,
) -> Result<ChangeResult> {
    change_with_log_n(options, old_password, new_password, SCRYPT_LOG_N)
}

/// Internal implementation of change with custom scrypt `log_n` parameter
///
/// This allows both the production function and tests to share the same logic
/// while using different scrypt parameters.
///
/// # Errors
///
/// Returns an error if:
/// - Password is required but not provided
/// - File cannot be read or written
/// - Encryption/decryption fails
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn change_with_log_n(
    options: &ChangeOptions<'_>,
    old_password: Option<&[u8]>,
    new_password: Option<&[u8]>,
    log_n: u8,
) -> Result<ChangeResult> {
    // Load the secret key
    let seckey = load_secret_key(options.secret_key_file)?;

    // Decrypt the secret key
    let (secret_key, keynum) = seckey.extract_key(old_password)?;

    // Create new secret key structure with new password (or remove password)
    let new_seckey = if options.remove_password {
        // Remove encryption
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        use rand_core::{OsRng, RngCore};

        // Re-encrypt with new password
        let new_pwd = new_password.ok_or(Error::PasswordRequired)?;

        // Generate new salt (cryptographically secure)
        let mut kdf_salt = [0u8; 32];
        OsRng.fill_bytes(&mut kdf_salt);

        // Calculate KDF parameters using libsodium formula
        let (kdf_opslimit, kdf_memlimit) = calculate_kdf_params(log_n, options.force_weak_kdf)?;

        SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            new_pwd,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            options.allow_kdf_fallback,
        )?
    };

    // Write the modified secret key back to file
    let seckey_comment = if options.remove_password {
        "minisign secret key"
    } else {
        "minisign encrypted secret key"
    };

    let seckey_contents = new_seckey.to_file_contents(seckey_comment);
    write_secret_key_file(options.secret_key_file, &seckey_contents, true)?;

    // Capture new credential ID for credential store
    let credential_id = new_seckey.credential_id();

    Ok(ChangeResult {
        secret_key_file: options.secret_key_file.to_path_buf(),
        encrypted: !options.remove_password,
        credential_id,
    })
}
