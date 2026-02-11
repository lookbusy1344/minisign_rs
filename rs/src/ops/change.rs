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

/// Builder for `ChangeOptions`
#[derive(Debug, Clone)]
pub struct ChangeOptionsBuilder<'a> {
    secret_key_file: &'a Path,
    remove_password: bool,
    allow_kdf_fallback: bool,
    force_weak_kdf: bool,
}

impl<'a> ChangeOptionsBuilder<'a> {
    /// Create a new builder with required fields
    #[must_use]
    pub const fn new(secret_key_file: &'a Path) -> Self {
        Self {
            secret_key_file,
            remove_password: false,
            allow_kdf_fallback: false,
            force_weak_kdf: false,
        }
    }

    /// Remove password (make unencrypted)
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
        self.force_weak_kdf = force;
        self
    }

    /// Build the `ChangeOptions`
    #[must_use]
    pub const fn build(self) -> ChangeOptions<'a> {
        // In release builds, force_weak_kdf must always be false
        #[cfg(not(debug_assertions))]
        assert!(
            !self.force_weak_kdf,
            "force_weak_kdf must be false in release builds"
        );

        ChangeOptions {
            secret_key_file: self.secret_key_file,
            remove_password: self.remove_password,
            allow_kdf_fallback: self.allow_kdf_fallback,
            force_weak_kdf: self.force_weak_kdf,
        }
    }
}

impl<'a> ChangeOptions<'a> {
    /// Create a builder for `ChangeOptions`
    #[must_use]
    pub const fn builder(secret_key_file: &'a Path) -> ChangeOptionsBuilder<'a> {
        ChangeOptionsBuilder::new(secret_key_file)
    }

    /// Create new change options (deprecated, use `builder()` instead)
    ///
    /// # Arguments
    ///
    /// * `secret_key_file` - Path to the secret key file
    /// * `remove_password` - Remove password (make unencrypted)
    /// * `allow_kdf_fallback` - Allow KDF parameter fallback (LESS SECURE, opt-in only)
    /// * `force_weak_kdf` - Force weak KDF parameters for testing (DEBUG ONLY, ignored in release builds)
    #[deprecated(
        since = "1.3.0",
        note = "use `builder()` instead for better API clarity"
    )]
    #[allow(clippy::fn_params_excessive_bools)]
    #[must_use]
    pub const fn new(
        secret_key_file: &'a Path,
        remove_password: bool,
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
            remove_password,
            allow_kdf_fallback,
            force_weak_kdf,
        }
    }
}

/// Result of password change operation
#[derive(Debug, Clone)]
pub struct ChangeResult {
    /// Path to the secret key file that was modified
    pub secret_key_file: PathBuf,
    /// Whether the key is now encrypted
    pub encrypted: bool,
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
    // Load the secret key (ignore HW slot for now - will be handled in Step 5.4)
    let (seckey, _hw_slot) = load_secret_key(options.secret_key_file)?;

    // Decrypt the secret key with old password
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = old_password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Create new secret key structure with new password
    let new_seckey = if options.remove_password {
        // Remove encryption
        SeckeyStruct::new_unencrypted(keynum, &secret_key)
    } else {
        // Re-encrypt with new password
        let new_pwd = new_password.ok_or(Error::PasswordRequired)?;

        // Generate new salt (cryptographically secure)
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).map_err(|e| Error::RngError(e.to_string()))?;

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
    // Always overwrite when changing password (force=true)
    write_secret_key_file(options.secret_key_file, &seckey_contents, true)?;

    Ok(ChangeResult {
        secret_key_file: options.secret_key_file.to_path_buf(),
        encrypted: !options.remove_password,
    })
}
