//! Password change operations
//!
//! This module implements changing or removing the password on a secret key.

use super::file_utils::{load_secret_key, write_secret_key_file};
use crate::{
    Result,
    constants::{
        LIBSODIUM_MEMLIMIT_MULTIPLIER, LIBSODIUM_OPSLIMIT_MULTIPLIER, SCRYPT_LOG_N, SCRYPT_R,
    },
    errors::Error,
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
    force_weak_kdf: bool,
}

impl<'a> ChangeOptions<'a> {
    /// Create new change options
    ///
    /// # Arguments
    ///
    /// * `secret_key_file` - Path to the secret key file
    /// * `remove_password` - Remove password (make unencrypted)
    /// * `allow_kdf_fallback` - Allow KDF parameter fallback (LESS SECURE, opt-in only)
    /// * `force_weak_kdf` - Force weak KDF parameters for testing (DEBUG ONLY, ignored in release builds)
    #[allow(clippy::fn_params_excessive_bools)]
    #[must_use]
    pub fn new(
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
    // Load the secret key
    let seckey = load_secret_key(options.secret_key_file)?;

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
