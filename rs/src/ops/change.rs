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
use std::path::PathBuf;

/// Options for changing secret key password
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChangeOptions {
    /// Path to the secret key file
    pub secret_key_file: PathBuf,
    /// Remove password (make unencrypted)
    pub remove_password: bool,
    /// Allow KDF parameter fallback (LESS SECURE, opt-in only)
    pub allow_kdf_fallback: bool,
    /// Force weak KDF parameters for testing (DEBUG ONLY)
    #[cfg(debug_assertions)]
    pub force_weak_kdf: bool,
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
    options: &ChangeOptions,
    old_password: Option<&[u8]>,
    new_password: Option<&[u8]>,
) -> Result<ChangeResult> {
    change_with_log_n(options, old_password, new_password, SCRYPT_LOG_N)
}

/// Internal implementation of change with custom scrypt `log_n` parameter
///
/// This allows both the production function and tests to share the same logic
/// while using different scrypt parameters.
fn change_with_log_n(
    options: &ChangeOptions,
    old_password: Option<&[u8]>,
    new_password: Option<&[u8]>,
    log_n: u8,
) -> Result<ChangeResult> {
    // Load the secret key
    let seckey = load_secret_key(&options.secret_key_file)?;

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
    write_secret_key_file(&options.secret_key_file, &seckey_contents, true)?;

    Ok(ChangeResult {
        secret_key_file: options.secret_key_file.clone(),
        encrypted: !options.remove_password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::generate_keypair, keys::SeckeyStruct};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_change_password_fast() {
        let temp_dir = TempDir::new().unwrap();

        // Create an encrypted key with fast parameters (N=2^14)
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let old_password = b"oldpassword";
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).unwrap();

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            old_password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false, // allow_fallback - tests use secure defaults
        )
        .unwrap();

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Change to new password
        let new_password = b"newpassword";
        let options = ChangeOptions {
            secret_key_file: sk_path.clone(),
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, Some(old_password), Some(new_password), 14)
            .expect("password change should succeed");

        assert_eq!(result.secret_key_file, sk_path);
        assert!(result.encrypted);

        // Verify can decrypt with new password
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(new_seckey.is_encrypted());
        new_seckey
            .decrypt(new_password)
            .expect("should decrypt with new password");

        // Verify old password no longer works
        let old_result = new_seckey.decrypt(old_password);
        assert!(old_result.is_err());
    }

    #[test]
    fn test_remove_password_from_encrypted_key() {
        let temp_dir = TempDir::new().unwrap();

        // Create an encrypted key with fast parameters
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let password = b"password";
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).unwrap();

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false, // allow_fallback - tests use secure defaults
        )
        .unwrap();

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Remove password
        let options = ChangeOptions {
            secret_key_file: sk_path.clone(),
            remove_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, Some(password), None, 14)
            .expect("password removal should succeed");

        assert_eq!(result.secret_key_file, sk_path);
        assert!(!result.encrypted);

        // Verify key is now unencrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(!new_seckey.is_encrypted());
        new_seckey
            .get_unencrypted_secret_key()
            .expect("should get key without password");
    }

    #[test]
    fn test_add_password_to_unencrypted_key() {
        let temp_dir = TempDir::new().unwrap();

        // Create an unencrypted key
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Add password
        let new_password = b"newpassword";
        let options = ChangeOptions {
            secret_key_file: sk_path.clone(),
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, None, Some(new_password), 14)
            .expect("adding password should succeed");

        assert!(result.encrypted);

        // Verify key is now encrypted
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        assert!(new_seckey.is_encrypted());
        new_seckey
            .decrypt(new_password)
            .expect("should decrypt with new password");
    }

    #[test]
    fn test_change_without_old_password_fails() {
        let temp_dir = TempDir::new().unwrap();

        // Create an encrypted key
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let password = b"password";
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).unwrap();

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false, // allow_fallback - tests use secure defaults
        )
        .unwrap();

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Try to change without old password
        let options = ChangeOptions {
            secret_key_file: sk_path,
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, None, Some(b"newpass"), 14);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
    }

    #[test]
    fn test_change_with_wrong_old_password_fails() {
        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let password = b"correctpassword";
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).unwrap();

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            false, // allow_fallback - tests use secure defaults
        )
        .unwrap();

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Try with wrong old password
        let options = ChangeOptions {
            secret_key_file: sk_path,
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, Some(b"wrongpassword"), Some(b"newpass"), 14);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_without_new_password_fails() {
        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Try to encrypt without providing new password
        let options = ChangeOptions {
            secret_key_file: sk_path,
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        let result = change_with_log_n(&options, None, None, 14);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
    }

    #[test]
    #[cfg(unix)]
    fn test_change_preserves_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Set initial permissions
        let metadata = fs::metadata(&sk_path).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&sk_path, permissions).unwrap();

        // Add password
        let options = ChangeOptions {
            secret_key_file: sk_path.clone(),
            remove_password: false,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        change_with_log_n(&options, None, Some(b"password"), 14)
            .expect("adding password should succeed");

        // Verify permissions are still 0600
        let metadata = fs::metadata(&sk_path).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_change_password_with_force_weak_kdf() {
        // Test that --force-weak-kdf creates weak keys when changing password
        use crate::crypto::generate_keypair;

        let temp_dir = TempDir::new().unwrap();
        let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
        let old_password = b"oldpassword";

        // Create a normal production-strength key
        let mut kdf_salt = [0u8; 32];
        getrandom::fill(&mut kdf_salt).unwrap();
        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            old_password,
            kdf_salt,
            33_554_432, // Production N=2^20
            1_073_741_824,
            false,
        )
        .unwrap();

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Change password with force_weak_kdf
        let new_password = b"newpassword";
        let options = ChangeOptions {
            secret_key_file: sk_path.clone(),
            remove_password: false,
            allow_kdf_fallback: false,
            force_weak_kdf: true, // Force weak parameters
        };

        let result = change_with_log_n(&options, Some(old_password), Some(new_password), 20)
            .expect("password change should succeed");

        assert!(result.encrypted);

        // Verify the key now has weak parameters
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

        assert!(new_seckey.is_weak_kdf(), "key should be weak after change");
        assert_eq!(new_seckey.kdf_opslimit(), 4_194_304); // N=2^17
        assert_eq!(new_seckey.kdf_memlimit(), 134_217_728); // 128 MB

        // Verify it can be decrypted with new password
        let (_sk, _kn) = new_seckey
            .decrypt(new_password)
            .expect("should decrypt with new password");
    }
}
