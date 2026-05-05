//! Key generation operations
//!
//! This module implements keypair generation for minisign.

use super::{EncryptionMode, OverwritePolicy};
use crate::{
    Result,
    constants::SCRYPT_LOG_N,
    crypto::{calculate_kdf_params, generate_keypair},
    errors::Error,
    formats::encode_base64,
    keys::{PubkeyStruct, SeckeyStruct},
};
use rand_core::RngCore;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

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
    let pubkey_contents = pubkey.to_file_contents(comment);
    if force {
        write_keypair_files_with_overwrite(
            options.secret_key_file,
            options.public_key_file,
            &seckey_contents,
            &pubkey_contents,
        )?;
    } else {
        write_keypair_files_create_new(
            options.secret_key_file,
            options.public_key_file,
            &seckey_contents,
            &pubkey_contents,
        )?;
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

fn write_temp_file(path: &Path, contents: &[u8], unix_mode: Option<u32>) -> Result<PathBuf> {
    #[cfg(not(unix))]
    let _ = unix_mode;

    let tmp_path = sibling_temp_path(path, "tmp");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(mode) = unix_mode {
            options.mode(mode);
        }
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options
        .open(&tmp_path)
        .map_err(|e| Error::file_write(&tmp_path, e))?;
    file.write_all(contents)
        .map_err(|e| Error::file_write(&tmp_path, e))?;
    file.sync_all()
        .map_err(|e| Error::file_write(&tmp_path, e))?;
    Ok(tmp_path)
}

fn sibling_temp_path(path: &Path, suffix: &str) -> PathBuf {
    let dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut nonce_bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = u64::from_le_bytes(nonce_bytes);
    let name = path
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("key"), ToOwned::to_owned);
    let name = name.to_string_lossy();
    dir.join(format!(".{name}.{nonce:016x}.{suffix}"))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let dir = File::open(parent).map_err(|e| Error::file_write(parent, e))?;
        dir.sync_all().map_err(|e| Error::file_write(parent, e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(debug_assertions))]
fn test_commit_failure() -> Option<TestCommitFailure> {
    None
}

#[cfg(debug_assertions)]
thread_local! {
    static TEST_COMMIT_FAILURE: std::cell::Cell<Option<TestCommitFailure>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg_attr(not(debug_assertions), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestCommitFailure {
    BeforePublicRename,
    BeforeSecretRename,
}

#[cfg(debug_assertions)]
pub struct GenerateCommitFailureGuard;

#[cfg(debug_assertions)]
impl Drop for GenerateCommitFailureGuard {
    fn drop(&mut self) {
        TEST_COMMIT_FAILURE.with(|slot| slot.set(None));
    }
}

#[cfg(debug_assertions)]
#[must_use]
pub fn inject_commit_failure_before_public_rename() -> GenerateCommitFailureGuard {
    TEST_COMMIT_FAILURE.with(|slot| slot.set(Some(TestCommitFailure::BeforePublicRename)));
    GenerateCommitFailureGuard
}

#[cfg(debug_assertions)]
fn test_commit_failure() -> Option<TestCommitFailure> {
    TEST_COMMIT_FAILURE.with(std::cell::Cell::get)
}

fn write_keypair_files_create_new(
    secret_path: &Path,
    public_path: &Path,
    secret_contents: &str,
    public_contents: &str,
) -> Result<()> {
    if secret_path.exists() {
        return Err(Error::FileExists(secret_path.into()));
    }
    if public_path.exists() {
        return Err(Error::FileExists(public_path.into()));
    }

    let secret_tmp = write_temp_file(secret_path, secret_contents.as_bytes(), Some(0o600))?;

    let public_tmp = match write_temp_file(public_path, public_contents.as_bytes(), None) {
        Ok(path) => path,
        Err(e) => {
            let _ = std::fs::remove_file(&secret_tmp);
            return Err(e);
        }
    };

    if let Err(e) = std::fs::hard_link(&secret_tmp, secret_path) {
        let _ = std::fs::remove_file(&secret_tmp);
        let _ = std::fs::remove_file(&public_tmp);
        return Err(Error::file_write(secret_path, e));
    }
    if let Err(e) = sync_parent_directory(secret_path) {
        let _ = std::fs::remove_file(secret_path);
        let _ = std::fs::remove_file(&secret_tmp);
        let _ = std::fs::remove_file(&public_tmp);
        return Err(e);
    }

    if let Err(e) = std::fs::hard_link(&public_tmp, public_path) {
        let _ = std::fs::remove_file(secret_path);
        let _ = std::fs::remove_file(&secret_tmp);
        let _ = std::fs::remove_file(&public_tmp);
        return Err(Error::file_write(public_path, e));
    }
    if let Err(e) = sync_parent_directory(public_path) {
        let _ = std::fs::remove_file(public_path);
        let _ = std::fs::remove_file(secret_path);
        let _ = std::fs::remove_file(&secret_tmp);
        let _ = std::fs::remove_file(&public_tmp);
        return Err(e);
    }

    let _ = std::fs::remove_file(&secret_tmp);
    let _ = std::fs::remove_file(&public_tmp);
    Ok(())
}

fn write_keypair_files_with_overwrite(
    secret_path: &Path,
    public_path: &Path,
    secret_contents: &str,
    public_contents: &str,
) -> Result<()> {
    #[cfg(not(unix))]
    if secret_path.exists() {
        return Err(Error::Other(
            "Overwriting an existing secret key (--force) is not yet supported on Windows. \
             Delete the key file manually and retry without --force."
                .into(),
        ));
    }

    let _lock = acquire_force_overwrite_lock(secret_path)?;

    let secret_tmp = write_temp_file(secret_path, secret_contents.as_bytes(), Some(0o600))?;

    let public_tmp = match write_temp_file(public_path, public_contents.as_bytes(), None) {
        Ok(path) => path,
        Err(e) => {
            let _ = std::fs::remove_file(&secret_tmp);
            return Err(e);
        }
    };

    let secret_backup = if secret_path.exists() {
        let backup = sibling_temp_path(secret_path, "bak");
        if let Err(e) = std::fs::rename(secret_path, &backup) {
            let _ = std::fs::remove_file(&secret_tmp);
            let _ = std::fs::remove_file(&public_tmp);
            return Err(Error::file_write(secret_path, e));
        }
        if let Err(e) = sync_parent_directory(secret_path) {
            let _ = std::fs::remove_file(&secret_tmp);
            let _ = std::fs::remove_file(&public_tmp);
            let _ = std::fs::rename(&backup, secret_path);
            return Err(e);
        }
        Some(backup)
    } else {
        None
    };

    let public_backup = if public_path.exists() {
        let backup = sibling_temp_path(public_path, "bak");
        if let Err(e) = std::fs::rename(public_path, &backup) {
            let _ = std::fs::remove_file(&secret_tmp);
            let _ = std::fs::remove_file(&public_tmp);
            if let Some(backup) = secret_backup.as_ref() {
                let _ = std::fs::rename(backup, secret_path);
            }
            return Err(Error::file_write(public_path, e));
        }
        if let Err(e) = sync_parent_directory(public_path) {
            let _ = std::fs::remove_file(&secret_tmp);
            let _ = std::fs::remove_file(&public_tmp);
            let _ = std::fs::rename(&backup, public_path);
            if let Some(backup) = secret_backup.as_ref() {
                let _ = std::fs::rename(backup, secret_path);
            }
            return Err(e);
        }
        Some(backup)
    } else {
        None
    };

    match commit_keypair_files(
        secret_path,
        public_path,
        &secret_tmp,
        &public_tmp,
        secret_backup.as_deref(),
        public_backup.as_deref(),
    ) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&secret_tmp);
            let _ = std::fs::remove_file(&public_tmp);
            if let Some(backup) = secret_backup.as_ref() {
                let _ = std::fs::rename(backup, secret_path);
            }
            if let Some(backup) = public_backup.as_ref() {
                let _ = std::fs::rename(backup, public_path);
            }
            Err(e)
        }
    }
}

fn acquire_force_overwrite_lock(secret_path: &Path) -> Result<ForceOverwriteLockGuard> {
    let lock_path = secret_path.with_file_name(format!(
        ".{}.force.lock",
        secret_path
            .file_name()
            .map_or_else(|| std::ffi::OsString::from("key"), ToOwned::to_owned)
            .to_string_lossy()
    ));

    loop {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => return Ok(ForceOverwriteLockGuard { lock_path }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(Error::file_write(&lock_path, e)),
        }
    }
}

struct ForceOverwriteLockGuard {
    lock_path: PathBuf,
}

impl Drop for ForceOverwriteLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

fn commit_keypair_files(
    secret_path: &Path,
    public_path: &Path,
    secret_tmp: &Path,
    public_tmp: &Path,
    secret_backup: Option<&Path>,
    public_backup: Option<&Path>,
) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(value) = test_commit_failure()
        && value == TestCommitFailure::BeforePublicRename
    {
        return Err(Error::Other("injected public key commit failure".into()));
    }

    std::fs::rename(public_tmp, public_path).map_err(|e| Error::file_write(public_path, e))?;
    sync_parent_directory(public_path)?;

    #[cfg(debug_assertions)]
    if let Some(value) = test_commit_failure()
        && value == TestCommitFailure::BeforeSecretRename
    {
        return Err(Error::Other("injected secret key commit failure".into()));
    }

    if let Err(e) = std::fs::rename(secret_tmp, secret_path) {
        let _ = std::fs::remove_file(public_path);
        if let Some(backup) = public_backup {
            let _ = std::fs::rename(backup, public_path);
        }
        if let Some(backup) = secret_backup {
            let _ = std::fs::rename(backup, secret_path);
        }
        return Err(Error::file_write(secret_path, e));
    }
    sync_parent_directory(secret_path)?;

    if let Some(backup) = secret_backup {
        let _ = std::fs::remove_file(backup);
    }
    if let Some(backup) = public_backup {
        let _ = std::fs::remove_file(backup);
    }

    Ok(())
}
