//! Public key recreation from secret key
//!
//! This module implements recreating a public key file from a secret key file.

use super::file_utils::{load_secret_key, write_public_key_file};
use crate::{
    Result,
    crypto::PublicKey,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
};
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

/// Options for recreating a public key
#[derive(Debug, Clone)]
pub struct RecreateOptions<'a> {
    /// Path to the secret key file
    secret_key_file: &'a Path,
    /// Path to write the public key file
    public_key_file: &'a Path,
    /// Comment for the public key file
    comment: Option<&'a str>,
    /// Force overwrite existing public key file
    force: bool,
}

impl<'a> RecreateOptions<'a> {
    #[must_use]
    pub const fn new(
        secret_key_file: &'a Path,
        public_key_file: &'a Path,
        comment: Option<&'a str>,
        force: bool,
    ) -> Self {
        Self {
            secret_key_file,
            public_key_file,
            comment,
            force,
        }
    }

    #[must_use]
    pub const fn secret_key_file(&self) -> &Path {
        self.secret_key_file
    }

    #[must_use]
    pub const fn public_key_file(&self) -> &Path {
        self.public_key_file
    }

    #[must_use]
    pub const fn comment(&self) -> Option<&str> {
        self.comment
    }

    #[must_use]
    pub const fn force(&self) -> bool {
        self.force
    }
}

/// Result of public key recreation
#[derive(Debug, Clone)]
pub struct RecreateResult {
    /// Path where the public key was written
    public_key_file: PathBuf,
    /// The keynum in hexadecimal format
    keynum_hex: String,
}

impl RecreateResult {
    #[must_use]
    pub fn public_key_file(&self) -> &Path {
        &self.public_key_file
    }

    #[must_use]
    pub fn keynum_hex(&self) -> &str {
        &self.keynum_hex
    }
}

/// Recreate a public key file from a secret key file
///
/// # Arguments
///
/// * `options` - Recreation options including file paths
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `RecreateResult` containing the public key file path and keynum
///
/// # Errors
///
/// Returns an error if:
/// - The secret key file cannot be loaded
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The public key file already exists (unless force is true)
/// - File I/O operations fail
pub fn recreate(options: &RecreateOptions<'_>, password: Option<&[u8]>) -> Result<RecreateResult> {
    let seckey = load_secret_key(options.secret_key_file())?;
    recreate_with_key(&seckey, options, password)
}

/// Recreate a public key from a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded (e.g., for credential store lookups).
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
/// * `options` - Recreation options (public key file path, comment, force flag)
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `RecreateResult` containing the public key file path and keynum
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The public key file already exists (unless force is true)
/// - File I/O operations fail
pub fn recreate_with_key(
    seckey: &SeckeyStruct,
    options: &RecreateOptions<'_>,
    password: Option<&[u8]>,
) -> Result<RecreateResult> {
    // Decrypt if necessary and get the keynum
    let (secret_key, keynum) = seckey.extract_key(password)?;

    let public_key = extract_public_key_from_secret(&secret_key)?;

    // Create public key structure
    let pubkey = PubkeyStruct::new(keynum, public_key);

    // Generate comment
    let keynum_hex = keynum.to_key_id();
    let default_comment = format!("minisign public key {keynum_hex}");
    let comment = options.comment().unwrap_or(&default_comment);

    // Write the public key file with atomic creation
    let pubkey_contents = pubkey.to_file_contents(comment);
    write_public_key_file(options.public_key_file(), &pubkey_contents, options.force())?;

    Ok(RecreateResult {
        public_key_file: options.public_key_file().to_path_buf(),
        keynum_hex,
    })
}

/// Extract the public key from an Ed25519 secret key, verifying scalar/pubkey consistency.
///
/// `from_keypair_bytes` validates that the stored public-key half (bytes 32..64) matches
/// the scalar (bytes 0..32). We return the *derived* key so tampered stored bytes are
/// always rejected, not silently trusted.
///
/// # Errors
///
/// Returns `Error::InvalidSecretKey` if the stored public-key bytes do not match the scalar.
// pub for unit tests
pub fn extract_public_key_from_secret(secret_key: &crate::crypto::SecretKey) -> Result<PublicKey> {
    let signing_key = SigningKey::from_keypair_bytes(secret_key.as_bytes())
        .map_err(|e| Error::InvalidSecretKey(format!("public key does not match scalar: {e}")))?;
    Ok(PublicKey::from_bytes(
        signing_key.verifying_key().to_bytes(),
    ))
}
