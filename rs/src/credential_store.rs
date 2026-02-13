//! OS credential store integration for password caching
//!
//! This module provides a thin wrapper around the `keyring` crate to store and
//! retrieve passwords in the OS-native credential store:
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (via libsecret/gnome-keyring)
//!
//! Passwords are keyed by the key ID (8-byte hex string) rather than file path,
//! so credential associations survive key file moves.

use crate::{Error, Result};
use zeroize::Zeroizing;

/// Service name for all minisign credential store entries
const SERVICE_NAME: &str = "minisign";

/// Save a password for a key ID in the OS credential store
///
/// # Arguments
/// * `key_id` - The key ID hex string (e.g., "a1b2c3d4e5f6g7h8")
/// * `password` - The password to save
///
/// # Errors
/// Returns `CredentialStoreError` if the credential store is unavailable or
/// the save operation fails. This error should be reported to the user but
/// should never prevent the primary operation from succeeding.
pub fn save_password(key_id: &str, password: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_id)
        .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;

    entry
        .set_password(password)
        .map_err(|e| Error::CredentialStoreError(format!("failed to save password: {e}")))?;

    Ok(())
}

/// Retrieve a saved password for a key ID
///
/// # Arguments
/// * `key_id` - The key ID hex string
///
/// # Returns
/// `Some(Zeroizing<String>)` if a password is saved, `None` otherwise.
/// Returns `None` on any error (missing entry, no backend, etc.) to ensure
/// credential store failures never block operations.
#[must_use]
pub fn get_password(key_id: &str) -> Option<Zeroizing<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_id).ok()?;
    let password = entry.get_password().ok()?;
    Some(Zeroizing::new(password))
}

/// Remove a saved password for a key ID
///
/// # Arguments
/// * `key_id` - The key ID hex string
///
/// # Errors
/// Returns `CredentialStoreError` if the credential store is unavailable or
/// the delete operation fails. This error should be reported to the user.
/// Attempting to delete a non-existent entry is not an error (idempotent).
pub fn forget_password(key_id: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, key_id)
        .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;

    // delete_credential is idempotent - deleting a non-existent entry succeeds
    // NotFound is not an error - we already achieved the desired state
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::CredentialStoreError(format!(
            "failed to delete password: {e}"
        ))),
    }
}

/// Check if a password is saved for a key ID
///
/// # Arguments
/// * `key_id` - The key ID hex string
///
/// # Returns
/// `true` if a password is saved and retrievable, `false` otherwise.
#[must_use]
pub fn has_password(key_id: &str) -> bool {
    get_password(key_id).is_some()
}
