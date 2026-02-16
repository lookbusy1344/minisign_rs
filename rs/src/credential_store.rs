//! OS credential store integration for password caching
//!
//! This module provides a thin wrapper around the `keyring` crate to store and
//! retrieve passwords in the OS-native credential store:
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (via libsecret/gnome-keyring)
//!
//! Passwords are keyed by the credential ID rather than file path, so credential
//! associations survive key file moves. The credential ID is:
//! - For encrypted keys: hex of the encrypted keynum bytes (deterministic, available
//!   without decryption)
//! - For unencrypted keys: the key ID (plaintext keynum hex)
//!
//! This ensures credentials can be looked up before password prompting, even when
//! the key is encrypted and the real keynum is unknown.
//!
//! When the `credential_store` feature is disabled, all functions become no-ops
//! that never access the OS keyring, avoiding keychain popup dialogs during testing.

use crate::Result;
use zeroize::Zeroizing;

#[cfg(feature = "credential_store")]
use crate::Error;

#[cfg(feature = "credential_store")]
use keyring::Entry;

/// Service name for all minisign credential store entries
#[cfg(feature = "credential_store")]
const SERVICE_NAME: &str = "minisign";

//
// Feature-enabled implementations (use real OS keyring)
//

/// Save a password for a credential ID in the OS credential store
///
/// # Arguments
/// * `credential_id` - The credential ID hex string (from `SeckeyStruct::credential_id()`)
/// * `password` - The password to save
///
/// # Errors
/// Returns `CredentialStoreError` if the credential store is unavailable or
/// the save operation fails. This error should be reported to the user but
/// should never prevent the primary operation from succeeding.
#[cfg(feature = "credential_store")]
pub fn save_password(credential_id: &str, password: &str) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, credential_id)
        .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;

    entry
        .set_password(password)
        .map_err(|e| Error::CredentialStoreError(format!("failed to save password: {e}")))?;

    Ok(())
}

/// Retrieve a saved password for a credential ID
///
/// # Arguments
/// * `credential_id` - The credential ID hex string (from `SeckeyStruct::credential_id()`)
///
/// # Returns
/// `Some(Zeroizing<String>)` if a password is saved, `None` otherwise.
/// Returns `None` on any error (missing entry, no backend, etc.) to ensure
/// credential store failures never block operations.
#[must_use]
#[cfg(feature = "credential_store")]
pub fn get_password(credential_id: &str) -> Option<Zeroizing<String>> {
    let entry = Entry::new(SERVICE_NAME, credential_id).ok()?;
    let password = entry.get_password().ok()?;
    Some(Zeroizing::new(password))
}

/// Remove a saved password for a credential ID
///
/// # Arguments
/// * `credential_id` - The credential ID hex string (from `SeckeyStruct::credential_id()`)
///
/// # Errors
/// Returns `CredentialStoreError` if the credential store is unavailable or
/// the delete operation fails. This error should be reported to the user.
/// Attempting to delete a non-existent entry is not an error (idempotent).
#[cfg(feature = "credential_store")]
pub fn forget_password(credential_id: &str) -> Result<()> {
    let entry = Entry::new(SERVICE_NAME, credential_id)
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

/// Check if a password is saved for a credential ID
///
/// # Arguments
/// * `credential_id` - The credential ID hex string (from `SeckeyStruct::credential_id()`)
///
/// # Returns
/// `true` if a password is saved and retrievable, `false` otherwise.
#[must_use]
#[cfg(feature = "credential_store")]
pub fn has_password(credential_id: &str) -> bool {
    get_password(credential_id).is_some()
}

//
// Stub implementations when feature is disabled (no keyring access)
//

/// No-op stub: Always returns Ok when credential store is disabled
///
/// # Errors
///
/// This function never returns an error when the credential store feature is disabled.
#[cfg(not(feature = "credential_store"))]
pub fn save_password(_credential_id: &str, _password: &str) -> Result<()> {
    Ok(())
}

/// No-op stub: Always returns None when credential store is disabled
#[must_use]
#[cfg(not(feature = "credential_store"))]
pub fn get_password(_credential_id: &str) -> Option<Zeroizing<String>> {
    None
}

/// No-op stub: Always returns Ok when credential store is disabled
///
/// # Errors
///
/// This function never returns an error when the credential store feature is disabled.
#[cfg(not(feature = "credential_store"))]
pub fn forget_password(_credential_id: &str) -> Result<()> {
    Ok(())
}

/// No-op stub: Always returns false when credential store is disabled
#[must_use]
#[cfg(not(feature = "credential_store"))]
pub fn has_password(_credential_id: &str) -> bool {
    false
}
