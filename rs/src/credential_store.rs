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

/// Whether a password is present in the OS credential store.
///
/// Used by `has_password` and stored in `InspectResult` so callers can
/// distinguish "definitely not saved" from "store unreachable".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// A password was found and retrieved successfully.
    Saved,
    /// No entry exists for this credential ID (`keyring::Error::NoEntry`).
    NotSaved,
    /// The credential store is locked, broken, or otherwise unavailable.
    /// The inner string contains the underlying error for display.
    Unavailable(String),
}

cfg_select! {
    feature = "credential_store" => {
        use crate::Error;
        use keyring::Entry;

        /// Service name for all minisign credential store entries.
        const SERVICE_NAME: &str = "minisign";

        /// Save a password for a credential ID in the OS credential store.
        ///
        /// # Errors
        /// Returns `CredentialStoreError` if the credential store is unavailable or
        /// the save operation fails. This error should be reported to the user but
        /// should never prevent the primary operation from succeeding.
        pub fn save_password(credential_id: &str, password: &str) -> Result<()> {
            let entry = Entry::new(SERVICE_NAME, credential_id)
                .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;

            entry
                .set_password(password)
                .map_err(|e| Error::CredentialStoreError(format!("failed to save password: {e}")))?;

            Ok(())
        }

        /// Retrieve a saved password for a credential ID.
        ///
        /// # Returns
        /// - `Ok(Some(...))` if a password was found
        /// - `Ok(None)` if no entry exists (`keyring::Error::NoEntry`)
        /// - `Err(...)` for any other keyring failure (locked keychain, broken D-Bus, etc.)
        ///
        /// # Errors
        /// Returns `CredentialStoreError` when the credential store is unavailable or
        /// returns an unexpected error. Callers should warn the user and fall back to
        /// prompting rather than silently treating this as "no password saved".
        pub fn get_password(credential_id: &str) -> Result<Option<Zeroizing<String>>> {
            let entry = Entry::new(SERVICE_NAME, credential_id)
                .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;
            match entry.get_password() {
                Ok(password) => Ok(Some(Zeroizing::new(password))),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(Error::CredentialStoreError(format!("failed to get password: {e}"))),
            }
        }

        /// Remove a saved password for a credential ID.
        ///
        /// # Errors
        /// Returns `CredentialStoreError` if the credential store is unavailable or
        /// the delete operation fails. This error should be reported to the user.
        /// Attempting to delete a non-existent entry is not an error (idempotent).
        pub fn forget_password(credential_id: &str) -> Result<()> {
            let entry = Entry::new(SERVICE_NAME, credential_id)
                .map_err(|e| Error::CredentialStoreError(format!("failed to create entry: {e}")))?;

            // delete_credential is idempotent — NoEntry is already the desired state.
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(Error::CredentialStoreError(format!(
                    "failed to delete password: {e}"
                ))),
            }
        }

        /// Check whether a password is saved for a credential ID.
        ///
        /// Returns [`CredentialStatus::Unavailable`] for any keyring error other than
        /// `NoEntry`, allowing callers to distinguish "not saved" from "store broken".
        #[must_use]
        pub fn has_password(credential_id: &str) -> CredentialStatus {
            match get_password(credential_id) {
                Ok(Some(_)) => CredentialStatus::Saved,
                Ok(None) => CredentialStatus::NotSaved,
                Err(e) => CredentialStatus::Unavailable(e.to_string()),
            }
        }
    }
    _ => {
        /// No-op stub: Always returns Ok when credential store is disabled.
        ///
        /// # Errors
        ///
        /// This function never returns an error when the credential store feature is disabled.
        pub fn save_password(_credential_id: &str, _password: &str) -> Result<()> {
            Ok(())
        }

        /// No-op stub: Always returns `Ok(None)` when credential store is disabled.
        ///
        /// # Errors
        ///
        /// This function never returns an error when the credential store feature is disabled.
        pub fn get_password(_credential_id: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(None)
        }

        /// No-op stub: Always returns Ok when credential store is disabled.
        ///
        /// # Errors
        ///
        /// This function never returns an error when the credential store feature is disabled.
        pub fn forget_password(_credential_id: &str) -> Result<()> {
            Ok(())
        }

        /// No-op stub: Always returns `NotSaved` when credential store is disabled.
        #[must_use]
        pub fn has_password(_credential_id: &str) -> CredentialStatus {
            CredentialStatus::NotSaved
        }
    }
}
