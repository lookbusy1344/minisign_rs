//! Linux TPM 2.0 backend for hardware key store
//!
//! This module provides hardware key storage via Linux TPM 2.0.
//! Keys are protected by TPM auth policy and never leave the TPM.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use zeroize::Zeroizing;

/// Linux TPM 2.0 key store
pub struct LinuxKeyStore {
    // TODO: Implementation fields
}

impl LinuxKeyStore {
    /// Create a new Linux TPM key store
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LinuxKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareKeyStore for LinuxKeyStore {
    fn generate_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreError {
            detail: "Linux TPM not yet implemented".to_string(),
        })
    }

    fn get_public_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreError {
            detail: "Linux TPM 2.0 support not yet implemented".to_string(),
        })
    }

    fn ecdh(&self, _label: &str, _peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        Err(Error::HardwareKeyStoreError {
            detail: "Linux TPM not yet implemented".to_string(),
        })
    }

    fn key_exists(&self, _label: &str) -> Result<bool> {
        Ok(false)
    }

    fn delete_key(&self, _label: &str) -> Result<()> {
        Err(Error::HardwareKeyStoreError {
            detail: "Linux TPM not yet implemented".to_string(),
        })
    }

    fn is_available(&self) -> bool {
        false
    }

    fn display_name(&self) -> &'static str {
        "TPM 2.0"
    }
}
