//! macOS Secure Enclave backend for hardware key store
//!
//! This module provides hardware key storage via macOS Secure Enclave.
//! Keys are protected by Touch ID / Face ID and never leave the secure boundary.
//!
//! ## Implementation Status
//!
//! This is a stub implementation. Full Secure Enclave integration requires:
//! - Complex FFI with Security.framework
//! - Proper error handling for biometric auth
//! - Keychain management
//!
//! The mock implementation provides full functionality for testing.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use zeroize::Zeroizing;

/// macOS Secure Enclave key store
///
/// Uses the Security framework to store P-256 keys in the Secure Enclave.
/// Keys require biometric authentication (Touch ID/Face ID) for use.
pub struct MacOSKeyStore;

impl MacOSKeyStore {
    /// Create a new macOS Secure Enclave key store
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacOSKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareKeyStore for MacOSKeyStore {
    fn generate_key(&self, _label: &str) -> Result<p256::PublicKey> {
        // TODO: Implement using security-framework
        // Requires: SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
        Err(Error::HardwareKeyStoreError {
            detail: "macOS Secure Enclave implementation in progress".to_string(),
        })
    }

    fn ecdh(&self, _label: &str, _peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        // TODO: Implement using security-framework
        // Requires: SecKeyCopyKeyExchangeResult with kSecKeyAlgorithmECDHKeyExchangeStandard
        Err(Error::HardwareKeyStoreError {
            detail: "macOS Secure Enclave implementation in progress".to_string(),
        })
    }

    fn key_exists(&self, _label: &str) -> Result<bool> {
        // TODO: Implement using security-framework ItemSearchOptions
        Ok(false)
    }

    fn delete_key(&self, _label: &str) -> Result<()> {
        // TODO: Implement using SecItemDelete
        Err(Error::HardwareKeyStoreError {
            detail: "macOS Secure Enclave implementation in progress".to_string(),
        })
    }

    fn is_available(&self) -> bool {
        // TODO: Check for Secure Enclave availability
        // Apple Silicon Macs and Intel Macs with T2 chip have Secure Enclave
        false
    }

    fn display_name(&self) -> &'static str {
        "Secure Enclave"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_keystore_basic() {
        let keystore = MacOSKeyStore::new();
        assert_eq!(keystore.display_name(), "Secure Enclave");

        // Currently stubbed, so not available
        assert!(!keystore.is_available());
    }
}
