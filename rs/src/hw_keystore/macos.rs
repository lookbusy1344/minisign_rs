//! macOS Secure Enclave backend for hardware key store
//!
//! This module provides hardware key storage via macOS Secure Enclave.
//! Keys are protected by Touch ID / Face ID and never leave the secure boundary.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::Location;
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult};
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use zeroize::Zeroizing;

/// macOS Secure Enclave key store
///
/// Uses the Security framework to store P-256 keys in the Secure Enclave.
/// Keys require biometric authentication (Touch ID/Face ID) for use.
///
/// This is a partial implementation. The mock provides full functionality for testing.
pub struct MacOSKeyStore;

impl MacOSKeyStore {
    /// Create a new macOS Secure Enclave key store
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Check if Secure Enclave is available on this device
    ///
    /// Secure Enclave is available on:
    /// - Mac computers with Apple Silicon (M1, M2, M3, M4, etc.)
    /// - Mac computers with T2 Security Chip (2018-2020 Intel Macs)
    ///
    /// This performs two checks:
    /// 1. Architecture check - SE only on ARM64 or `x86_64` with T2
    /// 2. Access control test - verifies biometric + SE flags can be created
    #[must_use]
    fn is_secure_enclave_available() -> bool {
        // Check 1: Architecture — only Apple Silicon and T2 Intel Macs have SE
        if !Self::is_likely_se_hardware() {
            return false;
        }

        // Check 2: Try creating an access control with SE flags
        // This validates that the system supports biometric + SE
        // without generating any keys or triggering a prompt
        Self::test_se_access_control()
    }

    /// Check if the hardware architecture is likely to have Secure Enclave
    #[must_use]
    fn is_likely_se_hardware() -> bool {
        #[cfg(target_arch = "aarch64")]
        {
            true // All Apple Silicon Macs have Secure Enclave
        }

        #[cfg(target_arch = "x86_64")]
        {
            true // Optimistic for T2 — validated by test_se_access_control()
        }

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            false
        }
    }

    /// Test if SE access control can be created
    ///
    /// This validates biometric + SE support without generating keys
    /// or triggering authentication prompts.
    #[must_use]
    fn test_se_access_control() -> bool {
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        )
        .is_ok()
    }
}

impl Default for MacOSKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareKeyStore for MacOSKeyStore {
    fn generate_key(&self, label: &str) -> Result<p256::PublicKey> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // 1. Create biometric-gated access control (safe API)
        let access_control = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
        )
        .map_err(|e| Error::HardwareKeyStoreError {
            detail: format!("failed to create access control: {e}"),
        })?;

        // 2. Configure key generation via builder (safe API)
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(label)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access_control);

        // 3. Generate key — triggers Touch ID prompt for SE key creation
        let private_key = SecKey::new(&opts)
            .map_err(|e| map_cf_error_to_hw_error(&e, "key generation failed"))?;

        // 4. Extract public key (safe API)
        let public_key_ref =
            private_key
                .public_key()
                .ok_or_else(|| Error::HardwareKeyStoreError {
                    detail: "failed to extract public key from SE private key".to_string(),
                })?;

        // 5. Export public key bytes (safe API)
        let pub_key_data = public_key_ref.external_representation().ok_or_else(|| {
            Error::HardwareKeyStoreError {
                detail: "failed to export public key representation".to_string(),
            }
        })?;

        // 6. Convert to p256::PublicKey
        sec1_bytes_to_p256_public_key(pub_key_data.bytes())
    }

    fn get_public_key(&self, label: &str) -> Result<p256::PublicKey> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // 1. Search keychain for private key by label (safe API)
        let private_key = find_se_key_by_label(label)?;

        // 2. Extract public key (safe API)
        let public_key_ref =
            private_key
                .public_key()
                .ok_or_else(|| Error::HardwareKeyStoreError {
                    detail: "failed to get public key from SE private key".to_string(),
                })?;

        // 3. Export and convert (same as generate_key)
        let pub_key_data = public_key_ref.external_representation().ok_or_else(|| {
            Error::HardwareKeyStoreError {
                detail: "failed to export public key representation".to_string(),
            }
        })?;

        sec1_bytes_to_p256_public_key(pub_key_data.bytes())
    }

    fn ecdh(&self, _label: &str, _peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // TODO: Implement ECDH with:
        // 1. Find private key in Keychain by label
        // 2. Import peer public key as SecKey
        // 3. SecKeyCopyKeyExchangeResult with kSecKeyAlgorithmECDHKeyExchangeStandard
        // 4. Return 32-byte shared secret
        //
        // This triggers biometric auth prompt automatically

        Err(Error::HardwareKeyStoreError {
            detail: "macOS Secure Enclave ECDH not yet implemented - use mock for testing"
                .to_string(),
        })
    }

    fn key_exists(&self, _label: &str) -> Result<bool> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // TODO: Search Keychain for key with matching application tag
        // Use ItemSearchOptions with kSecAttrApplicationTag filter

        Ok(false)
    }

    fn delete_key(&self, _label: &str) -> Result<()> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // TODO: Use SecItemDelete with query matching application tag
        // Returns errSecSuccess or errSecItemNotFound (both OK)

        Ok(())
    }

    fn is_available(&self) -> bool {
        Self::is_secure_enclave_available()
    }

    fn display_name(&self) -> &'static str {
        "Secure Enclave"
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Search Keychain for a private key matching the given label.
/// Returns the `SecKey` reference for further operations.
fn find_se_key_by_label(label: &str) -> Result<SecKey> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .label(label)
        .load_refs(true)
        .limit(1)
        .search()
        .map_err(|e| {
            // errSecItemNotFound = -25300
            if e.code() == -25300 {
                Error::HardwareKeyNotFound {
                    label: label.to_string(),
                }
            } else {
                Error::HardwareKeyStoreError {
                    detail: format!("keychain search failed: {e}"),
                }
            }
        })?;

    match results.into_iter().next() {
        Some(SearchResult::Ref(Reference::Key(sec_key))) => Ok(sec_key),
        _ => Err(Error::HardwareKeyNotFound {
            label: label.to_string(),
        }),
    }
}

/// Convert uncompressed SEC1 bytes (65 bytes: 0x04 || x || y) to `p256::PublicKey`
fn sec1_bytes_to_p256_public_key(bytes: &[u8]) -> Result<p256::PublicKey> {
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|e| Error::HardwareKeyStoreError {
        detail: format!("invalid P-256 public key ({} bytes): {e}", bytes.len()),
    })
}

/// Map Core Foundation `CFError` to minisign `HardwareKeyStoreError` with context
fn map_cf_error_to_hw_error(cf_error: &core_foundation::error::CFError, context: &str) -> Error {
    // errSecUserCanceled = -128, errSecAuthFailed = -25293
    const ERR_SEC_USER_CANCELED: isize = -128;
    const ERR_SEC_AUTH_FAILED: isize = -25293;

    let description = cf_error.description();
    let code = cf_error.code();

    match code {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => Error::HardwareKeyStoreAuthDenied,
        _ => Error::HardwareKeyStoreError {
            detail: format!("{context}: {description} (code {code})"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_keystore_basic() {
        let keystore = MacOSKeyStore::new();
        assert_eq!(keystore.display_name(), "Secure Enclave");

        // Currently not implemented, so not available
        assert!(!keystore.is_available());
    }

    #[test]
    fn test_macos_unavailable_returns_error() {
        let keystore = MacOSKeyStore::new();

        // All operations should return unavailable error
        let result = keystore.generate_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));

        let result = keystore.key_exists("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));

        let result = keystore.delete_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    // Full integration test requires completing the implementation
    #[test]
    #[ignore = "requires complete macOS Secure Enclave implementation"]
    fn test_macos_generate_and_delete() {
        // This test is a template for when implementation is complete
        if std::env::var("MINISIGN_TEST_HW_KEYSTORE").is_err() {
            return;
        }

        let keystore = MacOSKeyStore::new();
        if !keystore.is_available() {
            eprintln!("Secure Enclave not available, skipping test");
            return;
        }

        let label = "minisign-test-key-001";

        // Clean up
        let _ = keystore.delete_key(label);

        // Generate key
        let public_key = keystore
            .generate_key(label)
            .expect("Failed to generate key");
        assert_eq!(public_key.to_sec1_bytes().len(), 65);

        // Verify exists
        assert!(keystore.key_exists(label).unwrap());

        // Delete
        keystore.delete_key(label).expect("Failed to delete key");
        assert!(!keystore.key_exists(label).unwrap());
    }
}
