//! macOS Secure Enclave backend for hardware key store
//!
//! This module provides hardware key storage via macOS Secure Enclave.
//! Keys are protected by Touch ID / Face ID and never leave the secure boundary.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFErrorRef;
use core_foundation::number::CFNumber;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::Location;
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;
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

    fn ecdh(&self, label: &str, peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        // 1. Find our SE private key
        let private_key = find_se_key_by_label(label)?;

        // 2. Import peer public key as SecKey (ONE unsafe helper — see below)
        let peer_sec_key = import_p256_public_key(peer_public)?;

        // 3. Perform ECDH inside Secure Enclave (safe API)
        //    This triggers biometric authentication automatically
        let shared_secret_bytes = private_key
            .key_exchange(
                Algorithm::ECDHKeyExchangeStandard,
                &peer_sec_key,
                32,   // P-256 shared secret is 32 bytes (x-coordinate)
                None, // no shared_info — we do our own HKDF in ecies.rs
            )
            .map_err(|e| map_cf_error_to_hw_error(&e, "ECDH failed"))?;

        // 4. Convert to fixed-size array with Zeroizing wrapper
        if shared_secret_bytes.len() != 32 {
            return Err(Error::HardwareKeyStoreError {
                detail: format!(
                    "ECDH produced {} bytes, expected 32",
                    shared_secret_bytes.len()
                ),
            });
        }

        let mut shared_secret = Zeroizing::new([0u8; 32]);
        shared_secret.copy_from_slice(&shared_secret_bytes);

        Ok(shared_secret)
    }

    fn key_exists(&self, label: &str) -> Result<bool> {
        if !self.is_available() {
            return Ok(false);
        }

        match find_se_key_by_label(label) {
            Ok(_) => Ok(true),
            Err(Error::HardwareKeyNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        if !self.is_available() {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        let result = ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .delete();

        match result {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()), // errSecItemNotFound — idempotent
            Err(e) => Err(Error::HardwareKeyStoreError {
                detail: format!("failed to delete key: {e}"),
            }),
        }
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

/// Import a `p256::PublicKey` as a `SecKey` for use in ECDH.
///
/// This is the ONLY unsafe block in the macOS keystore implementation.
/// It is required because `security-framework` v3.5.1 does not provide a safe
/// wrapper around `SecKeyCreateWithData` for importing external key data.
///
/// # Safety boundary
///
/// The unsafe block calls `SecKeyCreateWithData` with:
/// - Well-formed `CFData` containing the SEC1-encoded public key
/// - A properly constructed attributes dictionary
/// - A mutable error pointer for failure reporting
///
/// All Core Foundation objects are wrapped in Rust types that handle
/// reference counting automatically (no manual `CFRelease` needed).
fn import_p256_public_key(public_key: &p256::PublicKey) -> Result<SecKey> {
    let encoded = public_key.to_encoded_point(false); // uncompressed SEC1
    let key_data = CFData::from_buffer(encoded.as_bytes());

    let mut attrs = CFMutableDictionary::new();

    // SAFETY: These are read-only extern static CFStringRef constants from
    // the Security framework. Accessing them behind the ToVoid trait is the
    // standard pattern used throughout security-framework's own source code.
    unsafe {
        attrs.add(
            &kSecAttrKeyType.to_void(),
            &kSecAttrKeyTypeECSECPrimeRandom.to_void(),
        );
        attrs.add(
            &kSecAttrKeyClass.to_void(),
            &kSecAttrKeyClassPublic.to_void(),
        );
        attrs.add(
            &kSecAttrKeySizeInBits.to_void(),
            &CFNumber::from(256i32).to_void(),
        );
    }

    let mut error: CFErrorRef = std::ptr::null_mut();

    // SAFETY: SecKeyCreateWithData is a well-documented Apple API.
    // We pass correctly typed CFData and CFDictionary refs.
    // The returned SecKey (if non-null) is immediately wrapped in a
    // Rust SecKey that will CFRelease it on drop.
    let sec_key_ref = unsafe {
        SecKeyCreateWithData(
            key_data.as_concrete_TypeRef(),
            attrs.to_immutable().as_concrete_TypeRef(),
            &raw mut error,
        )
    };

    if sec_key_ref.is_null() {
        if !error.is_null() {
            let cf_error =
                unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
            return Err(Error::HardwareKeyStoreError {
                detail: format!("failed to import peer public key: {cf_error}"),
            });
        }
        return Err(Error::HardwareKeyStoreError {
            detail: "failed to import peer public key".to_string(),
        });
    }

    // SAFETY: SecKeyCreateWithData returned a non-null SecKeyRef with +1 retain count.
    // wrap_under_create_rule takes ownership (will CFRelease on drop).
    Ok(unsafe { SecKey::wrap_under_create_rule(sec_key_ref) })
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

        // Availability depends on hardware (SE + Touch ID enrolled)
        // Returns true on Apple Silicon/T2 Macs with biometric enrolled
        let _available = keystore.is_available();
    }

    #[test]
    fn test_macos_operations_when_unavailable() {
        let keystore = MacOSKeyStore::new();

        // If SE is unavailable, operations should return unavailable error
        // (Skip test if SE is actually available)
        if keystore.is_available() {
            return;
        }

        let result = keystore.generate_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));

        let result = keystore.get_public_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));

        let result = keystore.delete_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    // Full integration test requires hardware and Touch ID interaction
    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_macos_generate_and_delete() {
        let keystore = MacOSKeyStore::new();
        if !keystore.is_available() {
            eprintln!("Secure Enclave not available, skipping test");
            return;
        }

        let label = "minisign:test_integration_001";

        // Clean up
        let _ = keystore.delete_key(label);
        assert!(!keystore.key_exists(label).unwrap());

        // Generate key (triggers Touch ID prompt)
        let public_key = keystore
            .generate_key(label)
            .expect("Failed to generate key");
        assert_eq!(public_key.to_sec1_bytes().len(), 65);

        // Verify exists
        assert!(keystore.key_exists(label).unwrap());

        // Retrieve public key
        let retrieved = keystore
            .get_public_key(label)
            .expect("Failed to retrieve public key");
        assert_eq!(public_key, retrieved);

        // Delete
        keystore.delete_key(label).expect("Failed to delete key");
        assert!(!keystore.key_exists(label).unwrap());
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_macos_ecdh_round_trip() {
        use p256::ecdh::EphemeralSecret;
        use rand::thread_rng;

        let keystore = MacOSKeyStore::new();
        if !keystore.is_available() {
            return;
        }

        let label = "minisign:test_ecdh_001";
        let _ = keystore.delete_key(label);

        // Generate HW key (triggers Touch ID)
        let _hw_pub = keystore.generate_key(label).expect("generate failed");

        // Ephemeral peer key
        let peer_secret = EphemeralSecret::random(&mut thread_rng());
        let peer_public = p256::PublicKey::from(&peer_secret);

        // ECDH inside SE (triggers Touch ID)
        let shared_secret = keystore.ecdh(label, &peer_public).expect("ecdh failed");
        assert_eq!(shared_secret.len(), 32);

        // Verify the shared secret is non-zero
        assert!(shared_secret.iter().any(|&b| b != 0));

        // Cleanup
        keystore.delete_key(label).expect("delete failed");
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_macos_delete_idempotent() {
        let keystore = MacOSKeyStore::new();
        if !keystore.is_available() {
            return;
        }

        let label = "minisign:test_idempotent_001";
        // Delete a key that doesn't exist — should succeed
        keystore
            .delete_key(label)
            .expect("idempotent delete failed");
    }
}
