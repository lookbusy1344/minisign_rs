# macOS Secure Enclave Implementation Plan

**Goal:** Fully implement macOS Secure Enclave backend for hardware-backed key protection, with skeletal Windows/Linux support.

**Status:** Implementation plan for making `--hardware-key` actually work on macOS

**Target:** macOS devices with Secure Enclave (Apple Silicon M1/M2/M3/M4 or Intel with T2 chip)

---

## Overview

The current `src/hw_keystore/macos.rs` is a stub that always returns `false` for `is_available()`. This plan provides step-by-step implementation to make it fully functional using Apple's Security framework.

## Prerequisites

### Dependencies Already in Place
- ✅ `security-framework = "3"` (optional dependency)
- ✅ `security-framework-sys = "2"` (low-level FFI)
- ✅ `core-foundation = "0.10"` (CF type handling)
- ✅ `p256` crate for P-256 key operations

### Development Requirements
- macOS device with Secure Enclave (Apple Silicon or T2 chip)
- Touch ID or Face ID enrolled
- Xcode command line tools (provides Security framework headers)

---

## Implementation Phases

### Phase 1: Secure Enclave Detection

**Goal:** Implement `is_secure_enclave_available()` to accurately detect hardware capability.

#### Implementation Steps

1. **Check for Secure Enclave chip presence**
   ```rust
   use core_foundation::base::TCFType;
   use security_framework::base::Result as SecResult;
   use security_framework_sys::base::errSecSuccess;
   use security_framework_sys::key::*;
   ```

2. **Detection strategy:**
   - Attempt to query Secure Enclave capabilities
   - Check system architecture (arm64 = likely has SE, x86_64 = check for T2)
   - Verify biometric enrollment status

3. **Code structure:**
   ```rust
   fn is_secure_enclave_available() -> bool {
       // Check 1: System architecture
       if !is_likely_se_hardware() {
           return false;
       }

       // Check 2: Try creating test access control with SE flag
       // This will fail gracefully if SE is not available
       if !test_se_access_control() {
           return false;
       }

       // Check 3: Verify biometric enrollment (optional but recommended)
       // If no biometrics enrolled, SE operations will fail at use time
       true
   }

   fn is_likely_se_hardware() -> bool {
       #[cfg(target_arch = "aarch64")]
       return true; // Apple Silicon has SE

       #[cfg(target_arch = "x86_64")]
       {
           // T2 chip detection is complex - we can try SE operation
           // and let it fail if not available
           true // Optimistic - will be validated by test_se_access_control
       }

       #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
       return false;
   }

   fn test_se_access_control() -> bool {
       use core_foundation::string::CFString;
       use security_framework_sys::access_control::*;

       unsafe {
           let access_control = SecAccessControlCreateWithFlags(
               std::ptr::null(),
               kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
               kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
               std::ptr::null_mut(),
           );

           if access_control.is_null() {
               return false;
           }

           core_foundation::base::CFRelease(access_control as *const _);
           true
       }
   }
   ```

4. **Error handling:**
   - Return `false` rather than panicking on detection failures
   - Log reasons for unavailability (optional, for debugging)

**Acceptance Criteria:**
- ✅ Returns `true` on M1/M2/M3/M4 Macs with Touch ID/Face ID enrolled
- ✅ Returns `true` on Intel Macs with T2 chip and Touch ID enrolled
- ✅ Returns `false` on older Intel Macs without T2
- ✅ Doesn't crash or panic on any macOS device
- ✅ Fast (< 10ms) - suitable for CLI startup

---

### Phase 2: Key Generation

**Goal:** Generate P-256 keys in Secure Enclave with biometric protection.

#### Security Framework APIs Required

```rust
use security_framework_sys::{
    access_control::*,
    item::*,
    key::*,
};
use core_foundation::{
    base::TCFType,
    dictionary::CFDictionary,
    string::CFString,
    data::CFData,
    boolean::CFBoolean,
};
```

#### Implementation Steps

1. **Create access control with biometric requirement:**
   ```rust
   fn create_se_access_control() -> Result<SecAccessControlRef> {
       unsafe {
           let mut error: CFErrorRef = std::ptr::null_mut();

           let access_control = SecAccessControlCreateWithFlags(
               kCFAllocatorDefault,
               kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
               kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
               &mut error,
           );

           if access_control.is_null() {
               if !error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(error);
                   let description = cf_error.description();
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("Failed to create access control: {description}"),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to create access control".to_string(),
               });
           }

           Ok(access_control)
       }
   }
   ```

2. **Generate P-256 key in Secure Enclave:**
   ```rust
   fn generate_key(&self, label: &str) -> Result<p256::PublicKey> {
       if !self.is_available() {
           return Err(Error::HardwareKeyStoreUnavailable);
       }

       // Create access control
       let access_control = create_se_access_control()?;

       unsafe {
           // Build key generation attributes
           let key_type = CFString::from("kSecAttrKeyTypeECSECPrimeRandom");
           let key_size = 256i32;
           let token_id = CFString::from("kSecAttrTokenIDSecureEnclave");
           let app_tag = CFData::from_buffer(label.as_bytes());
           let prompt = CFString::from("Authenticate to create your minisign signing key");

           // Build attributes dictionary
           let private_key_attrs = CFDictionary::from_CFType_pairs(&[
               (CFString::from("kSecAttrIsPermanent"), CFBoolean::true_value().as_CFType()),
               (CFString::from("kSecAttrApplicationTag"), app_tag.as_CFType()),
               (CFString::from("kSecUseOperationPrompt"), prompt.as_CFType()),
               (CFString::from("kSecAttrAccessControl"),
                core_foundation::base::TCFType::as_CFTypeRef(&access_control) as *const _),
           ]);

           let attributes = CFDictionary::from_CFType_pairs(&[
               (CFString::from("kSecAttrKeyType"), key_type.as_CFType()),
               (CFString::from("kSecAttrKeySizeInBits"),
                core_foundation::number::CFNumber::from(key_size).as_CFType()),
               (CFString::from("kSecAttrTokenID"), token_id.as_CFType()),
               (CFString::from("kSecPrivateKeyAttrs"), private_key_attrs.as_CFType()),
           ]);

           // Generate key
           let mut error: CFErrorRef = std::ptr::null_mut();
           let private_key = SecKeyCreateRandomKey(
               attributes.as_concrete_TypeRef(),
               &mut error,
           );

           // Release access_control
           core_foundation::base::CFRelease(access_control as *const _);

           if private_key.is_null() {
               if !error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(error);
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("Key generation failed: {}", cf_error.description()),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "Key generation failed".to_string(),
               });
           }

           // Extract public key
           let public_key_ref = SecKeyCopyPublicKey(private_key);
           core_foundation::base::CFRelease(private_key as *const _);

           if public_key_ref.is_null() {
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to extract public key".to_string(),
               });
           }

           // Export public key data
           let mut export_error: CFErrorRef = std::ptr::null_mut();
           let public_key_data = SecKeyCopyExternalRepresentation(
               public_key_ref,
               &mut export_error,
           );

           core_foundation::base::CFRelease(public_key_ref as *const _);

           if public_key_data.is_null() {
               if !export_error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(export_error);
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("Failed to export public key: {}", cf_error.description()),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to export public key".to_string(),
               });
           }

           // Convert to p256::PublicKey
           let data = core_foundation::data::CFData::wrap_under_create_rule(public_key_data);
           let bytes = data.bytes();

           // P-256 public key is 65 bytes in uncompressed form (0x04 + 32-byte X + 32-byte Y)
           if bytes.len() != 65 {
               return Err(Error::HardwareKeyStoreError {
                   detail: format!("Invalid public key size: {} bytes", bytes.len()),
               });
           }

           // Parse using p256 crate
           use p256::elliptic_curve::sec1::FromEncodedPoint;
           use p256::EncodedPoint;

           let encoded_point = EncodedPoint::from_bytes(bytes)
               .map_err(|e| Error::HardwareKeyStoreError {
                   detail: format!("Invalid P-256 point: {e}"),
               })?;

           let public_key = p256::PublicKey::from_encoded_point(&encoded_point)
               .into_option()
               .ok_or_else(|| Error::HardwareKeyStoreError {
                   detail: "Failed to parse P-256 public key".to_string(),
               })?;

           Ok(public_key)
       }
   }
   ```

**Key Implementation Notes:**
- Use `kSecAttrTokenIDSecureEnclave` to force Secure Enclave storage
- `kSecAccessControlBiometryCurrentSet` requires current biometric enrollment
- `kSecAttrApplicationTag` is the label (e.g., "minisign:a1b2c3d4")
- Prompt string appears in Touch ID/Face ID dialog
- Proper CF memory management (CFRelease) to avoid leaks

**Error Cases to Handle:**
- User cancels biometric prompt → `Error::HardwareKeyAuthDenied`
- No biometric enrolled → Clear error message
- Secure Enclave full (unlikely) → Error with details
- Key already exists with same label → Delete old or error

**Acceptance Criteria:**
- ✅ Generates P-256 key in Secure Enclave with biometric protection
- ✅ Returns public key in `p256::PublicKey` format
- ✅ Shows biometric prompt with custom message
- ✅ Handles user cancellation gracefully
- ✅ No memory leaks (verified with Instruments)

---

### Phase 3: Public Key Retrieval

**Goal:** Retrieve existing public key from Keychain by application tag.

#### Implementation Steps

1. **Search Keychain for key:**
   ```rust
   fn get_public_key(&self, label: &str) -> Result<p256::PublicKey> {
       if !self.is_available() {
           return Err(Error::HardwareKeyStoreUnavailable);
       }

       unsafe {
           let app_tag = CFData::from_buffer(label.as_bytes());

           // Build query dictionary
           let query = CFDictionary::from_CFType_pairs(&[
               (CFString::from("kSecClass"), CFString::from("kSecClassKey").as_CFType()),
               (CFString::from("kSecAttrApplicationTag"), app_tag.as_CFType()),
               (CFString::from("kSecAttrKeyType"), CFString::from("kSecAttrKeyTypeECSECPrimeRandom").as_CFType()),
               (CFString::from("kSecReturnRef"), CFBoolean::true_value().as_CFType()),
           ]);

           let mut result: CFTypeRef = std::ptr::null();
           let status = SecItemCopyMatching(
               query.as_concrete_TypeRef(),
               &mut result,
           );

           if status != errSecSuccess {
               if status == errSecItemNotFound {
                   return Err(Error::HardwareKeyNotFound {
                       label: label.to_string(),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: format!("Keychain search failed: {status}"),
               });
           }

           let private_key = result as SecKeyRef;
           let public_key_ref = SecKeyCopyPublicKey(private_key);
           core_foundation::base::CFRelease(private_key as *const _);

           if public_key_ref.is_null() {
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to get public key from private key".to_string(),
               });
           }

           // Export and convert (same as in generate_key)
           let mut export_error: CFErrorRef = std::ptr::null_mut();
           let public_key_data = SecKeyCopyExternalRepresentation(
               public_key_ref,
               &mut export_error,
           );

           core_foundation::base::CFRelease(public_key_ref as *const _);

           if public_key_data.is_null() {
               if !export_error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(export_error);
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("Failed to export public key: {}", cf_error.description()),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to export public key".to_string(),
               });
           }

           let data = core_foundation::data::CFData::wrap_under_create_rule(public_key_data);
           let bytes = data.bytes();

           // Parse P-256 public key
           use p256::elliptic_curve::sec1::FromEncodedPoint;
           use p256::EncodedPoint;

           let encoded_point = EncodedPoint::from_bytes(bytes)
               .map_err(|e| Error::HardwareKeyStoreError {
                   detail: format!("Invalid P-256 point: {e}"),
               })?;

           let public_key = p256::PublicKey::from_encoded_point(&encoded_point)
               .into_option()
               .ok_or_else(|| Error::HardwareKeyStoreError {
                   detail: "Failed to parse P-256 public key".to_string(),
               })?;

           Ok(public_key)
       }
   }
   ```

**Acceptance Criteria:**
- ✅ Retrieves public key for existing label
- ✅ Returns `Error::HardwareKeyNotFound` for non-existent key
- ✅ No biometric prompt (public key access doesn't require auth)

---

### Phase 4: ECDH Operation

**Goal:** Perform ECDH inside Secure Enclave to derive shared secret.

**Critical:** Private key never leaves Secure Enclave. ECDH computed inside the secure boundary.

#### Implementation Steps

1. **Perform ECDH with hardware private key:**
   ```rust
   fn ecdh(&self, label: &str, peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
       if !self.is_available() {
           return Err(Error::HardwareKeyStoreUnavailable);
       }

       unsafe {
           // Find private key in keychain
           let app_tag = CFData::from_buffer(label.as_bytes());
           let prompt = CFString::from("Authenticate to decrypt your minisign signing key");

           let query = CFDictionary::from_CFType_pairs(&[
               (CFString::from("kSecClass"), CFString::from("kSecClassKey").as_CFType()),
               (CFString::from("kSecAttrApplicationTag"), app_tag.as_CFType()),
               (CFString::from("kSecAttrKeyType"), CFString::from("kSecAttrKeyTypeECSECPrimeRandom").as_CFType()),
               (CFString::from("kSecReturnRef"), CFBoolean::true_value().as_CFType()),
               (CFString::from("kSecUseOperationPrompt"), prompt.as_CFType()),
           ]);

           let mut result: CFTypeRef = std::ptr::null();
           let status = SecItemCopyMatching(
               query.as_concrete_TypeRef(),
               &mut result,
           );

           if status != errSecSuccess {
               if status == errSecItemNotFound {
                   return Err(Error::HardwareKeyNotFound {
                       label: label.to_string(),
                   });
               }
               if status == errSecUserCanceled {
                   return Err(Error::HardwareKeyAuthDenied);
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: format!("Failed to retrieve key: {status}"),
               });
           }

           let private_key = result as SecKeyRef;

           // Convert peer public key to SecKey
           // P-256 public key in uncompressed form (0x04 + 32-byte X + 32-byte Y)
           use p256::elliptic_curve::sec1::ToEncodedPoint;
           let encoded_point = peer_public.to_encoded_point(false); // uncompressed
           let peer_key_bytes = encoded_point.as_bytes();

           let peer_key_data = CFData::from_buffer(peer_key_bytes);

           let peer_key_attrs = CFDictionary::from_CFType_pairs(&[
               (CFString::from("kSecAttrKeyType"), CFString::from("kSecAttrKeyTypeECSECPrimeRandom").as_CFType()),
               (CFString::from("kSecAttrKeyClass"), CFString::from("kSecAttrKeyClassPublic").as_CFType()),
               (CFString::from("kSecAttrKeySizeInBits"), core_foundation::number::CFNumber::from(256i32).as_CFType()),
           ]);

           let mut key_error: CFErrorRef = std::ptr::null_mut();
           let peer_sec_key = SecKeyCreateWithData(
               peer_key_data.as_concrete_TypeRef(),
               peer_key_attrs.as_concrete_TypeRef(),
               &mut key_error,
           );

           if peer_sec_key.is_null() {
               core_foundation::base::CFRelease(private_key as *const _);
               if !key_error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(key_error);
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("Failed to create peer public key: {}", cf_error.description()),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "Failed to create peer public key".to_string(),
               });
           }

           // Build ECDH parameters
           let algorithm = kSecKeyAlgorithmECDHKeyExchangeStandard;
           let params = CFDictionary::from_CFType_pairs(&[]);

           // Perform ECDH (computed inside Secure Enclave)
           let mut ecdh_error: CFErrorRef = std::ptr::null_mut();
           let shared_secret_data = SecKeyCopyKeyExchangeResult(
               private_key,
               algorithm,
               peer_sec_key,
               params.as_concrete_TypeRef(),
               &mut ecdh_error,
           );

           core_foundation::base::CFRelease(private_key as *const _);
           core_foundation::base::CFRelease(peer_sec_key as *const _);

           if shared_secret_data.is_null() {
               if !ecdh_error.is_null() {
                   let cf_error = core_foundation::error::CFError::wrap_under_create_rule(ecdh_error);
                   return Err(Error::HardwareKeyStoreError {
                       detail: format!("ECDH failed: {}", cf_error.description()),
                   });
               }
               return Err(Error::HardwareKeyStoreError {
                   detail: "ECDH failed".to_string(),
               });
           }

           let data = core_foundation::data::CFData::wrap_under_create_rule(shared_secret_data);
           let bytes = data.bytes();

           // ECDH output should be 32 bytes (P-256 shared secret is x-coordinate)
           if bytes.len() != 32 {
               return Err(Error::HardwareKeyStoreError {
                   detail: format!("Invalid shared secret size: {} bytes", bytes.len()),
               });
           }

           let mut shared_secret = Zeroizing::new([0u8; 32]);
           shared_secret.copy_from_slice(bytes);

           Ok(shared_secret)
       }
   }
   ```

**Important Security Details:**
- `SecKeyCopyKeyExchangeResult` performs ECDH **inside Secure Enclave**
- Private key never exposed to user space
- Biometric prompt shown (via `kSecUseOperationPrompt`)
- Shared secret is the x-coordinate of the ECDH point (32 bytes)

**Error Cases:**
- User cancels biometric prompt → `Error::HardwareKeyAuthDenied`
- Biometric changed since key creation → `kSecAccessControlBiometryCurrentSet` prevents access
- Invalid peer public key → ECDH fails with error

**Acceptance Criteria:**
- ✅ Performs ECDH with biometric authentication
- ✅ Returns 32-byte shared secret
- ✅ Private key never leaves Secure Enclave
- ✅ Handles cancellation gracefully
- ✅ Uses `Zeroizing` for shared secret memory protection

---

### Phase 5: Key Existence Check & Deletion

#### Key Existence Check

```rust
fn key_exists(&self, label: &str) -> Result<bool> {
    if !self.is_available() {
        return Ok(false);
    }

    unsafe {
        let app_tag = CFData::from_buffer(label.as_bytes());

        let query = CFDictionary::from_CFType_pairs(&[
            (CFString::from("kSecClass"), CFString::from("kSecClassKey").as_CFType()),
            (CFString::from("kSecAttrApplicationTag"), app_tag.as_CFType()),
            (CFString::from("kSecAttrKeyType"), CFString::from("kSecAttrKeyTypeECSECPrimeRandom").as_CFType()),
        ]);

        let mut result: CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(
            query.as_concrete_TypeRef(),
            &mut result,
        );

        if status == errSecSuccess {
            if !result.is_null() {
                core_foundation::base::CFRelease(result);
            }
            return Ok(true);
        }

        if status == errSecItemNotFound {
            return Ok(false);
        }

        Err(Error::HardwareKeyStoreError {
            detail: format!("Keychain query failed: {status}"),
        })
    }
}
```

#### Key Deletion

```rust
fn delete_key(&self, label: &str) -> Result<()> {
    if !self.is_available() {
        return Err(Error::HardwareKeyStoreUnavailable);
    }

    unsafe {
        let app_tag = CFData::from_buffer(label.as_bytes());

        let query = CFDictionary::from_CFType_pairs(&[
            (CFString::from("kSecClass"), CFString::from("kSecClassKey").as_CFType()),
            (CFString::from("kSecAttrApplicationTag"), app_tag.as_CFType()),
            (CFString::from("kSecAttrKeyType"), CFString::from("kSecAttrKeyTypeECSECPrimeRandom").as_CFType()),
        ]);

        let status = SecItemDelete(query.as_concrete_TypeRef());

        // Success or not found are both OK
        if status == errSecSuccess || status == errSecItemNotFound {
            return Ok(());
        }

        Err(Error::HardwareKeyStoreError {
            detail: format!("Failed to delete key: {status}"),
        })
    }
}
```

**Acceptance Criteria:**
- ✅ `key_exists()` returns true for existing keys, false for missing
- ✅ `delete_key()` removes key from Secure Enclave
- ✅ `delete_key()` succeeds even if key doesn't exist (idempotent)
- ✅ No biometric prompt for existence check or deletion

---

### Phase 6: Display Name

```rust
fn display_name(&self) -> &'static str {
    "macOS Secure Enclave"
}
```

---

## Testing Strategy

### Unit Tests (Mock-based)

Already in place - unit tests use `MockKeyStore` for automated testing.

### Integration Tests (Requires Hardware)

Create `tests/integration/macos_secure_enclave.rs`:

```rust
#![cfg(all(target_os = "macos", feature = "hw-keystore-macos"))]

use minisign::hw_keystore::HardwareKeyStore;

// Only run when explicitly requested
#[test]
#[ignore]
fn test_macos_se_availability() {
    let hw = minisign::hw_keystore::get_default_keystore();

    if !hw.is_available() {
        println!("Secure Enclave not available on this device");
        return;
    }

    assert_eq!(hw.display_name(), "macOS Secure Enclave");
}

#[test]
#[ignore]
fn test_macos_se_generate_and_retrieve() {
    let hw = minisign::hw_keystore::get_default_keystore();

    if !hw.is_available() {
        println!("Skipping: Secure Enclave not available");
        return;
    }

    let label = "minisign:test_key_12345678";

    // Clean up any existing test key
    let _ = hw.delete_key(label);

    // Generate key
    let public_key = hw.generate_key(label)
        .expect("Failed to generate key");

    // Retrieve public key
    let retrieved_key = hw.get_public_key(label)
        .expect("Failed to retrieve public key");

    assert_eq!(public_key.as_affine(), retrieved_key.as_affine());

    // Clean up
    hw.delete_key(label).expect("Failed to delete key");
}

#[test]
#[ignore]
fn test_macos_se_ecdh() {
    let hw = minisign::hw_keystore::get_default_keystore();

    if !hw.is_available() {
        println!("Skipping: Secure Enclave not available");
        return;
    }

    let label = "minisign:test_ecdh_87654321";

    // Clean up
    let _ = hw.delete_key(label);

    // Generate hardware key
    hw.generate_key(label).expect("Failed to generate key");

    // Generate ephemeral peer key
    use p256::SecretKey;
    let peer_secret = SecretKey::random(&mut rand::thread_rng());
    let peer_public = peer_secret.public_key();

    // Perform ECDH
    let shared_secret = hw.ecdh(label, &peer_public)
        .expect("ECDH failed");

    // Verify shared secret is 32 bytes
    assert_eq!(shared_secret.len(), 32);

    // Clean up
    hw.delete_key(label).expect("Failed to delete key");
}

#[test]
#[ignore]
fn test_macos_se_key_exists() {
    let hw = minisign::hw_keystore::get_default_keystore();

    if !hw.is_available() {
        println!("Skipping: Secure Enclave not available");
        return;
    }

    let label = "minisign:test_exists_abcdef12";

    // Clean up
    let _ = hw.delete_key(label);

    // Should not exist
    assert!(!hw.key_exists(label).expect("key_exists failed"));

    // Generate key
    hw.generate_key(label).expect("Failed to generate key");

    // Should exist now
    assert!(hw.key_exists(label).expect("key_exists failed"));

    // Delete
    hw.delete_key(label).expect("Failed to delete key");

    // Should not exist again
    assert!(!hw.key_exists(label).expect("key_exists failed"));
}
```

**Running Integration Tests:**
```bash
# Must have Secure Enclave hardware and biometrics enrolled
cargo test --features hw-keystore-macos -- --ignored --test-threads=1

# Individual test
cargo test --features hw-keystore-macos test_macos_se_generate_and_retrieve -- --ignored --nocapture
```

**Note:** Tests marked `#[ignore]` require manual invocation and biometric interaction.

---

## End-to-End CLI Testing

### Manual Test Script

```bash
#!/bin/bash
set -e

echo "=== Testing macOS Secure Enclave Integration ==="

# Build with hardware key support
cargo build --release --features hw-keystore-macos

BINARY="./target/release/minisign_rs"
TEMP_DIR=$(mktemp -d)
SK="$TEMP_DIR/test.key"
PK="$TEMP_DIR/test.pub"
MSG="$TEMP_DIR/message.txt"

echo "Test message" > "$MSG"

# Test 1: Generate with hardware key
echo -e "\n[1/5] Generating key with Secure Enclave protection..."
echo "testpass" | "$BINARY" -G --hardware-key -s "$SK" -p "$PK" --password-file /dev/stdin
if [ $? -ne 0 ]; then
    echo "❌ Failed to generate key"
    exit 1
fi
echo "✅ Key generated"

# Test 2: Inspect shows hardware key enrollment
echo -e "\n[2/5] Inspecting key..."
OUTPUT=$("$BINARY" -I -s "$SK" --no-decrypt)
if ! echo "$OUTPUT" | grep -q "Hardware Key Protection.*Enrolled"; then
    echo "❌ Hardware key not shown as enrolled"
    echo "$OUTPUT"
    exit 1
fi
echo "✅ Hardware key enrollment confirmed"

# Test 3: Sign with hardware key (will prompt for biometric)
echo -e "\n[3/5] Signing with hardware key (Touch ID/Face ID required)..."
echo "testpass" | "$BINARY" -S -s "$SK" -m "$MSG" --password-file /dev/stdin
if [ $? -ne 0 ]; then
    echo "❌ Failed to sign"
    exit 1
fi
echo "✅ Signed successfully"

# Test 4: Verify signature
echo -e "\n[4/5] Verifying signature..."
"$BINARY" -V -p "$PK" -m "$MSG"
if [ $? -ne 0 ]; then
    echo "❌ Verification failed"
    exit 1
fi
echo "✅ Verification successful"

# Test 5: Hardware key fallback to password if unavailable
# (This would require simulating hardware unavailability - skip for basic test)

# Cleanup
echo -e "\n[5/5] Cleaning up..."
rm -rf "$TEMP_DIR"

echo -e "\n✅ All tests passed!"
echo "Secure Enclave integration is working correctly"
```

**Save as:** `scripts/test_macos_secure_enclave.sh`

---

## Windows & Linux Skeletal Support

Keep the existing stub implementations but improve error messages:

### Windows (`src/hw_keystore/windows.rs`)

```rust
impl HardwareKeyStore for WindowsKeyStore {
    fn is_available(&self) -> bool {
        // TODO: Implement TPM 2.0 detection
        // Check for TPM chip via Windows Platform Crypto API
        false
    }

    fn display_name(&self) -> &'static str {
        "Windows TPM 2.0"
    }

    // Other methods return HardwareKeyStoreUnavailable or NotImplemented
}
```

### Linux (`src/hw_keystore/linux.rs`)

```rust
impl HardwareKeyStore for LinuxKeyStore {
    fn is_available(&self) -> bool {
        // TODO: Implement TPM 2.0 detection
        // Check for /dev/tpmrm0 or /dev/tpm0 and libtss2-esys
        std::path::Path::new("/dev/tpmrm0").exists() ||
        std::path::Path::new("/dev/tpm0").exists()
    }

    fn display_name(&self) -> &'static str {
        "Linux TPM 2.0"
    }

    // Other methods return HardwareKeyStoreUnavailable or NotImplemented
}
```

**Improved error messages:**
- Windows: "Windows TPM 2.0 support not yet implemented. Use mock for testing."
- Linux: "Linux TPM 2.0 support not yet implemented. Use mock for testing."

---

## Security Considerations

### Critical Security Properties

1. **Private key never leaves Secure Enclave:**
   - ✅ All crypto operations (ECDH) performed inside SE
   - ✅ Only public key exported
   - ✅ No SecKeyCopyExternalRepresentation on private key

2. **Biometric protection:**
   - ✅ `kSecAccessControlBiometryCurrentSet` requires current biometric enrollment
   - ✅ If biometric changes, key becomes inaccessible (security by design)
   - ✅ Recovery via password slot

3. **Memory safety:**
   - ✅ Proper CF type management (no leaks)
   - ✅ Shared secrets use `Zeroizing` wrapper
   - ✅ Sensitive data cleared after use

4. **Error handling:**
   - ✅ User cancellation distinguished from other errors
   - ✅ No panic in FFI code
   - ✅ Clear error messages for debugging

### Threat Model Coverage

| Threat | Mitigation |
|--------|------------|
| Key file stolen | Requires biometric auth on original device |
| Device stolen while unlocked | Biometric required for each signing operation |
| Malware on device | Key protected by Secure Enclave isolation |
| Biometric compromised | Recovery password as fallback |
| Device lost | Recovery password works on any device |

---

## Acceptance Criteria for Completion

### Functional Requirements

- ✅ `--hardware-key` flag generates keys in Secure Enclave on macOS
- ✅ Touch ID / Face ID prompt shown for key generation
- ✅ Biometric authentication required for signing operations
- ✅ `minisign_rs -I` shows "Hardware Key Protection: Enrolled"
- ✅ Full sign/verify workflow works with hardware-backed keys
- ✅ Recovery password decryption still works
- ✅ Graceful fallback if Secure Enclave unavailable

### Code Quality

- ✅ No `unsafe` code outside FFI boundaries
- ✅ Proper error handling (no panics in production paths)
- ✅ Memory leaks verified absent (Instruments check)
- ✅ Clippy pedantic passes
- ✅ All existing tests still pass

### Testing

- ✅ Unit tests pass (mock-based, automated)
- ✅ Integration tests pass (manual, requires hardware)
- ✅ CLI end-to-end test script passes
- ✅ Tested on Apple Silicon Mac
- ✅ Tested on Intel Mac with T2 (if available)

### Documentation

- ✅ Update `docs/hardware-key-protection.md` with actual usage
- ✅ Add troubleshooting section (biometric not enrolled, etc.)
- ✅ Update README with macOS Secure Enclave support status

---

## Implementation Checklist

### Phase 1: Detection
- [ ] Implement `is_likely_se_hardware()`
- [ ] Implement `test_se_access_control()`
- [ ] Update `is_secure_enclave_available()`
- [ ] Test on M1/M2/M3 Mac
- [ ] Test on Intel Mac without T2 (should return false)

### Phase 2: Key Generation
- [ ] Implement `create_se_access_control()`
- [ ] Implement `generate_key()` with SecKeyCreateRandomKey
- [ ] Handle biometric prompts
- [ ] Export public key to p256::PublicKey
- [ ] Test key generation (manual, requires biometric)
- [ ] Verify key stored in Secure Enclave (Keychain Access.app)

### Phase 3: Public Key Retrieval
- [ ] Implement `get_public_key()` with Keychain search
- [ ] Test retrieval matches generated key
- [ ] Test error on non-existent key

### Phase 4: ECDH
- [ ] Implement `ecdh()` with SecKeyCopyKeyExchangeResult
- [ ] Convert peer public key to SecKey
- [ ] Handle biometric auth for ECDH
- [ ] Test ECDH produces correct shared secret
- [ ] Verify private key never exported

### Phase 5: Existence & Deletion
- [ ] Implement `key_exists()`
- [ ] Implement `delete_key()`
- [ ] Test deletion removes key from Secure Enclave

### Phase 6: Integration
- [ ] Wire up in `get_default_keystore()`
- [ ] Update `display_name()` to return "macOS Secure Enclave"
- [ ] Test full generate → sign → verify workflow
- [ ] Test hardware key fallback to password

### Phase 7: Testing
- [ ] Write integration tests (ignored by default)
- [ ] Create manual test script
- [ ] Run on Apple Silicon
- [ ] Memory leak check with Instruments
- [ ] Performance benchmark (key generation, ECDH timing)

### Phase 8: Documentation
- [ ] Update hardware key protection docs
- [ ] Add troubleshooting guide
- [ ] Update README
- [ ] Add comments to complex FFI code

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| CF type conversions error-prone | High | Reference Apple docs, use existing `security-framework` examples |
| Biometric prompt UX unclear | Medium | Use standard system prompts, test on multiple macOS versions |
| Memory leaks in FFI | High | Instruments leak detection, careful CFRelease tracking |
| Key generation slow | Low | Secure Enclave operations are hardware-accelerated |
| Testing requires manual interaction | Medium | Automated mock tests + manual hardware tests pre-release |
| security-framework crate outdated | Low | Pin version, SE APIs stable since macOS 10.12 |

---

## Success Metrics

**Definition of Done:**
When a user on an Apple Silicon Mac can:
1. Run `minisign_rs -G --hardware-key -s key.key -p key.pub`
2. See a Touch ID prompt for key generation
3. Run `minisign_rs -S -s key.key -m file.txt`
4. See a Touch ID prompt for signing
5. Signature verifies correctly
6. If hardware unavailable, falls back to password gracefully

**Expected Timeline:**
- Phase 1-2: 2-3 days (detection + generation)
- Phase 3-4: 2 days (retrieval + ECDH)
- Phase 5-6: 1 day (utils + integration)
- Phase 7-8: 1-2 days (testing + docs)

**Total: ~1 week of focused development**

---

## References

### Apple Documentation
- [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
- [SecKey Documentation](https://developer.apple.com/documentation/security/seckey)
- [SecAccessControl Documentation](https://developer.apple.com/documentation/security/secaccesscontrol)

### Rust Crates
- [security-framework](https://docs.rs/security-framework/latest/security_framework/)
- [security-framework-sys](https://docs.rs/security-framework-sys/latest/security_framework_sys/)
- [core-foundation](https://docs.rs/core-foundation/latest/core_foundation/)
- [p256](https://docs.rs/p256/latest/p256/)

### Existing Code
- `src/ecies.rs` - ECIES primitives (already implemented)
- `src/ecies_wrap.rs` - Hardware key wrapping (uses this new backend)
- `tests/unit/ecies_wrap.rs` - Tests using MockKeyStore

---

## Open Questions

1. **Biometric change handling:** If user changes Touch ID, key becomes inaccessible. Should we:
   - Document this as expected behavior (security feature)
   - Provide a way to re-enroll with new biometric (complex)
   - **Decision:** Document as expected. Recovery password provides access.

2. **Multiple keys:** Should we support multiple hardware keys for same device?
   - **Decision:** Yes, label-based lookup supports multiple keys (minisign:keynum1, minisign:keynum2)

3. **Key cleanup:** Should we provide a command to list/delete orphaned hardware keys?
   - **Decision:** Future enhancement. Users can use Keychain Access.app for now.

---

**Author:** Claude (2026-02-12)
**Reviewer:** TBD
**Implementation Status:** Ready to begin
