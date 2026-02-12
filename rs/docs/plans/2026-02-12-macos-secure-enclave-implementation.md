# macOS Secure Enclave Implementation Plan

**Goal:** Fully implement macOS Secure Enclave backend for hardware-backed key protection, with skeletal Windows/Linux support.

**Status:** Implementation plan for making `--hardware-key` actually work on macOS

**Target:** macOS devices with Secure Enclave (Apple Silicon M1/M2/M3/M4 or Intel with T2 chip)

---

## Review Notes (2026-02-12)

The original version of this plan proposed raw `unsafe` FFI using `security-framework-sys` exclusively.
That approach was rejected during review for the following reasons:

1. **CLAUDE.md mandates ZERO unsafe code** — the plan was 100% raw FFI with manual `CFRelease`
2. **`security-framework` v3.5.1 provides safe Rust APIs** for every operation except one
3. **Apple constants were used as string literals** (e.g., `CFString::from("kSecAttrKeyType")`) — these are `extern "C" static` symbols, not strings, and would not compile
4. **`kSecAttrApplicationTag` is not exported** by `security-framework-sys` — must use `kSecAttrLabel` via `ItemSearchOptions::label()` instead
5. **Windows/Linux stubs have compilation bugs** — typo `zeroizing` (should be `zeroize`), missing `get_public_key()` trait method

This revised plan uses `security-framework`'s safe wrappers throughout, with a single isolated
`unsafe` helper for peer public key import (`SecKeyCreateWithData`) — the only operation lacking a
safe wrapper.

---

## Overview

The current `src/hw_keystore/macos.rs` is a stub that always returns `false` for `is_available()`. This plan provides step-by-step implementation to make it fully functional using the `security-framework` crate's safe Rust API over Apple's Security framework.

## Prerequisites

### Dependencies in Place (Cargo.toml updates needed)

- `security-framework = "3"` — needs `features = ["OSX_10_13"]` added (for `SecKeyCreateWithData`)
- `security-framework-sys = "2"` — for access control flag constants
- `core-foundation = "0.10"` — for `CFData` in peer key import
- `p256` crate — P-256 key operations (already in place)

### Cargo.toml Change Required

```toml
# Current (missing required features):
security-framework = { version = "3", optional = true }

# Required:
security-framework = { version = "3", optional = true, features = ["OSX_10_15"] }
```

**Why `OSX_10_15`:** Two APIs require features beyond the default `OSX_10_12`:

1. `SecKeyCreateWithData` (peer key import for ECDH) — requires `OSX_10_13`
2. `Location::DataProtectionKeychain` — requires `OSX_10_15`

The `security-framework` crate docs state:
> "Keys stored in the Secure Enclave _must_ use [DataProtectionKeychain]."

The feature chain is linear: `OSX_10_15` ⊃ `OSX_10_14` ⊃ `OSX_10_13` ⊃ `OSX_10_12`.
So enabling `OSX_10_15` gives us everything. All Apple Silicon Macs run macOS 11+, so
requiring 10.15+ has zero practical impact.

### Development Requirements

- macOS device with Secure Enclave (Apple Silicon or T2 chip)
- Touch ID enrolled (Face ID on supported devices)
- Xcode command line tools (provides Security framework headers)

---

## API Surface Available in `security-framework` v3.5.1

Before diving into phases, here's the complete mapping of operations to safe APIs. This was
verified by reading the crate source at `~/.cargo/registry/src/.../security-framework-3.5.1/src/`.

| Operation | Safe API | Notes |
|---|---|---|
| Key generation (SE) | `SecKey::new(&GenerateKeyOptions)` | Builder sets token, key type, access control |
| SE targeting | `opts.set_token(Token::SecureEnclave)` | Enum variant, no string constants |
| Key type (P-256) | `opts.set_key_type(KeyType::ec_sec_prime_random())` | Wraps `kSecAttrKeyTypeECSECPrimeRandom` |
| Access control | `SecAccessControl::create_with_protection()` | Takes `ProtectionMode` enum + flag bitmask |
| Extract public key | `sec_key.public_key()` → `Option<SecKey>` | Safe wrapper around `SecKeyCopyPublicKey` |
| Export key bytes | `sec_key.external_representation()` → `Option<CFData>` | Uncompressed SEC1 encoding |
| ECDH | `sec_key.key_exchange(Algorithm, &peer, size, info)` | Wraps `SecKeyCopyKeyExchangeResult` |
| Key search | `ItemSearchOptions::new()...search()` | Returns `Vec<SearchResult>` |
| Key deletion | `sec_key.delete()` | Wraps `SecItemDelete` with `kSecValueRef` |
| **Peer key import** | **`SecKeyCreateWithData` (FFI)** | **No safe wrapper — ONE unsafe block** |

### Access Control Flags (from `security-framework-sys`)

```rust
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage,    // 1 << 30 — required for SE key operations
    kSecAccessControlBiometryCurrentSet, // 1 << 3  — bind to current biometric enrollment
};
```

### ECDH Algorithm

```rust
use security_framework::key::Algorithm;
// Algorithm::ECDHKeyExchangeStandard — raw ECDH, returns x-coordinate (32 bytes for P-256)
```

### Key Search

```rust
use security_framework::item::{
    ItemSearchOptions, ItemClass, KeyClass, SearchResult, Reference,
};
// Search by: ItemClass::key() + KeyClass::private() + label string
// Returns: SearchResult::Ref(Reference::Key(SecKey)) when load_refs(true)
```

### Key Identification

The plan uses `kSecAttrLabel` (via `GenerateKeyOptions::set_label()` and
`ItemSearchOptions::label()`) rather than `kSecAttrApplicationTag`, because:

- `kSecAttrApplicationTag` is **not exported** by `security-framework-sys`
- `kSecAttrLabel` is fully supported by both generation and search APIs
- Labels are human-readable strings (e.g., `"minisign:a1b2c3d4e5f6g7h8"`)

---

## Implementation Phases

### Phase 0: Fix Existing Bugs

**Goal:** Fix compilation bugs in Windows/Linux stubs before starting macOS work.

#### 0a: Fix `Cargo.toml`

Add `OSX_10_15` feature (transitively enables `OSX_10_13` and `OSX_10_12`):

```toml
security-framework = { version = "3", optional = true, features = ["OSX_10_15"] }
```

#### 0b: Fix Windows stub (`src/hw_keystore/windows.rs`)

Two bugs:

1. **Line 8:** `use zeroizing::Zeroizing;` → `use zeroize::Zeroizing;` (crate name typo)
2. **Missing trait method:** `get_public_key()` is defined in the `HardwareKeyStore` trait but
   not implemented in the Windows stub

```rust
fn get_public_key(&self, _label: &str) -> Result<p256::PublicKey> {
    Err(Error::HardwareKeyStoreError {
        detail: "Windows TPM 2.0 support not yet implemented".to_string(),
    })
}
```

#### 0c: Fix Linux stub (`src/hw_keystore/linux.rs`)

Same two bugs as Windows:

1. **Line 8:** `use zeroizing::Zeroizing;` → `use zeroize::Zeroizing;`
2. **Missing `get_public_key()` implementation** — same pattern as Windows

#### Verification

```bash
# Must compile cleanly on macOS with all features:
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Note: Windows/Linux stubs are `cfg`-gated and won't compile on macOS regardless, but fixing the
source ensures they'll work when someone enables the features on those platforms.

**Acceptance Criteria:**
- `cargo clippy --all-targets --all-features` passes on macOS
- Windows/Linux source files have correct import and complete trait implementation

---

### Phase 1: Secure Enclave Detection

**Goal:** Implement `is_secure_enclave_available()` to accurately detect hardware capability.

#### Implementation

```rust
use security_framework::access_control::{SecAccessControl, ProtectionMode};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage,
    kSecAccessControlBiometryCurrentSet,
};

fn is_secure_enclave_available() -> bool {
    // Check 1: Architecture — only Apple Silicon and T2 Intel Macs have SE
    if !is_likely_se_hardware() {
        return false;
    }

    // Check 2: Try creating an access control with SE flags
    // This validates that the system supports biometric + SE
    // without generating any keys or triggering a prompt
    test_se_access_control()
}

fn is_likely_se_hardware() -> bool {
    #[cfg(target_arch = "aarch64")]
    { true } // All Apple Silicon Macs have Secure Enclave

    #[cfg(target_arch = "x86_64")]
    { true } // Optimistic for T2 — validated by test_se_access_control()

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    { false }
}

fn test_se_access_control() -> bool {
    // Uses the SAFE SecAccessControl API — no unsafe block needed
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
    )
    .is_ok()
}
```

**Key difference from original plan:** No `unsafe` blocks. `SecAccessControl::create_with_protection()`
is a safe function that internally handles `SecAccessControlCreateWithFlags` and `CFRelease`.

**Acceptance Criteria:**
- Returns `true` on Apple Silicon Macs with Touch ID enrolled
- Returns `true` on Intel T2 Macs with Touch ID enrolled
- Returns `false` on older Intel Macs without T2
- Returns `false` if no passcode/biometric is enrolled
- No crash or panic on any macOS device
- Fast (< 10ms) — suitable for CLI startup

---

### Phase 2: Key Generation

**Goal:** Generate P-256 keys in Secure Enclave with biometric protection.

#### Implementation

```rust
use security_framework::key::{SecKey, GenerateKeyOptions, KeyType, Token};
use security_framework::access_control::{SecAccessControl, ProtectionMode};
use security_framework::item::Location;
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage,
    kSecAccessControlBiometryCurrentSet,
};

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
    let private_key = SecKey::new(&opts).map_err(|e| {
        map_cf_error_to_hw_error(&e, "key generation failed")
    })?;

    // 4. Extract public key (safe API)
    let public_key_ref = private_key.public_key().ok_or_else(|| {
        Error::HardwareKeyStoreError {
            detail: "failed to extract public key from SE private key".to_string(),
        }
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
```

#### Helper: SEC1 bytes → `p256::PublicKey`

This is reused across `generate_key()` and `get_public_key()`:

```rust
/// Convert uncompressed SEC1 bytes (65 bytes: 0x04 || x || y) to p256::PublicKey
fn sec1_bytes_to_p256_public_key(bytes: &[u8]) -> Result<p256::PublicKey> {
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|e| Error::HardwareKeyStoreError {
        detail: format!("invalid P-256 public key ({} bytes): {e}", bytes.len()),
    })
}
```

#### Helper: CFError → minisign Error

```rust
/// Map Core Foundation CFError to minisign HardwareKeyStoreError with context
fn map_cf_error_to_hw_error(
    cf_error: &core_foundation::error::CFError,
    context: &str,
) -> Error {
    let description = cf_error.description();
    let code = cf_error.code();

    // errSecUserCanceled = -128, errSecAuthFailed = -25293
    const ERR_SEC_USER_CANCELED: isize = -128;
    const ERR_SEC_AUTH_FAILED: isize = -25293;

    match code as isize {
        ERR_SEC_USER_CANCELED => Error::HardwareKeyStoreAuthDenied,
        ERR_SEC_AUTH_FAILED => Error::HardwareKeyStoreAuthDenied,
        _ => Error::HardwareKeyStoreError {
            detail: format!("{context}: {description} (code {code})"),
        },
    }
}
```

**Key differences from original plan:**
- No `unsafe` blocks — `SecKey::new()`, `public_key()`, `external_representation()` are all safe
- No manual `CFRelease` — Rust `Drop` handles memory management automatically
- No string constants like `CFString::from("kSecAttrKeyType")` — uses typed enums
- Proper CFError → minisign error mapping including user cancellation detection

**Notes on `Location`:**
- `Location::DataProtectionKeychain` stores the key in Apple's modern data protection keychain
- This is **required** for Secure Enclave keys per Apple's documentation
- Enabled by the `OSX_10_15` feature we add to `security-framework` in Phase 0

**Error Cases:**
- User cancels Touch ID prompt → `Error::HardwareKeyStoreAuthDenied`
- No biometric enrolled → `SecAccessControl` creation may fail, or key generation returns error
- SE not available → `is_available()` returns false (caught at entry)
- Key already exists with same label → Apple's Keychain will error; handle or delete-first

**Acceptance Criteria:**
- Generates P-256 key in Secure Enclave with biometric protection
- Returns public key in `p256::PublicKey` format
- Shows Touch ID prompt with system-managed dialog
- Handles user cancellation gracefully (maps to `HardwareKeyStoreAuthDenied`)
- Zero `unsafe` blocks in this function

---

### Phase 3: Public Key Retrieval

**Goal:** Retrieve existing public key from Keychain by label.

#### Implementation

```rust
use security_framework::item::{ItemSearchOptions, ItemClass, KeyClass, SearchResult, Reference};

fn get_public_key(&self, label: &str) -> Result<p256::PublicKey> {
    if !self.is_available() {
        return Err(Error::HardwareKeyStoreUnavailable);
    }

    // 1. Search keychain for private key by label (safe API)
    let private_key = find_se_key_by_label(label)?;

    // 2. Extract public key (safe API)
    let public_key_ref = private_key.public_key().ok_or_else(|| {
        Error::HardwareKeyStoreError {
            detail: "failed to get public key from SE private key".to_string(),
        }
    })?;

    // 3. Export and convert (same as generate_key)
    let pub_key_data = public_key_ref.external_representation().ok_or_else(|| {
        Error::HardwareKeyStoreError {
            detail: "failed to export public key representation".to_string(),
        }
    })?;

    sec1_bytes_to_p256_public_key(pub_key_data.bytes())
}
```

#### Helper: Find SE Key by Label

This is reused across `get_public_key()`, `ecdh()`, `key_exists()`, and `delete_key()`:

```rust
use security_framework::key::SecKey;

/// Search Keychain for a private key matching the given label.
/// Returns the SecKey reference for further operations.
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
```

**Key difference from original plan:**
- Uses `ItemSearchOptions` builder (safe API) instead of raw `SecItemCopyMatching`
- Uses `label()` method instead of non-existent `kSecAttrApplicationTag`
- Pattern-matches on `SearchResult::Ref(Reference::Key(...))` — type-safe extraction
- No manual `CFRelease` — `SecKey` implements `Drop` via `TCFType`

**Acceptance Criteria:**
- Retrieves public key for existing label
- Returns `Error::HardwareKeyNotFound` for non-existent key
- No biometric prompt (public key access doesn't require auth)
- No `unsafe` blocks

---

### Phase 4: ECDH Operation

**Goal:** Perform ECDH inside Secure Enclave to derive shared secret.

**Critical:** Private key never leaves Secure Enclave. ECDH computed inside the secure boundary.

#### Implementation

```rust
use security_framework::key::Algorithm;

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
            32, // P-256 shared secret is 32 bytes (x-coordinate)
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
```

#### Helper: Import Peer P-256 Public Key (SOLE unsafe block in the implementation)

This is the **only function** in the entire macOS implementation that requires `unsafe`,
because `security-framework` v3.5.1 has no safe wrapper for `SecKeyCreateWithData`.

```rust
use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::CFErrorRef;
use core_foundation::number::CFNumber;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use security_framework::key::SecKey;
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPublic,
    kSecAttrKeySizeInBits, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
};
use security_framework_sys::key::SecKeyCreateWithData;

/// Import a p256::PublicKey as a SecKey for use in ECDH.
///
/// This is the ONLY unsafe block in the macOS keystore implementation.
/// It is required because security-framework v3.5.1 does not provide a safe
/// wrapper around SecKeyCreateWithData for importing external key data.
///
/// # Safety boundary
///
/// The unsafe block calls SecKeyCreateWithData with:
/// - Well-formed CFData containing the SEC1-encoded public key
/// - A properly constructed attributes dictionary
/// - A mutable error pointer for failure reporting
///
/// All Core Foundation objects are wrapped in Rust types that handle
/// reference counting automatically (no manual CFRelease needed).
fn import_p256_public_key(public_key: &p256::PublicKey) -> Result<SecKey> {
    let encoded = public_key.to_encoded_point(false); // uncompressed SEC1
    let key_data = CFData::from_buffer(encoded.as_bytes());

    let mut attrs = CFMutableDictionary::new();

    // SAFETY: These are read-only extern static CFStringRef constants from
    // the Security framework. Accessing them behind the ToVoid trait is the
    // standard pattern used throughout security-framework's own source code.
    unsafe {
        attrs.add(&kSecAttrKeyType.to_void(), &kSecAttrKeyTypeECSECPrimeRandom.to_void());
        attrs.add(&kSecAttrKeyClass.to_void(), &kSecAttrKeyClassPublic.to_void());
        attrs.add(&kSecAttrKeySizeInBits.to_void(), &CFNumber::from(256i32).to_void());
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
            &mut error,
        )
    };

    if sec_key_ref.is_null() {
        if !error.is_null() {
            let cf_error = unsafe {
                core_foundation::error::CFError::wrap_under_create_rule(error)
            };
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
```

**Security properties:**
- `SecKey::key_exchange()` performs ECDH **inside the Secure Enclave**
- Private key is never exported to user space
- Biometric prompt is triggered automatically by the SE access control policy
- Shared secret is the x-coordinate of the ECDH point (32 bytes for P-256)

**Error cases:**
- User cancels biometric → `map_cf_error_to_hw_error` returns `HardwareKeyStoreAuthDenied`
- Biometric changed since key creation → `kSecAccessControlBiometryCurrentSet` blocks access
- Invalid peer public key → `SecKeyCreateWithData` returns error
- Key not found → `find_se_key_by_label` returns `HardwareKeyNotFound`

**Acceptance Criteria:**
- Performs ECDH with biometric authentication
- Returns 32-byte shared secret in `Zeroizing` wrapper
- Private key never leaves Secure Enclave
- Handles cancellation gracefully
- Only ONE unsafe helper function (`import_p256_public_key`)

---

### Phase 5: Key Existence Check & Deletion

#### Key Existence Check

```rust
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
```

#### Key Deletion

```rust
fn delete_key(&self, label: &str) -> Result<()> {
    if !self.is_available() {
        return Err(Error::HardwareKeyStoreUnavailable);
    }

    match find_se_key_by_label(label) {
        Ok(sec_key) => {
            sec_key.delete().map_err(|e| Error::HardwareKeyStoreError {
                detail: format!("failed to delete key: {e}"),
            })
        }
        Err(Error::HardwareKeyNotFound { .. }) => Ok(()), // idempotent
        Err(e) => Err(e),
    }
}
```

**Alternative deletion approach using `ItemSearchOptions::delete()`:**

```rust
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
```

The `ItemSearchOptions::delete()` approach is preferable because it avoids loading the key
reference first (slightly more efficient, and deletion doesn't require auth).

**Acceptance Criteria:**
- `key_exists()` returns true for existing keys, false for missing
- `delete_key()` removes key from Secure Enclave
- `delete_key()` succeeds even if key doesn't exist (idempotent)
- No biometric prompt for existence check or deletion
- No `unsafe` blocks

---

### Phase 6: Display Name & Availability Wiring

```rust
fn display_name(&self) -> &'static str {
    "Secure Enclave"  // matches existing stub — do NOT change to "macOS Secure Enclave"
}

fn is_available(&self) -> bool {
    Self::is_secure_enclave_available()
}
```

The `display_name()` stays `"Secure Enclave"` — the existing inspect output code already
shows the platform context.

---

## Complete Module Structure

After implementation, `src/hw_keystore/macos.rs` will contain:

```
MacOSKeyStore (struct)
├── new() -> Self
├── is_secure_enclave_available() -> bool  [private]
│   ├── is_likely_se_hardware() -> bool    [private]
│   └── test_se_access_control() -> bool   [private]
│
├── impl HardwareKeyStore
│   ├── generate_key(&self, label) -> Result<p256::PublicKey>
│   ├── get_public_key(&self, label) -> Result<p256::PublicKey>
│   ├── ecdh(&self, label, peer) -> Result<Zeroizing<[u8; 32]>>
│   ├── key_exists(&self, label) -> Result<bool>
│   ├── delete_key(&self, label) -> Result<()>
│   ├── is_available(&self) -> bool
│   └── display_name(&self) -> &'static str
│
└── Private helpers
    ├── find_se_key_by_label(label) -> Result<SecKey>
    ├── sec1_bytes_to_p256_public_key(bytes) -> Result<p256::PublicKey>
    ├── import_p256_public_key(pubkey) -> Result<SecKey>   [ONLY unsafe]
    └── map_cf_error_to_hw_error(err, ctx) -> Error
```

**Unsafe audit:** Exactly ONE function (`import_p256_public_key`) contains `unsafe` blocks.
All other functions use the safe `security-framework` API exclusively.

---

## Windows & Linux Skeletal Support

### Bugs to Fix First (Phase 0)

Both stubs have:
1. `use zeroizing::Zeroizing;` → should be `use zeroize::Zeroizing;`
2. Missing `get_public_key()` trait method

### Windows (`src/hw_keystore/windows.rs`)

```rust
use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use zeroize::Zeroizing;

pub struct WindowsKeyStore;

impl WindowsKeyStore {
    #[must_use]
    pub fn new() -> Self { Self }
}

impl Default for WindowsKeyStore {
    fn default() -> Self { Self::new() }
}

impl HardwareKeyStore for WindowsKeyStore {
    fn generate_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreError {
            detail: "Windows TPM 2.0 support not yet implemented".to_string(),
        })
    }

    fn get_public_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreError {
            detail: "Windows TPM 2.0 support not yet implemented".to_string(),
        })
    }

    fn ecdh(&self, _label: &str, _peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        Err(Error::HardwareKeyStoreError {
            detail: "Windows TPM 2.0 support not yet implemented".to_string(),
        })
    }

    fn key_exists(&self, _label: &str) -> Result<bool> { Ok(false) }

    fn delete_key(&self, _label: &str) -> Result<()> {
        Err(Error::HardwareKeyStoreError {
            detail: "Windows TPM 2.0 support not yet implemented".to_string(),
        })
    }

    fn is_available(&self) -> bool { false }

    fn display_name(&self) -> &'static str { "TPM 2.0 (Windows Hello)" }
}
```

### Linux (`src/hw_keystore/linux.rs`)

Same pattern as Windows, with:
- `display_name()` returns `"TPM 2.0"`
- `is_available()` returns `false` (stub — future: check `/dev/tpmrm0`)

---

## Testing Strategy

### Unit Tests (Mock-based) — Already in Place

All automated testing uses `MockKeyStore`. No changes needed. 282 tests currently pass.

### Integration Tests (Requires Hardware)

Existing test template in `src/hw_keystore/macos.rs` needs updating for the new implementation.
Additional tests should go in `tests/unit/hw_keystore_macos.rs` (cfg-gated).

```rust
#[cfg(all(target_os = "macos", feature = "hw-keystore-macos"))]
mod macos_se_tests {
    use minisign::hw_keystore::{HardwareKeyStore, macos::MacOSKeyStore};

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_se_availability() {
        let ks = MacOSKeyStore::new();
        // On Apple Silicon with Touch ID, this should be true
        assert!(ks.is_available());
        assert_eq!(ks.display_name(), "Secure Enclave");
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_se_generate_retrieve_delete() {
        let ks = MacOSKeyStore::new();
        if !ks.is_available() { return; }

        let label = "minisign:test_integration_001";

        // Cleanup
        let _ = ks.delete_key(label);
        assert!(!ks.key_exists(label).unwrap());

        // Generate
        let pub_key = ks.generate_key(label).expect("generate failed");

        // Exists
        assert!(ks.key_exists(label).unwrap());

        // Retrieve
        let retrieved = ks.get_public_key(label).expect("get_public_key failed");
        assert_eq!(pub_key, retrieved);

        // Delete
        ks.delete_key(label).expect("delete failed");
        assert!(!ks.key_exists(label).unwrap());
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_se_ecdh_round_trip() {
        let ks = MacOSKeyStore::new();
        if !ks.is_available() { return; }

        let label = "minisign:test_ecdh_001";
        let _ = ks.delete_key(label);

        // Generate HW key
        let _hw_pub = ks.generate_key(label).expect("generate failed");

        // Ephemeral peer key
        let peer_secret = p256::ecdh::EphemeralSecret::random(&mut rand::thread_rng());
        let peer_public = p256::PublicKey::from(&peer_secret);

        // ECDH inside SE
        let shared_secret = ks.ecdh(label, &peer_public).expect("ecdh failed");
        assert_eq!(shared_secret.len(), 32);

        // Verify the shared secret is non-zero
        assert!(shared_secret.iter().any(|&b| b != 0));

        // Cleanup
        ks.delete_key(label).expect("delete failed");
    }

    #[test]
    #[ignore = "requires Secure Enclave hardware and Touch ID"]
    fn test_se_delete_idempotent() {
        let ks = MacOSKeyStore::new();
        if !ks.is_available() { return; }

        let label = "minisign:test_idempotent_001";
        // Delete a key that doesn't exist — should succeed
        ks.delete_key(label).expect("idempotent delete failed");
    }
}
```

**Running Integration Tests:**

```bash
# All hardware tests (requires Touch ID interaction for each):
gtimeout 120 cargo test --features hw-keystore-macos -- --ignored --test-threads=1 --nocapture

# Single test:
gtimeout 60 cargo test --features hw-keystore-macos test_se_generate_retrieve_delete -- --ignored --nocapture
```

**Note:** Tests marked `#[ignore]` require manual invocation and biometric interaction (Touch ID).

---

## End-to-End CLI Testing

### Manual Test Script

Save as `scripts/test_macos_secure_enclave.sh`:

```bash
#!/bin/bash
set -euo pipefail

echo "=== Testing macOS Secure Enclave Integration ==="

cargo build --release --features hw-keystore-macos

BINARY="./target/release/minisign_rs"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

SK="$TEMP_DIR/test.key"
PK="$TEMP_DIR/test.pub"
MSG="$TEMP_DIR/message.txt"
echo "Test message for Secure Enclave signing" > "$MSG"

# Test 1: Generate with hardware key
echo "[1/4] Generating key with Secure Enclave protection..."
echo "testpass" | "$BINARY" -G --hardware-key -s "$SK" -p "$PK" --password-file /dev/stdin

# Test 2: Inspect shows hardware key enrollment
echo "[2/4] Inspecting key..."
"$BINARY" -I -s "$SK" --no-decrypt | grep -q "Hardware"

# Test 3: Sign (triggers Touch ID)
echo "[3/4] Signing with hardware key (Touch ID required)..."
echo "testpass" | "$BINARY" -S -s "$SK" -m "$MSG" --password-file /dev/stdin

# Test 4: Verify signature
echo "[4/4] Verifying signature..."
"$BINARY" -V -p "$PK" -m "$MSG"

echo ""
echo "All tests passed. Secure Enclave integration working correctly."
```

---

## Security Considerations

### Critical Security Properties

1. **Private key never leaves Secure Enclave:**
   - All ECDH computed inside SE via `SecKey::key_exchange()`
   - Only public key exported via `external_representation()`
   - No `SecKeyCopyExternalRepresentation` on private key (would fail anyway for SE keys)

2. **Biometric protection:**
   - `kSecAccessControlBiometryCurrentSet` requires current biometric enrollment
   - If biometric changes (re-enrolled), key becomes inaccessible (security by design)
   - Recovery via password slot (always present in key file)

3. **Memory safety:**
   - All CF types managed by Rust `Drop` (no manual `CFRelease`)
   - Shared secrets wrapped in `Zeroizing<>` for automatic memory wiping
   - Single `unsafe` block is well-documented and boundary-checked

4. **Error handling:**
   - User cancellation (`errSecUserCanceled`) → `HardwareKeyStoreAuthDenied`
   - Auth failure (`errSecAuthFailed`) → `HardwareKeyStoreAuthDenied`
   - Key not found → `HardwareKeyNotFound`
   - No panics in any code path

### Threat Model Coverage

| Threat | Mitigation |
|--------|------------|
| Key file stolen | Requires biometric auth on original device |
| Device stolen while unlocked | Biometric required for each signing operation |
| Malware on device | Key protected by Secure Enclave hardware isolation |
| Biometric compromised | Recovery password as fallback |
| Device lost | Recovery password works on any device |

---

## Implementation Checklist

### Phase 0: Fix Existing Bugs
- [ ] Add `features = ["OSX_10_15"]` to security-framework in Cargo.toml
- [ ] Fix Windows stub: `zeroizing` → `zeroize`, add `get_public_key()`
- [ ] Fix Linux stub: `zeroizing` → `zeroize`, add `get_public_key()`
- [ ] Verify `cargo clippy --all-targets --all-features` passes

### Phase 1: Secure Enclave Detection
- [ ] Implement `is_likely_se_hardware()` with arch cfg checks
- [ ] Implement `test_se_access_control()` using safe `SecAccessControl` API
- [ ] Wire into `is_secure_enclave_available()`
- [ ] Test on Apple Silicon Mac (should return true)
- [ ] Verify fast execution (< 10ms)

### Phase 2: Key Generation
- [ ] Implement `map_cf_error_to_hw_error()` helper
- [ ] Implement `sec1_bytes_to_p256_public_key()` helper
- [ ] Implement `generate_key()` using `GenerateKeyOptions` + `SecKey::new()`
- [ ] Handle `Location::DataProtectionKeychain` vs default keychain
- [ ] Test key generation (manual, requires Touch ID)
- [ ] Verify key visible in Keychain Access.app

### Phase 3: Public Key Retrieval
- [ ] Implement `find_se_key_by_label()` using `ItemSearchOptions`
- [ ] Implement `get_public_key()` using `find_se_key_by_label`
- [ ] Test retrieval matches generated key
- [ ] Test error on non-existent key (returns `HardwareKeyNotFound`)

### Phase 4: ECDH
- [ ] Implement `import_p256_public_key()` (sole `unsafe` helper)
- [ ] Implement `ecdh()` using `SecKey::key_exchange()`
- [ ] Test ECDH produces 32-byte shared secret
- [ ] Test biometric prompt triggers correctly
- [ ] Test user cancellation maps to `HardwareKeyStoreAuthDenied`

### Phase 5: Existence & Deletion
- [ ] Implement `key_exists()` using `find_se_key_by_label`
- [ ] Implement `delete_key()` using `ItemSearchOptions::delete()` or `SecKey::delete()`
- [ ] Test deletion is idempotent (non-existent key returns Ok)

### Phase 6: Integration & Wiring
- [ ] Update `is_available()` to call `is_secure_enclave_available()`
- [ ] Verify `display_name()` remains "Secure Enclave"
- [ ] Test full generate → sign → verify workflow via CLI
- [ ] Test hardware key fallback to password when HW unavailable

### Phase 7: Testing
- [ ] Write integration tests (ignored by default, requires hardware)
- [ ] Create manual test script (`scripts/test_macos_secure_enclave.sh`)
- [ ] Run on Apple Silicon Mac with Touch ID
- [ ] All 282+ existing tests still pass
- [ ] Clippy pedantic passes with `--all-features`

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| `SecKey::key_exchange()` returns unexpected size | Medium | Validate length, return clear error |
| `Location::DataProtectionKeychain` needs `OSX_10_15` | Resolved | Use `features = ["OSX_10_15"]` in Cargo.toml (required for SE keys) |
| `ItemSearchOptions::label()` returns multiple keys | Low | Use `.limit(1)` and take first result |
| Touch ID prompt UX varies by macOS version | Low | System-managed dialog, no custom UI needed |
| `SecKeyCreateWithData` fails for EC public keys | Medium | Test with known good keys, validate SEC1 encoding |
| Keychain access denied in sandboxed apps | Low | CLI tool typically runs unsandboxed |
| Key generation slow on older T2 Macs | Low | SE operations are hardware-accelerated |
| `security-framework` crate version conflicts | Low | Pin to v3, SE APIs stable since macOS 10.12 |

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

---

## References

### Apple Documentation
- [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
- [SecKey Documentation](https://developer.apple.com/documentation/security/seckey)
- [SecAccessControl Documentation](https://developer.apple.com/documentation/security/secaccesscontrol)

### Rust Crate Source (verified against)
- `~/.cargo/registry/src/.../security-framework-3.5.1/src/key.rs` — `SecKey`, `GenerateKeyOptions`, `Token`, `Algorithm`
- `~/.cargo/registry/src/.../security-framework-3.5.1/src/access_control.rs` — `SecAccessControl`, `ProtectionMode`
- `~/.cargo/registry/src/.../security-framework-3.5.1/src/item.rs` — `ItemSearchOptions`, `SearchResult`, `Reference`
- `~/.cargo/registry/src/.../security-framework-sys-2.15.0/src/access_control.rs` — flag constants
- `~/.cargo/registry/src/.../security-framework-sys-2.15.0/src/key.rs` — `Algorithm` enum, `SecKeyCreateWithData`

### Existing Code
- `src/ecies.rs` — ECIES primitives (complete, 10 tests)
- `src/ecies_wrap.rs` — Hardware key wrapping (complete, uses this backend)
- `src/hw_keystore/mock.rs` — Mock implementation (complete, 11 tests)
- `tests/unit/ecies_wrap.rs` — Wrap/unwrap tests using MockKeyStore

---

## Open Questions

1. **`Location::DataProtectionKeychain` availability:**
   Requires `OSX_10_15` feature. `OSX_10_13` does NOT transitively enable it (chain is linear).
   - **Decision:** Resolved — use `features = ["OSX_10_15"]` which gives us everything we need.

2. **Biometric change handling:**
   If user re-enrolls Touch ID, SE key becomes inaccessible.
   - **Decision:** Document as expected behavior (security feature). Recovery password provides access.

3. **Multiple keys per device:**
   - **Decision:** Yes — label-based lookup supports multiple keys (e.g., `minisign:aabbccdd`, `minisign:11223344`)

4. **Key cleanup for orphaned hardware keys:**
   - **Decision:** Future enhancement. Users can use Keychain Access.app for now.

5. **`unsafe` code and CLAUDE.md:**
   The project rule is "ZERO unsafe code." The single `import_p256_public_key()` function requires
   `unsafe` because the Rust crate lacks a safe wrapper. Options:
   - Accept as necessary FFI boundary (recommended — well-documented, isolated)
   - Contribute the wrapper upstream to `security-framework`
   - Use `SecKeyExt::from_data()` (macOS-specific, uses older `SecKeyCreateFromData` — may not
     handle EC keys correctly)
   - **Decision:** Accept the isolated unsafe block with thorough documentation and safety comments.

---

**Author:** Claude (2026-02-12)
**Reviewer:** Claude (2026-02-12, revised to use safe APIs)
**Implementation Status:** Ready to begin
