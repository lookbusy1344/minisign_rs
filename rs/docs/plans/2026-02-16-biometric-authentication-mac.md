# Biometric Authentication (Touch ID) for macOS Credential Store

**Date:** 2026-02-16
**Branch:** `claude/add-fingerprint-auth-mac-fzmTi`
**Goal:** Allow macOS users with Touch ID to authenticate via fingerprint when accessing saved passwords, instead of the standard macOS password dialog.

## Background

### Current Behavior

When passwords are saved to the macOS Keychain via `--save-password`, the `keyring` crate creates items with **standard access control**. When the app retrieves these items, macOS shows a system password dialog (or no dialog at all if the app has keychain access). There is no Touch ID prompt because the keychain item was not created with a biometric requirement flag.

### How macOS Biometric Keychain Access Works

macOS only triggers a Touch ID prompt if the specific keychain item was created with a `SecAccessControl` that includes the `kSecAccessControlUserPresence` (or `kSecAccessControlBiometryAny`) flag. This is part of Apple's **Data Protection Keychain** (iOS-style keychain), as opposed to the legacy file-based keychain.

Key Apple APIs involved:
- `SecAccessControlCreateWithFlags` with `kSecAccessControlUserPresence`
- `kSecAttrAccessibleWhenUnlocked` accessibility attribute
- Items stored in the Data Protection Keychain (not the legacy keychain)

### The Constraint: Code Signing Required

The Data Protection Keychain with biometric access control **requires the binary to be code-signed with a provisioning profile**. Specifically:
- The binary must have the `com.apple.application-identifier` entitlement
- This entitlement is set by a provisioning profile (Developer ID or App Store)
- Without it, `SecItemAdd` with `kSecAttrAccessControl` returns error `-34018` ("A required entitlement isn't present")
- Ad-hoc signing (`codesign -s -`) is **not sufficient**

This means the biometric feature will only work when the binary is properly code-signed. The implementation must gracefully fall back when code signing is absent.

## Crate Ecosystem

### `apple-native-keyring-store` (v0.2.2)

A companion crate to `keyring`, specifically for Apple-native credential stores:

- **`keychain` feature**: For unsigned command-line apps. Uses legacy macOS Keychain. No biometric support. This is what `keyring` v3 with `apple-native` feature already uses internally.
- **`protected` feature**: For code-signed apps. Uses Apple Data Protection Keychain. **Supports biometric authentication** via `SecAccessControl` with `require-user-presence`.

The `protected` module works with `keyring-core` v0.7 (same version used internally by `keyring` v3).

### API Pattern

```rust
use apple_native_keyring_store::protected;
use keyring_core::Entry;
use std::collections::HashMap;

// Initialize the protected store (requires code signing)
keyring_core::set_default_store(protected::Store::new()?);

// Create entry with biometric requirement
let mods = HashMap::from([("access-policy", "require-user-presence")]);
let entry = Entry::new_with_modifiers("minisign-bio", "credential-id", &mods)?;

// Save password (stored with biometric access control)
entry.set_password("my-secret-password")?;

// Retrieve password (triggers Touch ID prompt)
let password = entry.get_password()?;

// Clean up
entry.delete_credential()?;
keyring_core::unset_default_store();
```

### Alternative Access Policies

| Policy | Behavior |
|--------|----------|
| `require-user-presence` | Touch ID or device passcode (recommended, most flexible) |
| `biometry-any` | Touch ID only (fails if Touch ID unavailable) |
| `biometry-current-set` | Touch ID with current enrolled fingerprints only |
| `after-first-unlock` | No per-access auth, just requires device unlock once |

We use `require-user-presence` for maximum compatibility: it triggers Touch ID when available, falls back to device passcode when not.

## Design

### UX Model

```
minisign_rs -S -m file.txt --save-password --biometric
  → Prompts for password (first time)
  → Signs the file
  → Saves password to biometric-protected keychain entry

minisign_rs -S -m file.txt
  → Detects biometric-protected entry exists
  → macOS shows Touch ID prompt
  → User authenticates with fingerprint
  → Password retrieved, file signed
```

### CLI Interface

**New flag:**

| Flag | Description |
|------|-------------|
| `--biometric` | Store password with biometric (Touch ID) protection (macOS only) |

The `--biometric` flag:
- Only meaningful when combined with `--save-password`
- macOS-only (ignored with a warning on other platforms)
- Requires code-signed binary (fails gracefully if not)

**Usage examples:**
```bash
# Save password with Touch ID protection
minisign_rs -G --save-password --biometric

# Sign using Touch ID (if biometric entry exists)
minisign_rs -S -m file.txt

# Save password with Touch ID after successful signing
minisign_rs -S -m file.txt --save-password --biometric

# Forget a biometric-protected password
minisign_rs -K --forget-password

# Inspect shows biometric status
minisign_rs -I
```

### Credential Store Architecture

Two separate stores coexist:

| Store | Service Name | Backend | Auth Method |
|-------|-------------|---------|-------------|
| Standard | `"minisign"` | `keyring` v3 (legacy Keychain) | System password / auto |
| Biometric | `"minisign-bio"` | `keyring-core` + `apple-native-keyring-store` protected | Touch ID / passcode |

Using distinct service names ensures:
- Existing standard credentials continue to work
- Biometric and standard entries don't conflict
- Migration is opt-in (user saves with `--biometric` when ready)

### Retrieval Priority

When retrieving a saved password, the order is:
1. **Biometric store** (if `biometric` feature enabled, macOS only) -- triggers Touch ID
2. **Standard store** (current behavior) -- no prompt
3. **User prompt** (fallback) -- terminal password input

If the biometric store returns an error (unsigned binary, user cancelled Touch ID, no hardware), it falls through silently to the next option.

### Inspect Display

```
Password saved: Yes (biometric)
```
or
```
Password saved: Yes
```
or
```
Password saved: No
```

## Implementation Steps

### Step 1: Add Dependencies

**`Cargo.toml` changes:**

```toml
[dependencies]
# Existing keyring stays as-is
keyring = { version = "3", features = ["apple-native", "windows-native", "sync-secret-service", "crypto-rust"], optional = true }

# New: for biometric-protected entries on macOS
keyring-core = { version = "0.7", optional = true }

[target.'cfg(target_os = "macos")'.dependencies]
apple-native-keyring-store = { version = "0.2", features = ["protected"], optional = true }

[features]
default = ["credential_store"]
credential_store = ["dep:keyring"]
credential_store_tests = ["credential_store"]

# New feature for biometric authentication (macOS only)
biometric = ["credential_store", "dep:keyring-core", "dep:apple-native-keyring-store"]
```

### Step 2: Add `--biometric` CLI Flag

**`src/cli.rs`:**

```rust
/// Store password with biometric (Touch ID) protection (macOS only)
/// Only effective when combined with --save-password
#[arg(long = "biometric")]
pub biometric: bool,
```

### Step 3: Extend `credential_store.rs`

Add biometric-aware functions alongside the existing standard functions:

```rust
// --- Biometric credential store (macOS only, requires code signing) ---

#[cfg(all(target_os = "macos", feature = "biometric"))]
const BIOMETRIC_SERVICE_NAME: &str = "minisign-bio";

/// Save a password with biometric (Touch ID) protection
#[cfg(all(target_os = "macos", feature = "biometric"))]
pub fn save_password_biometric(credential_id: &str, password: &str) -> Result<()> { ... }

/// Retrieve a biometric-protected password (triggers Touch ID prompt)
#[cfg(all(target_os = "macos", feature = "biometric"))]
pub fn get_password_biometric(credential_id: &str) -> Option<Zeroizing<String>> { ... }

/// Remove a biometric-protected password
#[cfg(all(target_os = "macos", feature = "biometric"))]
pub fn forget_password_biometric(credential_id: &str) -> Result<()> { ... }

/// Check if a biometric-protected password exists
#[cfg(all(target_os = "macos", feature = "biometric"))]
pub fn has_password_biometric(credential_id: &str) -> bool { ... }

// Stub implementations for non-macOS or when biometric feature disabled
#[cfg(not(all(target_os = "macos", feature = "biometric")))]
pub fn save_password_biometric(_: &str, _: &str) -> Result<()> { Ok(()) }
// ... etc
```

Implementation detail for the biometric save:

```rust
#[cfg(all(target_os = "macos", feature = "biometric"))]
pub fn save_password_biometric(credential_id: &str, password: &str) -> Result<()> {
    use apple_native_keyring_store::protected;
    use std::collections::HashMap;

    // Initialize protected store (requires code-signed binary)
    let store = protected::Store::new()
        .map_err(|e| Error::CredentialStoreError(
            format!("failed to initialize biometric store (is the binary code-signed?): {e}")
        ))?;

    keyring_core::set_default_store(store);

    let mods = HashMap::from([("access-policy", "require-user-presence")]);
    let entry = keyring_core::Entry::new_with_modifiers(BIOMETRIC_SERVICE_NAME, credential_id, &mods)
        .map_err(|e| Error::CredentialStoreError(format!("failed to create biometric entry: {e}")))?;

    let result = entry.set_password(password)
        .map_err(|e| Error::CredentialStoreError(format!("failed to save biometric password: {e}")));

    keyring_core::unset_default_store();
    result
}
```

### Step 4: Update `main.rs` Password Flow

**Modify `save_password_to_credential_store()`:**

```rust
fn save_password_to_credential_store(
    key_id: &str,
    password: Option<&Zeroizing<String>>,
    save_password: bool,
    biometric: bool,  // NEW parameter
    quiet: bool,
    extra_context_on_error: Option<&str>,
) {
    if save_password {
        if let Some(pwd) = password {
            // Try biometric save first if requested
            if biometric {
                match minisign::credential_store::save_password_biometric(key_id, pwd) {
                    Ok(()) => {
                        if !quiet {
                            eprintln!("Password saved with biometric (Touch ID) protection");
                        }
                        return;
                    }
                    Err(e) => {
                        eprintln!("Warning: Biometric save failed, falling back to standard: {e}");
                    }
                }
            }
            // Standard save (existing behavior)
            match minisign::credential_store::save_password(key_id, pwd) { ... }
        }
    }
}
```

**Modify `get_password_with_credential_store()`:**

```rust
fn get_password_with_credential_store(
    key_id: &str,
    quiet: bool,
    password_file: Option<&std::path::Path>,
) -> Result<Option<Zeroizing<String>>> {
    // Try biometric store first (triggers Touch ID if entry exists)
    if let Some(saved_pwd) = minisign::credential_store::get_password_biometric(key_id) {
        if !quiet {
            eprintln!("Authenticated with Touch ID");
        }
        return Ok(Some(saved_pwd));
    }

    // Fall back to standard store
    if let Some(saved_pwd) = minisign::credential_store::get_password(key_id) {
        if !quiet {
            eprintln!("Using saved password from credential store");
        }
        return Ok(Some(saved_pwd));
    }

    // Fall back to prompting
    Ok(Some(prompt_password("Password: ", password_file)?))
}
```

**Modify `handle_change()` for `--forget-password`:**

```rust
if cli.forget_password {
    // Forget from both stores
    let _ = minisign::credential_store::forget_password_biometric(&old_credential_id);
    let had_password = minisign::credential_store::has_password(&old_credential_id)
        || minisign::credential_store::has_password_biometric(&old_credential_id);
    return match minisign::credential_store::forget_password(&old_credential_id) { ... };
}
```

### Step 5: Update Inspect Display

In `display_inspect_result()`, enhance password saved display:

```rust
let bio_saved = minisign::credential_store::has_password_biometric(credential_id);
let std_saved = result.password_saved;

let status = if bio_saved {
    "Yes (biometric)"
} else if std_saved {
    "Yes"
} else {
    "No"
};
println!("├─ Password saved: {status}");
```

### Step 6: Update Inspect Result

Add a `password_saved_biometric` field to `InspectResult`:

```rust
pub struct InspectResult {
    // ... existing fields ...
    pub password_saved: bool,
    pub password_saved_biometric: bool,  // NEW
}
```

### Step 7: Tests

New test in `tests/unit/credential_store.rs`:

```rust
#[cfg(all(target_os = "macos", feature = "biometric", feature = "credential_store_tests"))]
mod biometric_tests {
    // These tests require:
    // 1. macOS with Touch ID hardware
    // 2. Code-signed binary with provisioning profile
    // 3. Interactive session (for Touch ID prompt)

    #[test]
    #[serial]
    fn biometric_round_trip() {
        let guard = CredentialGuard::new("biometric-test-key");
        save_password_biometric("biometric-test-key", "test-password").unwrap();
        let retrieved = get_password_biometric("biometric-test-key");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_str(), "test-password");
    }
}
```

Non-macOS stub tests to verify graceful fallback:

```rust
#[cfg(not(all(target_os = "macos", feature = "biometric")))]
mod biometric_stub_tests {
    #[test]
    fn biometric_stubs_are_no_ops() {
        assert!(save_password_biometric("key", "pwd").is_ok());
        assert!(get_password_biometric("key").is_none());
        assert!(forget_password_biometric("key").is_ok());
        assert!(!has_password_biometric("key"));
    }
}
```

## Dependency Changes

**Add to `[dependencies]`:**
- `keyring-core = { version = "0.7", optional = true }`

**Add to `[target.'cfg(target_os = "macos")'.dependencies]`:**
- `apple-native-keyring-store = { version = "0.2", features = ["protected"], optional = true }`

**Add to `[features]`:**
- `biometric = ["credential_store", "dep:keyring-core", "dep:apple-native-keyring-store"]`

**Net impact:** 2 new optional dependencies, only pulled in on macOS when feature enabled.

## Code Signing Guide (for users)

To use the `--biometric` flag, the minisign_rs binary must be code-signed with a provisioning profile.

### Option 1: Developer ID (outside App Store)

```bash
# 1. Create a provisioning profile at developer.apple.com
# 2. Build the binary
cargo build --release --features biometric

# 3. Sign with Developer ID and provisioning profile
codesign --sign "Developer ID Application: Your Name (TEAM_ID)" \
    --entitlements entitlements.plist \
    --options runtime \
    target/release/minisign_rs
```

Required `entitlements.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array/>
</dict>
</plist>
```

### Option 2: Wrap in .app Bundle

Some CLI tools (e.g., Teleport) package as a `.app` bundle for automatic provisioning profile association.

### Without Code Signing

If the binary is not code-signed, `--biometric` will print a warning and fall back to standard credential store behavior:

```
Warning: Biometric save failed, falling back to standard: failed to initialize
biometric store (is the binary code-signed?)
Password saved to OS credential store
```

## Risk Assessment

| Risk | Level | Mitigation |
|------|-------|------------|
| Code-signing requirement limits adoption | Medium | Graceful fallback, clear documentation |
| `apple-native-keyring-store` is young (v0.2, ~1K downloads) | Medium | Feature-flagged, optional dependency |
| Global `keyring-core` store state (`set_default_store`) | Low | Set/unset around each operation |
| Touch ID prompt in non-interactive context (SSH, cron) | Low | Returns error, falls through to standard store |
| Biometric entry survives between signed/unsigned builds | Low | Unsigned build ignores biometric store, prompts for password |

## Design Decisions

1. **Separate service names** (`"minisign"` vs `"minisign-bio"`): Prevents conflicts between standard and biometric entries. User can have both simultaneously.
2. **Biometric-first retrieval**: When retrieving, always try biometric store first. If the user saved with biometric, that's what they want. If it fails, fall through to standard store.
3. **Opt-in only**: The `--biometric` flag must be explicitly passed. No automatic biometric enrollment.
4. **Feature flag isolation**: The `biometric` feature is separate from `credential_store`. Users who don't want the extra dependencies can build without it.
5. **`require-user-presence` policy**: Most flexible -- allows Touch ID, Face ID, or device passcode as fallback. Works on all macOS hardware.
6. **`--forget-password` clears both stores**: When forgetting, remove from both biometric and standard stores. User shouldn't have to remember which they used.
