# Design: Display Credential ID in Key Inspection Output

**Date:** 2026-02-13
**Status:** Approved
**Author:** Claude Code

## Overview

Add credential ID to the key inspection output (`minisign_rs -I`) to help users identify which keychain entry corresponds to their key file.

## Motivation

When inspecting a private key, users currently see:
- Key ID
- Key ID (words)
- Encryption status
- Password saved status

But they don't see the **credential ID** that's actually used for keychain lookups. This makes it difficult to:
1. Identify which keychain entry corresponds to a key file
2. Debug credential store issues
3. Manually manage keychain entries

## Current Behavior

```
Security Level: HIGH [OK]

Key Information:
├─ Key ID: 357AE3725E9EAC1A
├─ Key ID (words): beehive pharmacy puppy frequency guidance tradition involve consulting
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
├─ Password saved: No
└─ KDF Parameters:
   ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   ├─ memlimit: 1073741824 (1024 MB)
   └─ Creation: Normal (production parameters)
```

## Proposed Behavior

```
Security Level: HIGH [OK]

Key Information:
├─ Key ID: 357AE3725E9EAC1A
├─ Key ID (words): beehive pharmacy puppy frequency guidance tradition involve consulting
├─ Credential ID: 1A2B3C4D5E6F7890
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
├─ Password saved: No
└─ KDF Parameters:
   ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   ├─ memlimit: 1073741824 (1024 MB)
   └─ Creation: Normal (production parameters)
```

## Design

### 1. Data Structure Changes

**File:** `src/ops/inspect.rs`

Add `credential_id` field to `InspectResult`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectResult {
    pub key_id: String,
    pub key_id_words: String,
    pub key_type: KeyType,
    pub security_level: Option<SecurityLevel>,
    pub kdf_info: Option<KdfInfo>,
    pub password_saved: bool,
    pub credential_id: Option<String>,  // NEW
}
```

**Type:** `Option<String>`
- `Some(credential_id)` for secret keys (encrypted or unencrypted)
- `None` for public keys (don't participate in credential storage)

**Rationale:**
- `Option` explicitly models that public keys don't have credential IDs
- Type-safe - forces callers to handle the None case
- Clear API intent

### 2. Credential ID Values

**For encrypted secret keys:**
- Credential ID = hex of encrypted keynum bytes (file offset 54-61)
- Available without decryption
- Example: `1A2B3C4D5E6F7890`

**For unencrypted secret keys:**
- Credential ID = Key ID (same as `keynum.to_key_id()`)
- Example: `357AE3725E9EAC1A`

**For public keys:**
- Credential ID = `None` (not applicable)

### 3. Function Updates

**Update `inspect_secret_key()`:**

```rust
fn inspect_secret_key(seckey: &SeckeyStruct) -> Result<InspectResult> {
    let key_id = seckey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(seckey.keynum());
    let credential_id = seckey.credential_id();  // NEW

    // ... existing code ...

    Ok(InspectResult {
        key_id,
        key_id_words,
        key_type: /* ... */,
        security_level: /* ... */,
        kdf_info: /* ... */,
        password_saved,
        credential_id: Some(credential_id),  // NEW
    })
}
```

**Update `inspect_private()`:**

Similar change - extract credential_id from seckey before creating result.

**Update `inspect_public_key()`:**

```rust
fn inspect_public_key(pubkey: &PubkeyStruct) -> InspectResult {
    // ... existing code ...

    InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::Public,
        security_level: None,
        kdf_info: None,
        password_saved: false,
        credential_id: None,  // NEW: Public keys don't have credential IDs
    }
}
```

### 4. Display Updates

**File:** `src/main.rs`

Update `display_inspect_result()` to show credential ID after "Key ID (words)":

```rust
fn display_inspect_result(result: &InspectResult) {
    // ... existing security level display ...

    println!("Key Information:");

    // ... existing key ID display ...

    // NEW: Show credential ID for secret keys only
    if let Some(ref cred_id) = result.credential_id {
        println!("├─ Credential ID: {cred_id}");
    }

    // ... rest of display logic ...
}
```

### 5. Testing

**Update existing tests:**
- All tests that construct `InspectResult` must include `credential_id` field
- Tests in `tests/unit/ops/inspect.rs` need updates

**Test cases to verify:**
1. Encrypted secret key shows correct credential ID (encrypted keynum hex)
2. Unencrypted secret key shows correct credential ID (same as key ID)
3. Public key has `None` for credential_id
4. Display function only shows credential ID for secret keys
5. Credential ID matches the value used for keychain lookups

## Implementation Plan

1. **Update `InspectResult` struct** - Add `credential_id: Option<String>` field
2. **Update `inspect_secret_key()`** - Populate credential_id for secret keys
3. **Update `inspect_private()`** - Populate credential_id when decrypting
4. **Update `inspect_public_key()`** - Set credential_id to None
5. **Update `display_inspect_result()`** - Show credential ID in output
6. **Update all tests** - Add credential_id to test assertions
7. **Run full test suite** - Verify no regressions

## Files Modified

- `rs/src/ops/inspect.rs` - Add credential_id field and populate it
- `rs/src/main.rs` - Display credential_id in output
- `rs/tests/unit/ops/inspect.rs` - Update test assertions

## Compatibility

**Backward compatibility:**
- Binary format: No changes (only affects display output)
- API: Additive change (new field with sensible default)
- C minisign: No interaction (display-only feature)

## Security Considerations

- Credential ID is NOT sensitive (it's derived from public/encrypted data)
- For encrypted keys: credential ID is based on encrypted keynum (already public in file)
- For unencrypted keys: credential ID equals key ID (already shown)
- No new security risks introduced

## Success Criteria

1. `minisign_rs -I` shows credential ID for secret keys
2. Credential ID is displayed after "Key ID (words)"
3. Credential ID matches the value used for keychain lookups
4. Public keys don't show credential ID
5. All tests pass
6. No clippy warnings
