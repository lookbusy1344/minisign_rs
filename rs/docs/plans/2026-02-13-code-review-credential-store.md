# Code Review: Credential Store Integration

**Date:** 2026-02-13
**Branch:** `lb_rust`
**Reviewer:** Claude Code Review
**Scope:** Full credential store integration review per plan `2026-02-12-credential-store-keynum-comment.md`

## Executive Summary

The credential store integration is **largely correct and well-implemented**. Both critical bugs
identified in the original plan (missing keyring backend features, zeroed key ID for credential
store lookup) have been fixed. Clippy (pedantic) passes cleanly, and all 305 tests (fast + slow)
pass.

However, the review found **1 high-severity usability bug**, **2 medium issues**, and
**4 low-severity issues** that should be addressed.

---

## Current State

| Check | Status |
|-------|--------|
| `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic` | PASS |
| `cargo fmt` | PASS |
| `cargo test` (fast, ~305 tests) | PASS |
| `cargo test -- --ignored` (slow, ~11 tests) | PASS |
| Plan Bug #1: keyring backend features | FIXED |
| Plan Bug #2: zeroed keynum credential lookup | FIXED (via `credential_id()`) |
| `credential_id()` method on `SeckeyStruct` | Implemented |
| `credential_id` field on `GenerateResult` | Implemented |
| `credential_id` field on `ChangeResult` | Implemented |
| All credential store call sites updated | Verified |
| Unit tests for `credential_id()` | Present (2 tests in `unit/keys.rs`) |
| CLI integration tests for credential store | Present (10 tests in `cli_test.rs`) |

---

## Issues Found

### HIGH-1: Missing Password Confirmation in Change-Password Flow

**File:** `src/main.rs:547-553`
**Severity:** HIGH (usability — potential data loss)

The `handle_change` function prompts for the new password only once:

```rust
let new_password = if cli.no_password {
    None
} else {
    Some(prompt_password(
        "New password: ",
        cli.password_file.as_deref(),
    )?)
};
```

The key generation flow (`handle_generate`) correctly uses `prompt_password_with_confirmation()`
which prompts twice and verifies the entries match. The change-password flow does not.

**Impact:** If the user typos the new password, the key becomes unusable. Recovery requires:
- A backup of the key file, OR
- The old password saved in the credential store

**C minisign behavior:** The C implementation (`minisign.c`) prompts twice for the new password
during `-K` (change password).

**Fix:** Replace `prompt_password(...)` with `prompt_password_with_confirmation(...)` in the
new password prompt section of `handle_change`.

---

### MED-1: Stale Documentation in `credential_store.rs`

**File:** `src/credential_store.rs:9`
**Severity:** MEDIUM (documentation correctness)

The module-level doc comment says:

> Passwords are keyed by the key ID (8-byte hex string) rather than file path

This is now inaccurate. Passwords are keyed by `credential_id`, which is:
- For encrypted keys: hex of the **encrypted** keynum bytes (not the key ID)
- For unencrypted keys: the key ID (plaintext keynum hex)

The parameter names (`key_id`) throughout the module are also misleading. They should be
`credential_id` to match the actual semantics.

**Fix:** Update module doc comment and rename `key_id` parameters to `credential_id` throughout
`credential_store.rs`.

---

### MED-2: `credential_id()` Inconsistent Hex Encoding Between Encrypted/Unencrypted Paths

**File:** `src/keys.rs:618-631`
**Severity:** MEDIUM (correctness/consistency)

The `credential_id()` method uses two different hex encoding strategies:

- **Encrypted path** (line 622-627): Byte-by-byte big-endian hex via `write!(s, "{b:02X}")`
  - Example: bytes `[0x01, 0x02, ..., 0x08]` → `"0102030405060708"`

- **Unencrypted path** (line 629): `self.keynum.to_key_id()` which interprets bytes as a
  little-endian u64, then formats
  - Example: same bytes → u64 `0x0807060504030201` → `"0807060504030201"`

**Impact:** Not a functional bug today — encrypted and unencrypted keys use different paths
consistently. However:
1. If you generate an unencrypted key, save a password (which makes no sense but is allowed),
   then add encryption via `-K`, the credential_id changes in a way that's not just due to
   encryption but also due to the hex encoding difference.
2. Anyone reading the code or debugging credential store issues will be confused by the
   inconsistency.

**Fix:** Use the same encoding in both paths. The encrypted path's byte-by-byte encoding is
simpler and doesn't depend on endianness interpretation. Either:
- (a) Change the encrypted path to match `to_key_id()` (interpret as LE u64), or
- (b) Change both paths to use byte-by-byte hex (requires adding a `to_hex()` method on KeyNum
  or changing `to_key_id()`)

Option (a) is simpler and maintains consistency with the display format. The change would be:
```rust
pub fn credential_id(&self) -> String {
    if self.encrypted {
        use crate::formats::read_u64_le;
        let value = read_u64_le(&self.encrypted_keynum)
            .expect("encrypted_keynum is always 8 bytes");
        format!("{value:016X}")
    } else {
        self.keynum.to_key_id()
    }
}
```

**Important:** This changes the credential store key for existing saved passwords on encrypted
keys. Any passwords saved before this fix will become orphaned. This is acceptable since:
1. The credential store is a convenience feature (graceful fallback to prompting)
2. Users can re-save with `--save-password`
3. The feature is new and the user base is small

---

### LOW-1: Misleading "Password removed" Message for Non-Existent Credentials

**File:** `src/main.rs:512-518`
**Severity:** LOW (UX polish)

When `--forget-password` is used on an unencrypted key (or a key that never had a saved
password), the user sees "Password removed from credential store" even though nothing was
actually removed. The `forget_password()` function treats `NoEntry` as success (idempotent),
which is correct for the API, but the user-facing message is misleading.

**Fix:** Either:
- (a) Check `has_password()` before calling `forget_password()` and print a different message, or
- (b) Return a boolean from `forget_password()` indicating whether anything was actually deleted

---

### LOW-2: Double/Triple Key File Loading

**File:** `src/main.rs` (multiple locations)
**Severity:** LOW (performance)

Several flows load the key file multiple times:

1. **`handle_sign`** (line 246, then again inside `sign()` → `load_and_decrypt_key()`):
   Loads twice — once for credential_id, once for signing.

2. **`handle_inspect`** (line 727 `inspect()`, then line 763 `load_secret_key()`, then
   line 778 `inspect_private()` which loads again): Loads up to three times for encrypted keys.

3. **`handle_recreate`** (line 466, then again inside `recreate()`): Loads twice.

**Impact:** Negligible for key files (tiny files, ~200 bytes). But it's indicative of an
API design issue where the ops functions take file paths instead of pre-loaded key structs.

**Fix:** Consider adding `_with_key` variants of the ops functions that accept a pre-loaded
`SeckeyStruct`. This is a refactoring task that doesn't need to block the credential store work.

---

### LOW-3: Misleading Comment in `SeckeyStruct::from_bytes`

**File:** `src/keys.rs:810`
**Severity:** LOW (documentation)

The comment says:
```rust
keynum,           // Contains encrypted keynum if encrypted, plaintext if not
```

For encrypted keys, `keynum` is actually `[0u8; KEYNUM_BYTES]` (zeroed), not the encrypted
keynum. The encrypted keynum is in `encrypted_keynum`. The inline comment at line 790 is correct
("zero keynum until decrypt") but the final comment is misleading.

**Fix:** Change to:
```rust
keynum,           // Zeroed if encrypted (real keynum recovered on decrypt), plaintext if not
```

---

### LOW-4: No Test for Change-Password Credential Store Flow

**Severity:** LOW (test coverage gap)

The existing credential store CLI tests cover:
- Generate with `--save-password`
- Sign using saved password
- Sign with `--save-password` then reuse
- `--forget-password` standalone
- Inspect shows password saved status

Missing test coverage:
- Change password (`-K`) with `--save-password`: verifying old credential is deleted and new
  credential is saved under the new `credential_id`
- Change password without `--save-password`: verifying old credential is deleted
- Remove password (`-K -W`): verifying old credential is deleted

---

## Remediation Plan

### Priority 1 — Must Fix Before Merge

| # | Issue | File | Effort |
|---|-------|------|--------|
| 1 | Add password confirmation to change-password flow | `src/main.rs` | ~5 lines |

### Priority 2 — Should Fix Soon

| # | Issue | File | Effort |
|---|-------|------|--------|
| 2 | Update `credential_store.rs` documentation and parameter names | `src/credential_store.rs` | ~20 lines |
| 3 | Fix `credential_id()` hex encoding consistency | `src/keys.rs` | ~10 lines |
| 4 | Add change-password credential store test | `tests/cli_test.rs` | ~60 lines |

### Priority 3 — Nice to Have

| # | Issue | File | Effort |
|---|-------|------|--------|
| 5 | Fix misleading "Password removed" message | `src/main.rs` | ~10 lines |
| 6 | Fix misleading comment in `from_bytes` | `src/keys.rs` | 1 line |
| 7 | Reduce redundant file loads (API refactor) | Multiple | ~100 lines |

---

## Implementation Details

### Fix 1: Password Confirmation in Change Flow

```rust
// In handle_change(), replace:
let new_password = if cli.no_password {
    None
} else {
    Some(prompt_password(
        "New password: ",
        cli.password_file.as_deref(),
    )?)
};

// With:
let new_password = if cli.no_password {
    None
} else {
    Some(prompt_password_with_confirmation(
        cli.password_file.as_deref(),
    )?)
};
```

Note: `prompt_password_with_confirmation` already handles both interactive (prompts twice)
and file-based (reads once) scenarios.

### Fix 2: Update `credential_store.rs` Documentation

Rename all `key_id` parameters to `credential_id` and update the module doc comment to
accurately describe the credential_id scheme.

### Fix 3: Consistent Hex Encoding

Update `credential_id()` encrypted path to use little-endian u64 interpretation matching
`to_key_id()`. Update the `test_credential_id_for_encrypted_key` unit test to match.

### Fix 4: Change-Password Credential Store Test

Add a test that:
1. Generates a key with `--save-password`
2. Changes the password with `-K --save-password`
3. Verifies old credential_id no longer has a password
4. Verifies new credential_id has the new password
5. Verifies signing works without password prompt (using new saved password)

---

## Architecture Notes

The credential store integration follows a clean separation of concerns:

```
credential_store.rs  — thin wrapper around `keyring` crate (save/get/forget/has)
       ↑
keys.rs              — credential_id() method on SeckeyStruct
       ↑
main.rs              — orchestration (lookup before prompt, save after operation)
ops/change.rs        — returns credential_id in ChangeResult
ops/generate.rs      — returns credential_id in GenerateResult
ops/inspect.rs       — uses credential_id for has_password check
```

The design correctly keeps credential store logic out of the core crypto/signing operations
and limits it to the CLI layer (`main.rs`) and the inspect display layer. The graceful
degradation (fall back to password prompt on any credential store failure) is well-implemented.

The `credential_id()` approach (using encrypted keynum bytes) is a sound solution to the
"can't know the real keynum without decrypting" problem. It's deterministic, available without
decryption, and unique per key+password+salt combination.
