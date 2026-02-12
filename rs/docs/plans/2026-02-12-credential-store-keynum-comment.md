# Plan: Fix Credential Store — Use Encrypted Keynum as Credential ID

## Context

The credential store feature (`--save-password` / `--forget-password`) has two bugs that
together render it completely non-functional:

1. **Missing keyring backend features** — `keyring = "3"` ships with no default backends.
   Without `apple-native`, `windows-native`, or `sync-secret-service` features, the crate
   silently uses a mock backend on all platforms. **(Already fixed — Cargo.toml updated.)**

2. **Zeroed key ID for encrypted keys** — `SeckeyStruct::from_bytes` sets
   `keynum = [0u8; 8]` for encrypted keys (the real keynum is inside the encrypted blob).
   The sign path calls `seckey.keynum().to_key_id()` before decryption, yielding
   `"0000000000000000"`, which never matches the key ID saved during `--save-password`
   (which uses the real keynum after decryption).

Both bugs were invisible because every test silently skips via `is_keyring_available()`,
and the graceful-degradation design (fall back to password prompt) masks lookup failures.

## Solution

Use the **encrypted keynum bytes** (positions 54-61 in the secret key binary) as the
credential store lookup key. These bytes are:
- Always available without decryption
- Unique per key+password+salt combination
- Deterministic for a given key file

For encrypted keys, these are the XOR of the derived key with the plaintext keynum.
For unencrypted keys, these are the plaintext keynum (same as today, and no password
to store anyway).

No file format changes. No comment modifications. No backwards compatibility concerns.

### Credential store key

A new method `SeckeyStruct::credential_id() -> String` returns a hex string suitable
for credential store lookup:
- Encrypted: hex of `encrypted_keynum` bytes (the raw bytes at file offset 54-61)
- Unencrypted: hex of plaintext `keynum` (same as `to_key_id()`)

### Trade-off

The encrypted keynum changes when the password or salt changes (e.g., via `-K`).
This is handled: the change-password flow deletes the old credential and saves the
new one under the new `credential_id()`. If someone changes the password via C minisign,
the Rust credential store lookup misses — graceful fallback to prompting.

### Save strategy (when `--save-password`)

Save under `credential_id()` (the encrypted keynum hex).
During generate: the new SeckeyStruct has the encrypted keynum.
During sign: `credential_id()` is available from the loaded key.
During change-password: delete old credential (old `credential_id()`), save new
credential (new `credential_id()` after re-encryption).

## Files to Modify

### 1. `src/keys.rs` — Add `credential_id()` method

**After line 601 (existing `keynum()` getter):**

Add getter for encrypted keynum and the `credential_id()` method:

```rust
/// Raw encrypted keynum bytes (positions 54-61 in the key file).
/// For unencrypted keys, returns all zeros.
#[must_use]
pub const fn encrypted_keynum(&self) -> &[u8; KEYNUM_BYTES] {
    &self.encrypted_keynum
}

/// Credential store lookup key — always available without decryption.
///
/// For encrypted keys: hex of the encrypted keynum bytes at file offset 54-61.
/// For unencrypted keys: hex of the plaintext keynum (same as `to_key_id()`).
///
/// This value is deterministic for a given key file and changes when the
/// password or KDF salt changes. It is unique per key+password+salt combination.
#[must_use]
pub fn credential_id(&self) -> String {
    if self.encrypted {
        // Use encrypted keynum bytes — available without decryption
        use std::fmt::Write;
        self.encrypted_keynum.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02X}");
            s
        })
    } else {
        self.keynum.to_key_id()
    }
}
```

### 2. `src/main.rs` — Update all credential store call sites

**`get_password_with_credential_store` (line 159):**
- Change `key_id` param from the zeroed keynum to `credential_id`.
- No signature change needed — it already takes `&str`.

**`handle_sign` (line 227-236):**
- Change `let key_id = seckey.keynum().to_key_id()` to `let credential_id = seckey.credential_id()`
- Use `credential_id` for credential store lookup and save.
- Keep the existing `key_id` logic (from `seckey.keynum().to_key_id()`) for display purposes
  where needed, but credential store operations use `credential_id`.

**`save_password_to_credential_store` (line 176):**
- Change `key_id` usage to `credential_id`.

**`handle_change_password` (line 474):**
- Before decryption: capture `let old_credential_id = seckey.credential_id()` for deleting
  old credential.
- After re-encryption: use `new_seckey.credential_id()` for saving new credential.
- Forget-password block (line 484): use `old_credential_id`.

**Change-password credential store flow (lines 501-515, 556-571):**
- Old password lookup at line 502: use `seckey.credential_id()`
- New password save at line 558: use the re-encrypted struct's `credential_id()`
- Need to also delete old credential entry when password changes and `--save-password`
  is used, since the `credential_id()` changes with the new password.

**Generate flow (line 125):**
- Change from `result.keynum_hex()` to using the `SeckeyStruct`'s `credential_id()`.
- The generate flow in `main.rs` line 125 uses `result.keynum_hex()`. We need access to
  the SeckeyStruct's credential_id. Either:
  (a) Add `credential_id` to `GenerateResult`
  (b) Pass `credential_id` back from the generate op
  Approach (a) is cleaner — add a `credential_id: String` field to `GenerateResult`
  in `src/ops/generate.rs`.

### 3. `src/ops/generate.rs` — Return `credential_id` in result

**`GenerateResult` struct (around line 183):**
- Add field: `credential_id: String`
- Add getter: `pub fn credential_id(&self) -> &str`

**`generate_with_log_n` (around line 354):**
- After creating the SeckeyStruct, capture `seckey.credential_id()` and include it in
  the `GenerateResult`.

### 4. `src/ops/inspect.rs` — Update `has_password` checks

**`inspect_secret_key` (line 250-288):**
- The `--no-decrypt` path. Currently uses `seckey.keynum().to_key_id()` which returns
  zeros for encrypted keys. Change to `seckey.credential_id()`.
- Line 288: `has_password(&key_id)` → `has_password(&seckey.credential_id())`
- This is the path at line 288 inside `inspect_secret_key`. The `key_id` variable
  at line 251 is used for display AND credential check. Split these: use
  `seckey.keynum().to_key_id()` for display, `seckey.credential_id()` for the
  credential store check.

**`inspect_private` (line 187-237):**
- The decrypt path. Currently uses `decrypted_keynum.to_key_id()` for the credential
  check (line 219). Change to `seckey.credential_id()` since the credential is stored
  under the encrypted keynum, not the decrypted one.

### 5. Tests

**Existing 3 new CLI tests (`tests/cli_test.rs`):**
- Should now pass with the corrected credential store flow.
- The `generate_key_with_saved_password` helper generates with `--save-password` (which
  saves under `credential_id()`), and the sign test looks up under `credential_id()`.

**Update `test_save_password_flag_with_generate` (line 2079):**
- Currently verifies with `credential_store::get_password(key_id)` where `key_id` is
  the decrypted keynum from inspect output. This will need to verify with the
  encrypted keynum-based credential ID instead. May need to expose credential_id
  or verify differently (e.g., just verify signing works without password-file).

**Update `test_inspect_shows_password_saved_status` (line 2352):**
- Currently saves password under decrypted key ID. Needs to save under credential_id.

**Update other existing credential store CLI tests** that directly call
`credential_store::save_password(key_id, ...)` with the decrypted key ID.

**Add unit test for `credential_id()`:**
- Encrypted key returns hex of encrypted_keynum
- Unencrypted key returns same as `keynum().to_key_id()`

## Implementation Order

1. ✅ Fix `Cargo.toml` keyring features (done)
2. `src/keys.rs` — add `encrypted_keynum()` getter and `credential_id()` method
3. `src/ops/generate.rs` — add `credential_id` to `GenerateResult`
4. `src/main.rs` — update all credential store call sites
5. `src/ops/inspect.rs` — update `has_password` checks
6. Tests — update existing tests, verify new end-to-end tests pass
7. Clippy + fmt + full test suite

## Verification

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
gtimeout 120 cargo test
gtimeout 120 cargo test -- --ignored
gtimeout 120 cargo test "credential_store" -- --nocapture
gtimeout 120 cargo test --test cli_test "test_sign_uses_saved_password" -- --nocapture
gtimeout 120 cargo test --test cli_test "test_sign_multiple_files_uses_saved" -- --nocapture
gtimeout 120 cargo test --test cli_test "test_save_password_on_sign_then_reuse" -- --nocapture
gtimeout 120 cargo test "compatibility" -- --nocapture
```
