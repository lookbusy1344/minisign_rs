# Plan: Credential Store — Cleartext Key ID in Secret Key Comment

## Context

The credential store feature (`--save-password` / `--forget-password`) has two bugs that
together render it completely non-functional:

1. **Missing keyring backend features** — `keyring = "3"` ships with no default backends.
   Without `apple-native`, `windows-native`, or `sync-secret-service` features, the crate
   silently uses a mock backend on all platforms. Every credential store operation appears
   to succeed but nothing persists. **(Already fixed in this session — Cargo.toml updated.)**

2. **Zeroed key ID for encrypted keys** — `SeckeyStruct::from_bytes` sets
   `keynum = [0u8; 8]` for encrypted keys (the real keynum is inside the encrypted blob).
   The sign path calls `seckey.keynum().to_key_id()` before decryption, yielding
   `"0000000000000000"`, which never matches the key ID saved during `--save-password`
   (which uses the real keynum after decryption).

Both bugs were invisible because every test silently skips via `is_keyring_available()`,
and the graceful-degradation design (fall back to password prompt) masks lookup failures.

## Solution

Store the key ID in cleartext in the secret key file's comment line. The key ID is already
public (present in `.pub` files and every `.minisig` signature). No security implications.

### Comment format

```
untrusted comment: minisign encrypted secret key 31FCAABFDC95A530
```

C minisign ignores the comment content, so this is fully backwards-compatible. Old key files
without the key ID in the comment continue to work — the credential store lookup simply
falls back to a file-path-based key.

### Credential store lookup order

1. **Key ID from comment** — if the secret key file has a key ID in the comment, look up
   the password by key ID (survives file moves).
2. **Canonical file path** — fall back to looking up by canonical absolute path of the
   secret key file (works for old files without key ID in comment, breaks on file move).
3. **Prompt** — if neither lookup succeeds, prompt the user.

### Credential store save strategy

When `--save-password` is used, save the password under **both**:
- The key ID (primary, stable)
- The canonical file path (fallback, for old-format files)

When `--forget-password` is used, forget under **both** keys.

## Files to Modify

### 1. `src/keys.rs` — Comment-based key ID

**`to_file_contents` (line 808):**
- If `self.keynum` is not all-zeros, append the key ID hex to the comment.
- Format: `"untrusted comment: {comment} {keynum_hex}\n{base64}\n"`
- If keynum is all-zeros (old encrypted key never re-saved), omit it.

**`from_file_contents` (line 792):**
- After splitting lines, extract the last whitespace-delimited token from the comment.
- Check if it's a 16-character uppercase hex string.
- If so, parse it as a `KeyNum` and set it on the struct (overriding the zeros).
- Add a helper: `fn parse_keynum_from_comment(comment: &str) -> Option<KeyNum>`

### 2. `src/credential_store.rs` — Path-based fallback

Add a `path:` prefix convention for file-path-based credential entries:

- `save_password_for_path(path: &Path, password: &str) -> Result<()>`
- `get_password_for_path(path: &Path) -> Option<Zeroizing<String>>`
- `forget_password_for_path(path: &Path) -> Result<()>`

These use `format!("path:{}", canonical_path.display())` as the keyring user/key.
Use `std::fs::canonicalize` to normalize the path.

### 3. `src/main.rs` — Updated lookup and save flows

**`get_password_with_credential_store` (line 159):**
- Change signature to accept `key_id: &str, secret_key_path: &Path, quiet, password_file`.
- Try `credential_store::get_password(key_id)` first (if key_id is not all-zeros).
- Fall back to `credential_store::get_password_for_path(secret_key_path)`.
- Fall back to prompting.

**`save_password_to_credential_store` (line 176):**
- Change signature to also accept `secret_key_path: &Path`.
- Save under both key ID and path.

**`handle_sign` (line 200):**
- Pass `secret_key_file` to the updated functions.

**`handle_change_password` (line 474):**
- Same — pass `secret_key_file` to updated functions.
- After re-encryption, the new SeckeyStruct has the real keynum (line 193-198),
  so `to_file_contents` will include it in the comment → future lookups work by key ID.

**Forget-password block (line 484):**
- Also forget by path: `credential_store::forget_password_for_path(secret_key_file)`.

### 4. `src/ops/generate.rs` — Key ID in generate comment

**Lines 339-343:** The secret key comment is currently a static string. No change needed —
`to_file_contents` will automatically append the keynum since the struct has it.

### 5. `src/ops/change.rs` — Key ID in change-password comment

**Lines 227-233:** Same — `new_seckey.to_file_contents(seckey_comment)` will automatically
include the keynum since the re-encrypted struct has the real keynum.

### 6. Tests

**`tests/cli_test.rs`:**
- The three new end-to-end tests written this session should now pass.
- Add a test for the file-path fallback: generate key (old format, no keynum in comment),
  manually save password by path, sign without `--password-file`.
- Add a test that a re-saved key (via `-K`) gets the keynum in the comment.

**`tests/unit/credential_store.rs`:**
- Add tests for `save_password_for_path` / `get_password_for_path` / `forget_password_for_path`.

**Compatibility tests:**
- Verify C minisign can still load key files with the new comment format.
- Verify this Rust implementation can load old key files without keynum in comment.

### 7. Existing tests — comment assertions

Search for tests that assert on the exact comment string content (e.g.,
`"minisign encrypted secret key"` without trailing key ID). These will need updating
to account for the appended key ID.

## Verification

```bash
# Clippy + format
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt

# Fast tests
gtimeout 120 cargo test

# Slow tests
gtimeout 120 cargo test -- --ignored

# Specifically run credential store tests
gtimeout 120 cargo test "credential_store" -- --nocapture

# Specifically run new end-to-end tests
gtimeout 120 cargo test --test cli_test "test_sign_uses_saved_password" -- --nocapture
gtimeout 120 cargo test --test cli_test "test_sign_multiple_files_uses_saved" -- --nocapture
gtimeout 120 cargo test --test cli_test "test_save_password_on_sign_then_reuse" -- --nocapture

# Verify C minisign compatibility (if C minisign installed)
gtimeout 120 cargo test "compatibility" -- --nocapture
```

## Implementation Order

1. Fix `Cargo.toml` keyring features ✅ (already done)
2. `keys.rs` — `to_file_contents` and `from_file_contents` changes
3. `credential_store.rs` — path-based fallback functions
4. `main.rs` — updated lookup/save/forget flows
5. Tests — update assertions for new comment format, verify end-to-end tests pass
6. Run full test suite + clippy
