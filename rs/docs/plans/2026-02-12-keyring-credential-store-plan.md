# Replace Secure Enclave with OS Credential Store (`keyring` crate)

**Date:** 2026-02-12
**Branch:** `hardware_key`
**Goal:** Replace the complex Secure Enclave + ECIES wrapping approach with simple OS credential store password caching, modelled on `gh auth`, `cargo publish`, and similar CLI tools.

## Motivation

The current approach (27 commits) builds ECIES wrapping around Secure Enclave P-256 keys. This requires:
- 4 extra crypto deps (`p256`, `aes-gcm`, `hkdf`, `sha2`)
- macOS code signing + entitlements
- Complex `HwSlot` file format (third line in key file)
- Platform-specific `HardwareKeyStore` trait with ECDH inside hardware
- ~1500 lines of code across `ecies.rs`, `ecies_wrap.rs`, `hw_keystore/`

The new approach stores the user's **password** in the OS credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service). No code signing, no ECIES, no format changes.

## Design

### UX Model

Matches established CLI tools:
- **`gh auth`**: stores token, uses it automatically
- **`cargo publish`**: stores token in credentials file
- **SSH agent**: caches passphrase for session

### Flow

```
Sign request (or any operation needing the password)
  → Check OS credential store for saved password (keyed by key ID)
    → If found: use it to decrypt secret key via existing scrypt path
    → If not found: prompt for password as normal
  → On successful decryption: if --save-password flag was used, save to credential store
```

### CLI Interface

**New flags (replace `--hardware-key`):**

| Flag | Short | Description |
|------|-------|-------------|
| `--save-password` | `--sp` | Save password to OS credential store after successful use |
| `--forget-password` | `--fp` | Remove saved password from OS credential store |

**Operations that use saved passwords:**
- `-S` (sign): auto-retrieve, `--save-password` to save
- `-K` (change): auto-retrieve for current password, `--save-password` to save new password
- `-R` (recreate): auto-retrieve
- `-I` (inspect): auto-retrieve when decrypting

**Operations that can save passwords:**
- `-G` (generate): `--save-password` saves the password used during generation
- `-S` (sign): `--save-password` saves after first successful decrypt
- `-K` (change): `--save-password` saves the new password

**`--forget-password` works standalone:**
```bash
minisign_rs -K --forget-password          # remove saved password for default key
minisign_rs -K --forget-password -s path  # remove saved password for specific key
```

### Credential Store Entry

- **Service name:** `"minisign"`
- **Account/key:** The key ID hex string (e.g., `"a1b2c3d4e5f6g7h8"`)
- **Secret:** The password string

Using key ID rather than file path means:
- Moving the key file doesn't break the credential association
- Multiple key files for the same keypair share one credential entry
- The key ID is visible via `minisign_rs -I` so the user can identify it

### Key File Format

**No changes.** The standard 2-line format is preserved. The `HwSlot` third line is removed entirely. Full C minisign compatibility maintained.

## Implementation Steps

### Phase 1: Remove Secure Enclave / ECIES infrastructure

**Files to delete entirely:**
- `src/ecies.rs` — ECIES crypto primitives
- `src/ecies_wrap.rs` — ECIES wrapping integration
- `src/hw_keystore/macos.rs` — macOS Secure Enclave backend
- `src/hw_keystore/linux.rs` — Linux TPM stub
- `src/hw_keystore/windows.rs` — Windows TPM stub
- `src/hw_keystore/unsupported.rs` — Unsupported platform stub
- `src/hw_keystore/mock.rs` — Mock implementation for testing
- `src/hw_keystore/mod.rs` — HardwareKeyStore trait and factory

**Files to modify for removal:**
1. **`Cargo.toml`** — Remove deps: `p256`, `aes-gcm`, `hkdf`, `sha2`, `security-framework`, `security-framework-sys`, `core-foundation`, `windows`, `tss-esapi`. Remove feature flags: `hw-keystore-macos`, `hw-keystore-windows`, `hw-keystore-linux`. Add dep: `keyring = "3"`.
2. **`src/lib.rs`** — Remove `pub mod ecies`, `pub mod ecies_wrap`, `pub mod hw_keystore`. Add new module.
3. **`src/keys.rs`** — Remove `HwSlot` struct and all its methods. Remove `decrypt_with_hw()`, `to_plaintext_blob()`, `build_plaintext_blob()`, `to_file_contents_with_hw_slot()`, `from_file_contents_with_hw_slot()`. Keep `to_file_contents()` and `from_file_contents()`.
4. **`src/errors.rs`** — Remove error variants: `HardwareKeyStoreUnavailable`, `HardwareKeyStoreAuthDenied`, `HardwareKeyNotFound`, `HardwareKeyStoreError`, `HwSlotCorrupted`. Add: `CredentialStoreError(String)`.
5. **`src/constants.rs`** — Remove: `HW_SLOT_VERSION`, `HW_SLOT_FIXED_SIZE`, `HW_KEY_LABEL_MAX_BYTES`.
6. **`src/ops/file_utils.rs`** — `load_secret_key()` returns `Result<SeckeyStruct>` instead of `Result<(SeckeyStruct, Option<HwSlot>)>`.

**Test files to delete:**
- `tests/unit/ecies_wrap.rs`
- `tests/unit/hw_slot.rs`
- `tests/unit/phase1_security_tests.rs`
- `tests/unit/phase2_h5_only.rs`
- `tests/unit/phase2_security_tests.rs`

**Test files to update:**
- `tests/unit.rs` — Remove mod declarations for deleted test files
- `tests/unit/ops/sign.rs` — Remove `hw` parameter from sign calls
- `tests/unit/ops/generate.rs` — Remove `hw` parameter, remove `hardware_key` builder calls
- `tests/unit/ops/change.rs` — Remove `hw_store` parameter, remove HW key add/remove tests
- `tests/unit/ops/inspect.rs` — Remove HW-related inspect tests
- `tests/unit/cli.rs` — Remove `--hardware-key` flag tests
- `tests/cli_test.rs` — Remove HW integration tests if present

### Phase 2: Add credential store module

**New file: `src/credential_store.rs`**

Thin wrapper around `keyring` crate with the following API:

```rust
/// Save a password for a key ID in the OS credential store
pub fn save_password(key_id: &str, password: &str) -> Result<()>;

/// Retrieve a saved password for a key ID, returns None if not found
pub fn get_password(key_id: &str) -> Option<String>;

/// Remove a saved password for a key ID
pub fn forget_password(key_id: &str) -> Result<()>;

/// Check if a password is saved for a key ID
pub fn has_password(key_id: &str) -> bool;
```

Implementation notes:
- Service name: `"minisign"` (constant)
- Uses `keyring::Entry::new("minisign", key_id)`
- `get_password` returns `None` on any error (missing entry, no backend, etc.) — never blocks operations
- `save_password` and `forget_password` report errors but never prevent the primary operation
- Returned password strings should be wrapped in `Zeroizing<String>`

### Phase 3: Rewire CLI and operations

**`src/cli.rs`:**
- Remove `hardware_key` field
- Add `save_password: bool` flag (`--save-password`, `--sp`)
- Add `forget_password: bool` flag (`--forget-password`, `--fp`)

**`src/ops/sign.rs`:**
- Remove `hw: Option<&dyn HardwareKeyStore>` parameter from `sign()`, `sign_single_file()`, `sign_multiple_files()`, `load_and_decrypt_key()`
- `load_and_decrypt_key()` becomes just the password path (no HW fallback logic)

**`src/ops/generate.rs`:**
- Remove `hw: Option<&dyn HardwareKeyStore>` parameter from `generate()`, `generate_with_log_n()`
- Remove HW enrollment block entirely
- `SeckeyStruct` uses `to_file_contents()` instead of `to_file_contents_with_hw_slot()`

**`src/ops/change.rs`:**
- Remove `hw_store: &dyn HardwareKeyStore` parameter from `change()`, `change_with_log_n()`
- Remove `add_hardware_key` / `remove_hardware_key` fields from `ChangeOptions`
- Remove HW key add/remove logic
- Simplify decrypt path (just password, no HW fallback)

**`src/ops/inspect.rs`:**
- Remove `InspectOptionsWithHw` struct entirely
- Remove `inspect_with_hw()` function
- Remove HW-related fields from `InspectResult`: `hw_enrolled`, `hw_label`, `hw_backend_name`, `hw_key_available`, `hw_unavailable_warning`
- Add `password_saved: bool` field to `InspectResult` (check credential store)

**`src/main.rs`:**
- Remove `use minisign::hw_keystore`
- Remove all `hw_keystore::get_default_keystore()` calls
- In `handle_sign()`: before prompting for password, check `credential_store::get_password(key_id)`. After successful sign with `--save-password`, save the password.
- In `handle_generate()`: if `--save-password`, save the password after key generation
- In `handle_change()`: remove HW store parameter. If `--save-password`, save new password. If `--forget-password`, remove from credential store.
- In `handle_inspect()`: replace HW status display with credential store status ("Password saved: Yes/No")
- In `handle_recreate()`: before prompting, check credential store
- Remove `display_inspect_result()` HW section, replace with credential store status

### Phase 4: Tests

**New test file: `tests/unit/credential_store.rs`**
- Test save/retrieve/forget round-trip
- Test get_password returns None for missing entry
- Test forget_password is idempotent
- Test with mock or real keyring backend (keyring crate supports mock backends)

**Update existing tests:**
- All tests that pass `hw: Option<&dyn HardwareKeyStore>` — remove the parameter
- All tests that reference `HwSlot` — remove
- CLI tests: replace `--hardware-key` with `--save-password` / `--forget-password`

### Phase 5: Cleanup

- Remove `docs/plans/2026-02-11-secure-enclave-ecies-plan.md`
- Remove `docs/plans/2026-02-12-macos-secure-enclave-implementation.md`
- Remove any Secure Enclave setup guides in `docs/`
- Update CLAUDE.md: remove `hw_keystore` from key locations, update dependency list
- Run full pre-commit checklist:
  ```bash
  cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
  cargo fmt
  cargo test
  cargo test -- --ignored
  ```

## Dependency Changes

**Remove from `[dependencies]`:**
- `p256`
- `aes-gcm`
- `hkdf`
- `sha2`

**Remove from `[target.'cfg(...)'.dependencies]`:**
- `security-framework`
- `security-framework-sys`
- `core-foundation`
- `windows`
- `tss-esapi`

**Remove `[features]`:**
- `hw-keystore-macos`
- `hw-keystore-windows`
- `hw-keystore-linux`

**Add to `[dependencies]`:**
- `keyring = "3"`

**Net result:** 9 dependencies removed, 1 added. No feature flags.

## Lines of Code Impact (Estimated)

| Area | Removed | Added |
|------|---------|-------|
| `ecies.rs` | ~430 | 0 |
| `ecies_wrap.rs` | ~280 | 0 |
| `hw_keystore/` (all files) | ~500 | 0 |
| `HwSlot` + related in `keys.rs` | ~250 | 0 |
| HW wiring in ops + main | ~200 | 0 |
| HW-related tests | ~300 | 0 |
| `credential_store.rs` | 0 | ~60 |
| Credential store integration in ops + main | 0 | ~80 |
| Credential store tests | 0 | ~60 |
| **Total** | **~1960** | **~200** |

## Risk Assessment

- **Low risk:** Key file format unchanged, existing keys work identically
- **Low risk:** Core signing/verification paths unchanged
- **Low risk:** `keyring` crate is mature (~4M downloads, maintained)
- **Medium risk:** Credential store failures must never block operations (defense: `get_password` returns `None` on any error)
- **None:** No code signing or entitlements required

## Design Decisions

1. **Opt-in saving:** Password is only saved to credential store when explicitly requested with `--save-password`. Never auto-saved. This is a signing tool — changing the security model silently would be wrong.
2. **Auto-retrieval:** If a password IS saved, it's used automatically without prompting. The user already opted in by saving it.
3. **Graceful degradation:** If the credential store is unavailable (headless Linux, etc.), the tool works exactly as before — prompts for password.
4. **Key ID as account:** Using the 8-byte key ID hex string rather than file path means the credential association survives key file moves.
