# File Load Optimization Design

**Date:** 2026-02-13
**Author:** Claude Code
**Status:** Approved
**Related:** Code Review Priority 3 - Fix 7

## Problem

Several CLI flows load the key file multiple times:

1. **`handle_sign`**: Loads twice (once for credential_id, once in sign_single_file)
2. **`handle_inspect`**: Loads up to 3 times (inspect, load_secret_key, inspect_private)
3. **`handle_recreate`**: Loads twice (once for credential_id, once in recreate)

Each load involves file I/O and parsing. While not performance-critical for small key files (~200 bytes), this indicates an API design issue where ops functions take file paths instead of pre-loaded key structs.

## Solution Overview

Add `_with_key` variants of the ops functions that accept pre-loaded `SeckeyStruct` references. Update `main.rs` to use these variants, eliminating redundant loads.

## Architecture

### New Functions

Add three new public functions to the ops modules:

- `sign_with_key()` in `src/ops/sign.rs`
- `inspect_with_key()` and `inspect_private_with_key()` in `src/ops/inspect.rs`
- `recreate_with_key()` in `src/ops/recreate.rs`

### Backwards Compatibility

The existing functions (`sign`, `inspect`, `inspect_private`, `recreate`) remain unchanged. External callers can continue using the path-based API. Internal CLI code uses the new `_with_key` variants.

### Data Flow

**Before:**
```
handle_sign:
  load_secret_key(path) → get credential_id
  sign(path, ...) → load_and_decrypt_key(path) [REDUNDANT LOAD]

handle_inspect:
  inspect(path) → read file [LOAD 1]
  load_secret_key(path) → get credential_id [LOAD 2]
  inspect_private(path) → read file [LOAD 3]

handle_recreate:
  load_secret_key(path) → get credential_id
  recreate(path, ...) → load_secret_key(path) [REDUNDANT LOAD]
```

**After:**
```
handle_sign:
  seckey = load_secret_key(path)
  sign_with_key(&seckey, ...) [NO LOAD]

handle_inspect:
  inspect(path) → read file [LOAD 1]
  seckey = load_secret_key(path) [LOAD 2, reuses for credential_id]
  inspect_private_with_key(&seckey, ...) [NO LOAD]

handle_recreate:
  seckey = load_secret_key(path)
  recreate_with_key(&seckey, ...) [NO LOAD]
```

## API Signatures

### sign_with_key

```rust
pub fn sign_with_key(
    message_file: &Path,
    seckey: &SeckeyStruct,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
) -> Result<SignResult>
```

- `message_file`: Direct parameter (replacing options.message_file for clarity)
- `seckey`: Pre-loaded secret key (borrowed, no clone)
- `options`: Signing options (signature file, comments, prehashed mode, etc.)
- `password`: Optional password for decryption

### inspect_with_key

```rust
pub fn inspect_with_key(seckey: &SeckeyStruct) -> Result<InspectResult>
```

- `seckey`: Pre-loaded secret key (borrowed)
- Returns inspection result without decryption (shows encrypted keynum placeholder if encrypted)

### inspect_private_with_key

```rust
pub fn inspect_private_with_key(
    seckey: &SeckeyStruct,
    password: &[u8],
) -> Result<InspectResult>
```

- `seckey`: Pre-loaded secret key (borrowed)
- `password`: Password for decryption
- Returns inspection result with real keynum (after decryption)

### recreate_with_key

```rust
pub fn recreate_with_key(
    seckey: &SeckeyStruct,
    options: &RecreateOptions<'_>,
    password: Option<&[u8]>,
) -> Result<RecreateResult>
```

- `seckey`: Pre-loaded secret key (borrowed)
- `options`: Recreation options (public key file path, comment, force flag)
- `password`: Optional password for decryption

## Implementation Details

### sign_with_key

1. Decrypt the key if needed using the provided password
2. Call the existing `sign_file_with_key` helper with the decrypted key
3. Return SignResult

This extracts the core logic from `sign_single_file` without the `load_and_decrypt_key` call.

### inspect_with_key

1. Call the existing `inspect_secret_key` helper directly with the loaded key
2. Return InspectResult

This is a thin wrapper around the existing helper.

### inspect_private_with_key

1. Check if key is encrypted
2. If encrypted: decrypt using password, get real keynum
3. If unencrypted: use existing keynum
4. Build and return InspectResult with real keynum

This extracts the core logic from `inspect_private` without the file read.

### recreate_with_key

1. Decrypt the key if needed using the provided password
2. Extract public key from secret key
3. Create PubkeyStruct and write to file
4. Return RecreateResult

This extracts the core logic from `recreate` without the `load_secret_key` call.

## Call Site Updates

### handle_sign (src/main.rs:246)

**Before:**
```rust
let seckey = load_secret_key(secret_key_file)?;
let credential_id = seckey.credential_id();
// ... get password ...
let result = sign(&options, password.as_ref().map(|p| p.as_bytes()))?;
```

**After:**
```rust
let seckey = load_secret_key(secret_key_file)?;
let credential_id = seckey.credential_id();
// ... get password ...
let result = sign_with_key(
    message_file,
    &seckey,
    &options,
    password.as_ref().map(|p| p.as_bytes())
)?;
```

### handle_inspect (src/main.rs:782)

**Before:**
```rust
let seckey = load_secret_key(path)?;
let credential_id = seckey.credential_id();
// ... get password ...
let options = InspectPrivateOptions::new(path);
result = inspect_private(&options, password.as_bytes())?;
```

**After:**
```rust
let seckey = load_secret_key(path)?;
let credential_id = seckey.credential_id();
// ... get password ...
result = inspect_private_with_key(&seckey, password.as_bytes())?;
```

### handle_recreate (src/main.rs:466)

**Before:**
```rust
let seckey = load_secret_key(secret_key_file)?;
// ... get password ...
let options = RecreateOptions::new(...);
let result = recreate(&options, password.as_ref().map(|p| p.as_bytes()))?;
```

**After:**
```rust
let seckey = load_secret_key(secret_key_file)?;
// ... get password ...
let options = RecreateOptions::new(...);
let result = recreate_with_key(
    &seckey,
    &options,
    password.as_ref().map(|p| p.as_bytes())
)?;
```

## Testing Strategy

### Validation Approach

No new tests required. The existing comprehensive test suite (305+ fast tests, 11 slow tests, 15 credential store tests) provides full coverage:

- All tests call CLI commands that will use the new `_with_key` variants internally
- If the refactor is correct, all existing tests should pass unchanged
- Tests cover encrypted/unencrypted keys, error cases, credential store integration

### Validation Steps

1. Run `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
2. Run `cargo fmt`
3. Run `cargo test` (fast tests, ~9s)
4. Run `cargo test -- --ignored` (slow security tests, ~16s)
5. Verify no behavior changes in test output

### Why Minimal Testing is Safe

- This is a refactoring, not a feature addition
- The core logic (signing, inspection, recreation) is unchanged
- We're only eliminating redundant file I/O
- Existing comprehensive test suite validates behavior
- All code paths are already exercised by CLI integration tests

### Optional Unit Tests

If desired for extra coverage, we could add unit tests in the ops modules that call `_with_key` variants directly. These would test the same scenarios but with pre-loaded keys. Not strictly necessary since CLI tests provide full coverage.

## Effort Estimate

- `sign_with_key`: ~30 lines
- `inspect_with_key` + `inspect_private_with_key`: ~40 lines
- `recreate_with_key`: ~30 lines
- Call site updates in main.rs: ~15 lines
- **Total: ~115 lines**

Matches the code review estimate of ~100 lines.

## Benefits

1. **Performance**: Eliminates redundant file I/O (2-3x improvement in file loads per operation)
2. **API Flexibility**: External callers can now optimize their own code by pre-loading keys
3. **Code Clarity**: Explicit separation between "load and operate" vs "operate on loaded key"
4. **Backwards Compatible**: Existing API unchanged, no breaking changes

## Trade-offs

- **API Surface**: Adds 4 new public functions (slightly larger API)
- **Maintenance**: Two code paths for each operation (but existing functions can become thin wrappers in the future)

The benefits outweigh the trade-offs, especially since this enables future optimizations without breaking changes.
