# File Load Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `_with_key` variants to ops functions to eliminate redundant file loads in CLI handlers.

**Architecture:** Create new public functions in ops modules that accept pre-loaded `SeckeyStruct` references. Update main.rs handlers to reuse loaded keys instead of loading multiple times. Existing path-based API remains for backwards compatibility.

**Tech Stack:** Rust, existing minisign ops modules, no new dependencies

---

## Task 1: Add sign_with_key to ops/sign.rs

**Files:**
- Modify: `src/ops/sign.rs` (add new function after line 375)
- Test: Run existing tests in `tests/cli_test.rs`

**Step 1: Implement sign_with_key function**

Add this function after `sign_single_file` (around line 375):

```rust
/// Sign a file with a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded (e.g., for credential store lookups).
///
/// # Arguments
///
/// * `message_file` - Path to the message file to sign
/// * `seckey` - Pre-loaded secret key structure
/// * `options` - Signing options (signature file, comments, prehashed mode, etc.)
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign_with_key(
    message_file: &Path,
    seckey: &SeckeyStruct,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
) -> Result<SignResult> {
    // Decrypt the key if needed
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Sign the file using the existing helper
    sign_file_with_key(message_file, &secret_key, keynum, options)
}
```

**Step 2: Run clippy to verify**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings or errors

**Step 3: Run existing sign tests**

```bash
cargo test test_sign
```

Expected: All sign-related tests pass (existing API still works)

**Step 4: Commit**

```bash
git add src/ops/sign.rs
git commit -m "feat(ops): add sign_with_key to reuse loaded keys

Adds new variant that accepts pre-loaded SeckeyStruct to avoid
redundant file loads. Existing sign API unchanged.

Part of file load optimization (Fix 7)."
```

---

## Task 2: Add inspect_with_key variants to ops/inspect.rs

**Files:**
- Modify: `src/ops/inspect.rs` (add new functions after line 160)
- Test: Run existing tests in `tests/cli_test.rs`

**Step 1: Implement inspect_with_key**

Add this function after the `inspect` function (around line 160):

```rust
/// Inspect a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded. For encrypted keys, shows the encrypted keynum
/// placeholder. Use `inspect_private_with_key` to decrypt and show the real keynum.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
///
/// # Returns
///
/// An `InspectResult` containing key information
pub fn inspect_with_key(seckey: &SeckeyStruct) -> Result<InspectResult> {
    inspect_secret_key(seckey)
}
```

**Step 2: Implement inspect_private_with_key**

Add this function after `inspect_with_key`:

```rust
/// Inspect a pre-loaded secret key by decrypting it first (if encrypted)
///
/// This variant accepts a pre-loaded `SeckeyStruct` and decrypts it to retrieve
/// the real key ID. For unencrypted keys, it behaves identically to `inspect_with_key`.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
/// * `password` - Password to decrypt the key (if encrypted)
///
/// # Returns
///
/// An `InspectResult` containing key information with real keynum
///
/// # Errors
///
/// Returns an error if:
/// - For encrypted keys: password is incorrect or decryption fails
pub fn inspect_private_with_key(
    seckey: &SeckeyStruct,
    password: &[u8],
) -> Result<InspectResult> {
    if !seckey.is_encrypted() {
        // Unencrypted secret key - behave like regular inspect
        return inspect_secret_key(seckey);
    }

    // Encrypted - decrypt to get the real keynum
    let (_secret_key, decrypted_keynum) = seckey.decrypt(password)?;

    // Get the base inspection result
    let mut result = inspect_secret_key(seckey)?;

    // Update with the real keynum
    result.key_id = decrypted_keynum.to_key_id();
    result.key_id_words = decrypted_keynum.to_words();

    Ok(result)
}
```

**Step 3: Run clippy to verify**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings or errors

**Step 4: Run existing inspect tests**

```bash
cargo test test_inspect
```

Expected: All inspect-related tests pass

**Step 5: Commit**

```bash
git add src/ops/inspect.rs
git commit -m "feat(ops): add inspect_with_key variants

Adds inspect_with_key and inspect_private_with_key to reuse
loaded keys and avoid redundant file I/O. Existing API unchanged.

Part of file load optimization (Fix 7)."
```

---

## Task 3: Add recreate_with_key to ops/recreate.rs

**Files:**
- Modify: `src/ops/recreate.rs` (add new function after line 140)
- Test: Run existing tests in `tests/cli_test.rs`

**Step 1: Implement recreate_with_key**

Add this function after the `recreate` function (around line 140):

```rust
/// Recreate a public key from a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded (e.g., for credential store lookups).
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
/// * `options` - Recreation options (public key file path, comment, force flag)
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `RecreateResult` containing the public key file path and keynum
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The public key file already exists (unless force is true)
/// - File I/O operations fail
pub fn recreate_with_key(
    seckey: &SeckeyStruct,
    options: &RecreateOptions<'_>,
    password: Option<&[u8]>,
) -> Result<RecreateResult> {
    // Decrypt if necessary and get the keynum
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Extract public key from secret key
    // Ed25519 secret keys contain the public key in the second half (bytes 32-64)
    let public_key = extract_public_key_from_secret(&secret_key);

    // Create public key struct
    let pubkey = PubkeyStruct::new(
        SIGALG,
        keynum,
        public_key,
        options.untrusted_comment().unwrap_or(""),
    );

    // Check if output file exists (unless force is set)
    let public_key_file = options.public_key_file();
    if public_key_file.exists() && !options.force() {
        return Err(Error::Io(format!(
            "Public key file already exists: {}. Use -f to overwrite.",
            public_key_file.display()
        )));
    }

    // Write the public key file
    let public_key_contents = pubkey.to_file_contents();
    fs::write(public_key_file, public_key_contents)
        .map_err(|e| Error::Io(format!("Failed to write public key file: {e}")))?;

    Ok(RecreateResult::new(public_key_file, keynum))
}
```

**Step 2: Run clippy to verify**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings or errors

**Step 3: Run existing recreate tests**

```bash
cargo test test_recreate
```

Expected: All recreate-related tests pass

**Step 4: Commit**

```bash
git add src/ops/recreate.rs
git commit -m "feat(ops): add recreate_with_key to reuse loaded keys

Adds new variant that accepts pre-loaded SeckeyStruct to avoid
redundant file loads. Existing recreate API unchanged.

Part of file load optimization (Fix 7)."
```

---

## Task 4: Update handle_sign to use sign_with_key

**Files:**
- Modify: `src/main.rs:264-289` (update sign call)
- Test: Run existing sign tests

**Step 1: Update handle_sign to use sign_with_key**

Find the single-file signing code around line 264-289 and update it:

**Old code:**
```rust
let mut builder = SignOptions::builder(secret_key_file, message_file)
    .signature_file(signature_file)
    .prehashed(prehashed);

if let Some(comment) = cli.trusted_comment.as_deref() {
    builder = builder.trusted_comment(comment);
}
if let Some(comment) = cli.untrusted_comment.as_deref() {
    builder = builder.untrusted_comment(comment);
}
builder = builder.force(cli.force);
let options = builder.build();

let result = sign(&options, password.as_ref().map(|p| p.as_bytes()))?;
```

**New code:**
```rust
let mut builder = SignOptions::builder(secret_key_file, message_file)
    .signature_file(signature_file)
    .prehashed(prehashed);

if let Some(comment) = cli.trusted_comment.as_deref() {
    builder = builder.trusted_comment(comment);
}
if let Some(comment) = cli.untrusted_comment.as_deref() {
    builder = builder.untrusted_comment(comment);
}
builder = builder.force(cli.force);
let options = builder.build();

// Use sign_with_key to avoid redundant file load
let result = minisign::ops::sign_with_key(
    message_file,
    &seckey,
    &options,
    password.as_ref().map(|p| p.as_bytes()),
)?;
```

Also update the multi-file signing around line 320:

**Old code:**
```rust
sign_multiple_files(message_files, &options, password.as_ref().map(|p| p.as_bytes()), cli.sequential)?;
```

Note: For multi-file signing, we keep using the existing API since it loads the key once and reuses it internally for all files.

**Step 2: Add import for sign_with_key**

At the top of main.rs, the ops functions should already be imported. Verify that `sign_with_key` is accessible (it's a public function in the same module we're already using).

**Step 3: Run clippy**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings

**Step 4: Run sign tests**

```bash
cargo test test_sign
```

Expected: All sign tests pass, demonstrating no behavior change

**Step 5: Commit**

```bash
git add src/main.rs
git commit -m "refactor(main): use sign_with_key to eliminate redundant load

handle_sign now uses sign_with_key with the already-loaded seckey
instead of sign which would load the file again.

Reduces file loads from 2 to 1 for single-file signing.

Part of file load optimization (Fix 7)."
```

---

## Task 5: Update handle_inspect to use inspect_private_with_key

**Files:**
- Modify: `src/main.rs:782` (update inspect_private call)
- Test: Run existing inspect tests

**Step 1: Update handle_inspect to use inspect_private_with_key**

Find the inspect_private call around line 782 and update it:

**Old code:**
```rust
let options = InspectPrivateOptions::new(path);
result = inspect_private(&options, password.as_bytes())?;
```

**New code:**
```rust
result = minisign::ops::inspect_private_with_key(&seckey, password.as_bytes())?;
```

The `seckey` is already loaded at line 767, so we're just reusing it.

**Step 2: Run clippy**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings

**Step 3: Run inspect tests**

```bash
cargo test test_inspect
```

Expected: All inspect tests pass

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "refactor(main): use inspect_private_with_key

handle_inspect now uses inspect_private_with_key with the
already-loaded seckey instead of inspect_private which would
load the file again.

Reduces file loads from 3 to 2 for encrypted key inspection.

Part of file load optimization (Fix 7)."
```

---

## Task 6: Update handle_recreate to use recreate_with_key

**Files:**
- Modify: `src/main.rs:483-490` (update recreate call)
- Test: Run existing recreate tests

**Step 1: Update handle_recreate to use recreate_with_key**

Find the recreate call around line 483-490 and update it:

**Old code:**
```rust
let options = RecreateOptions::new(
    secret_key_file,
    public_key_file,
    cli.untrusted_comment.as_deref(),
    cli.force,
);

let result = recreate(&options, password.as_ref().map(|p| p.as_bytes()))?;
```

**New code:**
```rust
let options = RecreateOptions::new(
    secret_key_file,
    public_key_file,
    cli.untrusted_comment.as_deref(),
    cli.force,
);

let result = minisign::ops::recreate_with_key(
    &seckey,
    &options,
    password.as_ref().map(|p| p.as_bytes()),
)?;
```

The `seckey` is already loaded at line 466, so we're reusing it.

**Step 2: Run clippy**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings

**Step 3: Run recreate tests**

```bash
cargo test test_recreate
```

Expected: All recreate tests pass

**Step 4: Commit**

```bash
git add src/main.rs
git commit -m "refactor(main): use recreate_with_key to eliminate redundant load

handle_recreate now uses recreate_with_key with the already-loaded
seckey instead of recreate which would load the file again.

Reduces file loads from 2 to 1 for public key recreation.

Part of file load optimization (Fix 7)."
```

---

## Task 7: Run full test suite to verify

**Files:**
- Test: All tests

**Step 1: Run fast tests**

```bash
cargo test
```

Expected: All 305+ tests pass

**Step 2: Run slow security tests**

```bash
cargo test -- --ignored
```

Expected: All 11 slow tests pass

**Step 3: Run cargo fmt**

```bash
cargo fmt
```

Expected: No changes (already formatted throughout)

**Step 4: Final clippy check**

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: Zero warnings or errors

---

## Task 8: Final verification commit

**Files:**
- Verify: All changes committed, working tree clean

**Step 1: Check git status**

```bash
git status
```

Expected: "nothing to commit, working tree clean"

**Step 2: Review commit log**

```bash
git log --oneline -7
```

Expected: 7 commits for this feature (3 ops functions + 3 main.rs updates + this test verification)

**Step 3: Verify no behavioral changes**

The optimization should be completely transparent:
- All tests pass unchanged
- No new warnings
- Same command-line behavior
- Only difference: fewer file I/O operations (invisible to users)

---

## Summary

**Lines changed:**
- `ops/sign.rs`: +35 lines (sign_with_key)
- `ops/inspect.rs`: +50 lines (inspect_with_key + inspect_private_with_key)
- `ops/recreate.rs`: +45 lines (recreate_with_key)
- `main.rs`: ~15 lines changed (3 call site updates)
- **Total: ~145 lines**

**Performance improvement:**
- `handle_sign`: 2 loads → 1 load (50% reduction)
- `handle_inspect`: 3 loads → 2 loads (33% reduction)
- `handle_recreate`: 2 loads → 1 load (50% reduction)

**Commits:** 6 commits (3 new functions + 3 call site updates)

**Testing:** No new tests needed - existing 316 tests validate behavior unchanged
