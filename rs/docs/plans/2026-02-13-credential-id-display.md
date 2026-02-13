# Credential ID Display Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add credential ID to key inspection output to help users identify keychain entries.

**Architecture:** Add `credential_id: Option<String>` field to `InspectResult` struct, populate it in all inspect functions, and display it in the CLI output after "Key ID (words)". The credential ID is already computed by `SeckeyStruct::credential_id()` - we just need to surface it.

**Tech Stack:** Rust, minisign crate structure, TDD with cargo test

---

## Task 1: Add credential_id field to InspectResult

**Files:**
- Modify: `rs/src/ops/inspect.rs:100-114`

**Step 1: Write a failing test**

File: `rs/tests/unit/ops/inspect.rs`

Add this test at the end of the file:

```rust
#[test]
fn test_inspect_result_includes_credential_id() {
    // Create an encrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let kdf_opslimit = 33_554_432;
    let kdf_memlimit = 1_073_741_824;

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);
    let options = InspectOptions::new(temp_file.path());
    let result = inspect(&options).unwrap();

    // Verify credential_id is present for secret keys
    assert!(result.credential_id.is_some());
    let credential_id = result.credential_id.unwrap();

    // Verify it matches the seckey's credential_id
    let expected_credential_id = seckey.credential_id();
    assert_eq!(credential_id, expected_credential_id);
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test test_inspect_result_includes_credential_id`

Expected: FAIL - compilation error about `credential_id` field not existing

**Step 3: Add credential_id field to InspectResult**

File: `rs/src/ops/inspect.rs`

Modify the `InspectResult` struct (around line 100):

```rust
/// Result of inspecting a key file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectResult {
    /// Key ID in base64 format
    pub key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    pub key_id_words: String,
    /// Whether this is a secret or public key
    pub key_type: KeyType,
    /// Security level (for secret keys)
    pub security_level: Option<SecurityLevel>,
    /// KDF information (for encrypted secret keys)
    pub kdf_info: Option<KdfInfo>,
    /// Whether a password is saved in the OS credential store for this key
    pub password_saved: bool,
    /// Credential ID used for keychain lookups (None for public keys)
    pub credential_id: Option<String>,
}
```

**Step 4: Run test to verify compilation (will still fail assertions)**

Run: `cd rs && cargo test test_inspect_result_includes_credential_id`

Expected: FAIL - compilation succeeds but test fails because credential_id is not populated

**Step 5: Commit the struct change**

```bash
cd rs
git add src/ops/inspect.rs tests/unit/ops/inspect.rs
git commit -m "feat(inspect): add credential_id field to InspectResult"
```

---

## Task 2: Update inspect_secret_key() to populate credential_id

**Files:**
- Modify: `rs/src/ops/inspect.rs:309-366`

**Step 1: Update inspect_secret_key function**

File: `rs/src/ops/inspect.rs`

Find the `inspect_secret_key` function (around line 309) and update it to include credential_id.

For the unencrypted key case (around line 314-325):

```rust
if !seckey.is_encrypted() {
    // Unencrypted key
    let password_saved = crate::credential_store::has_password(&credential_id);
    return Ok(InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::SecretUnencrypted,
        security_level: Some(SecurityLevel::None),
        kdf_info: None,
        password_saved,
        credential_id: Some(credential_id),  // NEW
    });
}
```

For the encrypted key case (around line 350-365):

```rust
Ok(InspectResult {
    key_id,
    key_id_words,
    key_type: KeyType::SecretEncrypted,
    security_level: Some(security_level),
    kdf_info: Some(KdfInfo {
        opslimit,
        memlimit,
        log_n,
        r,
        p,
        is_fallback,
        weakness_multiplier,
    }),
    password_saved,
    credential_id: Some(credential_id),  // NEW
})
```

**Step 2: Run test to verify it passes**

Run: `cd rs && cargo test test_inspect_result_includes_credential_id`

Expected: PASS

**Step 3: Run all inspect tests**

Run: `cd rs && cargo test ops::inspect`

Expected: Some tests FAIL - they need credential_id added to their assertions

**Step 4: Commit**

```bash
cd rs
git add src/ops/inspect.rs
git commit -m "feat(inspect): populate credential_id in inspect_secret_key"
```

---

## Task 3: Update inspect_public_key() to set credential_id to None

**Files:**
- Modify: `rs/src/ops/inspect.rs:369-381`

**Step 1: Write a failing test**

File: `rs/tests/unit/ops/inspect.rs`

Add this test:

```rust
#[test]
fn test_inspect_public_key_has_no_credential_id() {
    let (_, public_key, keynum) = generate_keypair().unwrap();
    let pubkey = minisign::keys::PubkeyStruct::new(keynum, public_key);
    let file_contents = pubkey.to_file_contents("test public key");
    let temp_file = create_temp_key_file(&file_contents);
    let options = InspectOptions::new(temp_file.path());
    let result = inspect(&options).unwrap();

    // Public keys should have None for credential_id
    assert!(result.credential_id.is_none());
    assert_eq!(result.key_type, KeyType::Public);
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test test_inspect_public_key_has_no_credential_id`

Expected: FAIL - credential_id is not set (compilation error or None assertion fails)

**Step 3: Update inspect_public_key function**

File: `rs/src/ops/inspect.rs`

Find `inspect_public_key` (around line 369):

```rust
/// Inspect a public key structure
fn inspect_public_key(pubkey: &PubkeyStruct) -> InspectResult {
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::Public,
        security_level: None,
        kdf_info: None,
        password_saved: false, // Public keys don't have passwords
        credential_id: None,   // NEW: Public keys don't have credential IDs
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cd rs && cargo test test_inspect_public_key_has_no_credential_id`

Expected: PASS

**Step 5: Commit**

```bash
cd rs
git add src/ops/inspect.rs tests/unit/ops/inspect.rs
git commit -m "feat(inspect): set credential_id to None for public keys"
```

---

## Task 4: Update inspect_private() to populate credential_id

**Files:**
- Modify: `rs/src/ops/inspect.rs:245-306`

**Step 1: Write a failing test**

File: `rs/tests/unit/ops/inspect.rs`

Add this test:

```rust
#[test]
fn test_inspect_private_includes_decrypted_credential_id() {
    use minisign::ops::inspect::{InspectPrivateOptions, inspect_private};

    // Create an encrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        33_554_432,
        1_073_741_824,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);
    let options = InspectPrivateOptions::new(temp_file.path());
    let result = inspect_private(&options, password).unwrap();

    // Verify credential_id is present
    assert!(result.credential_id.is_some());
    let credential_id = result.credential_id.unwrap();
    assert_eq!(credential_id, seckey.credential_id());
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test test_inspect_private_includes_decrypted_credential_id`

Expected: FAIL - credential_id not populated in inspect_private return

**Step 3: Update inspect_private function**

File: `rs/src/ops/inspect.rs`

Find the `inspect_private` function (around line 245). Update the return statement around line 280-295:

```rust
let key_id = decrypted_keynum.to_key_id();
let credential_id = seckey.credential_id();
let password_saved = crate::credential_store::has_password(&credential_id);

return Ok(InspectResult {
    key_id,
    key_id_words: crate::wordlist::keynum_to_words(&decrypted_keynum),
    key_type: KeyType::SecretEncrypted,
    security_level: Some(security_level),
    kdf_info: Some(KdfInfo {
        opslimit,
        memlimit,
        log_n,
        r,
        p,
        is_fallback,
        weakness_multiplier,
    }),
    password_saved,
    credential_id: Some(credential_id),  // NEW
});
```

**Step 4: Run test to verify it passes**

Run: `cd rs && cargo test test_inspect_private_includes_decrypted_credential_id`

Expected: PASS

**Step 5: Commit**

```bash
cd rs
git add src/ops/inspect.rs tests/unit/ops/inspect.rs
git commit -m "feat(inspect): populate credential_id in inspect_private"
```

---

## Task 5: Fix all existing tests that construct InspectResult

**Files:**
- Modify: `rs/tests/unit/ops/inspect.rs`

**Step 1: Run all tests to identify failures**

Run: `cd rs && cargo test`

Expected: Multiple test failures about missing `credential_id` field

**Step 2: Fix test compilation errors**

File: `rs/tests/unit/ops/inspect.rs`

Search for all tests that check `InspectResult` fields. For each test that verifies the result, you need to either:
- Add `credential_id: Some(_)` assertions for secret keys
- Add `credential_id: None` assertions for public keys
- Or simply verify with `assert!(result.credential_id.is_some())` for secret keys

Example fix for `test_inspect_production_strength_encrypted_key`:

```rust
#[test]
fn test_inspect_production_strength_encrypted_key() {
    // ... existing setup code ...

    let result = inspect(&options).unwrap();

    // Verify results
    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::High));
    assert!(result.credential_id.is_some()); // NEW: Verify credential_id exists

    // ... rest of assertions ...
}
```

Apply similar changes to all other tests in the file.

**Step 3: Run tests to verify all pass**

Run: `cd rs && cargo test`

Expected: All tests PASS

**Step 4: Commit**

```bash
cd rs
git add tests/unit/ops/inspect.rs
git commit -m "test(inspect): update tests for credential_id field"
```

---

## Task 6: Add display logic for credential_id

**Files:**
- Modify: `rs/src/main.rs:640-719`

**Step 1: Update display_inspect_result function**

File: `rs/src/main.rs`

Find the `display_inspect_result` function (around line 640). Add the credential_id display after "Key ID (words)" (around line 661):

```rust
fn display_inspect_result(result: &InspectResult) {
    // Display security level prominently first (for secret keys)
    if let Some(security_level) = result.security_level {
        match security_level {
            SecurityLevel::High => println!("Security Level: HIGH [OK]\n"),
            SecurityLevel::Medium => println!("Security Level: MEDIUM [WARNING]\n"),
            SecurityLevel::Low => println!("Security Level: LOW [CRITICAL]\n"),
            SecurityLevel::None => println!("Security Level: NONE (UNENCRYPTED) [WARNING]\n"),
        }
    }

    // Display key information
    println!("Key Information:");

    // For encrypted secret keys, key ID is not available without decryption
    if result.key_type == KeyType::SecretEncrypted && result.key_id == ENCRYPTED_KEYNUM_PLACEHOLDER
    {
        println!("├─ Key ID: [encrypted - password required to view]");
        println!("├─ Key ID (words): [decrypt key to view]");
    } else {
        println!("├─ Key ID: {}", result.key_id);
        println!("├─ Key ID (words): {}", result.key_id_words);
    }

    // NEW: Display credential ID for secret keys
    if let Some(ref credential_id) = result.credential_id {
        println!("├─ Credential ID: {credential_id}");
    }

    // ... rest of function unchanged ...
}
```

**Step 2: Test manually with a real key**

Run:
```bash
cd rs
cargo build --release
./target/release/minisign_rs -G -W  # Generate test key with no password
./target/release/minisign_rs -I     # Inspect it
```

Expected output should include:
```
├─ Key ID: [some hex]
├─ Key ID (words): [some words]
├─ Credential ID: [same as Key ID for unencrypted]
```

**Step 3: Test with encrypted key**

Run:
```bash
cd rs
./target/release/minisign_rs -G     # Generate encrypted key (will prompt)
./target/release/minisign_rs -I     # Inspect it
```

Expected output should include credential ID (different from Key ID).

**Step 4: Commit**

```bash
cd rs
git add src/main.rs
git commit -m "feat(inspect): display credential ID in CLI output"
```

---

## Task 7: Run full test suite and clippy

**Step 1: Run all tests**

Run:
```bash
cd rs
cargo test
```

Expected: All tests PASS (~420 tests)

**Step 2: Run clippy**

Run:
```bash
cd rs
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings or errors

**Step 3: Run cargo fmt**

Run:
```bash
cd rs
cargo fmt
```

Expected: Code formatted successfully

**Step 4: Final verification - run ignored tests**

Run:
```bash
cd rs
cargo test -- --ignored
```

Expected: All slow tests PASS

**Step 5: Final commit if fmt made changes**

```bash
cd rs
git add -A
git commit -m "chore: format code"
```

---

## Task 8: Manual integration testing

**Step 1: Test encrypted key inspection**

```bash
cd rs
cargo build --release

# Generate encrypted key
./target/release/minisign_rs -G -s test_encrypted.key -p test_encrypted.pub

# Inspect without decryption
./target/release/minisign_rs -I -s test_encrypted.key --no-decrypt

# Inspect with decryption
./target/release/minisign_rs -I -s test_encrypted.key
```

Verify:
- Credential ID appears in output
- For encrypted keys with --no-decrypt, credential ID is shown (based on encrypted keynum)
- For decrypted inspection, credential ID is shown (same value)

**Step 2: Test unencrypted key inspection**

```bash
# Generate unencrypted key
./target/release/minisign_rs -G -W -s test_unencrypted.key -p test_unencrypted.pub

# Inspect
./target/release/minisign_rs -I -s test_unencrypted.key
```

Verify:
- Credential ID appears and matches Key ID

**Step 3: Test public key inspection**

```bash
# Inspect public key
./target/release/minisign_rs -I -p test_encrypted.pub
```

Verify:
- No credential ID shown (public keys don't have them)

**Step 4: Clean up test keys**

```bash
rm -f test_encrypted.key test_encrypted.pub test_unencrypted.key test_unencrypted.pub
```

---

## Success Criteria Checklist

After completing all tasks, verify:

- [ ] `cargo test` passes all tests
- [ ] `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic` has no warnings
- [ ] `cargo fmt` has been run
- [ ] `minisign_rs -I` shows credential ID for secret keys
- [ ] Credential ID appears after "Key ID (words)" in output
- [ ] Public keys don't show credential ID
- [ ] Encrypted keys show credential ID without requiring decryption
- [ ] Credential ID matches the value from `SeckeyStruct::credential_id()`
- [ ] Manual testing confirms expected behavior for all key types

## Implementation Notes

**Key Points:**
- Credential ID is already computed by `SeckeyStruct::credential_id()` - we're just surfacing it
- For encrypted keys: credential ID = hex of encrypted keynum
- For unencrypted keys: credential ID = Key ID
- For public keys: credential ID = None (not applicable)
- The credential ID is the same value used for OS keychain lookups

**Testing Strategy:**
- TDD approach - write test first, then implementation
- Update existing tests to handle new field
- Manual integration testing for CLI output
- No changes to binary format or cryptographic operations

**Commit Strategy:**
- Small, focused commits after each task
- Each commit should compile and pass tests
- Use conventional commit format per CLAUDE.md
