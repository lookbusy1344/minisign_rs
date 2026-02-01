# Multi-File Signing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add support for signing multiple files in a single command with parallel execution using Rayon.

**Architecture:** Modify CLI to accept multiple message files, extract single-file signing logic into pure function, add Rayon-based parallel iterator with continue-on-error semantics, report progress inline with summary at end.

**Tech Stack:** Rayon for parallelism, existing minisign crypto stack (ed25519-dalek, blake2, scrypt)

---

## Task 1: Add Rayon Dependency

**Files:**
- Modify: `rs/Cargo.toml:28`

**Step 1: Add Rayon to dependencies**

Add after line 27 (`git-version`):

```toml
rayon = "~1.11.0"
```

**Step 2: Build to verify dependency**

Run: `cd rs && cargo build`
Expected: Build succeeds, Rayon downloaded

**Step 3: Commit**

```bash
git add rs/Cargo.toml rs/Cargo.lock
git commit -m "build: add rayon dependency for parallel file signing"
```

---

## Task 2: Update CLI to Accept Multiple Files

**Files:**
- Modify: `rs/src/cli.rs:66-67`
- Test: `rs/tests/unit/cli.rs`

**Step 1: Write failing test for multiple files**

Add to `rs/tests/unit/cli.rs`:

```rust
#[test]
fn cli_accepts_multiple_message_files() {
    let cli = Cli::try_parse_from(&[
        "minisign_rs",
        "-S",
        "-m", "file1.txt",
        "-m", "file2.txt",
        "-m", "file3.txt",
    ]).unwrap();

    assert_eq!(cli.message_files.len(), 3);
    assert_eq!(cli.message_files[0].to_str().unwrap(), "file1.txt");
    assert_eq!(cli.message_files[1].to_str().unwrap(), "file2.txt");
    assert_eq!(cli.message_files[2].to_str().unwrap(), "file3.txt");
}

#[test]
fn cli_accepts_single_message_file() {
    let cli = Cli::try_parse_from(&[
        "minisign_rs",
        "-S",
        "-m", "file.txt",
    ]).unwrap();

    assert_eq!(cli.message_files.len(), 1);
    assert_eq!(cli.message_files[0].to_str().unwrap(), "file.txt");
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test cli_accepts_multiple_message_files`
Expected: FAIL - `message_files` field doesn't exist

**Step 3: Update CLI struct**

In `rs/src/cli.rs`, replace lines 65-67:

```rust
/// Message file (required for sign and verify)
#[arg(short = 'm', long = "input", value_name = "FILE")]
pub message_file: Option<PathBuf>,
```

With:

```rust
/// Message files (required for sign and verify, multiple allowed for signing)
#[arg(short = 'm', long = "input", value_name = "FILE")]
pub message_files: Vec<PathBuf>,
```

**Step 4: Run test to verify it passes**

Run: `cd rs && cargo test cli_accepts_multiple_message_files`
Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add rs/src/cli.rs rs/tests/unit/cli.rs
git commit -m "feat(cli): accept multiple message files with -m flag"
```

---

## Task 3: Add Sequential Flag to CLI

**Files:**
- Modify: `rs/src/cli.rs:105` (after `signature_file` field)
- Test: `rs/tests/unit/cli.rs`

**Step 1: Write failing test**

Add to `rs/tests/unit/cli.rs`:

```rust
#[test]
fn cli_sequential_flag_defaults_false() {
    let cli = Cli::try_parse_from(&[
        "minisign_rs",
        "-S",
        "-m", "file.txt",
    ]).unwrap();

    assert!(!cli.sequential);
}

#[test]
fn cli_sequential_flag_can_be_set() {
    let cli = Cli::try_parse_from(&[
        "minisign_rs",
        "-S",
        "-m", "file.txt",
        "--sequential",
    ]).unwrap();

    assert!(cli.sequential);
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test cli_sequential_flag`
Expected: FAIL - `sequential` field doesn't exist

**Step 3: Add sequential flag**

In `rs/src/cli.rs`, add after the `signature_file` field (around line 105):

```rust
/// Process files sequentially instead of in parallel
#[arg(long)]
pub sequential: bool,
```

**Step 4: Run test to verify it passes**

Run: `cd rs && cargo test cli_sequential_flag`
Expected: PASS (both tests)

**Step 5: Commit**

```bash
git add rs/src/cli.rs rs/tests/unit/cli.rs
git commit -m "feat(cli): add --sequential flag for single-threaded signing"
```

---

## Task 4: Fix Compilation Errors from CLI Change

**Files:**
- Modify: `rs/src/main.rs:125-128,178-181`
- Modify: `rs/src/cli.rs:173-175` (default signature path method)

**Step 1: Update handle_sign() to use message_files**

In `rs/src/main.rs`, replace lines 123-128:

```rust
fn handle_sign(cli: &Cli) -> Result<()> {
    // Validate required arguments
    let message_file = cli
        .message_file
        .as_ref()
        .ok_or_else(|| Error::Usage("Message file (-m) is required for signing".into()))?;
```

With:

```rust
fn handle_sign(cli: &Cli) -> Result<()> {
    // Validate required arguments
    if cli.message_files.is_empty() {
        return Err(Error::Usage("Message file (-m) is required for signing".into()));
    }

    // For now, only handle single file (multi-file coming in next task)
    let message_file = &cli.message_files[0];
```

**Step 2: Update handle_verify() to use message_files**

In `rs/src/main.rs`, replace lines 176-181:

```rust
fn handle_verify(cli: &Cli) -> Result<()> {
    // Validate required arguments
    let message_file = cli
        .message_file
        .as_ref()
        .ok_or_else(|| Error::Usage("Message file (-m) is required for verification".into()))?;
```

With:

```rust
fn handle_verify(cli: &Cli) -> Result<()> {
    // Validate required arguments
    if cli.message_files.is_empty() {
        return Err(Error::Usage("Message file (-m) is required for verification".into()));
    }

    // Verification only supports single file
    if cli.message_files.len() > 1 {
        return Err(Error::Usage("Verification only supports a single message file".into()));
    }

    let message_file = &cli.message_files[0];
```

**Step 3: Update default_signature_path() method**

In `rs/src/cli.rs`, find the `default_signature_path` method (around line 173) and update signature to take `&Path` instead of `&PathBuf`:

```rust
pub fn default_signature_path(message_file: &Path) -> Result<PathBuf> {
    Ok(PathBuf::from(format!("{}.minisig", message_file.display())))
}
```

**Step 4: Build to verify compilation**

Run: `cd rs && cargo build`
Expected: Build succeeds

**Step 5: Run existing tests**

Run: `cd rs && gtimeout 30 cargo test`
Expected: All tests pass

**Step 6: Commit**

```bash
git add rs/src/main.rs rs/src/cli.rs
git commit -m "fix: update main.rs to use message_files vector"
```

---

## Task 5: Add Error Types for Multi-File Signing

**Files:**
- Modify: `rs/src/errors.rs`
- Test: `rs/tests/unit/errors.rs`

**Step 1: Write failing test**

Add to `rs/tests/unit/errors.rs`:

```rust
#[test]
fn partial_failure_error_displays_correctly() {
    let err = Error::PartialFailure;
    assert_eq!(
        err.to_string(),
        "Partial failure: some files could not be signed"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test partial_failure_error_displays_correctly`
Expected: FAIL - `PartialFailure` variant doesn't exist

**Step 3: Add error variant**

In `rs/src/errors.rs`, add to the `Error` enum:

```rust
#[error("Partial failure: some files could not be signed")]
PartialFailure,
```

**Step 4: Run test to verify it passes**

Run: `cd rs && cargo test partial_failure_error_displays_correctly`
Expected: PASS

**Step 5: Commit**

```bash
git add rs/src/errors.rs rs/tests/unit/errors.rs
git commit -m "feat(errors): add PartialFailure error variant"
```

---

## Task 6: Extract Single-File Signing Function

**Files:**
- Modify: `rs/src/ops/sign.rs:69-111`
- Test: `rs/tests/unit/ops/sign.rs`

**Step 1: Write failing test**

Add to `rs/tests/unit/ops/sign.rs`:

```rust
use std::path::Path;

#[test]
fn test_sign_single_file_success() {
    let temp_dir = TempDir::new().unwrap();
    let message_path = temp_dir.path().join("message.txt");
    fs::write(&message_path, b"Test message").unwrap();

    let opts = SignOptions {
        secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
        message_file: message_path.display().to_string(),
        signature_file: None,
        prehashed: true,
        trusted_comment: Some("Test".to_string()),
        untrusted_comment: None,
        force: false,
    };

    let result = sign_single_file(Path::new(&opts.message_file), &opts, None);
    assert!(result.is_ok());

    let sign_result = result.unwrap();
    assert_eq!(sign_result.trusted_comment, "Test");

    // Signature file should exist
    let sig_path = format!("{}.minisig", message_path.display());
    assert!(Path::new(&sig_path).exists());
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test test_sign_single_file_success`
Expected: FAIL - `sign_single_file` function doesn't exist

**Step 3: Extract sign_single_file() function**

In `rs/src/ops/sign.rs`, replace the `sign()` function (lines 69-111) with two functions:

```rust
/// Sign a single file with a secret key (pure function for multi-file support)
///
/// # Arguments
///
/// * `message_file` - Path to the message file
/// * `options` - Signing options (all fields except message_file are used)
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be loaded or decrypted
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign_single_file(
    message_file: &Path,
    options: &SignOptions,
    password: Option<&[u8]>,
) -> Result<SignResult> {
    // Load and decrypt the secret key
    let seckey = load_secret_key(&options.secret_key_file)?;

    // Decrypt if necessary (weak KDF warning is shown by decrypt() if applicable)
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Determine the signature file path
    let sig_file_path = options
        .signature_file
        .clone()
        .unwrap_or_else(|| format!("{}.minisig", message_file.display()));

    // Create the signature
    let sig_box = create_signature(
        &secret_key,
        keynum,
        &message_file.to_string_lossy(),
        options.prehashed,
        options.trusted_comment.as_deref(),
        options.untrusted_comment.as_deref(),
    )?;

    // Write the signature file atomically
    let sig_contents = sig_box.to_file_contents();
    write_signature_file(Path::new(&sig_file_path), &sig_contents, options.force)?;

    // Generate key ID display formats
    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(&keynum);

    Ok(SignResult {
        signature_file: sig_file_path,
        trusted_comment: sig_box.trusted_comment().to_string(),
        key_id,
        key_id_words,
    })
}

/// Sign a file with a secret key (backwards compatibility wrapper)
///
/// # Arguments
///
/// * `options` - Signing options including key, message, and comment settings
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be loaded or decrypted
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign(options: &SignOptions, password: Option<&[u8]>) -> Result<SignResult> {
    sign_single_file(Path::new(&options.message_file), options, password)
}
```

**Step 4: Update imports**

At the top of `rs/src/ops/sign.rs`, add `Path` import:

```rust
use std::{fs::OpenOptions, io::Write, path::Path};
```

**Step 5: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test test_sign_single_file_success`
Expected: PASS

**Step 6: Run all existing sign tests**

Run: `cd rs && gtimeout 30 cargo test ops::sign`
Expected: All tests pass

**Step 7: Commit**

```bash
git add rs/src/ops/sign.rs rs/tests/unit/ops/sign.rs
git commit -m "refactor(sign): extract sign_single_file for multi-file support"
```

---

## Task 7: Add Multi-File Signing Core Logic

**Files:**
- Modify: `rs/src/ops/sign.rs` (add new functions)
- Test: `rs/tests/unit/ops/sign.rs`

**Step 1: Write failing test for sequential signing**

Add to `rs/tests/unit/ops/sign.rs`:

```rust
use minisign::ops::sign::sign_multiple_files;

#[test]
fn test_sign_multiple_files_sequential() {
    let temp_dir = TempDir::new().unwrap();

    // Create three test files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file2, b"Message 2").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    let files = vec![file1.clone(), file2.clone(), file3.clone()];

    let opts = SignOptions {
        secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
        message_file: String::new(), // Not used for multi-file
        signature_file: None,
        prehashed: true,
        trusted_comment: Some("Batch signature".to_string()),
        untrusted_comment: None,
        force: false,
    };

    let result = sign_multiple_files(files, &opts, None, true);
    assert!(result.is_ok());

    // Verify all signature files exist
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}
```

**Step 2: Run test to verify it fails**

Run: `cd rs && cargo test test_sign_multiple_files_sequential`
Expected: FAIL - `sign_multiple_files` function doesn't exist

**Step 3: Add SignResult struct**

Add to `rs/src/ops/sign.rs` before the `sign_single_file` function:

```rust
/// Result of a single file signing operation (for batch processing)
#[derive(Debug, Clone)]
pub struct FileSignResult {
    /// Path to the file that was signed
    pub file: PathBuf,
    /// Result of the signing operation
    pub result: Result<SignResult>,
}
```

**Step 4: Add imports for Rayon**

At the top of `rs/src/ops/sign.rs`, add:

```rust
use rayon::prelude::*;
use std::path::PathBuf;
```

**Step 5: Implement sign_multiple_files function**

Add to `rs/src/ops/sign.rs` after the `sign()` function:

```rust
/// Sign multiple files (parallel or sequential)
///
/// # Arguments
///
/// * `files` - Vector of file paths to sign
/// * `options` - Signing options (message_file field is ignored)
/// * `password` - Password to decrypt the secret key (if encrypted)
/// * `sequential` - If true, process files sequentially; if false, use parallel execution
///
/// # Returns
///
/// `Ok(())` if all files signed successfully, `Err(PartialFailure)` if any failed
///
/// # Errors
///
/// Returns `PartialFailure` error if any files could not be signed.
/// Individual file errors are reported to stderr during execution.
pub fn sign_multiple_files(
    files: Vec<PathBuf>,
    options: &SignOptions,
    password: Option<&[u8]>,
    sequential: bool,
) -> Result<()> {
    // Fast path for single file
    if files.len() == 1 {
        let result = sign_single_file(&files[0], options, password)?;
        println!(
            "Signed: {} → {}.minisig",
            files[0].display(),
            files[0].display()
        );
        return Ok(());
    }

    // Multi-file path
    let results: Vec<FileSignResult> = if sequential {
        files
            .into_iter()
            .map(|file| {
                let result = sign_single_file(&file, options, password);
                report_file_result(&file, &result);
                FileSignResult { file, result }
            })
            .collect()
    } else {
        files
            .par_iter()
            .map(|file| {
                let result = sign_single_file(file, options, password);
                report_file_result(file, &result);
                FileSignResult {
                    file: file.clone(),
                    result,
                }
            })
            .collect()
    };

    print_summary(&results)
}

/// Report the result of signing a single file (called for each file)
fn report_file_result(file: &Path, result: &Result<SignResult>) {
    match result {
        Ok(_) => println!("Signed: {} → {}.minisig", file.display(), file.display()),
        Err(e) => eprintln!("Failed: {} ({})", file.display(), e),
    }
}

/// Print summary of batch signing operation
fn print_summary(results: &[FileSignResult]) -> Result<()> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|r| r.result.as_ref().err().map(|e| (&r.file, e)))
        .collect();

    let success_count = results.len() - failures.len();

    if !failures.is_empty() {
        eprintln!(
            "\nSummary: {} signed, {} failed",
            success_count,
            failures.len()
        );
        eprintln!("Failed files:");
        for (file, err) in failures {
            eprintln!("  - {}: {}", file.display(), err);
        }
        return Err(Error::PartialFailure);
    }

    Ok(())
}
```

**Step 6: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test test_sign_multiple_files_sequential`
Expected: PASS

**Step 7: Run clippy**

Run: `cd rs && cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
Expected: Zero warnings

**Step 8: Commit**

```bash
git add rs/src/ops/sign.rs rs/tests/unit/ops/sign.rs
git commit -m "feat(sign): add multi-file signing with sequential/parallel modes"
```

---

## Task 8: Add Parallel Execution Test

**Files:**
- Test: `rs/tests/unit/ops/sign.rs`

**Step 1: Write test for parallel signing**

Add to `rs/tests/unit/ops/sign.rs`:

```rust
#[test]
fn test_sign_multiple_files_parallel() {
    let temp_dir = TempDir::new().unwrap();

    // Create 10 test files to better test parallelism
    let mut files = Vec::new();
    for i in 0..10 {
        let file = temp_dir.path().join(format!("file{}.txt", i));
        fs::write(&file, format!("Message {}", i).as_bytes()).unwrap();
        files.push(file);
    }

    let opts = SignOptions {
        secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
        message_file: String::new(),
        signature_file: None,
        prehashed: true,
        trusted_comment: Some("Parallel batch".to_string()),
        untrusted_comment: None,
        force: false,
    };

    let result = sign_multiple_files(files.clone(), &opts, None, false);
    assert!(result.is_ok());

    // Verify all signature files exist
    for file in &files {
        let sig_path = format!("{}.minisig", file.display());
        assert!(Path::new(&sig_path).exists(), "Signature missing for {:?}", file);
    }
}
```

**Step 2: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test test_sign_multiple_files_parallel`
Expected: PASS

**Step 3: Commit**

```bash
git add rs/tests/unit/ops/sign.rs
git commit -m "test(sign): add parallel multi-file signing test"
```

---

## Task 9: Add Error Handling Tests

**Files:**
- Test: `rs/tests/unit/ops/sign.rs`

**Step 1: Write test for partial failure**

Add to `rs/tests/unit/ops/sign.rs`:

```rust
#[test]
fn test_sign_multiple_files_partial_failure() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("nonexistent.txt"); // This will fail
    let file3 = temp_dir.path().join("file3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    let files = vec![file1.clone(), file2.clone(), file3.clone()];

    let opts = SignOptions {
        secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
        message_file: String::new(),
        signature_file: None,
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: false,
    };

    let result = sign_multiple_files(files, &opts, None, true);

    // Should return PartialFailure error
    assert!(result.is_err());
    match result {
        Err(Error::PartialFailure) => {},
        _ => panic!("Expected PartialFailure error"),
    }

    // file1 and file3 should have signatures despite file2 failing
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(!file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}
```

**Step 2: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test test_sign_multiple_files_partial_failure`
Expected: PASS

**Step 3: Write test for continue-on-error behavior**

Add to `rs/tests/unit/ops/sign.rs`:

```rust
#[test]
fn test_sign_multiple_files_all_attempted() {
    let temp_dir = TempDir::new().unwrap();

    // Create mix of valid and invalid files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("missing1.txt");
    let file3 = temp_dir.path().join("file3.txt");
    let file4 = temp_dir.path().join("missing2.txt");
    let file5 = temp_dir.path().join("file5.txt");

    fs::write(&file1, b"M1").unwrap();
    fs::write(&file3, b"M3").unwrap();
    fs::write(&file5, b"M5").unwrap();

    let files = vec![
        file1.clone(),
        file2.clone(),
        file3.clone(),
        file4.clone(),
        file5.clone(),
    ];

    let opts = SignOptions {
        secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
        message_file: String::new(),
        signature_file: None,
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: false,
    };

    let result = sign_multiple_files(files, &opts, None, true);
    assert!(matches!(result, Err(Error::PartialFailure)));

    // All valid files should be signed despite errors
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
    assert!(file5.with_extension("txt.minisig").exists());

    // Invalid files should not have signatures
    assert!(!file2.with_extension("txt.minisig").exists());
    assert!(!file4.with_extension("txt.minisig").exists());
}
```

**Step 4: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test test_sign_multiple_files_all_attempted`
Expected: PASS

**Step 5: Commit**

```bash
git add rs/tests/unit/ops/sign.rs
git commit -m "test(sign): add error handling tests for multi-file signing"
```

---

## Task 10: Wire Up Multi-File Signing in Main

**Files:**
- Modify: `rs/src/main.rs:123-173`

**Step 1: Update handle_sign() to use multi-file signing**

In `rs/src/main.rs`, replace the `handle_sign` function (lines 123-173):

```rust
fn handle_sign(cli: &Cli) -> Result<()> {
    // Validate required arguments
    if cli.message_files.is_empty() {
        return Err(Error::Usage("Message file (-m) is required for signing".into()));
    }

    // Get secret key path
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Prompt for password (we'll check if the key needs it later)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password("Password: ", cli.password_file.as_deref())?)
    };

    // Handle single file vs multiple files
    if cli.message_files.len() == 1 {
        // Single file path - preserve original behavior
        let message_file = &cli.message_files[0];

        let signature_file = match &cli.signature_file {
            Some(path) => path.clone(),
            None => Cli::default_signature_path(message_file)?,
        };

        let options = SignOptions {
            secret_key_file: secret_key_file.to_string_lossy().to_string(),
            message_file: message_file.to_string_lossy().to_string(),
            signature_file: Some(signature_file.to_string_lossy().to_string()),
            trusted_comment: cli.trusted_comment.clone(),
            untrusted_comment: cli.untrusted_comment.clone(),
            prehashed: !cli.legacy,
            force: cli.force,
        };

        let result = sign(&options, password.as_ref().map(|p| p.as_bytes()))?;

        if !cli.quiet {
            println!(
                "Signing with key: {} ({})",
                result.key_id, result.key_id_words
            );
            println!("Signature written to {}", result.signature_file);
        }
    } else {
        // Multiple files path - use new multi-file API
        if cli.signature_file.is_some() {
            return Err(Error::Usage(
                "Custom signature file (-x) not supported with multiple message files".into(),
            ));
        }

        let options = SignOptions {
            secret_key_file: secret_key_file.to_string_lossy().to_string(),
            message_file: String::new(), // Not used for multi-file
            signature_file: None,
            trusted_comment: cli.trusted_comment.clone(),
            untrusted_comment: cli.untrusted_comment.clone(),
            prehashed: !cli.legacy,
            force: cli.force,
        };

        use minisign::ops::sign::sign_multiple_files;
        sign_multiple_files(
            cli.message_files.clone(),
            &options,
            password.as_ref().map(|p| p.as_bytes()),
            cli.sequential,
        )?;
    }

    Ok(())
}
```

**Step 2: Build to verify compilation**

Run: `cd rs && cargo build`
Expected: Build succeeds

**Step 3: Run all tests**

Run: `cd rs && gtimeout 60 cargo test`
Expected: All tests pass

**Step 4: Run clippy**

Run: `cd rs && cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
Expected: Zero warnings

**Step 5: Commit**

```bash
git add rs/src/main.rs
git commit -m "feat(main): wire up multi-file signing in CLI handler"
```

---

## Task 11: Add CLI Integration Tests

**Files:**
- Test: `rs/tests/cli_test.rs`

**Step 1: Write test for basic multi-file signing**

Add to `rs/tests/cli_test.rs`:

```rust
#[test]
fn cli_sign_multiple_files() {
    let temp_dir = TempDir::new().unwrap();

    // Create test files
    let file1 = temp_dir.path().join("msg1.txt");
    let file2 = temp_dir.path().join("msg2.txt");
    let file3 = temp_dir.path().join("msg3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file2, b"Message 2").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    Command::cargo_bin("minisign_rs")
        .unwrap()
        .args(&[
            "-S",
            "-s", "tests/fixtures/keys/unencrypted.key",
            "-m", file1.to_str().unwrap(),
            "-m", file2.to_str().unwrap(),
            "-m", file3.to_str().unwrap(),
            "-q",
        ])
        .assert()
        .success();

    // All signature files should exist
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}
```

**Step 2: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test cli_sign_multiple_files`
Expected: PASS

**Step 3: Write test for sequential flag**

Add to `rs/tests/cli_test.rs`:

```rust
#[test]
fn cli_sign_multiple_files_sequential() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("a.txt");
    let file2 = temp_dir.path().join("b.txt");

    fs::write(&file1, b"A").unwrap();
    fs::write(&file2, b"B").unwrap();

    Command::cargo_bin("minisign_rs")
        .unwrap()
        .args(&[
            "-S",
            "-s", "tests/fixtures/keys/unencrypted.key",
            "-m", file1.to_str().unwrap(),
            "-m", file2.to_str().unwrap(),
            "--sequential",
            "-q",
        ])
        .assert()
        .success();

    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
}
```

**Step 4: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test cli_sign_multiple_files_sequential`
Expected: PASS

**Step 5: Write test for partial failure exit code**

Add to `rs/tests/cli_test.rs`:

```rust
#[test]
fn cli_sign_multiple_files_partial_failure_exit_code() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("exists.txt");
    let file2 = temp_dir.path().join("missing.txt");

    fs::write(&file1, b"Exists").unwrap();

    Command::cargo_bin("minisign_rs")
        .unwrap()
        .args(&[
            "-S",
            "-s", "tests/fixtures/keys/unencrypted.key",
            "-m", file1.to_str().unwrap(),
            "-m", file2.to_str().unwrap(),
            "-q",
        ])
        .assert()
        .failure() // Should fail with exit code 1
        .code(1);

    // Valid file should still be signed
    assert!(file1.with_extension("txt.minisig").exists());
}
```

**Step 6: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test cli_sign_multiple_files_partial_failure_exit_code`
Expected: PASS

**Step 7: Write test for backwards compatibility**

Add to `rs/tests/cli_test.rs`:

```rust
#[test]
fn cli_sign_single_file_backwards_compatible() {
    let temp_dir = TempDir::new().unwrap();
    let file = temp_dir.path().join("single.txt");
    fs::write(&file, b"Single").unwrap();

    let output = Command::cargo_bin("minisign_rs")
        .unwrap()
        .args(&[
            "-S",
            "-s", "tests/fixtures/keys/unencrypted.key",
            "-m", file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);

    // Should show key ID and signature path (original output format)
    assert!(stdout.contains("Signing with key:"));
    assert!(stdout.contains("Signature written to"));

    assert!(file.with_extension("txt.minisig").exists());
}
```

**Step 8: Run test to verify it passes**

Run: `cd rs && gtimeout 30 cargo test cli_sign_single_file_backwards_compatible`
Expected: PASS

**Step 9: Commit**

```bash
git add rs/tests/cli_test.rs
git commit -m "test(cli): add integration tests for multi-file signing"
```

---

## Task 12: Run Full Test Suite and Clippy

**Files:**
- None (verification only)

**Step 1: Run fast tests**

Run: `cd rs && gtimeout 60 cargo test`
Expected: All tests pass (~150+ tests)

**Step 2: Run slow tests**

Run: `cd rs && gtimeout 120 cargo test -- --ignored`
Expected: All slow tests pass (~11 tests)

**Step 3: Run clippy pedantic**

Run: `cd rs && cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
Expected: Zero warnings

**Step 4: Run cargo fmt**

Run: `cd rs && cargo fmt`
Expected: No changes (all files already formatted)

**Step 5: Verify no uncommitted changes**

Run: `git status`
Expected: Working tree clean

If there are any failures, fix them before proceeding.

---

## Task 13: Manual Testing

**Files:**
- None (manual verification)

**Step 1: Build release binary**

Run: `cd rs && cargo build --release`
Expected: Build succeeds

**Step 2: Test signing single file**

```bash
cd rs
echo "Test message" > /tmp/test1.txt
./target/release/minisign_rs -S -s tests/fixtures/keys/unencrypted.key -m /tmp/test1.txt
ls -la /tmp/test1.txt.minisig
```

Expected: Signature file created, output shows "Signing with key" and "Signature written to"

**Step 3: Test signing multiple files (parallel)**

```bash
cd rs
echo "Message 1" > /tmp/m1.txt
echo "Message 2" > /tmp/m2.txt
echo "Message 3" > /tmp/m3.txt

./target/release/minisign_rs -S -s tests/fixtures/keys/unencrypted.key \
    -m /tmp/m1.txt -m /tmp/m2.txt -m /tmp/m3.txt

ls -la /tmp/m*.minisig
```

Expected: Three signature files, progress output for each file

**Step 4: Test sequential flag**

```bash
cd rs
echo "A" > /tmp/a.txt
echo "B" > /tmp/b.txt

./target/release/minisign_rs -S -s tests/fixtures/keys/unencrypted.key \
    -m /tmp/a.txt -m /tmp/b.txt --sequential

ls -la /tmp/a.txt.minisig /tmp/b.txt.minisig
```

Expected: Two signature files created

**Step 5: Test partial failure handling**

```bash
cd rs
echo "Good" > /tmp/good.txt

./target/release/minisign_rs -S -s tests/fixtures/keys/unencrypted.key \
    -m /tmp/good.txt -m /tmp/nonexistent.txt

echo "Exit code: $?"
ls -la /tmp/good.txt.minisig
```

Expected: Exit code 1, error shown for missing file, good.txt signature created, summary shows "1 signed, 1 failed"

**Step 6: Clean up test files**

```bash
rm -f /tmp/test1.txt* /tmp/m*.txt* /tmp/a.txt* /tmp/b.txt* /tmp/good.txt*
```

---

## Task 14: Update Documentation

**Files:**
- Create: `rs/docs/multi-file-signing.md`

**Step 1: Write user documentation**

Create `rs/docs/multi-file-signing.md`:

```markdown
# Multi-File Signing

As of version 1.1.0, minisign_rs supports signing multiple files in a single command with parallel execution for improved performance.

## Basic Usage

Sign multiple files by specifying the `-m` flag multiple times:

```bash
minisign_rs -S -m file1.txt -m file2.bin -m release.tar.gz
```

Each file will get its own `.minisig` signature file:
- `file1.txt.minisig`
- `file2.bin.minisig`
- `release.tar.gz.minisig`

## Parallel Execution (Default)

By default, files are signed in parallel using all available CPU cores for improved performance:

```bash
# Signs files in parallel
minisign_rs -S -m file1.txt -m file2.txt -m file3.txt
```

## Sequential Mode

Force single-threaded execution with `--sequential`:

```bash
minisign_rs -S -m file1.txt -m file2.txt --sequential
```

Use sequential mode when:
- Signing very large files (>1GB each)
- Running on memory-constrained systems
- Debugging signing issues

## Progress Output

Each file reports its status as it completes:

```
Signed: file1.txt → file1.txt.minisig
Signed: file2.txt → file2.txt.minisig
Failed: file3.txt (No such file or directory)
Signed: file4.txt → file4.txt.minisig

Summary: 3 signed, 1 failed
Failed files:
  - file3.txt: No such file or directory
```

## Error Handling

If any files fail to sign:
- Processing continues for remaining files
- Failed files are reported to stderr
- A summary shows success/failure counts
- Exit code is 1 (failure) even if some files succeeded

This allows you to fix errors and re-run signing for only the failed files.

## Backwards Compatibility

Single-file signing behavior is unchanged:

```bash
# Same as before
minisign_rs -S -m file.txt
```

Output format remains identical for single files.

## Limitations

- Custom signature path (`-x`) is not supported with multiple files
  - Each file automatically gets `<filename>.minisig`
- Verification still supports only one file at a time
- All files use the same trusted/untrusted comments

## Performance

Parallel execution scales linearly up to the number of CPU cores:

- 8-core CPU signing 100 files: ~8× faster than sequential
- Memory usage: `cores × average_file_size`
- Typical usage (8 cores × 50MB files): ~400MB
```

**Step 2: Commit documentation**

```bash
git add rs/docs/multi-file-signing.md
git commit -m "docs: add multi-file signing user guide"
```

---

## Task 15: Final Integration Test

**Files:**
- None (final verification)

**Step 1: Run complete test suite**

Run: `cd rs && gtimeout 120 cargo test --all-targets --all-features`
Expected: All tests pass

**Step 2: Run clippy one final time**

Run: `cd rs && cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
Expected: Zero warnings

**Step 3: Format code**

Run: `cd rs && cargo fmt`
Expected: No changes

**Step 4: Verify git status**

Run: `git status`
Expected: Working tree clean

**Step 5: Review commit history**

Run: `git log --oneline -15`
Expected: Clean, descriptive commit messages following conventional format

---

## Success Criteria Checklist

- [x] Rayon dependency added
- [x] CLI accepts multiple `-m` flags
- [x] `--sequential` flag works
- [x] Single-file behavior unchanged (backwards compatible)
- [x] Multi-file signing works in parallel mode
- [x] Multi-file signing works in sequential mode
- [x] Partial failures handled correctly (continue-on-error)
- [x] Summary shows success/failure counts
- [x] Exit code 1 on any failure
- [x] All unit tests pass (fast + slow)
- [x] All integration tests pass
- [x] Zero clippy warnings (pedantic)
- [x] Code formatted with `cargo fmt`
- [x] Documentation written
- [x] Manual testing completed

## Estimated Time

- Tasks 1-6: ~30 minutes (setup, CLI changes, errors)
- Tasks 7-9: ~45 minutes (core multi-file logic + tests)
- Tasks 10-11: ~30 minutes (wiring + integration tests)
- Tasks 12-13: ~20 minutes (verification + manual testing)
- Tasks 14-15: ~15 minutes (docs + final checks)

**Total: ~2.5 hours**
