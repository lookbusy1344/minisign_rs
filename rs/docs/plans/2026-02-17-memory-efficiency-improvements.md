# Memory Efficiency Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate four categories of unnecessary heap allocation: intermediate Vec in wordlist joining, spurious `.to_vec()` on fixed-size hash arrays, needless `PathBuf` clones in the parallel signing/verification path, and a double-allocation on `Cow<str>` in the CLI.

**Architecture:** Each fix is isolated to a single function or code block with no cross-cutting concerns. Itertools is added as a dependency for its `Itertools::join` on iterators (avoids the collect-then-join pattern). The hash array fix uses a pair of typed local bindings to satisfy the Rust type system without merging both arms into `Vec<u8>`.

**Tech Stack:** Rust, Rayon (existing), itertools (new dependency)

---

## Background

A prior optimization pass (2026-02-02) addressed `Option<PathBuf>` clones in the CLI layer. It explicitly marked parallel iterator clones as "required for thread safety" — that conclusion was incorrect. Rayon's `into_par_iter()` consumes the source Vec and gives ownership to each parallel task, exactly like `into_iter()` does on the sequential path (which already uses `into_iter()` correctly).

Four new issues remain:

| # | Location | Issue | Allocation cost |
|---|----------|-------|-----------------|
| 1 | `wordlist.rs:576` | `collect::<Vec<&str>>().join()` | Heap Vec per key display |
| 2 | `ops/sign.rs:634`, `ops/verify.rs:421` | `blake2b_512_stream(…)?.to_vec()` | 64-byte heap Vec per prehashed file |
| 3 | `ops/sign.rs:523`, `ops/verify.rs:534` | `file.clone()` inside `par_iter()` | N PathBuf allocations for N-file parallel ops |
| 4 | `cli.rs:234` | `to_string_lossy().to_string()` | Second allocation on already-owned Cow |

---

## Pre-flight

```bash
cd rs
cargo test --no-default-features
cargo test --no-default-features -- --ignored
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

All must pass before starting.

---

## Task 1: Add itertools and fix `bytes_to_words`

**Files:**
- Modify: `Cargo.toml` (add itertools)
- Modify: `src/wordlist.rs:565-578`

### Context

`bytes_to_words` converts a `&[u8]` to a space-separated string of words from two lookup tables. The current implementation collects into an intermediate `Vec<&str>` in order to call `[T]::join`, which requires a slice. This wastes a heap allocation on every call — which happens at every key display during signing and verification.

Itertools provides `Itertools::join` directly on iterators, skipping the intermediate Vec.

### Step 1: Write the failing test

In `src/wordlist.rs`, add to the `#[cfg(test)]` block at the bottom of the file. If no `mod tests` block exists, create one.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_words_no_intermediate_vec() {
        // Verify correctness of the existing function — the refactor must not change output.
        // Two bytes: position 0 (even) -> EVEN_WORDS[0], position 1 (odd) -> ODD_WORDS[0]
        let result = bytes_to_words(&[0x00, 0x01]);
        let parts: Vec<&str> = result.split(' ').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], EVEN_WORDS[0]);
        assert_eq!(parts[1], ODD_WORDS[1]);
    }

    #[test]
    fn bytes_to_words_empty() {
        assert_eq!(bytes_to_words(&[]), "");
    }

    #[test]
    fn bytes_to_words_single_even() {
        let result = bytes_to_words(&[0x00]);
        assert_eq!(result, EVEN_WORDS[0]);
    }

    #[test]
    fn bytes_to_words_single_odd_at_pos_one() {
        // Single byte at index 1 would be odd, but with only one byte it's at index 0 (even)
        let result = bytes_to_words(&[0xFF]);
        assert_eq!(result, EVEN_WORDS[255]);
    }
}
```

### Step 2: Run tests to confirm they pass against current code

```bash
cargo test --no-default-features wordlist
```

Expected: PASS (these tests verify existing behaviour, not a new behaviour).

### Step 3: Add itertools to Cargo.toml

In `Cargo.toml`, under `[dependencies]`, add:

```toml
itertools = "0.14"
```

The pinning policy in this project applies only to cryptographic crates. `itertools` is a utility crate and does not require exact-version pinning.

### Step 4: Rewrite `bytes_to_words` using `Itertools::join`

In `src/wordlist.rs`, add the import at the top of the file (or in the function body):

```rust
use itertools::Itertools as _;
```

Replace the function body at lines 565-578:

```rust
#[must_use]
pub fn bytes_to_words(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, &byte)| {
            if i % 2 == 0 {
                EVEN_WORDS[usize::from(byte)]
            } else {
                ODD_WORDS[usize::from(byte)]
            }
        })
        .join(" ")
}
```

The only change is removing `.collect::<Vec<&str>>()` — `Itertools::join` operates directly on the iterator.

### Step 5: Run clippy and tests

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo test --no-default-features wordlist
```

Expected: no warnings, all tests PASS.

### Step 6: Commit

```bash
git add Cargo.toml Cargo.lock src/wordlist.rs
git commit -m "perf(wordlist): eliminate intermediate Vec in bytes_to_words via itertools"
```

---

## Task 2: Eliminate `.to_vec()` on prehashed blake2b output

**Files:**
- Modify: `src/ops/sign.rs` (~line 630-642)
- Modify: `src/ops/verify.rs` (~line 418-427)

### Context

`blake2b_512_stream` returns `Result<[u8; 64]>` — a fixed-size stack-allocated array. Both the signing and verification functions immediately call `.to_vec()` on the result so the `if/else` arms unify to `Vec<u8>`. The Vec is then immediately passed as `&data_to_sign` to `crypto_sign` / `crypto_verify`, which accept `&[u8]`. The `Vec<u8>` is never needed.

The correct fix is to hold the two possible data sources in separate bindings and let the `if/else` assign a `&[u8]` slice to a single reference:

```rust
let hash_buf;   // typed [u8; 64], only initialised on the prehash path
let file_buf;   // typed Vec<u8>,  only initialised on the non-prehash path
let data: &[u8] = if prehashed {
    hash_buf = blake2b_512_stream(…)?;
    &hash_buf
} else {
    file_buf = std::fs::read(…)?;
    &file_buf
};
```

Rust's MIR guarantees that exactly one of `hash_buf` / `file_buf` is initialised, and the unused one is never dropped. This is idiomatic for unifying branches with different-sized stack types.

### Step 1: Write tests that exercise the prehash path

Find the existing test module in `src/ops/sign.rs` (or `tests/` directory). Add:

```rust
#[test]
fn sign_prehashed_produces_prehash_sig() {
    // Arrange: generate a key pair, write a temp file, sign with --prehash
    use tempfile::NamedTempFile;
    let mut f = NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut f, b"hello prehash world").unwrap();

    // This calls sign_file_inner with prehashed=true — exercises the changed branch
    // Use the existing test helpers if they exist, otherwise build SignOptions via its builder
    // (check existing tests in this file for the correct builder pattern)
    // The test must compile and exercise the prehash branch without panicking.
    // Signature correctness is verified by round-tripping through verify.
}
```

Check the existing test helpers and builder pattern in `src/ops/sign.rs` tests before writing this — match the existing style exactly.

### Step 2: Run the test to confirm it exercises the right path

```bash
cargo test --no-default-features sign_prehashed
```

Expected: PASS (tests existing behaviour before the refactor).

### Step 3: Refactor the data binding in `sign.rs`

Locate the block (approximately lines 630-642):

```rust
// Current:
let data_to_sign = if prehashed {
    let file =
        std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
    blake2b_512_stream(file)?.to_vec()
} else {
    check_file_size_limit(message_file)?;
    std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
};
```

Replace with:

```rust
// Refactored: avoid heap allocation for prehash path
let hash_buf;
let file_buf;
let data_to_sign: &[u8] = if prehashed {
    let file =
        std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
    hash_buf = blake2b_512_stream(file)?;
    &hash_buf
} else {
    check_file_size_limit(message_file)?;
    file_buf = std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?;
    &file_buf
};
```

The downstream `crypto_sign(secret_key, &data_to_sign)` call at line 645 already borrows — no further changes needed there (remove the `&` if `data_to_sign` is now already `&[u8]`).

### Step 4: Apply the same refactor in `verify.rs`

Locate the equivalent block (approximately lines 418-427):

```rust
// Current:
let data_to_verify = if sig_box.sig_struct().is_prehashed() {
    let file =
        std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
    blake2b_512_stream(file)?.to_vec()
} else {
    check_file_size_limit(message_file)?;
    std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
};
```

Replace with:

```rust
let hash_buf;
let file_buf;
let data_to_verify: &[u8] = if sig_box.sig_struct().is_prehashed() {
    let file =
        std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
    hash_buf = blake2b_512_stream(file)?;
    &hash_buf
} else {
    check_file_size_limit(message_file)?;
    file_buf = std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?;
    &file_buf
};
```

### Step 5: Run clippy and tests

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo test --no-default-features
```

Expected: no warnings, all tests PASS.

### Step 6: Commit

```bash
git add src/ops/sign.rs src/ops/verify.rs
git commit -m "perf(ops): eliminate Vec allocation for prehashed blake2b output"
```

---

## Task 3: Replace `par_iter()` + clone with `into_par_iter()`

**Files:**
- Modify: `src/ops/sign.rs` (~lines 517-527)
- Modify: `src/ops/verify.rs` (~lines 528-538)

### Context

The multi-file parallel path uses `par_iter()` which yields `&PathBuf` references, forcing a `file.clone()` inside the closure to satisfy `FileSignResult { file: PathBuf, … }`. The sequential path in the same function already correctly uses `into_iter()`, which consumes the Vec and gives ownership to the closure — no clone needed.

Rayon's `into_par_iter()` on `Vec<T>` works identically to `into_iter()` but schedules work across threads. Switching to it eliminates N `PathBuf` allocations for N-file parallel operations. This is safe because `files` is not used after the parallel `.collect()`.

### Step 1: Confirm there is no use of `files` after the parallel block

Before changing anything, read the full function body after line 527 in `sign.rs` and 538 in `verify.rs`. Confirm that `files` is not accessed after the `if sequential { … } else { … }` block. The result is stored in `results` and `files` is consumed.

### Step 2: Write a test for multi-file parallel signing

Find the existing multi-file sign test (search for `test_sign_multiple` or similar). Confirm it exercises the parallel path (i.e., `sequential = false`). If it does not, add a variant:

```rust
#[test]
fn sign_multiple_files_parallel() {
    // Sign 3 temp files with sequential=false, verify each signature after
    // Use the existing test infrastructure (key generation helpers, etc.)
    // See existing tests for the pattern
}
```

Run the existing multi-file test to confirm it passes before modifying:

```bash
cargo test --no-default-features sign_multiple
```

### Step 3: Refactor `sign.rs` parallel branch

Current code (approximately lines 517-527):

```rust
} else {
    files
        .par_iter()
        .map(|file| {
            let result = sign_file_with_key(file, &secret_key, keynum, options);
            report_file_result(file, &result, options);
            FileSignResult {
                file: file.clone(),
                result,
            }
        })
        .collect()
};
```

Replace with:

```rust
} else {
    files
        .into_par_iter()
        .map(|file| {
            let result = sign_file_with_key(&file, &secret_key, keynum, options);
            report_file_result(&file, &result, options);
            FileSignResult { file, result }
        })
        .collect()
};
```

Note: `into_par_iter()` yields owned `PathBuf`, so `file` can be moved into `FileSignResult` directly. The existing call sites `sign_file_with_key(file, …)` and `report_file_result(file, …)` accept `&Path` — pass `&file`.

### Step 4: Refactor `verify.rs` parallel branch

Current code (approximately lines 528-538):

```rust
} else {
    files
        .par_iter()
        .map(|file| {
            let result = verify_file_with_key(file, &pubkey, options);
            report_file_result(file, &result, options);
            FileVerifyResult {
                file: file.clone(),
                result,
            }
        })
        .collect()
};
```

Replace with:

```rust
} else {
    files
        .into_par_iter()
        .map(|file| {
            let result = verify_file_with_key(&file, &pubkey, options);
            report_file_result(&file, &result, options);
            FileVerifyResult { file, result }
        })
        .collect()
};
```

### Step 5: Run clippy and full tests

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo test --no-default-features
cargo test --no-default-features -- --ignored
```

Expected: no warnings, all tests PASS.

### Step 6: Commit

```bash
git add src/ops/sign.rs src/ops/verify.rs
git commit -m "perf(ops): replace par_iter+clone with into_par_iter in parallel sign/verify"
```

---

## Task 4: Fix double-allocation on `Cow<str>` in `default_signature_path`

**Files:**
- Modify: `src/cli.rs` (~line 234)

### Context

`Path::file_name()` returns `Option<&OsStr>`. Calling `.to_string_lossy()` returns `Cow<'_, str>`:
- **Borrowed** variant when the filename is valid UTF-8 (the common case on macOS/Linux) — points into the OsStr data with no allocation.
- **Owned** variant when it contains invalid UTF-8 — allocates a String with replacement characters.

The current code then calls `.to_string()` on that `Cow<str>`. For the Borrowed case this allocates a fresh `String` by copying from the borrowed `&str`. For the Owned case it allocates a second `String` by cloning the already-allocated one. Either way, one allocation is wasted.

Calling `.into_owned()` instead returns the inner `String` directly when it is Owned, and allocates (once) when it is Borrowed. The push_str mutation below is unchanged.

### Step 1: Write a test for `default_signature_path`

Find the test module in `src/cli.rs` or `tests/`. Add:

```rust
#[test]
fn default_signature_path_appends_minisig() {
    use std::path::Path;
    let result = SignArgs::default_signature_path(Path::new("/tmp/myfile.txt")).unwrap();
    assert_eq!(result, std::path::PathBuf::from("/tmp/myfile.txt.minisig"));
}

#[test]
fn default_signature_path_no_filename_errors() {
    use std::path::Path;
    assert!(SignArgs::default_signature_path(Path::new("/")).is_err());
}
```

Adjust the struct name (`SignArgs` or whatever the containing type is) to match what's in the file — check the `impl` block containing `default_signature_path`.

### Step 2: Run the tests to confirm they pass before the change

```bash
cargo test --no-default-features default_signature_path
```

Expected: PASS.

### Step 3: Apply the fix in `cli.rs`

Current code (approximately line 234):

```rust
let mut file_name_string = file_name.to_string_lossy().to_string();
```

Replace with:

```rust
let mut file_name_string = file_name.to_string_lossy().into_owned();
```

No other changes needed — `push_str` and `set_file_name` calls below are unchanged.

### Step 4: Run clippy and tests

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo test --no-default-features
```

Expected: no warnings, all tests PASS.

### Step 5: Commit

```bash
git add src/cli.rs
git commit -m "perf(cli): use into_owned instead of to_string on Cow<str> in default_signature_path"
```

---

## Post-flight

Run the complete check sequence from CLAUDE.md:

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
cargo test --no-default-features
cargo test --no-default-features -- --ignored
```

All must pass. `cargo fmt` last, before any further commits.
