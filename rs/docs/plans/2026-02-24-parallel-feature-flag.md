# Parallel Feature Flag Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make rayon an optional Cargo dependency gated behind a `parallel` feature flag (included in `default`), so users can build a smaller binary by excluding parallel processing.

**Architecture:** Add `parallel = ["dep:rayon"]` to `[features]` and gate all rayon imports and `into_par_iter()` call sites with `#[cfg(feature = "parallel")]`. When the feature is off the `sequential` CLI flag disappears and all multi-file operations fall back to `into_iter()`. Five files change: `Cargo.toml`, `ops/sign.rs`, `ops/verify.rs`, `cli.rs`, `main.rs`, plus updates to three test files.

**Tech Stack:** Rust, Cargo optional dependencies, `#[cfg(feature = …)]` conditional compilation.

---

### Task 1: Make rayon optional in Cargo.toml

**Files:**
- Modify: `rs/Cargo.toml`

**Step 1: Edit Cargo.toml**

Change the `rayon` line from:
```toml
rayon = "1"
```
to:
```toml
rayon = { version = "1", optional = true }
```

Add `parallel` to `[features]` and include it in `default`:
```toml
[features]
default = ["credential_store", "parallel"]
credential_store = ["dep:keyring"]
parallel = ["dep:rayon"]
credential_store_tests = ["credential_store"]
```

**Step 2: Verify the default build still compiles**

Run from `rs/`:
```bash
cargo check
```
Expected: succeeds (rayon pulled in via `parallel` which is in `default`).

**Step 3: Verify the no-parallel build fails with a helpful error**

```bash
cargo check --no-default-features
```
Expected: **FAIL** — rayon is no longer available but `sign.rs` and `verify.rs` still import it unconditionally. This is the red state we'll fix in the next tasks.

**Step 4: Commit**

```bash
git add rs/Cargo.toml
git commit -m "build: make rayon optional behind parallel feature flag"
```

---

### Task 2: Gate rayon in ops/sign.rs

**Files:**
- Modify: `rs/src/ops/sign.rs`

**Step 1: Gate the import**

Replace:
```rust
use rayon::prelude::*;
```
with:
```rust
#[cfg(feature = "parallel")]
use rayon::prelude::*;
```

**Step 2: Gate the parallel branch**

The existing code is:
```rust
let results: Vec<FileSignResult> = if sequential {
    files
        .into_iter()
        .map(|file| {
            let result = sign_file_with_key(&file, &secret_key, keynum, options);
            report_file_result(&file, &result, options);
            FileSignResult { file, result }
        })
        .collect()
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

Replace the `else` block so both cfg arms are present:
```rust
let results: Vec<FileSignResult> = if sequential {
    files
        .into_iter()
        .map(|file| {
            let result = sign_file_with_key(&file, &secret_key, keynum, options);
            report_file_result(&file, &result, options);
            FileSignResult { file, result }
        })
        .collect()
} else {
    #[cfg(feature = "parallel")]
    {
        files
            .into_par_iter()
            .map(|file| {
                let result = sign_file_with_key(&file, &secret_key, keynum, options);
                report_file_result(&file, &result, options);
                FileSignResult { file, result }
            })
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        files
            .into_iter()
            .map(|file| {
                let result = sign_file_with_key(&file, &secret_key, keynum, options);
                report_file_result(&file, &result, options);
                FileSignResult { file, result }
            })
            .collect()
    }
};
```

**Step 3: Verify sign.rs compiles in both modes**

```bash
cargo check
cargo check --no-default-features
```
Expected: both succeed (verify.rs still fails in no-default-features mode — that's fine, it gets fixed next).

**Step 4: Commit**

```bash
git add rs/src/ops/sign.rs
git commit -m "feat(sign): gate rayon behind parallel feature"
```

---

### Task 3: Gate rayon in ops/verify.rs

**Files:**
- Modify: `rs/src/ops/verify.rs`

**Step 1: Gate the import**

Replace:
```rust
use rayon::prelude::*;
```
with:
```rust
#[cfg(feature = "parallel")]
use rayon::prelude::*;
```

**Step 2: Gate the parallel branch**

The existing code is:
```rust
let results: Vec<FileVerifyResult> = if sequential {
    files
        .into_iter()
        .map(|file| {
            let result = verify_file_with_key(&file, &pubkey, options);
            report_file_result(&file, &result, options);
            FileVerifyResult { file, result }
        })
        .collect()
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

Apply the same cfg-arm pattern:
```rust
let results: Vec<FileVerifyResult> = if sequential {
    files
        .into_iter()
        .map(|file| {
            let result = verify_file_with_key(&file, &pubkey, options);
            report_file_result(&file, &result, options);
            FileVerifyResult { file, result }
        })
        .collect()
} else {
    #[cfg(feature = "parallel")]
    {
        files
            .into_par_iter()
            .map(|file| {
                let result = verify_file_with_key(&file, &pubkey, options);
                report_file_result(&file, &result, options);
                FileVerifyResult { file, result }
            })
            .collect()
    }
    #[cfg(not(feature = "parallel"))]
    {
        files
            .into_iter()
            .map(|file| {
                let result = verify_file_with_key(&file, &pubkey, options);
                report_file_result(&file, &result, options);
                FileVerifyResult { file, result }
            })
            .collect()
    }
};
```

**Step 3: Verify in both modes**

```bash
cargo check
cargo check --no-default-features
```
Expected: both succeed (cli.rs and main.rs still reference `sequential` unconditionally, but that compiles fine — `sequential` is a field that exists in both builds at this point).

**Step 4: Commit**

```bash
git add rs/src/ops/verify.rs
git commit -m "feat(verify): gate rayon behind parallel feature"
```

---

### Task 4: Gate the `--sequential` flag in cli.rs

**Files:**
- Modify: `rs/src/cli.rs`

**Step 1: Gate the sequential field**

Find the block:
```rust
/// Process files sequentially instead of in parallel
#[arg(long)]
pub sequential: bool,
```

Replace with:
```rust
#[cfg(feature = "parallel")]
/// Process files sequentially instead of in parallel
#[cfg_attr(feature = "parallel", arg(long))]
pub sequential: bool,
```

Wait — clap derive uses `#[arg(...)]` as an attribute. The correct way to conditionally apply both the doc comment, the `#[arg]` and the field itself is:

```rust
#[cfg(feature = "parallel")]
#[doc = "Process files sequentially instead of in parallel"]
#[arg(long)]
pub sequential: bool,
```

**Step 2: Verify in both modes**

```bash
cargo check
cargo check --no-default-features
```
Expected: both succeed. In the no-parallel build, `--sequential` is not a recognised flag.

**Step 3: Commit**

```bash
git add rs/src/cli.rs
git commit -m "feat(cli): gate --sequential flag behind parallel feature"
```

---

### Task 5: Gate cli.sequential usages in main.rs

**Files:**
- Modify: `rs/src/main.rs`

There are exactly two call sites.

**Step 1: Gate in sign call (around line 374)**

Find:
```rust
sign_multiple_files(
    message_files,
    &options,
    password.map(|p| p.as_bytes()),
    cli.sequential,
)?;
```

Replace with:
```rust
sign_multiple_files(
    message_files,
    &options,
    password.map(|p| p.as_bytes()),
    #[cfg(feature = "parallel")]
    cli.sequential,
    #[cfg(not(feature = "parallel"))]
    true,
)?;
```

**Step 2: Gate in verify call (around line 471)**

Find:
```rust
verify_multiple_files(message_files.into_owned(), &options, cli.sequential)?;
```

Replace with:
```rust
verify_multiple_files(
    message_files.into_owned(),
    &options,
    #[cfg(feature = "parallel")]
    cli.sequential,
    #[cfg(not(feature = "parallel"))]
    true,
)?;
```

**Step 3: Verify in both modes**

```bash
cargo check
cargo check --no-default-features
```
Expected: both succeed with zero warnings.

**Step 4: Commit**

```bash
git add rs/src/main.rs
git commit -m "feat(main): pass sequential=true when parallel feature is disabled"
```

---

### Task 6: Update tests

**Files:**
- Modify: `rs/tests/unit/cli.rs`
- Modify: `rs/tests/cli_test.rs`

#### tests/unit/cli.rs

**Step 1: Gate the 5 struct-literal field initialisations**

There are 5 struct literals containing `sequential: false`. In each one, wrap the line:
```rust
#[cfg(feature = "parallel")]
sequential: false,
```

Rust struct literal expressions accept `#[cfg]` attributes on individual fields.

**Step 2: Gate the two sequential-flag tests**

Add `#[cfg(feature = "parallel")]` above each of these two tests:

```rust
#[cfg(feature = "parallel")]
#[test]
fn cli_sequential_flag_defaults_false() { … }

#[cfg(feature = "parallel")]
#[test]
fn cli_sequential_flag_can_be_set() { … }
```

#### tests/cli_test.rs

**Step 3: Gate the CLI integration test**

Find `fn cli_sign_multiple_files_sequential` and add `#[cfg(feature = "parallel")]` above its `#[test]` attribute:

```rust
#[cfg(feature = "parallel")]
#[test]
fn cli_sign_multiple_files_sequential() { … }
```

**Step 4: Verify in both modes**

```bash
cargo check --tests
cargo check --tests --no-default-features
```
Expected: both succeed.

**Step 5: Commit**

```bash
git add rs/tests/unit/cli.rs rs/tests/cli_test.rs
git commit -m "test: gate sequential-specific tests behind parallel feature"
```

---

### Task 7: Full verification

**Step 1: Clippy (full features)**

Run from `rs/`:
```bash
gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```
Expected: zero warnings.

**Step 2: Clippy (no-default-features)**

```bash
gtimeout 60 cargo clippy --all-targets --no-default-features -- -D clippy::all -D clippy::pedantic
```
Expected: zero warnings.

**Step 3: Format**

```bash
cargo fmt
```

**Step 4: Full test suite (default features)**

```bash
gtimeout 120 cargo test --no-default-features
```

Note: `--no-default-features` here is the project's standard test command (avoids keyring prompts) and still includes the `parallel` feature via `default`. This is correct.

**Step 5: Full test suite without parallel**

```bash
gtimeout 120 cargo test --no-default-features --features ""
```

Or equivalently (to explicitly confirm no-parallel build passes tests):
```bash
gtimeout 120 cargo test --no-default-features
```

Wait — `--no-default-features` strips *all* defaults including `parallel`. So the project's standard test invocation already tests the no-parallel path. Confirm this is intentional by checking the project's test instructions (`rs/.claude/rules/run-tests.md` at repo root: `gtimeout 120 cargo test --no-default-features`).

**Step 6: Commit if fmt produced changes**

```bash
git add -p
git commit -m "chore: cargo fmt after parallel feature flag changes"
```
(Skip if `git diff` shows nothing after fmt.)

---

### Task 8: Release build size check (optional smoke test)

**Step 1: Build release with parallel**

```bash
cargo build --release
ls -lh target/release/minisign_rs
```

**Step 2: Build release without parallel**

```bash
cargo build --release --no-default-features
ls -lh target/release/minisign_rs
```

Compare binary sizes. The no-parallel build should be measurably smaller due to rayon and its transitive dependencies being excluded.
