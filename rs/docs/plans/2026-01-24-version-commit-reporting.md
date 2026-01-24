# Version and Commit Hash Reporting Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add build-time git commit hash to version output, displaying format `minisign_rs 0.12.0 (6a4f667)` in `--version` and `--help`.

**Architecture:** Build script (`build.rs`) extracts git commit hash at compile time and sets environment variable. CLI version attribute uses this variable to construct version string. Clap handles display in both `--version` and `--help` automatically.

**Tech Stack:** Rust build scripts, git command-line, clap derive macros, assert_cmd for integration testing.

---

## Task 1: Write Integration Tests First

**Files:**
- Modify: `rs/tests/cli_test.rs` (add new tests at end)

**Context:** Following TDD, write tests first. These tests verify version output includes commit hash in parentheses.

**Step 1: Write failing tests for version reporting**

Add these tests at the end of `rs/tests/cli_test.rs`:

```rust
#[test]
fn test_version_includes_commit_hash() {
    Command::cargo_bin("minisign_rs")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")))
        .stdout(predicates::str::contains("("));
}

#[test]
fn test_help_shows_version() {
    Command::cargo_bin("minisign_rs")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}
```

**Step 2: Run tests to verify they fail**

```bash
cd rs
cargo test test_version_includes_commit_hash -- --nocapture
```

Expected: FAIL - currently shows "0.12.0 (Rust)" not commit hash in parens

**Step 3: Commit the failing tests**

```bash
git add rs/tests/cli_test.rs
git commit -m "test: add version commit hash reporting tests"
```

---

## Task 2: Create Build Script for Git Hash Extraction

**Files:**
- Create: `rs/build.rs`

**Context:** Build scripts run at compile time before source compilation. This extracts git commit hash and makes it available as compile-time environment variable.

**Step 1: Create build.rs with git hash extraction**

Create `rs/build.rs`:

```rust
use std::process::Command;

fn main() {
    // Get commit hash from git
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();

    let commit_hash = match output {
        Ok(output) if output.status.success() => {
            let hash = String::from_utf8_lossy(&output.stdout);
            // Take first 7 characters (standard short hash)
            hash.trim().chars().take(7).collect()
        }
        _ => {
            // Fallback for non-git builds (tarballs, etc.)
            "unknown".to_string()
        }
    };

    // Set environment variable for use in source code
    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);

    // Rebuild if git HEAD changes (new commits)
    println!("cargo:rerun-if-changed=.git/HEAD");
}
```

**Step 2: Verify build script works**

```bash
cd rs
cargo clean
cargo build
```

Expected: Build succeeds, no errors. The environment variable is now available.

**Step 3: Check that GIT_COMMIT_HASH is set**

```bash
cd rs
cargo build --verbose 2>&1 | grep GIT_COMMIT_HASH
```

Expected: Output shows `GIT_COMMIT_HASH=<7-char-hash>`

**Step 4: Commit build script**

```bash
git add rs/build.rs
git commit -m "build: add git commit hash extraction to build.rs"
```

---

## Task 3: Update CLI Version Attribute

**Files:**
- Modify: `rs/src/cli.rs:12`

**Context:** Replace the hardcoded " (Rust)" suffix with the git commit hash from build.rs. Clap will automatically use this in `--version` and `--help` output.

**Step 1: Update version attribute in cli.rs**

In `rs/src/cli.rs`, replace line 12:

```rust
// Before:
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (Rust)"))]

// After:
#[command(version = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("GIT_COMMIT_HASH"),
    ")"
))]
```

**Step 2: Verify it compiles**

```bash
cd rs
cargo build
```

Expected: Build succeeds.

**Step 3: Test version output manually**

```bash
cd rs
./target/debug/minisign_rs --version
```

Expected: Output shows `minisign_rs 0.12.0 (<7-char-hash>)` where hash matches current commit.

**Step 4: Test help output manually**

```bash
cd rs
./target/debug/minisign_rs --help
```

Expected: Top of help shows version with commit hash.

**Step 5: Commit the change**

```bash
git add rs/src/cli.rs
git commit -m "feat: add git commit hash to version output"
```

---

## Task 4: Run Integration Tests

**Files:**
- Test: `rs/tests/cli_test.rs`

**Context:** Verify our integration tests now pass with the implementation complete.

**Step 1: Run the new version tests**

```bash
cd rs
cargo test test_version_includes_commit_hash
cargo test test_help_shows_version
```

Expected: Both tests PASS.

**Step 2: Run all CLI tests**

```bash
cd rs
cargo test --test cli_test
```

Expected: All CLI tests pass (was 16, now 18 tests).

**Step 3: Run full test suite (fast tests)**

```bash
cd rs
cargo test
```

Expected: All tests pass (was 148, now 150 tests).

---

## Task 5: Verify Fallback Behavior

**Files:**
- None (manual testing only)

**Context:** Ensure graceful fallback when git is unavailable (tarball builds, CI without git).

**Step 1: Test without .git directory**

```bash
# Create temporary copy without .git
mkdir -p /tmp/minisign-test
cp -r rs /tmp/minisign-test/
rm -rf /tmp/minisign-test/rs/.git
cd /tmp/minisign-test/rs
cargo build --release
./target/release/minisign_rs --version
```

Expected: Output shows `minisign_rs 0.12.0 (unknown)`

**Step 2: Clean up test directory**

```bash
rm -rf /tmp/minisign-test
cd -  # Return to original directory
```

---

## Task 6: Run Full Test Suite and Clippy

**Files:**
- All source files

**Context:** Final verification before considering complete. Run all tests including slow tests and clippy pedantic checks.

**Step 1: Run fast test suite**

```bash
cd rs
gtimeout 30 cargo test
```

Expected: All ~150 tests pass in ~9 seconds.

**Step 2: Run slow security tests**

```bash
cd rs
gtimeout 30 cargo test -- --ignored
```

Expected: All 11 slow tests pass in ~16 seconds.

**Step 3: Run clippy with pedantic checks**

```bash
cd rs
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
```

Expected: No warnings or errors.

**Step 4: Run cargo fmt check**

```bash
cd rs
cargo fmt --check
```

Expected: No formatting issues.

---

## Task 7: Manual Verification and Documentation Review

**Files:**
- Verify: `rs/README.md` (check if version examples need updating)

**Context:** Final checks to ensure user-facing documentation is consistent.

**Step 1: Check README for version references**

```bash
cd rs
grep -n "version" README.md
grep -n "0\.12\.0" README.md
```

Expected: Check if any version examples need updating to show new format.

**Step 2: Build release binary and test**

```bash
cd rs
cargo build --release
./target/release/minisign_rs --version
./target/release/minisign_rs --help | head -5
```

Expected: Version shows commit hash, help shows version at top.

**Step 3: Verify current git commit matches displayed hash**

```bash
git rev-parse HEAD | head -c 7
cd rs
./target/release/minisign_rs --version
```

Expected: The 7-character hash in version output matches git commit.

---

## Task 8: Final Commit and Review

**Files:**
- All modified files

**Context:** Ensure all changes are committed and feature is complete.

**Step 1: Check git status**

```bash
git status
```

Expected: All changes committed, working directory clean.

**Step 2: Review commit history**

```bash
git log --oneline -6
```

Expected: See commits for tests, build.rs, cli.rs update.

**Step 3: Create summary of changes**

The implementation adds:
- `rs/build.rs` - Git commit hash extraction at build time
- `rs/src/cli.rs:12` - Updated version string to include commit hash
- `rs/tests/cli_test.rs` - Two new integration tests
- Total: +2 integration tests (148→150 fast tests)

**Step 4: Verify feature completeness**

All requirements met:
- ✓ Version format: `minisign_rs 0.12.0 (6a4f667)`
- ✓ Displayed in `--version` flag
- ✓ Displayed in `--help` output (automatic via clap)
- ✓ Build-time extraction (no runtime git dependency)
- ✓ Graceful fallback when git unavailable
- ✓ Integration tests verify behavior
- ✓ Full test suite passes
- ✓ Clippy pedantic clean

---

## Success Criteria

- [ ] Build script (`rs/build.rs`) extracts git commit hash
- [ ] Version output shows `minisign_rs 0.12.0 (<hash>)`
- [ ] Help output shows version with commit hash at top
- [ ] Integration tests pass (2 new tests)
- [ ] Full test suite passes (150 fast + 11 slow)
- [ ] Clippy pedantic passes with no warnings
- [ ] Fallback to "unknown" works when .git absent
- [ ] All changes committed with conventional commits

## Rollback Plan

If issues arise:
```bash
git log --oneline -6  # Find commit before this work
git revert <commit-hash>  # Revert specific commits
```

Or full rollback:
```bash
git reset --hard <commit-before-feature>
```
