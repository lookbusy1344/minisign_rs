# Minisign-rs Testing Guide

Complete guide to running and writing tests for minisign-rs.

**See also:**
- [README.md](../README.md) - Quick start
- [USAGE.md](USAGE.md) - Usage guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---

## Overview

Minisign-rs has a comprehensive test suite ensuring cryptographic correctness, C minisign compatibility, and security guarantees. This guide covers running tests, understanding test categories, and adding new tests.

### Test Coverage Statistics

- **479 total tests** covering all operations and CLI behavior
- Comprehensive unit tests covering all crypto operations, key handling, and file formats
- CLI integration tests using assert_cmd for end-to-end validation
- Credential store tests (skip gracefully when OS keyring unavailable)
- Compatibility tests verifying interoperability with C minisign
- Cross-binary tests ensuring full C minisign compatibility
- Edge case tests for unicode, symlinks, and large files
- Fuzzing tests using proptest for property-based testing
- Concurrent access tests for multi-process safety
- Production-strength scrypt parameter tests (N=2^20)
- C compatibility tests skip with a warning when C minisign is not installed

## Test Categories

Minisign-rs organizes tests into two main categories: standard tests and credential store tests.

### Standard Tests

**Runtime:** ~30 seconds
**Scrypt parameters:** Most tests use N=2^14 (fast); a handful validate production N=2^20 parameters

The standard test suite covers all operations. Tests that require the C minisign binary will skip with a warning if it is not installed; all other tests run unconditionally.

**Run with:**
```bash
# Recommended: No keychain popups
cargo test --no-default-features

# With keychain access (may show popups on macOS/Windows)
cargo test
```

### Credential Store Tests

**Count:** ~15 tests
**Runtime:** Variable (requires user interaction)
**Requirements:** User authorization, sequential execution

Credential store tests verify OS keyring integration (macOS Keychain, Windows Credential Manager, Linux Secret Service). These tests:

- **Require user interaction** (authorization prompts)
- **Must run sequentially** (`--test-threads=1`) to avoid parallel prompts
- Are marked with `#[cfg_attr(not(feature = "credential_store_tests"), ignore)]`
- Use RAII cleanup guards to ensure credentials removed even on panic

**When to use:** When modifying credential store functionality.

**Run with:**
```bash
# Credential store tests only (requires clicking through prompts)
cargo test --features credential_store_tests -- --test-threads=1

# Use test runner script
./run_all_tests.sh --credential-store

# All tests including credential store
./run_all_tests.sh --all
```

## Running Tests

### Quick Reference

```bash
# All tests, no keychain popups (recommended for development)
cargo test --no-default-features

# Credential store tests (requires user interaction)
./run_all_tests.sh --credential-store

# All tests including credential store
./run_all_tests.sh --all
```

### Running Tests Without Keychain Popups

By default, the `credential_store` feature is enabled, which may trigger macOS Keychain or Windows Credential Manager popups during tests. To run tests without these popups:

```bash
# Recommended: Run tests without credential store (no keychain popups)
cargo test --no-default-features

# Use the test runner script (no keychain popups by default)
./run_all_tests.sh
```

### Testing Credential Store Functionality

To explicitly test OS credential store integration (requires user interaction):

```bash
# Run credential store tests (requires clicking through keychain prompts)
cargo test --features credential_store_tests -- --test-threads=1

# Or use the script
./run_all_tests.sh --credential-store
```

**Note:** Credential store tests require manual authorization and must run sequentially to avoid multiple simultaneous prompts.

### Advanced Test Options

```bash
# Run with output visible
cargo test --no-default-features -- --nocapture

# Run specific test
cargo test --no-default-features test_sign_verify_roundtrip

# Run only unit tests (in src/)
cargo test --lib

# Run only CLI integration tests
cargo test --test cli_test

# Run only compatibility tests
cargo test --test compatibility

# Run only cross-binary tests
cargo test --test cross_binary_test

```

### Test Runner Script Options

The `run_all_tests.sh` script provides convenient test execution:

```bash
./run_all_tests.sh                     # All tests (default, no keychain popups)
./run_all_tests.sh --credential-store  # Credential store tests only
./run_all_tests.sh --all               # All tests including credential store
```

## Test Requirements

### Required Dependencies

**For all tests:**
- Rust 1.93+ (edition 2024)
- cargo

**For full test suite:**
- **C minisign** (for compatibility and cross-binary tests): `brew install minisign`
  - Without C minisign: ~461 tests run (skips 18 cross-binary tests)
  - With C minisign: All 479 tests run

### Credential Store Feature

The `credential_store` feature controls OS keyring integration (macOS Keychain, Windows Credential Manager, Linux Secret Service):

- **Enabled by default** for production builds
- **Disable during development** to avoid keychain popup dialogs:
  ```bash
  cargo test --no-default-features     # Run tests without keychain access
  cargo build --no-default-features    # Build without keyring dependency
  ```
- When disabled, credential store functions become no-ops (return Ok/None/false)

### Test Directory Structure

**IMPORTANT:** All tests MUST be in the `tests/` directory (not `src/`) to enable proper CodeQL security analysis exclusions.

```
tests/
├── cli_test.rs           # CLI integration tests
├── compatibility.rs      # C minisign cross-tests
├── concurrent_access.rs  # Multi-process safety tests
├── cross_binary_test.rs  # C/Rust interop tests
├── edge_cases.rs         # Unicode, symlinks, large files
├── fuzzing.rs            # Property-based testing with proptest
├── security_attacks.rs   # Security attack vector tests
├── unit.rs               # Unit test harness
├── unit/                 # Unit test modules
└── fixtures/             # Test fixtures
    ├── keys/             # Key pairs (public + secret)
    ├── messages/         # Test message files
    └── signatures/       # Pre-generated signatures
```

## C Minisign Compatibility Testing

Cross-binary tests verify full interoperability with C minisign by executing both implementations and validating they can decrypt each other's keys and verify each other's signatures.

### Prerequisites

C minisign must be installed:

```bash
# macOS
brew install minisign

# Verify installation
minisign -v
```

### Running Compatibility Tests

```bash
# Run all cross-binary tests
cargo test --test cross_binary_test
```

### Test Coverage

Cross-binary tests verify:
- ✅ Rust can decrypt and use C-generated encrypted keys
- ✅ Rust can verify C-generated signatures
- ✅ C minisign can verify Rust-generated signatures
- ✅ Key files are interchangeable between implementations
- ✅ All CLI flags and behaviors match exactly

### Skipping When C Minisign Unavailable

Tests use the `require_c_minisign!()` macro to gracefully skip when C minisign is not installed:

```rust
#[test]
fn test_cross_something() {
    require_c_minisign!();  // Skips test if C minisign not found

    // Test logic...
}
```

**Result:** Without C minisign, ~461 tests run (skips 18 cross-binary tests). With C minisign, all 479 tests run.

## Adding New Tests

### Test Organization Philosophy

Tests in minisign-rs follow strict organization principles:

1. **All tests in `tests/` directory** - Not in `src/` (enables CodeQL exclusions)
2. **Fast by default** - Use N=2^14 for scrypt in regular tests; use N=2^20 only when specifically validating production KDF behaviour
3. **Separate credential store tests** - Avoid accidental user prompts during development
4. **Cross-binary tests require C minisign** - Use `require_c_minisign!()` macro to skip with a warning when unavailable

### Naming Convention

```rust
#[test]
fn test_{operation}_{variant}_{expected_outcome}() {
    // Examples:
    // test_sign_encrypted_key_success
    // test_decrypt_wrong_password_fails
    // test_verify_tampered_message_fails
}
```

### Testing Encrypted Keys

**DO NOT** use real scrypt parameters in regular tests:

```rust
// ❌ BAD - Takes 15-30 seconds
let key = SeckeyStruct::new_encrypted(..., 20, 8, 1)?; // Production params

// ✅ GOOD - Use fast parameters for logic tests
let key = SeckeyStruct::new_encrypted(..., 14, 8, 1)?; // Fast test params (N=2^14)

// ✅ GOOD - Use pre-generated fixtures for compatibility tests
let key_bytes = include_bytes!("../fixtures/keys/c_encrypted_password123.key");
```

### Writing Cross-Binary Tests

Always use the `require_c_minisign!()` macro:

```rust
#[test]
fn test_cross_something() {
    require_c_minisign!();  // Skips test if C minisign not found

    // Test logic...
}
```

### Testing Password Input

For CLI tests requiring password input, use `--password-file`:

```rust
let password_file = temp_dir.path().join("password.txt");
fs::write(&password_file, "mypassword\n")?;

rust_minisign()
    .arg("-S")
    .arg("-m")
    .arg(&message_file)
    .arg("-s")
    .arg(&secret_key)
    .arg("--password-file")
    .arg(&password_file)
    .assert()
    .success();
```

For C minisign (requires shell):

```rust
// Use shell to pipe password
let c_sign = StdCommand::new("sh")
    .arg("-c")
    .arg(format!(
        "cat {} | minisign -S -m {} -s {}",
        password_file.display(),
        message_file.display(),
        secret_key.display()
    ))
    .output()?;
```

### Test Fixtures

Test fixtures are located in `tests/fixtures/` and include:

- **keys/** - Key pairs (public + secret) with documented passwords
- **messages/** - Test message files
- **signatures/** - Pre-generated signatures

All test fixture passwords are documented in `tests/fixtures/keys/README.md`.

Common fixtures:
- `test.key` - Password: `test`
- `c_encrypted_password123.key` - Password: `password123`
- `c_encrypted_testpw.key` - Password: `testpw`
- `unencrypted.key` - No password

**Security Note:** These are test fixtures only. Never use these keys or passwords in production.

## Pre-Commit Testing Checklist

Before committing code, run these checks in order:

```bash
# 1. Run clippy (pedantic mode)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 2. Format code (ALWAYS run AFTER clippy, BEFORE commit)
cargo fmt

# 3. Run tests (~30 seconds)
cargo test --no-default-features
```

**Note:** `cargo fmt` MUST be the last formatting step before commit to ensure consistent style.

## CI/CD Testing

### All Tests (runs on all commits)

- **Workflow**: `.github/workflows/rust.yml`
- **Platforms**: Linux, macOS, Windows
- **Tests**: Full test suite; C compatibility tests run on Linux (where C minisign is installed) and skip on macOS/Windows
- **Timeout**: 10 minutes

### Memory Safety (runs weekly + on push)

- **Workflow**: `.github/workflows/miri.yml`
- **Platform**: Linux
- **Tests**: Unit tests only
- **Purpose**: Catch undefined behavior

### Coverage Reporting

- **Workflow**: `.github/workflows/coverage.yml`
- **Platform**: Linux
- **Tool**: cargo-tarpaulin
- **Reports**: Coverage percentage on every PR

## Debugging Test Failures

### Scrypt Parameter Mismatches

If tests fail with `ChecksumFailed` on encrypted keys:
- Check scrypt parameters (log_n, r, p)
- Verify KDF output length (should be 72 bytes for encrypted keys)
- Compare with C minisign behavior

### Cross-Binary Test Failures

If cross-binary tests fail:
- Verify C minisign is installed: `minisign -v`
- Check C minisign version matches expected
- Run test with `--nocapture` to see C minisign output
- Verify password file format (should end with newline)

### Timeout Failures

If tests timeout:
- Check if using production scrypt parameters (N=2^20) where N=2^14 would suffice
- Tests using fast parameters (N=2^14) should complete in <1s per test

### Credential Store Test Failures

If credential store tests fail:
- Verify OS keyring is accessible
- Check permissions for keychain access
- Ensure tests run sequentially (`--test-threads=1`)
- Verify cleanup guards are properly removing test credentials

## Test-Driven Development

For this security-critical project, we follow strict TDD:

1. **Write the test first** - Define expected behavior
2. **Watch it fail** - Verify test fails for the right reason
3. **Implement minimally** - Just enough to pass
4. **Refactor** - Improve while keeping tests green
5. **Repeat** - Build incrementally

### Example TDD Session

```rust
// 1. Write test first
#[test]
fn test_sign_with_encrypted_key() {
    let seckey = load_encrypted_key("tests/fixtures/keys/test.key");
    let message = b"test message";
    let signature = sign(seckey, message, b"password").unwrap();
    assert!(verify(&signature, message, seckey.public_key()));
}

// 2. Run test - it fails (function doesn't exist)
// 3. Implement sign() function minimally
// 4. Test passes
// 5. Refactor for clarity, tests still pass
```

## Security Requirements for Tests

- All secret material must use `#[derive(Zeroize, ZeroizeOnDrop)]`
- No secret data in error messages or debug output
- No `.unwrap()` or `.expect()` in production code paths
- All cryptographic comparisons must be constant-time
- Credential store tests must clean up even on panic (use RAII guards)

## Test Coverage Goals

While we don't enforce specific coverage percentages, comprehensive testing is expected for:

- **Critical paths**: 100% coverage required
  - `SeckeyStruct::new_encrypted()` - All branches
  - `SeckeyStruct::decrypt()` - Success, wrong password, corrupt data
  - `derive_key_with_params()` - Success and all error conditions
  - Signature creation and verification

- **All modules**: High coverage expected
  - All crypto operations
  - All CLI commands and flags
  - All error paths
  - Edge cases (unicode, symlinks, large files)

## Summary

- Use `--no-default-features` to avoid keychain popups during development
- Use `./run_all_tests.sh` for convenient test execution
- C compatibility tests skip with a warning when C minisign is not installed; on Linux CI it is installed so they run fully
- All tests in `tests/` directory for proper CI/CD integration
- Credential store tests are completely separate to avoid accidental prompts
