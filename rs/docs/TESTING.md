# Testing Guidelines for Minisign Rust

## Test Categories

### Unit Tests (inline in `src/*.rs`)
- Test single functions in isolation
- Mock external dependencies
- Must run in < 1 second
- No filesystem or network access

### Integration Tests (`tests/integration/`)
- Test multiple components together
- May use tempfiles
- Must run in < 5 seconds each
- No external binaries required

### Compatibility Tests (`tests/compatibility.rs`)
- Verify behavior matches C minisign
- Use pre-generated fixtures
- Must run in < 1 second each (fast path)
- Some may be marked `#[ignore]` for slow operations

### Cross-Binary Tests (`tests/cross_binary_test.rs`)
- Execute both Rust and C binaries
- Require C minisign installed
- Run in slow-tests CI job
- Use `require_c_minisign!()` macro

## Writing New Tests

### Naming Convention
```rust
#[test]
fn test_{operation}_{variant}_{expected_outcome}() {
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

### Cross-Binary Tests

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

## Test Fixtures

### Directory Structure
```
tests/fixtures/
├── keys/           # Key pairs (public + secret)
├── messages/       # Test message files
├── signatures/     # Pre-generated signatures
└── README.md       # Documents each fixture
```

### Creating New Fixtures

1. Generate with known, documented parameters
2. Record the password in `fixtures/keys/README.md`
3. Add both encrypted and unencrypted variants
4. Commit the fixture files

### Updating Fixtures

If fixture regeneration is needed:
1. Document the regeneration in PR description
2. Verify all tests still pass
3. Update `fixtures/keys/README.md` with any changes

## Coverage Requirements

### Minimum Coverage by Module

| Module | Minimum | Target | Critical Paths |
|--------|---------|--------|----------------|
| keys.rs | 80% | 90% | encrypt/decrypt |
| crypto.rs | 85% | 95% | KDF, signing |
| ops/sign.rs | 80% | 90% | sign_file |
| ops/verify.rs | 80% | 90% | verify_signature |

### Critical Path Coverage

These paths MUST have 100% test coverage:
- `SeckeyStruct::new_encrypted()` - All branches
- `SeckeyStruct::decrypt()` - Success, wrong password, corrupt data
- `derive_key_with_params()` - Success and all error conditions
- Signature creation and verification

### Checking Coverage Locally

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out Html
open tarpaulin-report.html
```

### Coverage in CI

Coverage is reported on every PR. PRs that decrease coverage below minimums will fail CI.

## Fast vs Slow Tests

### Fast Tests (default `cargo test`)

Use when testing:
- Logic correctness (encryption XOR, checksum calculation)
- Error handling paths
- Serialization/deserialization
- CLI argument parsing

Fast test parameters for scrypt:
```rust
const FAST_LOG_N: u8 = 14;  // 2^14 = 16384 (vs 2^20 = 1M for production)
const FAST_R: u32 = 8;
const FAST_P: u32 = 1;
```

### Slow Tests (`cargo test -- --ignored`)

Use when testing:
- Compatibility with C minisign using real parameters
- Performance characteristics
- Production parameter validation

Mark slow tests with `#[ignore]`:
```rust
#[test]
#[ignore = "Slow: uses production scrypt parameters"]
fn test_decrypt_c_generated_encrypted_key() {
    // Uses real KDF parameters, takes 15-30 seconds
}
```

### When to Add Slow Tests

Add a slow test when:
1. Testing byte-level compatibility with C implementation
2. Validating production parameter handling
3. The behavior differs between fast and production parameters

### Running Slow Tests

```bash
# Run all slow tests
cargo test -- --ignored

# Run specific slow test
cargo test test_decrypt_c_generated_encrypted_key -- --ignored

# Run all tests including slow ones
cargo test -- --include-ignored
```

## Running Tests

```bash
# Run all fast tests (default)
gtimeout 60 cargo test

# Run with output visible
gtimeout 60 cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run only unit tests (in src/)
cargo test --lib

# Run only CLI integration tests
cargo test --test cli_test

# Run only compatibility tests
cargo test --test compatibility

# Run only cross-binary tests
cargo test --test cross_binary_test

# Run slow/ignored tests
cargo test -- --ignored --nocapture
```

## CI Testing

### Fast Tests (runs on all commits)
- **Workflow**: `.github/workflows/rust.yml`
- **Platforms**: Linux, macOS, Windows
- **Tests**: All unit, integration, and fast compatibility tests
- **Timeout**: 10 minutes

### Slow Tests (runs on all commits + nightly)
- **Workflow**: `.github/workflows/slow-tests.yml`
- **Platform**: Linux only
- **Tests**: All `#[ignore]` tests + cross-binary tests
- **Requires**: C minisign installed
- **Timeout**: 30 minutes for ignored tests, 15 minutes for cross-binary

### Memory Safety (runs weekly + on push)
- **Workflow**: `.github/workflows/miri.yml`
- **Platform**: Linux
- **Tests**: Unit tests only
- **Purpose**: Catch undefined behavior

## Test-Driven Development Workflow

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
- Check if using production scrypt parameters (N=2^20)
- Tests using fast parameters (N=2^14) should complete in <1s
- Production parameter tests should be marked `#[ignore]`

## Pre-Commit Checklist

Before committing code:
```bash
# 1. Format code
cargo fmt

# 2. Run clippy with EXACT CI flags (required)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 3. Run fast tests
gtimeout 60 cargo test

# 4. If you modified encrypted key code, run slow tests
cargo test -- --ignored
```

## Test Fixtures Password Reference

All test fixture passwords are documented in `tests/fixtures/keys/README.md`.

Common fixtures:
- `test.key` - Password: `test`
- `c_encrypted_password123.key` - Password: `password123`
- `c_encrypted_testpw.key` - Password: `testpw`
- `unencrypted.key` - No password

**Security Note**: These are test fixtures only. Never use these keys or passwords in production.
