# Minisign-rs Development Guide

Developer workflow and guidelines for contributing to minisign-rs.

**See also:**
- [README.md](../README.md) - Project overview
- [USAGE.md](USAGE.md) - Usage guide
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [TESTING.md](TESTING.md) - Testing guide

---

## Development Environment Setup

### Prerequisites

- Rust 1.93+ (edition 2024) - released January 2026
- Standard build tools (cargo)
- For testing: C minisign (optional): `brew install minisign`

### Building

```bash
# Build the project
cargo build --release

# Build without credential store (development)
cargo build --no-default-features

# Run the binary
./target/release/minisign_rs --help
```

## Before Committing

**These checks are mandatory - run in this exact order:**

```bash
# 1. Run clippy (pedantic mode)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 2. Format code (REQUIRED: Always run AFTER clippy, BEFORE commit)
cargo fmt

# 3. Run fast test suite (~9 seconds)
cargo test --no-default-features

# 4. Run slow security tests (~16 seconds)
cargo test --no-default-features -- --ignored
```

**Note:** `cargo fmt` MUST be the last formatting step before commit to ensure consistent style.

## Adding New Features

### Development Workflow

1. **Write tests first** - Define expected behavior with failing tests
2. **Implement incrementally** - Small, focused changes
3. **Verify compatibility** - Cross-test with C minisign when changing crypto or file formats
4. **Document public APIs** - Use rustdoc comments with examples

### Example TDD Workflow

```bash
# 1. Write failing test
vim tests/new_feature_test.rs

# 2. Run test to verify it fails
cargo test --no-default-features test_new_feature

# 3. Implement feature
vim src/ops/new_feature.rs

# 4. Run tests until they pass
cargo test --no-default-features

# 5. Run full suite
cargo test --no-default-features
cargo test --no-default-features -- --ignored

# 6. Commit
git add tests/new_feature_test.rs src/ops/new_feature.rs
git commit -m "feat: add new feature"
```

## Security Requirements

### Code Security Rules

- **Zero unsafe code** - No `unsafe` blocks allowed
- **Zeroize all secrets** - All secret material must use `#[derive(Zeroize, ZeroizeOnDrop)]`
- **No secret leakage** - No secret data in error messages or debug output
- **No unwrap/expect** - No `.unwrap()` or `.expect()` in production code paths (use `?` operator)
- **Constant-time comparisons** - All cryptographic comparisons must use `subtle::ConstantTimeEq`

### Example: Secure Secret Handling

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    #[zeroize(skip)]  // Don't zeroize metadata
    pub key_num: KeyNum,

    // This will be zeroized on drop
    secret_key: [u8; 64],
}
```

## Security Auditing

**Run periodically (weekly or before releases):**

```bash
cargo audit  # Check for known vulnerabilities in dependencies
```

**Install with:**
```bash
cargo install cargo-audit
```

**After dependency updates:**
1. Review changelogs for breaking changes
2. Update version in Cargo.toml
3. Run full test suite including slow tests
4. Run `cargo audit` to check for vulnerabilities

## Dependencies

### Crypto Dependencies (ONLY These)

- `ed25519-dalek` - Ed25519 signatures
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time comparisons

**Do not add other crypto libraries** without discussion. Use audited pure-Rust implementations only.

### Other Key Dependencies

> **Source of truth**: always check `Cargo.toml` and `Cargo.lock` for the current
> dependency list and pinned versions. This section is a human-readable summary only.

- `keyring` - OS credential store integration (macOS Keychain, Windows Credential Manager, Linux Secret Service) — optional, enabled by default via `credential_store` feature
- `pico-args` - Lightweight CLI argument parsing (no proc-macros)
- `rayon` - Parallel file operations — optional, enabled by default via `parallel` feature
- `thiserror` - Error type definitions
- `base64` - Base64 encoding/decoding
- `rand_core` - Cryptographic random number generation (OS entropy)
- `rpassword` - Secure password input
- `dirs` - Cross-platform directory discovery (home directory, config paths)

### Development Dependencies

- `assert_cmd` - CLI testing
- `predicates` - Test assertions
- `tempfile` - Temporary file handling
- `proptest` - Property-based testing
- `rand` - Random number generation for tests
- `hex` - Hex encoding for tests
- `serial_test` - Sequential test execution for credential store tests

## CI/CD

### GitHub Actions Workflows

Three workflows ensure code quality:

#### 1. **rust.yml** - Build and Test

Runs on every push:
- Builds on Linux, macOS, Windows
- Runs clippy pedantic checks
- Runs full test suite with timeout
- Verifies zero unsafe code
- Checks formatting with `cargo fmt --check`

#### 2. **miri.yml** - Memory Safety

Runs weekly and on every push:
- Uses Rust's Miri interpreter
- Detects undefined behavior
- Tests pure computation modules
- Verifies memory safety guarantees

#### 3. **release.yml** - Binary Releases

Triggers on version tags (`v*`):
- Builds for 6 targets:
  - Linux x86_64 (glibc and musl)
  - macOS x86_64 and ARM64
  - Windows x86_64 and ARM64
- Creates GitHub releases with checksums
- Strips binaries for minimal size
- Uploads artifacts

### Caching

All workflows use cargo caching for faster builds:
- Dependencies cached by Cargo.lock hash
- Build artifacts cached by rustc version
- Cache restored on every run

## Code Review

### What Reviewers Check

- **Security**: Proper zeroization, no secret leakage, constant-time operations
- **Testing**: All new code has tests, tests follow TDD principles
- **Compatibility**: Changes maintain C minisign file format compatibility
- **Style**: Code passes clippy pedantic, follows Rust conventions
- **Documentation**: Public APIs have rustdoc comments with examples

### Pre-Review Checklist

Before requesting review:
- [ ] All tests pass (fast and slow)
- [ ] Clippy passes with pedantic mode
- [ ] Code is formatted with `cargo fmt`
- [ ] Public APIs have documentation
- [ ] Security requirements followed
- [ ] C minisign compatibility verified (if applicable)

## Common Development Tasks

### Running Different Test Suites

```bash
# Fast tests only (development)
cargo test --no-default-features

# Slow security tests
cargo test --no-default-features -- --ignored

# All tests without credential store
cargo test --no-default-features && cargo test --no-default-features -- --ignored

# Use test runner script
./run_all_tests.sh

# Specific test
cargo test --no-default-features test_sign_verify_roundtrip

# With output
cargo test --no-default-features -- --nocapture
```

### Checking Code Quality

```bash
# Run clippy
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# Check formatting
cargo fmt -- --check

# Count lines of code
tokei rs/src rs/tests

# Check for unsafe code
rg "unsafe" src/
```

### Building for Different Platforms

```bash
# macOS ARM64
cargo build --release --target aarch64-apple-darwin

# Linux musl (static binary)
cargo build --release --target x86_64-unknown-linux-musl

# Windows
cargo build --release --target x86_64-pc-windows-gnu
```

## Performance Profiling

### Benchmarking

Use `hyperfine` for CLI benchmarking:

```bash
# Install hyperfine
brew install hyperfine

# Benchmark signing
hyperfine 'minisign_rs -S -m testfile.txt -W' \
          'minisign -S -m testfile.txt -W'

# Benchmark verification
hyperfine 'minisign_rs -V -m testfile.txt -p minisign.pub' \
          'minisign -V -m testfile.txt -p minisign.pub'
```

### Memory Profiling

```bash
# Check memory usage with Valgrind (Linux)
valgrind --tool=massif ./target/release/minisign_rs -S -m file.txt

# Check memory usage with Instruments (macOS)
instruments -t Allocations ./target/release/minisign_rs -S -m file.txt
```

## Troubleshooting

### Build Issues

**Issue**: Compilation fails with linker errors
**Fix**: Ensure you have the correct build tools:
```bash
# macOS
xcode-select --install

# Linux
sudo apt-get install build-essential
```

**Issue**: `scrypt` crate fails to build
**Fix**: This is a dependency issue. Try:
```bash
cargo clean
cargo update
cargo build
```

### Test Issues

**Issue**: Keychain popups during tests
**Fix**: Use `--no-default-features`:
```bash
cargo test --no-default-features
```

**Issue**: C minisign tests fail
**Fix**: Install C minisign:
```bash
brew install minisign  # macOS
sudo apt-get install minisign  # Linux
```

**Issue**: Tests timeout
**Fix**: Slow tests can take 15-30s. Increase timeout or run separately:
```bash
cargo test --no-default-features -- --ignored --test-threads=1
```

## Contributing Guidelines

### Commit Message Format

Use conventional commit format:

```
<type>: <description>
<type>(subsystem): <description>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or modifications
- `chore`: Maintenance tasks
- `refactor`: Code restructuring
- `perf`: Performance improvements
- `build`: Build system changes
- `ci`: CI/CD changes

**Examples:**
```
feat: add OCR text extraction from images
fix(paste): handle app activation timeout
docs: update README with new examples
test(monitor): add clipboard change detection tests
```

### Pull Request Process

1. Create feature branch from `lb_rust`
2. Implement changes with tests
3. Run full pre-commit checklist
4. Push and create PR
5. Address review feedback
6. Merge when approved

See [TESTING.md](TESTING.md) for complete testing guide.
