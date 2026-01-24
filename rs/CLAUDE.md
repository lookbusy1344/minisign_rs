# Minisign Rust Implementation - Development Guidelines

## Project Overview

This is a **security-critical** pure Rust rewrite of minisign. The implementation must maintain byte-level compatibility with the C version while adhering to the highest standards of Rust development and cryptographic engineering.

### Current Status (2026-01-24)

**Phase 7 Complete - Production Ready** - All implementation phases finished:

- ✅ **Crypto Layer**: Ed25519, Blake2b, Scrypt with pure Rust implementations
- ✅ **Data Structures**: Key files, signature files, all binary formats
- ✅ **Operations Module**: All 5 operations fully functional
  - `generate`: Create new keypairs with/without passwords
  - `sign`: Sign files with encrypted/unencrypted keys
  - `verify`: Verify signatures with C-generated compatibility
  - `recreate`: Recover public keys from secret keys
  - `change`: Add/remove/change passwords on keys
- ✅ **CLI Integration**: Complete command-line interface matching C minisign
- ✅ **Test Suite**: 159 total tests (107 unit + 16 CLI + 7 compatibility + 12 cross-binary + 6 edge cases + 11 slow), all passing
- ✅ **Code Quality**: Zero clippy pedantic warnings, ~5,100 lines, zero unsafe code
- ✅ **CI/CD**: Multi-platform releases, memory safety verification, cross-platform testing
- ✅ **Documentation**: COMPATIBILITY.md proves 100% C minisign compatibility

**Status**: Ready for production use

**Test Results**: 
- Fast tests: `cargo test` - 148 tests pass in ~9 seconds
- Slow tests: `cargo test -- --ignored` - 11 tests pass in ~16 seconds

### Phase 7 Deliverables (Completed 2026-01-24)

All Phase 7 requirements from the design document have been completed:

1. ✅ **Cross-platform CI** - Linux, macOS, Windows (`.github/workflows/rust.yml`)
2. ✅ **Release binaries** - Multi-platform builds (`.github/workflows/release.yml`)
   - Linux x86_64 (glibc and musl for maximum compatibility)
   - macOS x86_64 and ARM64 (Apple Silicon)
   - Windows x86_64
3. ✅ **README updates** - Reflects production-ready status
4. ✅ **COMPATIBILITY.md** - Comprehensive compatibility documentation
5. ✅ **Memory safety verification** - Miri checks (`.github/workflows/miri.yml`)
6. ✅ **Full test suite** - 134 tests passing on all platforms

**Performance**: Comparable to C minisign (scrypt KDF dominates timing in both)

## Core Principles

### 1. Pure Rust - Zero Unsafe Code

- **NO** `unsafe` blocks anywhere in the codebase
- **NO** FFI bindings to C libraries
- Use only audited, pure-Rust cryptographic libraries (RustCrypto ecosystem)
- All dependencies must be vetted for safety and security

### 2. Modern Rust Practices

- **Edition:** 2024 (latest stable)
- **MSRV:** 1.90+ (update yearly)
- Use modern idioms: `?` operator, `impl Trait`, const generics
- Leverage type system for correctness (newtype pattern for keys/signatures)
- Zero-copy parsing where possible
- Explicit lifetimes only when necessary
- **Avoid magic values:** Use named constants or enumerations instead of hardcoded numbers/strings

### 3. Test-Driven Development (TDD)

**This is non-negotiable for a security project.**

#### TDD Workflow

1. **Write the test first** - Define expected behavior before implementation
2. **Watch it fail** - Verify the test fails for the right reason
3. **Implement minimally** - Write just enough code to pass
4. **Refactor** - Improve code while keeping tests green
5. **Repeat** - Build incrementally with confidence

#### Test Requirements

- **Every function** must have unit tests in `#[cfg(test)]` modules
- **Every module** must achieve >90% code coverage
- **Property-based tests** for parsers and serializers (using `proptest`)
- **Integration tests** in `tests/` for end-to-end behavior
- **Compatibility tests** verifying interoperability with C minisign
- Fast tests must complete in under 15 seconds
- Slow tests should complete in under 30 seconds

#### Test Categories

```rust
#[cfg(test)]
mod tests {
    // Unit tests - test individual functions
    #[test]
    fn test_sign_verify_roundtrip() { }

    // Property tests - test invariants hold for random inputs
    #[proptest]
    fn prop_base64_roundtrip(data: Vec<u8>) { }

    // Edge cases - boundary conditions
    #[test]
    fn test_empty_file_signature() { }

    // Security tests - verify zeroization, constant-time ops
    #[test]
    fn test_secret_key_zeroized() { }
}
```

### 4. Security Standards

#### Memory Safety

- All secret material **MUST** use `#[derive(Zeroize, ZeroizeOnDrop)]`
- No secret data in error messages or debug output
- Use `#[derive(Debug)]` carefully - implement manual Debug for sensitive types
- Explicit scope limiting for sensitive operations

#### Constant-Time Operations

- All cryptographic comparisons must be constant-time
- Use `ed25519-dalek` (has constant-time guarantees)
- Use `subtle::ConstantTimeEq` for manual comparisons if needed

#### Error Handling

- Never unwrap on production code paths
- Use `Result<T>` and `?` operator consistently
- Errors must be actionable and informative (but not leak secrets)
- Use `thiserror` for library errors, `anyhow` for application errors

#### Pre-Commit Requirements

**ESSENTIAL - These steps are MANDATORY before committing any Rust code:**

1. **Format code:** `cargo fmt`
   - No exceptions - code must be formatted
   - Run automatically before every commit

2. **Run clippy with EXACT CI flags:** `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
   - **CRITICAL:** Running just `cargo clippy` is NOT sufficient - you MUST include ALL flags
   - This exact command matches the CI workflow (.github/workflows/rust.yml:56)
   - All warnings are errors in pedantic mode
   - Pedantic mode catches subtle issues (ignore_without_reason, unreadable_literal, uninlined_format_args, etc.)
   - Must pass with zero warnings before committing

3. **Run fast test suite:** `cargo test`
   - All 148 fast tests must pass (~9 seconds)
   - No skipped tests

4. **Run slow security tests:** `cargo test -- --ignored`
   - All 11 slow tests must pass (~16 seconds)
   - With performance improvements, these are now fast enough to run before every commit
   - Verifies production scrypt parameters work correctly

5. **Security audit:** `cargo audit` (if available)
   - Check for known vulnerabilities

6. **Manual verification:**
   - No `unsafe` blocks
   - No `.unwrap()` or `.expect()` in production code paths
   - No panics in production code paths

## Development Workflow

**⚠️ Before EVERY commit, you MUST run:**
```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo test                    # 148 fast tests (~9s)
cargo test -- --ignored       # 11 slow tests (~16s) - performance improved, run before committing
```
These commands match the CI workflow exactly (.github/workflows/rust.yml). Running just `cargo clippy` is insufficient.

**Note:** Slow tests now complete in ~16 seconds thanks to performance improvements. They should be run before every commit to verify production scrypt parameters work correctly.

**CI Workflows:**
- **rust.yml**: Runs on every push - builds, clippy, tests on Linux/macOS/Windows
- **miri.yml**: Weekly + on push - memory safety verification with Rust's Miri
- **release.yml**: On version tags - builds multi-platform release binaries

### Adding New Features

1. **Read the design doc** (`docs/plans/2026-01-23-rust-rewrite-design.md`)
2. **Write tests first** - Define expected behavior
3. **Implement incrementally** - One function at a time
4. **Verify compatibility** - Cross-test with C minisign
5. **Document** - Add doc comments for public APIs

### Testing Strategy

```bash
# Run fast tests (148 tests: 107 unit + 16 CLI + 7 compatibility + 12 cross-binary + 6 edge cases)
cargo test                          # ~9 seconds

# Run slow security tests (11 tests marked #[ignore])
cargo test -- --ignored             # ~16 seconds

# Run ALL tests (159 total)
cargo test && cargo test -- --ignored    # ~25 seconds

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run only unit tests
cargo test --lib

# Run only CLI integration tests
cargo test --test cli_test

# Run only compatibility tests
cargo test --test compatibility

# Run with coverage (if tarpaulin installed)
cargo tarpaulin --out Html

# Check for issues (REQUIRED before commit - must match CI exactly)
cargo fmt
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# Memory safety check (requires nightly Rust)
cargo +nightly miri test --lib
```

### Scrypt Testing Strategy

**Problem:** Scrypt with production parameters (N=2^20) takes 1-5 seconds per operation, making tests slow.

**Solution:** Dual testing approach for encrypted key operations:

1. **Fast Tests (N=2^14, ~50ms per operation)** - Run by default in CI
   - 148 tests covering logic and encryption/decryption flow
   - Use weaker scrypt parameters for speed
   - Example: `test_generate_encrypted_key_fast()`
   - Complete in ~9 seconds total
   - Verify correctness without security overhead

2. **Slow Tests (N=2^20, ~1-5s per operation)** - Marked with `#[ignore]`
   - 11 tests with production-strength scrypt parameters
   - Verify full security properties
   - Example: `test_generate_encrypted_key()`
   - Complete in ~16 seconds total (performance improved!)
   - **Should be run before every commit** - now fast enough

**Rationale:**
- Scrypt is **intentionally slow** as a security feature (memory-hard KDF)
- N=2^20 uses ~128MB RAM and makes brute-force attacks prohibitive
- Fast tests give rapid feedback during development
- Slow tests ensure security parameters work correctly

**When to run slow tests:**
```bash
# Before EVERY commit (performance improved - only ~16 seconds)
cargo test -- --ignored

# Run all tests together (~25 seconds total)
cargo test && cargo test -- --ignored
```

**Performance Note:** Recent optimizations have improved slow test performance significantly. What previously took 1-5 seconds per operation now completes the entire 11-test suite in ~16 seconds. This makes it practical to run slow tests before every commit, ensuring production scrypt parameters are always verified.

**Test fixture strategy:**
- C-generated fixtures in `tests/fixtures/keys/test.key` use N=2^20
- Compatibility tests verify we can decrypt these (marked `#[ignore]`)
- Fast variants generate their own keys with N=2^14

### Compatibility Testing

**Prerequisites:**
- The C implementation of minisign must be installed as a binary package on the development machine
- Verify installation: `minisign -v`
- This is used for cross-compatibility testing to ensure Rust behavior matches C exactly

**Current Compatibility Status:**
- ✅ **100% compatible** - See COMPATIBILITY.md for full documentation
- ✅ All file formats byte-identical (verified with 5 compatibility tests)
- ✅ Keys and signatures fully interchangeable between implementations
- ✅ All CLI flags and behaviors match exactly

After implementing any cryptographic operation:

1. Generate test vectors with C minisign
2. Verify Rust implementation matches byte-for-byte
3. Cross-verify: Rust signs → C verifies, C signs → Rust verifies
4. Document any behavioral differences in `COMPATIBILITY.md` (currently: none!)

## Code Organization

### Module Structure

```
src/
├── lib.rs          # Public API, re-exports
├── main.rs         # CLI entry point (complete)
├── errors.rs       # Error types (thiserror)
├── formats.rs      # Base64, binary serialization
├── crypto.rs       # Cryptographic primitives
├── keys.rs         # Key structures and operations
├── signature.rs    # Signature structures
├── cli.rs          # Clap command-line interface (complete)
└── ops/            # High-level operations
    ├── mod.rs      # Module exports
    ├── generate.rs # Key generation
    ├── sign.rs     # File signing
    ├── verify.rs   # Signature verification
    ├── recreate.rs # Public key recovery
    └── change.rs   # Password management

tests/
├── cli_test.rs         # CLI integration tests (15 tests)
└── compatibility.rs    # C minisign compatibility (5 tests)
```

### Type Safety Patterns

Use newtype wrappers for domain types:

```rust
// Good: Type-safe, impossible to mix up
pub struct PublicKey([u8; 32]);
pub struct SecretKey([u8; 64]);
pub struct Signature([u8; 64]);

// Bad: Easy to mix up parameters
fn verify(pk: &[u8], sig: &[u8], msg: &[u8]) -> bool
```

### Documentation Standards

Every public item needs documentation:

```rust
/// Signs a message with a secret key
///
/// # Arguments
///
/// * `secret_key` - The Ed25519 secret key
/// * `message` - The message to sign
///
/// # Returns
///
/// A 64-byte Ed25519 signature
///
/// # Errors
///
/// Returns `Error::InvalidKey` if the key is malformed
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature>
```

## Common Patterns

### Error Propagation

```rust
// Good: Use ? operator
pub fn load_key(path: &Path) -> Result<PublicKey> {
    let contents = fs::read(path)
        .map_err(|e| Error::file_read(path, e))?;
    parse_key(&contents)?
}

// Bad: Manual unwrapping
pub fn load_key(path: &Path) -> Result<PublicKey> {
    let contents = fs::read(path).expect("file read failed");
    parse_key(&contents).unwrap()
}
```

### Testing Private Functions

```rust
// Prefer testing through public API, but if needed:
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_helper() {
        // Test internal functions here
        assert_eq!(internal_fn(), expected);
    }
}
```

## Performance Considerations

- **Correctness first, performance second** - This is a security tool
- Profile before optimizing - use `cargo bench` with criterion
- Avoid premature optimization - clarity is more important
- Document any performance-critical sections

## Dependencies Policy

### Adding Dependencies

Before adding a new dependency:

1. Check it's maintained (recent commits)
2. Verify it's audited (check RustSec)
3. Prefer pure-Rust implementations
4. Consider transitive dependencies
5. Check for `unsafe` usage in the dependency

### Allowed Cryptographic Libraries

- `ed25519-dalek` - Ed25519 signatures
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation
- `rand` - Random number generation
- `zeroize` - Memory zeroization

**Do not** use other cryptographic libraries without explicit approval.

## Commit Message Format

Follow conventional commits as specified in the global CLAUDE.md:

```
feat(crypto): implement Ed25519 signing
test(formats): add property tests for base64
fix(keys): correct checksum validation logic
```

## Release Checklist

Before any release:

- [x] All tests pass on Linux, macOS, Windows (CI enforced)
- [x] Cargo clippy passes with no warnings (CI enforced)
- [x] Compatibility tests pass with C minisign (5 tests passing)
- [x] Documentation is up to date (README.md, COMPATIBILITY.md)
- [ ] CHANGELOG updated (for next release)
- [x] Security audit completed (Miri runs weekly, zero unsafe code)
- [ ] Performance benchmarks run (optional - comparable to C)

**Automated via CI:**
- Release workflow builds binaries for all platforms on version tags
- Miri checks memory safety weekly and on every push
- All tests run on Linux, macOS, Windows for every commit

## Documentation Files

The project includes comprehensive documentation:

- **README.md** - User-facing documentation, installation, usage, project status
- **COMPATIBILITY.md** - Detailed compatibility analysis with C minisign
  - File format compatibility verification
  - Cross-platform testing results
  - Migration guide (none needed!)
  - Performance comparison
- **CLAUDE.md** (this file) - Development guidelines for contributors
- **Design Document** (`../docs/plans/2026-01-23-rust-rewrite-design.md`) - Implementation plan

All documentation should be kept in sync when making significant changes.

## When in Doubt

1. **Read the design doc** - It has the answers
2. **Check COMPATIBILITY.md** - Understand how we maintain C compatibility
3. **Look at the C implementation** - Match its behavior
4. **Write a test** - Clarify expected behavior
5. **Ask for review** - Security is too important to guess

---

**Remember:** This is a security tool. A single mistake can compromise user data. Take your time, write tests, and verify everything.
