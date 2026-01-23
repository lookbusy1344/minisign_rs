# Minisign Rust Implementation - Development Guidelines

## Project Overview

This is a **security-critical** pure Rust rewrite of minisign. The implementation must maintain byte-level compatibility with the C version while adhering to the highest standards of Rust development and cryptographic engineering.

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
- All tests must run with `gtimeout 120 cargo test`

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

2. **Run clippy with strict lints:** `cargo clippy --color=always -- -D clippy::all -D clippy::pedantic`
   - All warnings are errors
   - Pedantic mode catches subtle issues
   - Must pass with zero warnings

3. **Run full test suite:** `gtimeout 120 cargo test`
   - All tests must pass
   - No skipped tests

4. **Security audit:** `cargo audit` (if available)
   - Check for known vulnerabilities

5. **Manual verification:**
   - No `unsafe` blocks
   - No `.unwrap()` or `.expect()` in production code paths
   - No panics in production code paths

## Development Workflow

### Adding New Features

1. **Read the design doc** (`docs/plans/2026-01-23-rust-rewrite-design.md`)
2. **Write tests first** - Define expected behavior
3. **Implement incrementally** - One function at a time
4. **Verify compatibility** - Cross-test with C minisign
5. **Document** - Add doc comments for public APIs

### Testing Strategy

```bash
# Run all tests
gtimeout 120 cargo test

# Run tests with output
gtimeout 120 cargo test -- --nocapture

# Run specific test
gtimeout 120 cargo test test_name

# Run with coverage (if tarpaulin installed)
cargo tarpaulin --out Html

# Check for issues (REQUIRED before commit)
cargo fmt
cargo clippy --color=always -- -D clippy::all -D clippy::pedantic
```

### Compatibility Testing

After implementing any cryptographic operation:

1. Generate test vectors with C minisign
2. Verify Rust implementation matches byte-for-byte
3. Cross-verify: Rust signs → C verifies, C signs → Rust verifies
4. Document any behavioral differences in `COMPATIBILITY.md`

## Code Organization

### Module Structure

```
src/
├── lib.rs          # Public API, re-exports
├── main.rs         # CLI entry point
├── errors.rs       # Error types (thiserror)
├── formats.rs      # Base64, binary serialization
├── crypto.rs       # Cryptographic primitives
├── keys.rs         # Key structures and operations
├── signature.rs    # Signature structures
└── cli.rs          # Clap command-line interface
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

- [ ] All tests pass on Linux, macOS, Windows
- [ ] Cargo clippy passes with no warnings
- [ ] Compatibility tests pass with C minisign
- [ ] Documentation is up to date
- [ ] CHANGELOG updated
- [ ] Security audit completed
- [ ] Performance benchmarks run

## When in Doubt

1. **Read the design doc** - It has the answers
2. **Look at the C implementation** - Match its behavior
3. **Write a test** - Clarify expected behavior
4. **Ask for review** - Security is too important to guess

---

**Remember:** This is a security tool. A single mistake can compromise user data. Take your time, write tests, and verify everything.
