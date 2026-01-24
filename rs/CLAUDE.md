# Minisign Rust Implementation - Development Guidelines

## Project Overview

Security-critical pure Rust rewrite of minisign. Must maintain byte-level compatibility with C version. Zero unsafe code. Production ready.

## Pre-Commit Requirements (MANDATORY)

```bash
# 1. Format code
cargo fmt

# 2. Run clippy with EXACT CI flags (do NOT skip flags)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 3. Run fast test suite (148 tests, ~9 seconds)
cargo test

# 4. Run slow security tests (11 tests, ~16 seconds)
cargo test -- --ignored

# 5. Verify manually:
#    - No unsafe blocks
#    - No .unwrap()/.expect() in production code paths
#    - No panics in production code paths
```

**Note:** Slow tests now fast enough (~16s) to run before every commit. They verify production scrypt parameters (N=2^20) work correctly.

## Core Principles

### 1. Pure Rust - Zero Unsafe Code
- **NO** `unsafe` blocks anywhere
- **NO** FFI bindings to C libraries
- Use only audited, pure-Rust crypto libraries (RustCrypto ecosystem)

### 2. Modern Rust (Edition 2024, MSRV 1.90+)
- Use `?` operator, `impl Trait`, const generics
- Newtype pattern for keys/signatures (type safety)
- Explicit lifetimes only when necessary
- Named constants over magic values

### 3. Test-Driven Development (TDD Required)

**Use TDD for all changes** - This is non-negotiable for a security project:

1. **Write the test first** - Define expected behavior before implementing
2. **Watch it fail** - Verify test fails for the right reason
3. **Implement minimally** - Write just enough code to pass
4. **Refactor** - Improve code while keeping tests green
5. **Repeat** - Build incrementally with confidence

Requirements:
- Every function must have unit tests in `#[cfg(test)]` modules
- >90% code coverage per module
- Property-based tests for parsers/serializers (proptest)
- Integration tests in `tests/` for end-to-end behavior

### 4. Security Standards

**Memory Safety:**
- All secret material **MUST** use `#[derive(Zeroize, ZeroizeOnDrop)]`
- No secret data in error messages or debug output
- Implement manual `Debug` for sensitive types (don't derive)

**Constant-Time Operations:**
- Use `ed25519-dalek` (has constant-time guarantees)
- Use `subtle::ConstantTimeEq` for manual comparisons

**Error Handling:**
- Never unwrap on production code paths
- Use `Result<T>` and `?` operator consistently
- Errors must be actionable but not leak secrets
- Use `thiserror` for library errors, `anyhow` for application errors

## Testing Strategy

### Test Commands

```bash
# Fast tests (148 tests: 107 unit + 16 CLI + 7 compat + 12 cross + 6 edge)
cargo test                          # ~9 seconds

# Slow security tests (11 tests with production scrypt N=2^20)
cargo test -- --ignored             # ~16 seconds

# All tests (159 total)
cargo test && cargo test -- --ignored    # ~25 seconds

# Specific test
cargo test test_name

# Only unit tests
cargo test --lib

# Only integration tests
cargo test --test cli_test

# Memory safety check (requires nightly)
cargo +nightly miri test --lib
```

### Scrypt Testing Strategy

**Problem:** Scrypt with N=2^20 (production params) takes ~1-5s per operation.

**Solution:**
1. **Fast Tests (N=2^14)** - Default, 148 tests, verify logic in ~9s
2. **Slow Tests (N=2^20)** - Marked `#[ignore]`, 11 tests, verify production params in ~16s

**Run both before every commit** - slow tests are now fast enough (~16s) thanks to performance improvements.

### Compatibility Testing

**Prerequisites:** C minisign must be installed (`minisign -v` to verify).

Cross-test after any crypto operation:
1. Generate test vectors with C minisign
2. Verify Rust matches byte-for-byte
3. Cross-verify: Rust signs → C verifies, C signs → Rust verifies
4. Document differences in `COMPATIBILITY.md` (currently: none!)

## Project Structure

```
src/
├── lib.rs          # Public API
├── main.rs         # CLI entry point
├── cli.rs          # Clap command-line interface
├── errors.rs       # Error types (thiserror)
├── formats.rs      # Base64, binary serialization
├── crypto.rs       # Ed25519, Blake2b, Scrypt wrappers
├── keys.rs         # Key types, generation, encryption
├── signature.rs    # Signature creation/verification
└── ops/            # High-level operations
    ├── generate.rs # Key generation
    ├── sign.rs     # File signing
    ├── verify.rs   # Signature verification
    ├── recreate.rs # Public key recovery
    └── change.rs   # Password management

tests/
├── cli_test.rs         # CLI integration tests
├── compatibility.rs    # C minisign compatibility
├── cross_binary_test.rs # Cross-binary tests
└── edge_cases.rs       # Edge case tests
```

## Dependencies

### Cryptographic Libraries (Vetted Only)
- `ed25519-dalek` - Ed25519 signatures
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation
- `rand` - Random number generation
- `zeroize` - Memory zeroization
- `subtle` - Constant-time operations

**Do not** add other crypto libraries without explicit approval.

### Adding Dependencies

Before adding any dependency:
1. Check it's actively maintained (recent commits)
2. Verify it's audited (check RustSec)
3. Prefer pure-Rust implementations
4. Consider transitive dependencies
5. Check for `unsafe` usage

## CI/CD

### Workflows
- **rust.yml** - Every push: build, clippy pedantic, tests on Linux/macOS/Windows
- **miri.yml** - Weekly + on push: memory safety verification
- **release.yml** - On version tags: multi-platform release binaries

All workflows use exact same clippy flags as pre-commit requirements.

## Quick Reference

**Build:** `cargo build --release`  
**Format:** `cargo fmt`  
**Clippy:** `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`  
**Fast tests:** `cargo test`  
**Slow tests:** `cargo test -- --ignored`  
**All tests:** `cargo test && cargo test -- --ignored`

**Documentation:**
- `README.md` - User-facing docs, installation, usage
- `COMPATIBILITY.md` - Detailed C minisign compatibility proof
- `CLAUDE.md` (this file) - Essential dev guidelines
- `docs/2026-01-23-rust-rewrite-design.md` - Implementation plan

---

**Remember:** This is a security tool. A single mistake can compromise user data. Take your time, write tests, and verify everything.
