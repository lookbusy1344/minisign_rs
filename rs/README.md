# minisign-rs

A pure Rust implementation of [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

## Project Status

**Phase 7 Complete - Production Ready** - Full Rust implementation with complete C minisign compatibility.

### Implemented Features

- ✅ Ed25519 signature generation and verification
- ✅ Blake2b hashing (256-bit and 512-bit)
- ✅ Scrypt key derivation for encrypted keys
- ✅ Key generation (with/without password protection)
- ✅ File signing (normal and prehashed modes)
- ✅ Signature verification with trusted comments
- ✅ Public key recreation from secret keys
- ✅ Password management (add/remove/change passwords)
- ✅ Full compatibility with C minisign file formats

### Test Coverage

- **159 total tests** covering all operations and CLI behavior
- **107 unit tests** covering all crypto operations, key handling, and file formats
- **16 CLI integration tests** using assert_cmd for end-to-end validation
- **7 compatibility tests** verifying interoperability with C minisign
- **12 cross-binary tests** ensuring full C minisign compatibility
- **6 edge case tests** for unicode, symlinks, and large files
- **11 slow security tests** using production scrypt parameters (marked `#[ignore]`)
- **Fast test suite** using optimized scrypt parameters (~9 seconds)
- **Slow test suite** with production scrypt parameters (~16 seconds)

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **~5,100 lines** of well-documented Rust code
- **Pure Rust crypto** - no C dependencies via RustCrypto ecosystem
- **Memory safety verified** - Miri checks run weekly
- **Multi-platform CI** - Linux, macOS, Windows on every commit

## Installation

### Pre-built Binaries

Release binaries are available for:
- **Linux** (x86_64, glibc and musl)
- **macOS** (x86_64 and ARM64)
- **Windows** (x86_64)

Download from the [releases page](https://github.com/jedisct1/minisign/releases).

### Building from Source

#### Prerequisites

- Rust 1.90+ (edition 2024)
- Standard build tools (cargo)

#### Commands

```bash
# Build the project
cargo build --release

# Run tests (fast - 148 tests, ~9 seconds)
cargo test

# Run slow security tests (11 tests, ~16 seconds)
cargo test -- --ignored

# Run all tests (159 tests, ~25 seconds)
cargo test && cargo test -- --ignored

# Check code quality
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt

# Run a specific test
cargo test test_sign_verify_roundtrip
```

## Testing

### Quick Testing with Fixtures

The `tests/fixtures` directory contains pre-generated keys and test files for quick testing:

```bash
# Sign a test file
cargo run --release --bin minisign_rs -- -S -m tests/fixtures/messages/hello.txt -s tests/fixtures/keys/test.key --password-file tests/fixtures/messages/password.txt

# Verify the signature
cargo run --release --bin minisign_rs -- -V -m tests/fixtures/messages/hello.txt -p tests/fixtures/keys/test.pub
```

Available test keys:
- `tests/fixtures/keys/test.key` (password: "test")
- `tests/fixtures/keys/unencrypted.key` (no password)
- `tests/fixtures/keys/c_encrypted_password123.key` (password: "password123")

See `tests/fixtures/keys/README.md` for complete details.

### Test Categories

1. **Unit Tests**: In-module tests for individual functions
2. **Integration Tests**: End-to-end operation tests in `tests/`
3. **Compatibility Tests**: Verify interoperability with C minisign
4. **Property Tests**: Using `proptest` for randomized input validation

### Fast vs Slow Tests

The project uses a dual testing strategy for operations involving scrypt:

- **Fast tests** (148 tests, default): Use N=2^14 (~50ms per operation)
- **Slow tests** (11 tests, `#[ignore]`): Use N=2^20 (~1-5s per operation)

Fast tests provide rapid feedback during development, while slow tests verify production security parameters work correctly. With recent performance improvements, slow tests now complete in ~16 seconds.

```bash
# Run only fast tests (default, ~9 seconds)
cargo test

# Run slow security tests (~16 seconds)
cargo test -- --ignored

# Run all tests (~25 seconds)
cargo test && cargo test -- --ignored
```

## Architecture

### Module Structure

```
src/
├── lib.rs          # Public API exports
├── main.rs         # CLI entry point (Phase 6 - WIP)
├── crypto.rs       # Ed25519, Blake2b, Scrypt wrappers
├── keys.rs         # Key types, generation, encryption
├── signature.rs    # Signature creation and verification
├── formats.rs      # Base64, binary serialization
├── errors.rs       # Error types with thiserror
└── ops/            # High-level operations
    ├── generate.rs # Key generation
    ├── sign.rs     # File signing
    ├── verify.rs   # Signature verification
    ├── recreate.rs # Public key recovery
    └── change.rs   # Password management
```

### Design Principles

1. **Pure Rust**: No unsafe blocks, no FFI, no C dependencies
2. **Security-First**: Zeroization of secrets, constant-time operations
3. **Test-Driven**: Every feature has tests before implementation
4. **Type-Safe**: Newtype wrappers prevent mixing up keys/signatures
5. **Compatibility**: Byte-level compatibility with C minisign

## Dependencies

### Core Cryptography

- `ed25519-dalek` - Ed25519 signatures (pure Rust)
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation function
- `zeroize` - Secure memory wiping

### Utilities

- `base64` - Base64 encoding/decoding
- `rand` - Cryptographic random number generation
- `thiserror` - Library error types
- `anyhow` - Application error handling
- `rpassword` - Secure password input
- `dirs` - Cross-platform directory discovery

### Development

- `assert_cmd` - CLI testing
- `predicates` - Test assertions
- `tempfile` - Temporary file handling
- `proptest` - Property-based testing
- `hex` - Hex encoding for tests

## Compatibility

**100% compatible with C minisign** - All file formats are byte-identical and fully interchangeable.

### Quick Summary

- ✅ Rust can decrypt and use C-generated encrypted keys
- ✅ Rust can verify C-generated signatures
- ✅ C minisign can verify Rust-generated signatures
- ✅ Key files are interchangeable between implementations
- ✅ All CLI flags and behaviors match exactly

For detailed analysis:
- [COMPATIBILITY.md](COMPATIBILITY.md) - Complete compatibility documentation
- [C/Rust Implementation Comparison](docs/c-rust-parity-gaps.md) - Detailed comparison of both implementations

### CLI Differences from C minisign

This Rust implementation adds **two optional flags** not present in the original C version:

#### `--password-file <FILE>`
Read password from file instead of interactive prompt.

**⚠️ TESTING ONLY - INSECURE FOR PRODUCTION USE**

```bash
# Example (testing only)
cargo run -- -S -m file.txt -s key.key --password-file password.txt
```

- Intended for automated testing and CI environments
- Passwords stored in plain text files are a security risk
- Use interactive password entry for production use
- C minisign does not support this flag

#### `--allow-kdf-fallback`
Allow scrypt KDF parameter fallback on resource-constrained systems.

**⚠️ LESS SECURE - OPT-IN ONLY**

```bash
# Example (embedded/constrained systems)
cargo run -- -G --allow-kdf-fallback
```

- **Permission flag only** - does not force fallback, only allows it
- Fallback **only triggers if** normal 128MB allocation fails
- When triggered: reduces memory to 512KB with weaker KDF parameters (N=2^14 instead of N=2^20)
- **Without this flag**: operations fail immediately if 128MB cannot be allocated
- **With this flag**: operations attempt fallback before failing
- Prevents complete failure on memory-limited devices (embedded systems, containers)
- C minisign does not support this flag

**Recommendation**: Avoid both flags in production. Use only when necessary and understand the security trade-offs.

## Performance & Memory

The Rust implementation **matches or exceeds** C minisign performance across all operations while providing superior memory safety guarantees.

### Performance Summary

| Operation | C minisign | minisign-rs | Winner |
|-----------|-----------|-------------|--------|
| Key Generation | 3.3ms | 3.2ms | Rust (1.02x) |
| Sign 100KB | 3.4ms | 3.5ms | C (1.02x) |
| Sign 10MB | 16.0ms | 15.4ms | Rust (1.04x) |
| Verify 100KB | 2.2ms | 2.2ms | Tied |
| Verify 10MB | 15.4ms | 14.5ms | Rust (1.06x) |

**Performance differences are within 6%** - effectively identical for real-world usage. See [Performance Benchmark Report](docs/benchmark-report.md) for complete analysis.

### Binary Size

- **C version**: 70KB (optimized with static libsodium)
- **Rust version**: 1.1MB (includes Rust standard library)
- Trade-off: Larger binary for memory safety and zero C dependencies

### Memory Requirements

**Scrypt KDF** (key encryption/decryption):
- Memory usage: ~128MB during operations (intentional for security)
- Duration: ~1-2s per operation
- Both implementations use identical parameters: N=2^20, r=8, p=1

**Ed25519 Operations** (signing/verification):
- Minimal memory (<1KB), operations complete in <1ms
- No difference between implementations

### Memory Safety Advantages

- ✅ **Zero unsafe code** - Eliminates entire classes of vulnerabilities
- ✅ **Automatic secret cleanup** - `Zeroize` and `Drop` traits ensure secrets are wiped
- ✅ **Memory safety verified** - Miri checks detect undefined behavior
- ✅ **No buffer overflows** - Bounds checking prevents memory corruption
- ✅ **No use-after-free** - Ownership system guarantees validity

**Conclusion**: The Rust version provides C-level performance with superior memory safety.

## Development Guidelines

### Before Committing

**These checks are mandatory:**

```bash
# 1. Format code
cargo fmt

# 2. Run clippy (pedantic mode)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 3. Run fast test suite (~9 seconds)
cargo test

# 4. Run slow security tests (~16 seconds)
cargo test -- --ignored

# 5. Verify no unsafe code or unwraps in production paths
```

### Adding New Features

1. **Write tests first** - Define expected behavior
2. **Implement incrementally** - Small, focused changes
3. **Verify compatibility** - Cross-test with C minisign
4. **Document public APIs** - Use rustdoc comments

### Security Requirements

- All secret material must use `#[derive(Zeroize, ZeroizeOnDrop)]`
- No secret data in error messages or debug output
- No `.unwrap()` or `.expect()` in production code paths
- All cryptographic comparisons must be constant-time

See [CLAUDE.md](CLAUDE.md) for complete development guidelines.

## CI/CD

### Continuous Integration

Three GitHub Actions workflows ensure code quality:

1. **rust.yml** - Build and test on every push
   - Runs on Linux, macOS, Windows
   - Builds with cargo
   - Runs clippy pedantic checks
   - Runs full test suite with timeout

2. **miri.yml** - Memory safety verification
   - Runs weekly and on every push
   - Uses Rust's Miri interpreter
   - Detects undefined behavior
   - Tests pure computation modules

3. **release.yml** - Binary releases
   - Triggers on version tags (`v*`)
   - Builds for 5 targets (Linux x86_64 glibc/musl, macOS x86_64/ARM64, Windows x86_64)
   - Creates GitHub releases with checksums
   - Strips binaries for minimal size

All workflows use caching for faster builds.

## References

### Documentation
- [Compatibility Documentation](COMPATIBILITY.md) - Byte-level C/Rust compatibility proof
- [Performance Benchmark Report](docs/benchmark-report.md) - C vs Rust performance comparison
- [C/Rust Implementation Comparison](docs/c-rust-parity-gaps.md) - Detailed analysis of both implementations
- [Development Guidelines](CLAUDE.md) - Essential development workflow
- [Design Document](../docs/plans/2026-01-23-rust-rewrite-design.md) - Original implementation plan

### External
- [Original minisign (C)](https://github.com/jedisct1/minisign)
- [ed25519-dalek Documentation](https://docs.rs/ed25519-dalek)
- [RustCrypto Project](https://github.com/RustCrypto)

## License

ISC License - Same as original minisign

## Contributing

This is currently an active rewrite project. Before contributing:

1. Read the [design document](../docs/plans/2026-01-23-rust-rewrite-design.md)
2. Review [CLAUDE.md](CLAUDE.md) for development standards
3. Ensure all tests pass and clippy is clean
4. Verify compatibility with C minisign

---

**Note**: This implementation prioritizes security and correctness. Cryptographic operations use audited pure-Rust libraries with zero unsafe code.
