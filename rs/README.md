# minisign-rs

A pure Rust implementation of [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

## Project Status

**Phase 5 Complete** - Core library implementation finished, CLI integration in progress.

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

- **94 unit tests** covering all crypto operations, key handling, and file formats
- **5 compatibility tests** verifying interoperability with C minisign
- **Fast test suite** using optimized scrypt parameters (~6 seconds)
- **Slow security tests** using production scrypt parameters (marked `#[ignore]`)

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **~4,464 lines** of well-documented Rust code
- **Pure Rust crypto** - no C dependencies via RustCrypto ecosystem

## Building

### Prerequisites

- Rust 1.90+ (edition 2024)
- Standard build tools (cargo)

### Commands

```bash
# Build the project
cargo build --release

# Run tests (fast)
gtimeout 60 cargo test

# Run tests including slow security tests
gtimeout 120 cargo test -- --ignored

# Check code quality
cargo fmt --check
cargo clippy -- -D clippy::all -D clippy::pedantic

# Run a specific test
cargo test test_sign_verify_roundtrip
```

## Testing

### Test Categories

1. **Unit Tests**: In-module tests for individual functions
2. **Integration Tests**: End-to-end operation tests in `tests/`
3. **Compatibility Tests**: Verify interoperability with C minisign
4. **Property Tests**: Using `proptest` for randomized input validation

### Fast vs Slow Tests

The project uses a dual testing strategy for operations involving scrypt:

- **Fast tests** (default): Use N=2^14 (~50ms per operation)
- **Slow tests** (`#[ignore]`): Use N=2^20 (~1-5s per operation)

Fast tests provide rapid feedback during development, while slow tests ensure production security parameters work correctly.

```bash
# Run only fast tests (default)
cargo test

# Run slow security tests
cargo test -- --ignored --nocapture
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

### File Formats

All file formats are byte-identical to C minisign:

- **Secret keys** (`.key`): 158-byte encrypted or plaintext format
- **Public keys** (`.pub`): 42-byte format with keynum
- **Signatures** (`.minisig`): 74-byte signature + trusted comment + global signature

### Verified Interoperability

- ✅ Rust can decrypt and use C-generated encrypted keys
- ✅ Rust can verify C-generated signatures
- ✅ C minisign can verify Rust-generated signatures (tested)
- ✅ Key files are interchangeable between implementations

### Test Fixtures

Compatibility tests use C-generated test fixtures:

- `tests/fixtures/keys/test.key` - Encrypted key (password: "test")
- `tests/fixtures/keys/test.pub` - Corresponding public key
- `tests/fixtures/signatures/` - Various C-generated signatures

## Development Guidelines

### Before Committing

**These checks are mandatory:**

```bash
# 1. Format code
cargo fmt

# 2. Run clippy (pedantic mode)
cargo clippy -- -D clippy::all -D clippy::pedantic

# 3. Run full test suite
gtimeout 60 cargo test

# 4. Verify no unsafe code or unwraps in production paths
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

## References

- [Original minisign (C)](https://github.com/jedisct1/minisign)
- [Design Document](../docs/plans/2026-01-23-rust-rewrite-design.md)
- [Development Guidelines](CLAUDE.md)
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

**Note**: This implementation prioritizes security and correctness over performance. Cryptographic operations use audited pure-Rust libraries with no unsafe code.
