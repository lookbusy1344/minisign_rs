# minisign-rs

[![Rust CI](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml)
[![CodeQL scan](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml)
[![Coverage](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml)
[![Slow Tests](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml)

A pure Rust implementation of the classic C project [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

We aim for 100% compatibility with the C/Zig version, with a few extra switches for enhanced security and usability.

## Project Status

**Version 1.0.0 Release** - Production-ready Rust implementation with complete C minisign compatibility.

### Implemented Features

- ✅ Ed25519 signature generation and verification
- ✅ Blake2b hashing (256-bit and 512-bit)
- ✅ Scrypt key derivation for encrypted keys
- ✅ Key generation (with/without password protection)
- ✅ File signing (normal and prehashed modes)
- ✅ Signature verification with trusted comments
- ✅ Public key recreation from secret keys
- ✅ Password management (add/remove/change passwords)
- ✅ Key security inspection (KDF parameter auditing)
- ✅ Weak key detection with persistent warnings
- ✅ Full compatibility with C minisign file formats

### Test Coverage

- **366 total tests** covering all operations and CLI behavior
- Comprehensive unit tests covering all crypto operations, key handling, and file formats
- CLI integration tests using assert_cmd for end-to-end validation
- Compatibility tests verifying interoperability with C minisign
- Cross-binary tests ensuring full C minisign compatibility
- Edge case tests for unicode, symlinks, and large files
- Fuzzing tests using proptest for property-based testing
- Concurrent access tests for multi-process safety
- **11 slow security tests** using production scrypt parameters (marked `#[ignore]`)
- **Fast test suite** (355 tests) using optimized scrypt parameters (~10 seconds)
- **Slow test suite** (11 tests) with production scrypt parameters (~11 seconds)

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **9,647 lines** of well-documented Rust code (13,921 total with comments)
- **Pure Rust crypto** - no C dependencies via RustCrypto ecosystem
- **Memory safety verified** - Miri checks run weekly
- **Multi-platform CI** - Linux, macOS, Windows on every commit

## Installation

### Pre-built Binaries

Release binaries are available for:
- **Linux** (x86_64, glibc and musl)
- **macOS** (x86_64 and ARM64)
- **Windows** (x86_64 and ARM64)

### Building from Source

#### Prerequisites

- Rust 1.93+ (edition 2024) - released January 2026
- Standard build tools (cargo)

**For testing (optional):**
- Original C minisign (for compatibility tests): `brew install minisign`
- All tests except compatibility tests will run without C minisign installed

#### Commands

```bash
# Build the project
cargo build --release

# Run tests (fast - 355 tests, ~10 seconds)
cargo test

# Run slow security tests (11 tests, ~11 seconds)
cargo test -- --ignored

# Run all tests (366 tests, ~21 seconds)
cargo test && cargo test -- --ignored

# Check code quality
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt

# Run a specific test
cargo test test_sign_verify_roundtrip
```

## Usage

### Command-Line Options

minisign-rs provides a simple, intuitive command-line interface with both short and long option names for better usability.

These reflect zig-minisign where it differs from classic C implementation. https://github.com/jedisct1/zig-minisign

#### Actions

| Short | Long | Description |
|-------|------|-------------|
| `-G` | `--generate` | Generate a new keypair |
| `-S` | `--sign` | Sign files |
| `-V` | `--verify` | Verify a signature |
| `-R` | `--recreate` | Recreate a public key from a secret key |
| `-K` | `--change-password` | Change or remove password from a secret key |
| `-I` | `--inspect` | Inspect a key file and display security parameters |

#### Key and File Options

| Short | Long | Description |
|-------|------|-------------|
| `-s <FILE>` | `--secretkey-path <FILE>` | Secret key file path |
| `-p <FILE>` | `--publickey-path <FILE>` | Public key file path |
| `-P <STRING>` | `--publickey <STRING>` | Public key as BASE64-encoded string |
| `-m <FILE>` | `--input <FILE>` | Input file (message to sign/verify) |
| `-x <FILE>` | `--signature <FILE>` | Signature file (default: `<file>.minisig`) |

#### Comment Options

| Short | Long | Description |
|-------|------|-------------|
| `-t <STRING>` | `--trusted-comment <STRING>` | Add a trusted comment to the signature |
| `-c <STRING>` | `--untrusted-comment <STRING>` | Add an untrusted comment to the signature |

#### Mode Options

| Short | Long | Description |
|-------|------|-------------|
| `-l` | `--legacy` | Create a legacy signature (non-prehashed) |
| `-H` | `--prehashed` | Sign or verify a prehashed file |
| `-q` | `--quiet` | Quiet mode (minimal output) |
| `-Q` | `--pretty-quiet` | Pretty quiet mode (show only trusted comment) |
| `-f` | `--force` | Force overwrite of existing files |
| `-o` | `--output` | Output verification result to stdout |
| `-W` | `--no-password` | Do not use password (generate and change only) |

#### Additional Options

| Short | Long | Description |
|-------|------|-------------|
| `-h` | `--help` | Display help message and exit |
| `-v` | `--version` | Show version information and exit |
| | `--password-file <FILE>` | Read password from file (testing only - insecure) |
| | `--allow-kdf-fallback` | Allow KDF parameter fallback on low-memory systems |

### Common Usage Examples

#### Generate a new keypair

```bash
# Interactive (prompts for password)
minisign_rs -G

# With custom paths
minisign_rs --generate --secretkey-path mykey.key --publickey-path mykey.pub

# Without password protection
minisign_rs -G -W

# Force overwrite existing keys
minisign_rs -G -f
```

**Password Strength:** Use 20+ character passwords or passphrases. Despite strong KDF parameters (scrypt N=2^20), weak passwords enable offline brute-force attacks. Avoid dictionary words, personal information, and short passwords (<16 characters).

#### Sign a file

```bash
# Sign with default keys
minisign_rs --sign --input file.txt

# Sign with custom key
minisign_rs -S -m file.txt -s custom.key

# Sign with custom comment
minisign_rs -S -m file.txt --trusted-comment "v1.0.0 release"

# Sign in legacy mode (non-prehashed)
minisign_rs -S -m file.txt --legacy

# Sign without password (for unencrypted keys)
minisign_rs -S -m file.txt -W
```

#### Verify a signature

```bash
# Verify with default public key
minisign_rs --verify --input file.txt

# Verify with specific public key
minisign_rs -V -m file.txt -p key.pub

# Verify using base64 public key
minisign_rs -V -m file.txt --publickey RWQwpZXcv6r8MS48...

# Verify in quiet mode
minisign_rs -V -m file.txt --quiet
```

#### Recreate public key from secret key

```bash
# Recreate using default paths
minisign_rs --recreate

# Recreate with custom paths
minisign_rs -R --secretkey-path mykey.key --publickey-path recovered.pub
```

#### Change password

```bash
# Change password on default key
minisign_rs --change-password

# Change password on specific key
minisign_rs -K -s mykey.key

# Remove password
minisign_rs -K -W
```

#### Inspect key security

```bash
# Inspect default secret key
minisign_rs --inspect

# Inspect specific secret key
minisign_rs -I -s mykey.key

# Inspect public key file
minisign_rs -I -p key.pub

# Inspect public key from command line (base64)
minisign_rs -I -P RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
```

## Signature File Format

Minisign creates `.minisig` files with 4 lines:
1. **Untrusted comment** - Human-readable, not verified (`-c` flag)
2. **Signature data** - Base64-encoded Ed25519 signature of the file
3. **Trusted comment** - Cryptographically verified (`-t` flag)
4. **Global signature** - Signs lines 2+3 together

**Security:** Only the trusted comment (line 3) is cryptographically protected. The untrusted comment (line 1) can be modified without breaking verification.

## Configuration

**`MINISIGN_CONFIG_DIR`** - Override default key directory (default: `~/.minisign/` on Unix, `%USERPROFILE%\.minisign\` on Windows). Useful for custom security policies, multi-user systems, or containers. Compatible with C minisign.

## Testing

### Test Requirements

**Required:**
- Rust 1.93+ and cargo (for all tests)

**Optional (for full test suite):**
- **C minisign** (for compatibility and cross-binary tests): `brew install minisign`
  - Without C minisign: ~359 tests run (skips 7 compatibility tests)
  - With C minisign: All 366 tests run

**Fast vs slow tests:** 355 fast tests (N=2^14, ~10s) for development, 11 slow tests (N=2^20, ~11s) for production parameter verification.

```bash
# Run only fast tests (default, ~10 seconds)
cargo test

# Run slow security tests (~11 seconds)
cargo test -- --ignored

# Run all tests (~21 seconds)
cargo test && cargo test -- --ignored
```

## Architecture

### Module Structure

```
src/
├── lib.rs          # Public API exports
├── main.rs         # CLI entry point
├── cli.rs          # Command-line interface
├── constants.rs    # Centralized size and parameter constants
├── crypto.rs       # Ed25519, Blake2b, Scrypt wrappers
├── keys.rs         # Key types, generation, encryption
├── signature.rs    # Signature creation and verification
├── formats.rs      # Binary and base64 encoding/decoding
├── validation.rs   # Comment and input validation (C compatibility)
├── errors.rs       # Error types with thiserror
└── ops/            # High-level operations
    ├── generate.rs    # Key generation
    ├── sign.rs        # File signing
    ├── verify.rs      # Signature verification
    ├── recreate.rs    # Public key recovery
    ├── change.rs      # Password management
    ├── inspect.rs     # Security auditing
    └── file_utils.rs  # File I/O utilities
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

### Rust-Specific Enhancements

Additional flags not in C minisign:

- **`-I/--inspect`** - Audit key security parameters and KDF strength (see [Inspecting Key Security](#inspecting-key-security))
- **`--password-file <FILE>`** - Read password from file (testing only, insecure)
- **`--allow-kdf-fallback`** - Allow weak KDF on low-memory systems (opt-in, reduces security)
- **`--force-weak-kdf`** - Create intentionally weak keys (debug builds only, testing)

See [KDF Fallback Security Analysis](docs/kdf-fallback-security-analysis.md) for detailed security implications.

### Inspecting Key Security

The `-I/--inspect` command audits the security parameters of your minisign keys, useful for detecting keys created with weak KDF parameters.

**Key ID formats:** Displays both base64 (e.g., `RWQwpZ...`) for scripting and PGP Word List (e.g., `physique aftermath edict...`) for human verification.

```bash
# Inspect default secret key (~/.minisign/minisign.key)
cargo run -- -I

# Inspect specific secret key
cargo run -- -I -s path/to/key.key

# Inspect public key (file or base64 string)
cargo run -- -I -p key.pub
cargo run -- -I -P RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
```

**Example output - Production key:**
```
Security Level: HIGH [OK]

Key Information:
├─ Key ID: RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
├─ Key ID (words): physique aftermath edict lockup tactics Eskimo blockade commence
├─ Encrypted: Yes
└─ KDF Parameters: opslimit=33554432 (N=2^20), memlimit=1073741824 (1024 MB)
```

**Example output - Weak key:**
```
Security Level: LOW [CRITICAL]

Key Information:
├─ Key ID: RWQwpZXcv6r8MS...
├─ Key ID (words): physique aftermath edict lockup tactics Eskimo blockade commence
├─ Encrypted: Yes
└─ KDF Parameters: opslimit=4194304 (N=2^17), memlimit=134217728 (128 MB)
   Brute-force resistance: 8x weaker than production strength

*** RECOMMENDATION: Regenerate this key on a system with >=2GB RAM for full security.
```

**Security levels:**
- **HIGH**: Production parameters (N=2^20, 1024 MB)
- **MEDIUM**: Reduced parameters (N=2^19-18, 256-512 MB) - 2-4x weaker
- **LOW**: Weak parameters (N≤2^17, ≤128 MB) - 8x+ weaker
- **NONE**: Unencrypted (no password protection)

**Note:** Public keys show only key ID and type. KDF parameters are only in secret key files.

## Performance & Memory

**Performance:** Within 6% of C minisign across all operations. See [Performance Benchmark Report](docs/benchmark-report.md).

**Binary size:** 1.1MB (vs C's 70KB) - larger binary for memory safety and zero C dependencies.

**Memory requirements:**
- Scrypt KDF: ~128MB, ~1-2s (N=2^20 for security)
- Ed25519: <1KB, <1ms
- Prehashed mode (default): Streaming, minimal memory
- Legacy mode (`--legacy`): Loads entire file into memory (1GB max)

**Safety advantages:** Zero unsafe code, automatic secret cleanup, verified memory safety, no buffer overflows or use-after-free.

## Development Guidelines

### Before Committing

**These checks are mandatory:**

```bash
# 1. Format code
cargo fmt

# 2. Run clippy (pedantic mode)
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic

# 3. Run fast test suite (~10 seconds)
cargo test

# 4. Run slow security tests (~11 seconds)
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
- [rsign2 Comparison](docs/rsign2-comparison.md) - Comprehensive comparison with rsign2 Rust implementation
- [KDF Fallback Security Analysis](docs/kdf-fallback-security-analysis.md) - Security implications of weak KDF parameters
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
