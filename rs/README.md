# minisign-rs

[![Rust CI](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml)
[![CodeQL scan](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml)
[![Coverage](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml)
[![Slow Tests](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml)

A pure Rust implementation of the classic C project [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

We aim for 100% compatibility with the C/Zig version, with a few extra switches for enhanced security and usability.

## Project Status

**Production Ready** - Full Rust implementation with complete C minisign compatibility.

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

- **320 total tests** covering all operations and CLI behavior
- **217 unit tests** covering all crypto operations, key handling, and file formats
- **42 CLI integration tests** using assert_cmd for end-to-end validation
- **7 compatibility tests** verifying interoperability with C minisign
- **18 cross-binary tests** ensuring full C minisign compatibility
- **6 edge case tests** for unicode, symlinks, and large files
- **8 fuzzing tests** using proptest for property-based testing
- **6 concurrent access tests** for multi-process safety
- **11 slow security tests** using production scrypt parameters (marked `#[ignore]`)
- **Fast test suite** using optimized scrypt parameters (~10 seconds)
- **Slow test suite** with production scrypt parameters (~11 seconds)

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **~8,800 lines** of well-documented Rust code (11,546 total with comments)
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

# Run tests (fast - 309 tests, ~10 seconds)
cargo test

# Run slow security tests (11 tests, ~11 seconds)
cargo test -- --ignored

# Run all tests (320 tests, ~21 seconds)
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
| `-x <FILE>` | | Signature file (default: `<file>.minisig`) |

#### Comment Options

| Short | Long | Description |
|-------|------|-------------|
| `-t <STRING>` | `--trusted-comment <STRING>` | Add a trusted comment to the signature |
| `-c <STRING>` | `--untrusted-comment <STRING>` | Add an untrusted comment to the signature |

#### Mode Options

| Short | Long | Description |
|-------|------|-------------|
| `-l` | `--legacy` | Create a legacy signature (non-prehashed) |
| `-H` | | Sign or verify a prehashed file |
| `-q` | `--quiet` | Quiet mode (minimal output) |
| `-Q` | | Pretty quiet mode (show only trusted comment) |
| `-f` | | Force overwrite of existing files |
| `-o` | `--output` | Output verification result to stdout |
| `-W` | | Do not use password (generate and change only) |

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

### Long vs Short Options

All commonly used flags now support long option names for improved readability and script maintainability:

```bash
# These commands are equivalent:
minisign_rs -S -m file.txt -s key.key -t "v1.0"
minisign_rs --sign --input file.txt --secretkey-path key.key --trusted-comment "v1.0"

# Mix and match as preferred:
minisign_rs --sign -m file.txt --secretkey-path key.key -t "v1.0"
```

## Configuration

### Environment Variables

#### `MINISIGN_CONFIG_DIR`

Override the default configuration directory for secret keys.

**Default behavior:**
- Unix/Linux/macOS: `~/.minisign/minisign.key`
- Windows: `%USERPROFILE%\.minisign\minisign.key`

**With `MINISIGN_CONFIG_DIR` set:**
```bash
# Set custom config directory
export MINISIGN_CONFIG_DIR=/opt/secure/minisign

# Secret key will now be at: /opt/secure/minisign/minisign.key
cargo run -- -G
```

**Use cases:**
- Custom security policies requiring keys in specific directories
- Multi-user systems with centralized key management
- Containerized environments with mounted volumes
- Compatibility with C minisign deployments using this variable

**Compatibility:** This environment variable is also supported by the C implementation of minisign, ensuring consistent behavior across both versions.

## Testing

### Test Requirements

**Required:**
- Rust 1.93+ and cargo (for all tests)

**Optional (for full test suite):**
- **C minisign** (for compatibility and cross-binary tests): `brew install minisign`
  - Without C minisign: ~313 tests run (skips 7 compatibility tests)
  - With C minisign: All 320 tests run

Most development can be done without C minisign installed. Install it only when you need to verify cross-compatibility or run the full test suite.

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

- **Fast tests** (309 tests, default): Use N=2^14 (~50ms per operation)
- **Slow tests** (11 tests, `#[ignore]`): Use N=2^20 (~1-5s per operation)

Fast tests provide rapid feedback during development, while slow tests verify production security parameters work correctly. With recent performance improvements, slow tests now complete in ~11 seconds.

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

### CLI Differences from C minisign

This Rust implementation adds **security enhancements** and **optional flags** not present in the original C version:

#### `-I/--inspect`
Inspect a key file and display its security parameters (KDF configuration, strength rating).

**✅ SECURITY ENHANCEMENT**

```bash
# Inspect a secret key
cargo run -- -I -s key.key

# Inspect using default key location
cargo run -- -I

# Inspect a public key file
cargo run -- -I -p key.pub

# Inspect a public key from command line (-P flag)
cargo run -- -I -P RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
```

- Displays security level (High/Medium/Low/None)
- Shows exact KDF parameters (N, r, p, opslimit, memlimit)
- Calculates weakness multiplier for fallback keys
- Provides recommendations for weak keys
- Works with both secret and public keys (file paths or base64 strings)
- Shows inspection source (file path, command-line literal, or default)
- Fully compatible with C-generated keys
- C minisign does not provide this capability

See [Inspecting Key Security](#inspecting-key-security) for detailed usage.

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
Rust version is secure by default. This flag enables a scrypt KDF parameter fallback on resource-constrained systems.

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
- C minisign does not support this flag (it always allows fallback automatically)

**Recommendation**: Avoid both flags in production. Use only when necessary and understand the security trade-offs.

#### `--force-weak-kdf` (Debug Builds Only)

**🔥 DEBUG ONLY - INTENTIONALLY INSECURE 🔥**

Forces creation of weak KDF parameters (N=2^17, 8x easier to brute-force) for testing purposes.

```bash
# Example (debug builds only)
cargo run -- -G --force-weak-kdf --password-file test.txt

# Works with password changes too
cargo run -- -C -s test.key --force-weak-kdf --password-file newpass.txt
```

- **Only available in debug builds** (`cargo build` without `--release`)
- **Not available in release builds** for safety
- Creates keys with N=2^17 instead of N=2^20 (8x weaker)
- Displays loud warnings about intentional insecurity
- Useful for:
  - Testing weak key detection logic
  - Creating fixture files for security testing
  - Manual QA of warning systems
- **NEVER use in production** - these keys are intentionally compromised

**For detailed security analysis**, see [KDF Fallback Security Analysis](docs/kdf-fallback-security-analysis.md) which explains:
- Why fallback keys are permanently weaker (8-64x easier to brute-force)
- How C minisign's automatic fallback differs from Rust's opt-in approach
- How to detect and audit weak keys
- How to force weak key creation for testing
- Migration strategies for production deployments

### Inspecting Key Security

The `-I/--inspect` command allows you to audit the security parameters of your minisign keys. This is particularly useful for detecting keys created with weak KDF parameters.

```bash
# Inspect a secret key (default: ~/.minisign/minisign.key)
cargo run -- -I

# Inspect a specific secret key
cargo run -- -I -s path/to/key.key

# Inspect a public key file
cargo run -- -I -p path/to/key.pub

# Inspect a public key from command line (base64 string)
cargo run -- -I -P RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
```

**Note:** The inspect command now displays the source being inspected (file path or command-line literal) to avoid confusion when using default keys or base64 strings.

#### Public vs Secret Keys

**Important:** Public keys do not contain security information. KDF parameters (scrypt opslimit/memlimit) are only stored in secret key files because they're used for password-based encryption. When inspecting a public key (via `-p` file or `-P` base64 string), only the key ID and type are displayed - this is by design, not a limitation.

- **Secret keys** (.key files): Show full security details including KDF parameters, encryption status, and security level
- **Public keys** (.pub files or base64): Show only key ID and type - no KDF or security information available

#### Example Output

**Production-strength key:**
```
Inspecting: /Users/name/.minisign/minisign.key (default)

Security Level: HIGH ✓

Key Information:
├─ Key ID: RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
└─ KDF Parameters:
   ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   ├─ memlimit: 1073741824 (1024 MB)
   └─ Creation: Normal (production parameters)
```

**Weak key (created with fallback):**
```
Inspecting: path/to/weak.key

Security Level: LOW 🔥

Key Information:
├─ Key ID: RWQwpZXcv6r8MS...
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
└─ KDF Parameters:
   ├─ opslimit: 4194304 (N=2^17, r=8, p=1)
   ├─ memlimit: 134217728 (128 MB)
   ├─ Creation: Fallback (reduced parameters)
   └─ Brute-force resistance: 8x weaker than production strength

⚠️  RECOMMENDATION: Regenerate this key on a system with ≥2GB RAM for full security.
```

**Unencrypted key:**
```
Inspecting: path/to/unencrypted.key

Security Level: NONE (UNENCRYPTED) ⚠

Key Information:
├─ Key ID: RWQwpZXcv6r8MS...
└─ Encrypted: No

⚠️  WARNING: This key is stored in plaintext.
   Anyone with file access can use it without a password.
```

**Public key from command line:**
```
Inspecting: public key from command line (-P)

Key Information:
├─ Key ID: RWQwpZXcv6r8MS...
└─ Type: Ed25519 Public Key

Note: Public keys do not contain KDF parameters or security information.
      Only secret keys (.key files) store encryption and KDF data.
```

**Public key from file:**
```
Inspecting: path/to/key.pub

Key Information:
├─ Key ID: RWQwpZXcv6r8MS...
└─ Type: Ed25519 Public Key

Note: Public keys do not contain KDF parameters or security information.
      Only secret keys (.key files) store encryption and KDF data.
```

#### Security Levels

The inspect command classifies keys into four security levels:

- **HIGH** ✓: Production parameters (N=2^20, 1024 MB) - full security
- **MEDIUM** ⚠: 1-2 fallbacks (N=2^19-18, 256-512 MB) - 2-4x weaker
- **LOW** 🔥: 3+ fallbacks (N≤2^17, ≤128 MB) - 8x+ weaker
- **NONE** ⚠: Unencrypted (no password protection)

#### Use Cases

- **Audit existing keys**: Check if your keys were created with weak parameters
- **Verify key strength**: Confirm production-strength parameters before deployment
- **Security compliance**: Ensure all keys meet minimum security requirements
- **Migration planning**: Identify keys that should be regenerated
- **C minisign compatibility**: Works with keys generated by the C implementation

**Note**: The inspect command reads KDF parameters directly from bytes 38-53 of the key file, making it fully compatible with both C and Rust-generated keys.

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
