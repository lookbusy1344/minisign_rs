# minisign_rs

[![Rust CI](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml)
[![CodeQL scan](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml)
[![Coverage](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml)
[![Slow Tests](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/slow-tests.yml)

A pure Rust implementation of the classic C project [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

We aim for 100% compatibility with the C/Zig version, with a few extra switches for enhanced security and usability.

## Project Status

**Version 1.3.2 Release** - Production-ready Rust implementation with complete C minisign compatibility.

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
- ✅ Multi-file signing with parallel execution (Rayon)
- ✅ Multi-file verification with parallel execution (Rayon)
- ✅ OS credential store integration for password caching (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- ✅ Full compatibility with C minisign file formats

### Test Coverage

- **479 total tests** covering all operations and CLI behavior
- Comprehensive unit tests covering all crypto operations, key handling, and file formats
- CLI integration tests using assert_cmd for end-to-end validation
- Credential store tests (skip gracefully when OS keyring unavailable)
- Compatibility tests verifying interoperability with C minisign
- Cross-binary tests ensuring full C minisign compatibility
- Edge case tests for unicode, symlinks, and large files
- Fuzzing tests using proptest for property-based testing
- Concurrent access tests for multi-process safety
- **11 slow security tests** using production scrypt parameters (marked `#[ignore]`)
- **Fast test suite** (468 tests) using optimized scrypt parameters (~10 seconds)
- **Slow test suite** (11 tests) with production scrypt parameters (~11 seconds)

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **4,236 lines** of production code in `src/` (7,227 total with comments)
- **10,000 lines** of test code in `tests/` (13,806 total with comments)
- **Test-to-code ratio**: 2.36:1 demonstrating thorough test coverage
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

# Run tests without keychain popups (recommended for development)
./run_all_tests.sh                                         # Fast + slow tests (~21s)
cargo test --no-default-features                           # Fast tests only (~10s)
cargo test --no-default-features -- --ignored              # Slow tests only (~11s)

# Run tests with credential store enabled (may show keychain popups)
cargo test                                                 # Fast tests
cargo test -- --ignored                                    # Slow tests

# Check code quality
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt

# Run a specific test
cargo test --no-default-features test_sign_verify_roundtrip
```

## Usage

For complete usage documentation, see [docs/USAGE.md](docs/USAGE.md).

### Quick Start

#### Generate a keypair
```bash
minisign_rs -G
```

#### Sign a file
```bash
minisign_rs -S -m file.txt
```

#### Verify a signature
```bash
minisign_rs -V -m file.txt -p minisign.pub
```

## Testing

See [docs/TESTING.md](docs/TESTING.md) for complete testing guide.

**Quick commands:**
```bash
# Fast tests (~9s)
cargo test --no-default-features

# Slow tests (~16s)
cargo test --no-default-features -- --ignored
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for internal design details.

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
- **`--no-decrypt`** - Skip password prompt for encrypted keys during inspection (non-interactive mode)
- **`--save-password/--sp`** - Save password to OS credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service) after successful use
- **`--forget-password/--fp`** - Remove saved password from OS credential store (see [Password Storage in OS Keychain](#password-storage-in-os-keychain))
- **`--password-file <FILE>`** - Read password from file (testing only, insecure)
- **`--allow-kdf-fallback`** - Allow weak KDF on low-memory systems (opt-in, reduces security)
- **`--force-weak-kdf`** - Create intentionally weak keys (debug builds only, testing)

See [KDF Fallback Security Analysis](docs/kdf-fallback-security-analysis.md) for detailed security implications.

### Inspecting Key Security

The `-I/--inspect` command audits the security parameters of keys and signatures, useful for detecting keys created with weak KDF parameters or identifying which key signed a file.

**Works with:** Private keys, public keys, public key strings, and signature files.

**Smart decryption:** Automatically detects encrypted keys and prompts for password only when needed. For public keys and unencrypted secret keys, no password prompt occurs. Use `--no-decrypt` to skip password prompting for non-interactive scripts.

**Key ID formats:** Displays both hexadecimal (e.g., `31FCAABFDC95A530`) for scripting and PGP Word List (e.g., `physique aftermath edict...`) for human verification.

```bash
# Inspect default secret key (prompts for password if encrypted)
cargo run -- -I

# Inspect specific secret key (smart: prompts only if encrypted)
cargo run -- -Is path/to/key.key

# Inspect without decrypting (non-interactive, shows [encrypted] for key ID)
cargo run -- -Is path/to/key.key --no-decrypt

# Inspect public key (never prompts)
cargo run -- -Ip key.pub
cargo run -- -IP RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa

# Inspect signature file (shows key ID used to sign)
cargo run -- -Ix file.txt.minisig
```

**Example output - Production key (decrypted):**
```
Inspecting: mykey.key (decrypted)

Security Level: HIGH [OK]

Key Information:
├─ Key ID: 31FCAABFDC95A530
├─ Key ID (words): physique aftermath edict lockup tactics Eskimo blockade commence
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
├─ Password saved: Yes
└─ KDF Parameters:
   ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   ├─ memlimit: 1073741824 (1024 MB)
   └─ Creation: Normal (production parameters)
```

**Example output - Production key (--no-decrypt):**
```
Inspecting: mykey.key

Security Level: HIGH [OK]

Key Information:
├─ Key ID: [encrypted - password required to view]
├─ Key ID (words): [decrypt key to view]
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
└─ KDF Parameters:
   ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   ├─ memlimit: 1073741824 (1024 MB)
   └─ Creation: Normal (production parameters)
```

**Example output - Weak key:**
```
Security Level: LOW [CRITICAL]

Key Information:
├─ Key ID: 31FCAABFDC95A530
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

### Password Storage in OS Keychain

When you save a password to the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service), two identifiers are involved:

- **Key ID**: The cryptographic identifier of your signing key (e.g., `31FCAABFDC95A530`).
- **Credential ID**: The identifier used to store/retrieve passwords from the OS keychain.

For **encrypted keys**, the credential ID must be different from the key ID because the key ID is encrypted inside the secret key file. The credential ID can be computed from the encrypted file without decryption, avoiding the chicken-and-egg problem of needing the password to get the key ID to retrieve the password.

For **unencrypted keys**, the credential ID and key ID are the same since there's no decryption barrier.

## Performance & Memory

**Performance:** Within 6% of C minisign across all operations. See [Performance Benchmark Report](docs/benchmark-report.md).

**Binary size:** 1.1MB (vs C's 70KB) - larger binary for memory safety and zero C dependencies.

**Memory requirements:**
- Scrypt KDF: ~128MB, ~1-2s (N=2^20 for security)
- Ed25519: <1KB, <1ms
- Prehashed mode (default): Streaming, minimal memory
- Legacy mode (`--legacy`): Loads entire file into memory (1GB max)

**Safety advantages:** Zero unsafe code, automatic secret cleanup, verified memory safety, no buffer overflows or use-after-free.

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development workflow and guidelines.

## Documentation

- **[docs/USAGE.md](docs/USAGE.md)** - Complete usage guide and CLI reference
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Internal design and structure
- **[docs/TESTING.md](docs/TESTING.md)** - Testing guide
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** - Development workflow
- [COMPATIBILITY.md](COMPATIBILITY.md) - C/Rust compatibility proof
- [docs/benchmark-report.md](docs/benchmark-report.md) - Performance comparison
- [docs/rsign2-comparison.md](docs/rsign2-comparison.md) - Comparison with rsign2
- [docs/2026-02-17-security-audit.md](docs/2026-02-17-security-audit.md) - Security audit (v1.3.1)
- [CLAUDE.md](CLAUDE.md) - Quick reference for AI assistants

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
