# minisign_rs

[![Rust CI](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/rust.yml)
[![CodeQL scan](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/codeql-analysis.yml)
[![Coverage](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml/badge.svg)](https://github.com/lookbusy1344/minisign/actions/workflows/coverage.yml)

A pure Rust implementation of the classic C project [minisign](https://jedisct1.github.io/minisign/), a dead simple tool to sign files and verify signatures.

We aim for 100% compatibility with the C/Zig version, with a few extra switches for enhanced security and usability.

## Project Status

**Version 1.3.6 Release** - Production-ready Rust implementation with complete C minisign compatibility.

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
- ✅ Multi-file signing with parallel execution (Rayon, optional `parallel` feature)
- ✅ Multi-file verification with parallel execution (Rayon, optional `parallel` feature)
- ✅ OS credential store integration for password caching (macOS Keychain, Windows Credential Manager, Linux Secret Service, optional `credential_store` feature)
- ✅ Full compatibility with C minisign file formats

### Test Coverage

- **484 total tests** covering all operations and CLI behavior
- Comprehensive unit tests covering all crypto operations, key handling, and file formats
- CLI integration tests using assert_cmd for end-to-end validation
- Credential store tests (skip gracefully when OS keyring unavailable)
- Compatibility tests verifying interoperability with C minisign
- Cross-binary tests ensuring full C minisign compatibility
- Edge case tests for unicode, symlinks, and large files
- Fuzzing tests using proptest for property-based testing
- Concurrent access tests for multi-process safety
- Production-strength scrypt parameter tests (N=2^20)
- C compatibility tests skip with a warning when C minisign is not installed

### Code Quality

- **Zero unsafe code** - 100% safe Rust
- **Zero clippy warnings** - passes `clippy::pedantic` checks
- **4,177 lines** of production code in `src/` (5,204 total with comments)
- **10,458 lines** of test code in `tests/` (14,070 total with comments)
- **Test-to-code ratio**: 2.50:1 demonstrating thorough test coverage
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
./run_all_tests.sh                                         # All tests (~30s)
cargo test --no-default-features                           # All tests (~30s)

# Run tests with credential store enabled (may show keychain popups)
cargo test

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
cargo test --no-default-features
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
- **`--sequential`** - Disable parallel processing for multi-file operations (`parallel` feature only)

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
├─ Key ID: [encrypted - password required]
├─ Key ID (words): [encrypted]
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

### macOS Keychain prompts after rebuilding

After rebuilding the binary, macOS will prompt for Keychain access **once per stored credential**, not once per binary. This is expected macOS security behaviour: each Keychain item has its own Access Control List (ACL) tied to the binary's code identity, so a freshly built binary is treated as a new application for each item independently.

With 3 keys stored, you will see 3 prompts. This is not a bug — it is macOS enforcing per-item access control.

To avoid repeated prompts during development, sign the binary with a stable identity after each build:

```bash
# Ad-hoc signature (content-derived, changes every rebuild — prompts reset each time)
codesign --force --sign - target/release/minisign_rs

# Preferred: sign with a Developer ID certificate for a stable identity across rebuilds
codesign --force --sign "Developer ID Application: Your Name" target/release/minisign_rs
```

## Performance & Memory

**Performance:** Matches C minisign on single-file operations (≤10% variance, within noise); marginally faster on large-file work. Multi-file signing runs in parallel via Rayon — up to **8.4x faster** than C's sequential single-invocation mode (e.g. 10 × 10MB: 10ms vs 87ms). C has no multi-file verify; Rust parallel verify is up to **6.2x faster** than Rust sequential. See [Performance Benchmark Report](docs/benchmark-report.md).

**Binary size:** 525 KB with default features (vs C's 70KB) — reduced from ~910 KB by replacing `clap` with `pico-args` (saves ~385 KB). Smaller still with `--no-default-features` (658 KB, no keychain or parallel support). Larger than C due to memory safety guarantees and zero C dependencies.

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

### Security Audits

Both audits were conducted on 2026-02-20 by static analysis against the `lb_rust` branch (commit `5f75f2c`), with all actionable findings remediated in the `security_audit` branch (merged at commit `679958e`).

- [docs/2026-02-20-rust-security-audit.md](docs/2026-02-20-rust-security-audit.md) — Rust implementation audit with full C/Zig comparison (9 findings; all actioned)
- [docs/2026-02-20-c-zig-security-audit.md](docs/2026-02-20-c-zig-security-audit.md) — C/Zig implementation audit (20 findings; 1 Critical, 4 High)

**Summary:** The Rust implementation begins with zero Critical/High issues — Rust's type system, ownership model, and `zeroize`/`subtle` crates structurally eliminate the most severe C/Zig vulnerability classes (secret-material leakage, buffer overflows, timing side-channels). Post-remediation, only two informational items remain (RS-7: cache-line side-channel inherent to any multi-threaded design; RS-8: OS keyring API limitation).

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
