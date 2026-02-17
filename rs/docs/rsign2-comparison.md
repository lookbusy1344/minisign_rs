# Comparison: minisign-rs vs rsign2

**Date:** 2026-02-17 (updated from 2026-01-26)
**Author:** Comparative Analysis
**Purpose:** Evaluate the technical and functional differences between two Rust implementations of minisign

---

## Executive Summary

Both **minisign-rs** and **rsign2** are pure Rust implementations of the minisign cryptographic signing tool, maintaining compatibility with the original C implementation. However, they differ significantly in scope, maturity, features, and development philosophy.

**Quick Verdict:**
- **minisign-rs**: Comprehensive, production-ready rewrite with extensive testing, documentation, and enhanced security features
- **rsign2**: Lightweight, library-focused implementation with minimal dependencies and WebAssembly support

---

## Project Overview

### minisign-rs
- **Repository:** `lookbusy1344/minisign`
- **Version:** 1.3.1
- **License:** ISC
- **Status:** Production Ready
- **Rust Edition:** 2024
- **Rust Version:** 1.93+ (latest edition)

### rsign2
- **Repository:** `jedisct1/rsign2`
- **Version:** 0.6.5 (unchanged since November 2025)
- **License:** MIT
- **Status:** Maintained Fork
- **Rust Edition:** 2018
- **Maintained By:** Frank Denis (original minisign author)
- **Last Commit:** 2025-12-29 ("Don't display unprintable characters")

---

## Core Philosophy

### minisign-rs
Aims for **100% command-line compatibility** with C minisign while adding security enhancements:
- Complete feature parity with C implementation
- Enhanced security auditing capabilities
- Extensive test coverage (479 tests)
- Zero unsafe code with formal verification (Miri)
- Production-grade documentation

### rsign2
Focuses on **library-first design** with minimal dependencies:
- Maintained fork of original rsign
- Reduced dependency footprint
- WebAssembly compilation support
- Embeddable library architecture
- Command-line tool as secondary interface

---

## Feature Comparison

| Feature | minisign-rs | rsign2 | Notes |
|---------|-------------|--------|-------|
| **Core Operations** |
| Key Generation | ✅ | ✅ | Both support Ed25519 keypairs |
| File Signing | ✅ | ✅ | Compatible signature format |
| Signature Verification | ✅ | ✅ | Cross-compatible |
| Trusted Comments | ✅ | ✅ | Full support |
| Prehashed Mode | ✅ | ✅ | Large file support |
| **Unique to minisign-rs** |
| Key Security Inspection | ✅ | ❌ | `-I/--inspect`: audits KDF strength, rates key security |
| Weak Key Detection | ✅ | ❌ | Persistent warnings on every operation with weak keys |
| KDF Fallback Control | ✅ | ❌ | `--allow-kdf-fallback`: fail-secure by default |
| OS Credential Store | ✅ | ❌ | macOS Keychain, Windows Credential Manager, Linux Secret Service |
| Multi-threaded Operations | ✅ | ❌ | Parallel multi-file signing and verification via `rayon` |
| Public Key Recreation | ✅ | ❌ | `-R`: recover public key from secret key |
| Password Management | ✅ | ❌ | `-K`: add/remove/change password on secret keys |
| Long Flag Names | ✅ | ❌ | `--generate`, `--sign`, `--verify`, etc. |
| Config Dir Override | ✅ | ❌ | `MINISIGN_CONFIG_DIR` env var |
| **Unique to rsign2** |
| WebAssembly | ❌ | ✅ | WASM compilation for browser deployment |
| **Security (shared)** |
| Scrypt KDF | ✅ | ✅ | Both use production parameters |
| Memory Wiping | ✅ | ✅ | Zeroize support |
| Constant-Time Ops | ✅ | ✅ | Subtle crate |
| **Platform Support** |
| Linux / macOS / Windows | ✅ | ✅ | Both |
| WebAssembly | ❌ | ✅ | rsign2 only |
| **Development Quality** |
| Test Coverage | 479 tests | Unknown | minisign-rs: 3x increase since Jan 2026 |
| Unsafe Code | 0 blocks | Unknown | minisign-rs: 100% safe |
| Clippy Pedantic | ✅ | Unknown | minisign-rs: Zero warnings |
| Memory Safety (Miri) | ✅ | Unknown | minisign-rs: Weekly checks |
| CI/CD | Multi-platform | Unknown | Both likely have CI |

---

## Technical Architecture

### minisign-rs

**Module Structure** (20 source files, ~11,780 lines):
```
src/
├── lib.rs              # Public API exports
├── main.rs             # CLI entry point
├── crypto.rs           # Ed25519, Blake2b, Scrypt wrappers
├── keys.rs             # Key types, generation, encryption
├── signature.rs        # Signature creation and verification
├── formats.rs          # Binary and base64 encoding
├── validation.rs       # Comment/input validation
├── constants.rs        # Centralized constants
├── errors.rs           # Error types with thiserror
├── cli.rs              # Command-line parsing
├── credential_store.rs # OS keychain integration (optional)
├── wordlist.rs         # Wordlist utilities
└── ops/                # High-level operations
    ├── generate.rs     # Key generation
    ├── sign.rs         # File signing
    ├── verify.rs       # Signature verification
    ├── recreate.rs     # Public key recovery
    ├── change.rs       # Password management
    ├── inspect.rs      # Security auditing
    └── file_utils.rs   # File operation helpers
```

**Design Principles:**
1. Pure Rust - No unsafe blocks
2. Security-first - Zeroization, constant-time operations
3. Test-driven - Tests before implementation
4. Type-safe - Newtype wrappers prevent key/signature mixing
5. Compatibility - Byte-level compatibility with C
6. Encapsulated APIs - Private fields with getter methods, builder patterns

### rsign2

**Architecture:**
- Library-first design (uses `minisign` crate v0.7.9)
- Command-line wrapper around core library
- Minimal dependency footprint
- WebAssembly compilation target

**Dependencies:**
- `minisign` 0.7.9 (core library)
- `clap` 4.x (CLI parsing)
- `dirs` 6.0.0 (path management)

---

## Dependencies Analysis

### minisign-rs (15 dependencies, 1 optional)

**Cryptography:**
- `ed25519-dalek` 2.2 - Ed25519 signatures
- `blake2` 0.10 - Blake2b hashing
- `scrypt` 0.11 - Key derivation
- `zeroize` 1.8 - Memory wiping
- `subtle` 2.6 - Constant-time operations
- `rand` 0.8 - CSPRNG
- `rand_core` 0.6 - RNG core traits

**Utilities:**
- `base64` 0.22 - Encoding
- `thiserror` 2.x - Error types
- `rpassword` 7.4 - Password input
- `dirs` 6.x - Directory paths
- `clap` 4.5 - CLI parsing (derive)
- `git-version` 0.3 - Version embedding
- `rayon` 1.x - Parallel iteration

**Optional:**
- `keyring` 3.x - OS credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service)

**Dev Dependencies:**
- `assert_cmd`, `predicates`, `tempfile`, `proptest`, `hex`

### rsign2 (3 dependencies)

**Main:**
- `minisign` 0.7.9 - Core library (abstracts crypto)
- `clap` 4.x - CLI parsing
- `dirs` 6.0.0 - Path management

**Observation:** rsign2 uses the `minisign` library crate, which internally handles all cryptographic dependencies. This creates a clean separation but relies on an external library maintained by the same author.

---

## Testing & Quality

### minisign-rs

**Test Suite:**
- **479 total tests** across multiple categories (up from 159 in Jan 2026)
- **468 fast tests** - Unit, integration, compatibility, property-based, doc tests
- **11 slow security tests** - Production scrypt parameters (N=2^20)
- Includes: crypto, key handling, formats, CLI integration (`assert_cmd`), C interop, cross-binary, edge cases, doc tests

**Performance:**
- Fast tests: ~10 seconds (N=2^14 scrypt)
- Slow tests: ~11 seconds (N=2^20 production scrypt)
- Total suite: ~21 seconds

**Quality Metrics:**
- Zero unsafe code
- Zero clippy warnings (pedantic mode)
- Miri memory safety checks (weekly)
- Multi-platform CI (Linux, macOS, Windows)
- Property-based testing with `proptest`

### rsign2

**Test Coverage:** Not documented in available materials

**Quality Assurance:** Unknown specifics, likely follows standard Rust practices

---

## Security Features

### minisign-rs: Enhanced Security Model

**1. Key Security Inspection (`-I/--inspect`)**
```bash
minisign_rs -I -s key.key
```

**Unique Feature:** Audits KDF parameters and rates key strength:
- **HIGH** ✓ - Production parameters (N=2^20, 1024 MB)
- **MEDIUM** ⚠ - Fallback parameters (N=2^19-18)
- **LOW** 🔥 - Weak parameters (N≤2^17)
- **NONE** ⚠ - Unencrypted keys

**Security Value:**
- Detects weak keys created on low-memory systems
- Calculates brute-force resistance multipliers
- Provides actionable remediation recommendations
- Works with both C and Rust-generated keys

**2. Opt-In KDF Fallback**
```bash
minisign_rs -G --allow-kdf-fallback
```

**Philosophy:** Secure by default
- Rust version **fails** if 128MB allocation fails
- `--allow-kdf-fallback` permits weaker parameters only if necessary
- C minisign automatically falls back (less secure default)

**3. Weak Key Persistent Warnings**

When using weak keys, every operation displays:
```
⚠️  WARNING: This key uses weak KDF parameters (8x easier to brute-force)
⚠️  RECOMMENDATION: Regenerate on a system with ≥2GB RAM
```

### rsign2: Standard Security Model

- Uses standard Rust cryptographic libraries
- Follows minisign specification
- No documented enhanced security features
- Relies on underlying `minisign` crate security

---

## Performance & Binary Size

### minisign-rs

**Performance** (vs C minisign):
| Operation | C minisign | minisign-rs | Difference |
|-----------|-----------|-------------|------------|
| Key Generation | 3.3ms | 3.2ms | +1.02x (Rust) |
| Sign 100KB | 3.4ms | 3.5ms | -1.02x (C) |
| Sign 10MB | 16.0ms | 15.4ms | +1.04x (Rust) |
| Verify 100KB | 2.2ms | 2.2ms | Tied |
| Verify 10MB | 15.4ms | 14.5ms | +1.06x (Rust) |

**Verdict:** Performance parity (within 6%)

**Binary Size:**
- Release build: ~1.1 MB (includes Rust stdlib)
- C minisign: ~70 KB (static libsodium)

### rsign2

**Performance:** Not documented

**Binary Size:** Unknown (likely similar to minisign-rs)

**Optimization:** Cargo.toml configures LTO and opt-level 3

---

## Documentation & Usability

### minisign-rs

**Documentation Quality:** Exceptional
- Comprehensive README (700+ lines)
- COMPATIBILITY.md - Byte-level C/Rust compatibility proof
- benchmark-report.md - Performance analysis
- c-rust-parity-gaps.md - Implementation comparison
- kdf-fallback-security-analysis.md - Security deep-dive
- TESTING.md - Test methodology
- Multiple design documents in `docs/plans/`

**CLI Usability:**
- Short flags: `-G`, `-S`, `-V`, `-R`, `-K`, `-I`
- Long flags: `--generate`, `--sign`, `--verify`, `--recreate`, `--change-password`, `--inspect`
- Detailed help with examples
- Clear error messages

**Examples in README:** Extensive usage patterns with comments

### rsign2

**Documentation:** Standard
- README with basic usage
- Help command for operations
- Links to minisign documentation

**CLI:** Standard minisign interface

---

## Compatibility with C Minisign

### minisign-rs

**Compatibility Status:** 100% verified

**Testing:**
- 7 dedicated compatibility tests
- 12 cross-binary tests (C→Rust, Rust→C)
- Byte-level format verification
- Full CLI behavior matching

**Interoperability:**
- ✅ Rust decrypts C-generated encrypted keys
- ✅ Rust verifies C-generated signatures
- ✅ C verifies Rust-generated signatures
- ✅ Key files fully interchangeable
- ✅ All CLI flags and behaviors match

**Deviations:** Only additive (new security features)

### rsign2

**Compatibility:** Claimed and likely accurate

**Verification:** "All signatures produced by rsign can be verified with minisign"

**Interoperability:** Stated but not formally tested in documentation

---

## Development Status & Maintenance

### minisign-rs

**Status:** Active development
- Production ready (v1.3.1, up from v0.12.0 in three weeks)
- Using latest Rust edition (2024)
- Recent commits (February 2026)
- Comprehensive CI/CD
- Significant refactoring: builder patterns, encapsulated APIs, security hardening
- New feature: OS credential store integration

**Roadmap:** Active feature development and quality improvements

**Maintenance:** Highly active with frequent updates

### rsign2

**Status:** Low-activity maintenance
- Stable release (v0.6.5, November 2025)
- Last commit: December 2025 (minor fix for unprintable characters)
- No commits in 2026
- Using older Rust edition (2018)
- Maintained by original minisign author

**Philosophy:** Bug fixes only, no feature expansion

---

## Unique Advantages

### minisign-rs Strengths

1. **Security Auditing:** Unique `-I/--inspect` command for key strength analysis
2. **OS Credential Store:** Native keychain integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
3. **Multi-threaded Operations:** Parallel multi-file signing and verification via `rayon`
4. **Test Coverage:** 479 comprehensive tests with C compatibility validation
5. **Documentation:** Exceptional technical documentation and analysis
6. **Modern Rust:** Edition 2024, latest idioms, builder patterns, encapsulated APIs
7. **Secure Defaults:** Opt-in KDF fallback (fail-secure), weak key warnings
8. **Development Tools:** Password management, key recreation, long flag names
9. **Quality Assurance:** Zero unsafe code, Miri verification, clippy pedantic
10. **Rapid Development:** v0.12.0 to v1.3.1 in three weeks

### rsign2 Strengths

1. **WebAssembly:** Compiles to WASM for browser deployment
2. **Minimal Dependencies:** Only 3 dependencies (vs 14)
3. **Library Architecture:** Clean separation of concerns
4. **Original Author:** Maintained by Frank Denis (minisign creator)
5. **Lightweight:** Reduced footprint for embedded use
6. **Proven Stability:** Maintained fork with established track record

---

## Use Case Scenarios

### CLI signing tool on a developer workstation

**Recommendation: minisign-rs**

You're signing release artifacts, binaries, or packages from your development machine. You want to store your password in the OS keychain rather than typing it repeatedly, inspect key strength after migration, and get warnings if a colleague hands you a weak key file. You may sign batches of files and want parallel operations. Long flag names (`--sign`, `--verify`) make scripts more readable.

rsign2 works for basic sign/verify, but offers no credential store, no key inspection, no multi-file parallelism, and no protection against weak keys.

### CI/CD pipeline signing

**Recommendation: minisign-rs**

Automated builds sign artifacts before publishing. Secret keys are loaded from environment variables or secret managers. In this context, memory zeroization matters: if the CI runner crashes, minisign-rs ensures secret key material is overwritten and Debug output shows `[REDACTED]`. The `minisign` crate's Debug impl would dump raw secret key bytes into crash logs. The fail-secure KDF default prevents accidentally generating weak keys in memory-constrained containers.

rsign2's lack of zeroization and its secret-leaking Debug impl are a concrete risk in shared CI environments where crash logs may be retained or forwarded.

### Browser or edge deployment (WebAssembly)

**Recommendation: rsign2**

You need signature verification running in a browser or WASM runtime. rsign2 compiles to WebAssembly via the `minisign` crate's WASM support. minisign-rs does not support WASM.

Note the security trade-offs: the `minisign` crate's hand-rolled crypto runs in a sandboxed WASM environment where memory forensics and core dump risks are lower, partially mitigating the lack of zeroization.

### Embedding as a Rust library in another project

**Recommendation: rsign2 (with caveats)**

The `minisign` crate is designed as a library with a clean public API. minisign-rs exposes a library interface via `lib.rs` but is primarily designed as a CLI tool.

However, be aware of the security implications: the `minisign` crate's `SecretKey` is `Clone` with no zeroization, its Debug impl leaks key bytes, and the underlying crypto is hand-rolled rather than using audited crates. If your project has strong security requirements, consider wrapping minisign-rs's library API instead, or adding your own zeroization layer around the `minisign` crate.

### Security compliance or audit environment

**Recommendation: minisign-rs**

Your organization requires documented security practices, key strength auditing, and evidence of testing. minisign-rs provides: `-I/--inspect` for key strength auditing, 479 tests including cross-binary C compatibility validation, Miri memory safety verification, zero unsafe code, and comprehensive documentation. rsign2 has 23 tests, no key auditing capability, and no documented security verification process.

### Signing on resource-constrained or embedded systems

**Recommendation: Depends on constraints**

If the constraint is WASM, rsign2 is the only option. If the constraint is memory or binary size on a native target, both work - rsign2 has a smaller dependency tree, but minisign-rs's fail-secure KDF default is more important on low-memory systems where silent KDF fallback could produce weak keys without the user knowing.

---

## Code Quality Comparison

### minisign-rs

**Metrics:**
- Lines of code: ~11,780 (src only, up from ~8,620)
- Source files: 20
- Unsafe blocks: 0
- Clippy warnings: 0 (pedantic)
- Tests: 479 (up from 159)
- Documentation: Extensive inline + external docs

**Practices:**
- Test-driven development
- Property-based testing
- Memory safety verification (Miri)
- Multi-platform CI
- Conventional commits

### rsign2 / minisign crate

**Metrics** (from `minisign` crate v0.8.0, the library rsign2 depends on):
- Crypto source: ~2,918 lines of hand-rolled Ed25519, Curve25519, SHA-512, Blake2b
- Tests: 16 tests in `tests.rs` (263 lines)
- rsign2 CLI itself: 3 source files (main.rs, helpers.rs, parse_args.rs)

---

## Coding Style & Security Architecture

This section compares the security engineering practices, coding patterns, and architectural decisions between the two projects.

### Cryptographic Implementation

| Aspect | minisign-rs | rsign2 / minisign crate |
|--------|-------------|------------------------|
| Ed25519 | `ed25519-dalek` (RustCrypto, audited) | Hand-rolled (~2,150 lines: curve25519.rs + ed25519.rs) |
| Blake2b | `blake2` crate (RustCrypto, audited) | Hand-rolled (289 lines) |
| SHA-512 | Not needed (uses Blake2b throughout) | Hand-rolled (366 lines) |
| Scrypt | `scrypt` crate (RustCrypto) | `scrypt` crate (same) |
| Constant-time eq | `subtle` crate (audited, widely used) | Hand-rolled `fixed_time_eq` (14 lines) |

**Analysis:** minisign-rs delegates all cryptographic primitives to the audited RustCrypto ecosystem. The `minisign` crate (used by rsign2) hand-rolls its own Ed25519, Curve25519, SHA-512, and Blake2b implementations totaling ~2,900 lines. Hand-rolled crypto is a significant risk factor - these implementations have not been independently audited and carry the burden of correctness without the scrutiny that RustCrypto receives.

The `minisign` crate's `crypto/mod.rs` also suppresses multiple clippy warnings (`needless_range_loop`, `unreadable_literal`, `cast_lossless`, `suspicious_arithmetic_impl`, `identity_op`) across the entire crypto module - a practice that reduces static analysis coverage in the most security-critical code.

### Memory Zeroization

| Aspect | minisign-rs | rsign2 / minisign crate |
|--------|-------------|------------------------|
| Secret key zeroization | `#[derive(Zeroize, ZeroizeOnDrop)]` on all secret types | None - `SecretKey` derives `Clone`, no `Drop` impl |
| Password handling | `Zeroizing<String>` wrapper on all passwords | Plain `String`, not zeroized after use |
| Intermediate buffers | `Zeroizing<Vec<u8>>` for decrypted blobs | Plain `Vec<u8>`, left in memory |
| Debug output | `SecretKey` prints `[REDACTED]` | `SecretKey` Debug impl **prints raw hex of secret key bytes** |

**Analysis:** This is the most significant security difference. minisign-rs uses the `zeroize` crate to ensure all secret material is overwritten on drop:

```rust
// minisign-rs: SecretKey is zeroized automatically when dropped
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_BYTES]);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}
```

The `minisign` crate's `SecretKey` has no zeroization at all:

```rust
// minisign crate: SecretKey is Clone, no Zeroize, no ZeroizeOnDrop
#[derive(Clone)]
pub struct SecretKey {
    pub(crate) keynum_sk: KeynumSK,
    // ... fields with raw secret key material
}

// Debug prints the actual secret key bytes as hex
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in self.keynum_sk.sk.iter() {
            write!(f, "{byte:x}")?
        }
        Ok(())
    }
}
```

This means secret key material in rsign2 persists in memory after use and can be leaked via debug formatting, core dumps, or memory inspection.

### Type Safety & Encapsulation

| Aspect | minisign-rs | rsign2 / minisign crate |
|--------|-------------|------------------------|
| Secret key fields | Private, accessed via getters | `pub(crate)`, freely accessible within crate |
| Public key type | Newtype wrapper with const constructors | Struct with public-ish fields |
| Key number type | Newtype `KeyNum([u8; 8])` with `Zeroize` | Raw `[u8; KEYNUM_BYTES]` array |
| Signature type | Newtype with private fields, getters | Raw byte arrays |
| Error handling | `thiserror` with typed variants | Custom `PError` with string messages |
| Clippy strictness | Pedantic, zero warnings | Suppressed warnings in crypto module |
| `#[must_use]` | On all getters | Not used |

**Analysis:** minisign-rs uses newtype wrappers to prevent accidental misuse (e.g., passing a public key where a secret key is expected). The `minisign` crate uses raw byte arrays throughout, relying on naming conventions rather than the type system for correctness.

### Error Handling

| Aspect | minisign-rs | rsign2 / minisign crate |
|--------|-------------|------------------------|
| Error type | `thiserror`-derived enum with typed variants | `PError` with `ErrorKind` enum + string messages |
| `.unwrap()` in production | None (enforced by policy) | Present in rsign2 CLI (e.g., `sign_action.get_one::<String>("data").unwrap()`) |
| `.expect()` in production | None | Present in minisign crate (e.g., `unix_timestamp`) |

### Testing

| Aspect | minisign-rs | rsign2 / minisign crate |
|--------|-------------|------------------------|
| Test count | 479 | 16 (in `minisign` crate) + 7 (in rsign2 `helpers.rs`) = 23 |
| Property-based tests | Yes (`proptest`) | No |
| C interop tests | 12 cross-binary tests | None documented |
| Doc tests | Yes | No |
| Miri verification | Weekly CI runs | No |
| CI platforms | Linux, macOS, Windows | Unknown |

---

## Dependency Security

### minisign-rs

**Cryptographic Dependencies:**
- `ed25519-dalek` - RustCrypto, independently audited
- `blake2` - RustCrypto, independently audited
- `scrypt` - RustCrypto
- `zeroize` - RustCrypto, security-critical
- `subtle` - RustCrypto, constant-time operations

**Audit Status:** All crypto delegated to audited RustCrypto ecosystem

**Direct Control:** All dependencies explicitly chosen and managed

### rsign2

**Cryptographic Implementation:** The `minisign` crate hand-rolls Ed25519, Curve25519, SHA-512, and Blake2b (~2,900 lines). Only `scrypt` uses an external crate.

**Dependency Chain:** rsign2 → `minisign` crate → hand-rolled crypto + `scrypt`

**Audit Status:** Not independently audited. Maintained by Frank Denis (high trust, author of libsodium), but the hand-rolled Rust crypto has not received the same scrutiny as the C libsodium implementation.

---

## Community & Ecosystem

### minisign-rs

- GitHub: `lookbusy1344/minisign`
- Stars: Unknown (newer project)
- Contributors: Active development team
- Issues: Tracked on GitHub
- Documentation: Self-contained

### rsign2

- GitHub: `jedisct1/rsign2`
- Stars: 149
- Author: Frank Denis (jedisct1)
- Ecosystem: Part of jedisct1's security tool suite
- Documentation: Links to broader minisign ecosystem

---

## Limitations & Tradeoffs

### minisign-rs

**Limitations:**
- ❌ No WebAssembly support
- ⚠️ Larger binary size (~1.1 MB vs 70 KB C)
- ⚠️ More dependencies to audit (15 vs 3)
- ⚠️ Newer project (less battle-tested)

**Tradeoffs:**
- Comprehensive features → More complexity
- Enhanced security → Additional maintenance
- Extensive tests → Longer CI times

### rsign2

**Limitations:**
- ❌ No security auditing features
- ❌ Limited advanced operations
- ⚠️ Older Rust edition (2018 vs 2024)
- ⚠️ Less comprehensive documentation

**Tradeoffs:**
- Minimal dependencies → Fewer features
- Library-first → Less CLI polish
- Lightweight → Limited enhancements

---

## Future Outlook

### minisign-rs

**Trajectory:** Rapid feature development with strong quality discipline

**Recent Additions (since v0.12.0):**
- OS credential store integration (keyring)
- Builder pattern APIs for options structs
- Encapsulated fields with getter methods
- Security hardening (improved zeroization)
- Major test expansion (159 → 479 tests)

**Potential Future Additions:**
- macOS biometric (Touch ID) authentication (design plan exists)
- Hardware security module (HSM) support
- Additional key management enhancements

**Maintenance:** Highly active, frequent releases

### rsign2

**Trajectory:** Minimal maintenance, no feature development

**Focus:** Occasional bug fixes only

**Activity:** Last commit December 2025, no commits in 2026

**Maintenance:** Low activity; appears to be in maintenance-only mode

---

## Technical Deep Dives

### KDF Parameter Handling

**minisign-rs Approach:**
```rust
// Default: N=2^20 (33,554,432 ops, 1GB RAM)
// Fallback only with --allow-kdf-fallback flag
// Fails immediately if allocation fails (secure default)
```

**Security Philosophy:** Fail-secure by default
- Forces explicit opt-in for weaker security
- Provides persistent warnings for weak keys
- Enables security auditing of existing keys

**rsign2 Approach:**
Uses underlying `minisign` crate behavior (likely standard fallback)

### Memory Safety Verification

**minisign-rs:**
- Weekly Miri runs in CI
- Detects undefined behavior in pure Rust code
- Tests crypto operations under strict scrutiny
- Verifies zeroization effectiveness

**rsign2:**
- Standard Rust safety guarantees
- Likely no formal Miri verification

### Signature Format Compatibility

Both implementations use identical signature formats:
```
untrusted comment: <comment>
<base64_signature>
trusted comment: <comment>
<base64_global_signature>
```

**Verification:** minisign-rs has 12 cross-binary tests confirming format compatibility

---

## Conclusion

### Clear Advantages: minisign-rs

**Security Architecture:**

1. **Audited cryptographic primitives** - All crypto delegated to the RustCrypto ecosystem (`ed25519-dalek`, `blake2`, `scrypt`, `subtle`), which receives independent audits and broad community scrutiny. The `minisign` crate used by rsign2 hand-rolls ~2,900 lines of Ed25519, Curve25519, SHA-512, and Blake2b that have not been independently audited.
2. **Memory zeroization** - All secret types derive `Zeroize` and `ZeroizeOnDrop`, passwords are wrapped in `Zeroizing<String>`, and intermediate decrypted buffers use `Zeroizing<Vec<u8>>`. The `minisign` crate has no zeroization at all - secret key material persists in memory after use.
3. **Safe Debug output** - `SecretKey` debug prints `[REDACTED]`. The `minisign` crate's `SecretKey` debug impl prints the raw secret key bytes as hex, meaning logging, panics, or `dbg!()` calls could leak key material to logs or crash reports.
4. **Fail-secure KDF** - Refuses to generate weak keys by default; requires explicit `--allow-kdf-fallback` opt-in. The `minisign` crate silently falls back to weaker parameters.
5. **Key security inspection** (`-I/--inspect`) - Audits KDF parameters, rates key strength (HIGH/MEDIUM/LOW/NONE), calculates brute-force resistance, provides remediation advice.
6. **Weak key warnings** - Persistent warnings on every operation when using keys with weak KDF parameters.

**Features:**

7. **OS credential store** - Stores passwords in macOS Keychain, Windows Credential Manager, or Linux Secret Service instead of prompting every time.
8. **Multi-threaded operations** - Parallel signing and verification of multiple files via `rayon`.
9. **Password management** (`-K`) - Add, remove, or change password on existing secret keys.
10. **Public key recreation** (`-R`) - Recover public key from secret key.
11. **Long flag names** - `--generate`, `--sign`, `--verify`, `--inspect`, etc.

**Code Quality:**

12. **479 tests vs 23** - Including C interop, cross-binary, property-based (`proptest`), and doc tests. rsign2 + the `minisign` crate have 23 tests combined.
13. **Zero unsafe code** - Enforced by policy. The `minisign` crate's hand-rolled crypto, while technically safe Rust, suppresses clippy warnings (`suspicious_arithmetic_impl`, `cast_lossless`, etc.) across the entire crypto module.
14. **Type safety** - Newtype wrappers with private fields and `#[must_use]` getters prevent misuse at compile time. The `minisign` crate uses raw byte arrays throughout.
15. **No `.unwrap()` in production** - Enforced by policy. rsign2's CLI uses `.unwrap()` on user input parsing.
16. **Miri verification** - Weekly CI runs detect undefined behavior and verify zeroization effectiveness.
17. **Modern Rust** - Edition 2024, builder patterns, encapsulated APIs. rsign2 uses edition 2018.
18. **Active development** - v0.12.0 to v1.3.1 in three weeks (Jan-Feb 2026).

### Clear Advantages: rsign2

1. **WebAssembly compilation** - Compiles to WASM for browser and edge deployment. minisign-rs does not support WASM.
2. **Fewer direct dependencies** - 3 direct dependencies vs 15. However, this is partly because the `minisign` crate hand-rolls crypto that minisign-rs delegates to audited libraries, so the "smaller audit surface" argument cuts both ways: fewer crates to audit, but ~2,900 lines of unaudited hand-rolled crypto to review instead.
3. **Library-first architecture** - Designed for embedding in other Rust projects via the `minisign` crate.
4. **Original author** - Maintained by Frank Denis, creator of C minisign and libsodium.
5. **Smaller binary footprint** - Fewer transitive dependencies, lighter binary.

### Shared Capabilities

Both implementations provide:
- Ed25519 signing and verification, compatible with C minisign
- Scrypt KDF with production parameters
- Constant-time comparison (via `subtle` crate or hand-rolled `fixed_time_eq`)
- Prehashed mode for large files
- Trusted and untrusted comments
- Cross-platform support (Linux, macOS, Windows)

**Note:** The original comparison listed "Memory wiping via `zeroize`" as shared. This is incorrect - the `minisign` crate does not use `zeroize` or any memory wiping mechanism. Only minisign-rs zeroizes secret material.

### Security Implications

The differences above have concrete security implications:

| Scenario | minisign-rs | rsign2 |
|----------|-------------|--------|
| Process crash with core dump | Secret keys zeroized, debug output redacted | Secret keys in plaintext in core dump, Debug leaks hex bytes |
| Memory forensics after signing | Passwords and keys overwritten on drop | Passwords and keys persist in memory until overwritten by allocator |
| Weak key generated on low-RAM system | Fails by default; explicit opt-in required | Silently falls back to weaker parameters |
| Key created with weak KDF discovered later | `-I/--inspect` identifies it, every operation warns | No way to detect or audit key strength |
| Logging framework captures Debug output | `SecretKey([REDACTED])` | Raw secret key bytes in hex |

### Recommendation Matrix

| Requirement | Recommendation | Why |
|-------------|---------------|-----|
| Production deployment | minisign-rs | Zeroization, audited crypto, 479 tests, active development |
| Security compliance | minisign-rs | Key inspection, zeroization, safe Debug, no `.unwrap()` |
| Memory-safe secret handling | minisign-rs | `Zeroize`/`ZeroizeOnDrop` on all secrets; rsign2 has none |
| Audited crypto primitives | minisign-rs | RustCrypto ecosystem vs ~2,900 lines hand-rolled |
| Credential management | minisign-rs | OS keychain integration, password management |
| Multi-file workflows | minisign-rs | Parallel signing/verification via rayon |
| Command-line power user | minisign-rs | Long flags, inspect, recreate, advanced features |
| C compatibility proof | minisign-rs | Formally tested with cross-binary validation |
| WebAssembly/browser | rsign2 | Native WASM compilation support |
| Embedded in Rust projects | rsign2 | Library-first design via `minisign` crate |

### Final Verdict

**CLI tool (developer workstation, CI/CD, scripting):** minisign-rs. Credential store integration, key inspection, multi-threaded operations, memory zeroization, safe Debug output, and 479 tests make it the production-grade choice. rsign2's lack of zeroization and secret-leaking Debug impl are concrete risks in any environment where crash logs are retained or processes are shared.

**WebAssembly (browser, edge, serverless):** rsign2. It's the only option that compiles to WASM. The sandboxed execution model partially mitigates the zeroization and memory forensics concerns.

**Rust library embedding:** rsign2 has the cleaner library API via the `minisign` crate, but with significant security caveats (no zeroization, hand-rolled crypto, Debug leaks secrets). For security-critical applications, consider wrapping minisign-rs's library interface instead.

**Security audit or compliance:** minisign-rs. Key strength auditing (`--inspect`), documented testing (479 tests with Miri verification), audited RustCrypto dependencies, and comprehensive documentation provide the evidence trail that compliance environments require.

**Both projects** produce signatures that are fully compatible with C minisign and with each other.

---

## Appendix: Quick Reference

### Command Comparison

| Operation | minisign-rs | rsign2 |
|-----------|-------------|--------|
| Generate keys | `minisign_rs -G` | `rsign2 generate` |
| Sign file | `minisign_rs -S -m file.txt` | `rsign2 sign file.txt` |
| Verify signature | `minisign_rs -V -m file.txt -p key.pub` | `rsign2 verify file.txt -p key.pub` |
| Inspect key | `minisign_rs -I -s key.key` | ❌ Not available |
| Change password | `minisign_rs -K` | ❌ Not available |
| Recreate pubkey | `minisign_rs -R` | ❌ Not available |
| Credential store | Built-in (keyring feature) | ❌ Not available |

### Resource Links

**minisign-rs:**
- Repository: https://github.com/lookbusy1344/minisign
- Documentation: ./README.md, ./COMPATIBILITY.md, ./docs/*

**rsign2:**
- Repository: https://github.com/jedisct1/rsign2
- WAPM Package: https://wapm.io/package/jedisct1/rsign2

**Original minisign:**
- Repository: https://github.com/jedisct1/minisign
- Website: https://jedisct1.github.io/minisign/

---

**Report Version:** 2.0
**Generated:** 2026-02-17 (updated from 2026-01-26)
**Comparison Basis:** minisign-rs v1.3.1, rsign2 v0.6.5
