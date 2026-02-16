# Minisign-rs Architecture

Internal design and code organization for minisign-rs.

**See also:**
- [README.md](../README.md) - Project overview
- [USAGE.md](USAGE.md) - Usage guide
- [TESTING.md](TESTING.md) - Testing guide
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---

## Overview

Minisign-rs is a pure Rust implementation of minisign, designed for byte-level compatibility with the original C implementation. The architecture prioritizes security, maintainability, and type safety while avoiding unsafe code and C dependencies.

## Module Structure

```
src/
├── lib.rs              # Public API exports
├── main.rs             # CLI entry point
├── cli.rs              # Command-line interface
├── constants.rs        # Centralized size and parameter constants
├── crypto.rs           # Ed25519, Blake2b, Scrypt wrappers
├── keys.rs             # Key types, generation, encryption
├── signature.rs        # Signature creation and verification
├── credential_store.rs # OS credential store integration
├── formats.rs          # Binary and base64 encoding/decoding
├── validation.rs       # Comment and input validation (C compatibility)
├── wordlist.rs         # PGP Word List for human-readable key IDs
├── errors.rs           # Error types with thiserror
└── ops/                # High-level operations
    ├── generate.rs    # Key generation
    ├── sign.rs        # File signing
    ├── verify.rs      # Signature verification
    ├── recreate.rs    # Public key recovery
    ├── change.rs      # Password management
    ├── inspect.rs     # Security auditing
    └── file_utils.rs  # File I/O utilities
```

## Design Principles

1. **Pure Rust**: No unsafe blocks, no FFI, no C dependencies
2. **Security-First**: Zeroization of secrets, constant-time operations
3. **Test-Driven**: Every feature has tests before implementation
4. **Type-Safe**: Newtype wrappers prevent mixing up keys/signatures
5. **Compatibility**: Byte-level compatibility with C minisign

## Type System and Key Abstractions

### Newtype Wrappers

The codebase uses strongly-typed newtype wrappers to prevent type confusion and enforce security properties:

```rust
// Security-sensitive types with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 64]);

// Public cryptographic types
pub struct PublicKey([u8; 32]);
pub struct Signature([u8; 64]);
pub struct KeyNum([u8; 8]);
```

These newtypes prevent accidental misuse (e.g., passing a signature where a public key is expected) and enable implementing trait-based security controls.

### Binary Format Types

File format structures mirror the on-disk binary layout:

- `PubkeyStruct` - 42-byte public key file format
- `SeckeyStruct` - 158-byte secret key file format
- `SigStruct` - 74-byte signature structure
- `SignatureBox` - Complete signature file with comments

All format types include explicit byte offset constants and validation logic to ensure compatibility with the C implementation.

### Builder Pattern

Complex operations use the builder pattern to provide ergonomic APIs with many optional parameters:

```rust
SignOptionsBuilder::new(secret_key_file, message_file)
    .prehashed(true)
    .trusted_comment(Some("my comment"))
    .force(true)
    .build()
```

This pattern replaced functions with 3+ boolean parameters, significantly improving code clarity and reducing the potential for argument confusion.

## Error Handling

### Error Types

The `Error` enum (defined in `src/errors.rs`) uses `thiserror` for ergonomic error handling:

```rust
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read file {path:?}: {source}")]
    FileRead { path: PathBuf, source: io::Error },

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("decryption failed: wrong password")]
    DecryptionFailed,

    // ... other variants
}
```

### Error Propagation

All operations use the `?` operator for error propagation. The codebase strictly avoids:

- `.unwrap()` in production code paths
- `.expect()` in production code paths
- Panic-based error handling

### Security-Conscious Errors

Error messages never expose sensitive data:

- Secret keys shown as `SecretKey([REDACTED])` in debug output
- No password hints or fragments in error messages
- File paths sanitized to prevent information leakage

## Security Model

### Memory Safety and Zeroization

All security-sensitive types use automatic zeroization:

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_BYTES]);
```

The `Zeroizing` wrapper provides scope-based cleanup for temporary secrets:

```rust
let password = Zeroizing::new(password_bytes);
// Automatically zeroed when dropped
```

### Constant-Time Operations

Cryptographic comparisons use constant-time operations from the `subtle` crate:

```rust
use subtle::ConstantTimeEq;

if checksum.ct_eq(&expected_checksum).into() {
    // Comparison resistant to timing attacks
}
```

This prevents timing side-channel attacks when comparing:
- Checksums during decryption
- Key IDs during verification
- Any security-critical values

### Cryptographic Primitives

All cryptographic operations are delegated to audited pure-Rust libraries:

- **Ed25519 signatures**: `ed25519-dalek` (pure Rust, no unsafe code)
- **Blake2b hashing**: `blake2` (RustCrypto)
- **Scrypt KDF**: `scrypt` (RustCrypto)
- **Random generation**: `rand_core` with `OsRng` (OS entropy source)

### Secure Defaults

- Prehashed mode enabled by default (efficient for large files)
- Production-strength scrypt parameters (N=2^20, ~1GB memory)
- Encrypted keys by default (password required)
- No credential storage unless explicitly enabled with `--save-password`

### Zero Unsafe Code

The entire codebase maintains a strict "no unsafe code" policy. All memory safety is guaranteed by Rust's type system and borrow checker. This is verified by:

- Clippy pedantic mode in CI
- Regular security audits
- No `#[allow(unsafe)]` annotations

## Component Interaction

### Data Flow: Signing

```
CLI (cli.rs)
  └─> sign operation (ops/sign.rs)
       ├─> load secret key (ops/file_utils.rs)
       │    └─> decrypt if needed (keys.rs)
       │         └─> scrypt KDF (crypto.rs)
       ├─> hash file with Blake2b (crypto.rs)
       ├─> sign hash with Ed25519 (crypto.rs)
       └─> write signature file (signature.rs)
```

### Data Flow: Verification

```
CLI (cli.rs)
  └─> verify operation (ops/verify.rs)
       ├─> load public key (ops/file_utils.rs)
       │    └─> parse base64 format (formats.rs)
       ├─> load signature (signature.rs)
       ├─> hash file with Blake2b (crypto.rs)
       └─> verify with Ed25519 (crypto.rs)
```

### Multi-File Operations

Multi-file signing and verification use Rayon for parallel execution:

```rust
files.par_iter().for_each(|file| {
    // Sign or verify each file in parallel
});
```

Results are collected, errors are reported, and exit codes reflect partial vs. total failure.

### Credential Store Integration

The credential store feature (`credential_store.rs`) provides optional OS keyring integration:

```
sign/verify operation
  └─> password required
       ├─> check credential store (if --save-password)
       │    └─> OS keyring API (keyring crate)
       └─> prompt user if not found
            └─> optionally save to credential store
```

When the `credential_store` feature is disabled (default for tests), all credential store operations become no-ops.

## Dependencies

### Core Cryptography

- `ed25519-dalek` - Ed25519 signatures (pure Rust)
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation function
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time comparisons

### System Integration

- `keyring` - OS credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service)

### Utilities

- `rayon` - Data-parallel iteration for multi-file signing/verification
- `base64` - Base64 encoding/decoding
- `rand_core` - Cryptographic random number generation (OS entropy)
- `thiserror` - Library error types
- `rpassword` - Secure password input
- `dirs` - Cross-platform directory discovery
- `clap` - CLI argument parsing
- `git-version` - Embed git version info at compile time

### Development

- `assert_cmd` - CLI testing
- `predicates` - Test assertions
- `tempfile` - Temporary file handling
- `proptest` - Property-based testing
- `rand` - Random number generation for tests
- `hex` - Hex encoding for tests
- `serial_test` - Sequential test execution for credential store tests

## Performance Considerations

### Memory Efficiency

The codebase avoids unnecessary cloning:

- References (`&Path`, `&str`, `&[T]`) preferred over owned types
- `as_ref()`/`as_deref()` used to extract references from `Option<T>`
- `Cow<T>` for conditional ownership

### Streaming Operations

Blake2b hashing uses streaming with 8KB buffers to minimize memory usage for large files:

```rust
const STREAM_BUFFER_SIZE: usize = 8192;

let mut buffer = [0u8; STREAM_BUFFER_SIZE];
while let Ok(n) = reader.read(&mut buffer) {
    hasher.update(&buffer[..n]);
}
```

This enables signing files of arbitrary size without loading them entirely into memory.

### Parallel Execution

Multi-file operations leverage Rayon for automatic parallelization across CPU cores, significantly reducing wall-clock time for batch operations.

## API Design

### Encapsulation

Security-sensitive types use private fields with accessor methods:

```rust
pub struct PubkeyStruct {
    sig_alg: [u8; 2],      // private
    keynum: KeyNum,        // private
    public_key: PublicKey, // private
}

impl PubkeyStruct {
    #[must_use]
    pub const fn keynum(&self) -> &KeyNum { &self.keynum }

    #[must_use]
    pub const fn public_key(&self) -> &PublicKey { &self.public_key }
}
```

This provides:
- Future flexibility (can change internal representation)
- Invariant enforcement (fields can't be independently modified)
- Better API documentation surface

### Must-Use Annotations

Getters and constructors use `#[must_use]` to catch accidental unused results:

```rust
#[must_use]
pub const fn keynum(&self) -> &KeyNum { &self.keynum }
```

This prevents bugs where functions are called but their results ignored.

## Compatibility Layer

### Binary Format Compatibility

All binary formats exactly match the C implementation:

- Byte ordering (little-endian for multi-byte integers)
- Field sizes and offsets
- Magic bytes and algorithm identifiers
- Base64 encoding format

### Comment Validation

The validation module (`validation.rs`) enforces C-compatible constraints:

- Maximum comment lengths matching C buffers
- Allowed character sets
- Null terminator handling
- Windows path validation

### Scrypt Parameter Conversion

Scrypt parameters convert between Rust (N, r, p) and C libsodium (opslimit, memlimit) formats using the libsodium formulas:

```rust
opslimit = N * r * p * MULTIPLIER
memlimit = (N * r * 128) * p * MULTIPLIER
```

This ensures encrypted keys are interoperable between C and Rust implementations.

## Configuration

### Feature Flags

- `credential_store` (default) - OS keyring integration
- `credential_store_tests` (opt-in) - Interactive credential store tests

### Environment Variables

- `MINISIGN_CONFIG_DIR` - Override default key directory

### Scrypt Test Parameters

Fast tests use reduced scrypt parameters (N=2^14) for quick iteration, while slow tests (`#[ignore]`) use production parameters (N=2^20) for security validation.

## Testing Strategy

See [TESTING.md](TESTING.md) for comprehensive testing documentation.

Key testing principles:

- **TDD required** - tests before implementation
- **Fast test suite** (~468 tests, ~9s) with reduced scrypt parameters
- **Slow security tests** (11 tests, ~11s) with production scrypt parameters
- **Compatibility tests** with C minisign for binary format verification
- **Property-based tests** with proptest for fuzzing-style validation
- **All tests in `tests/` directory** for proper CodeQL analysis exclusions
