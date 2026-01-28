# Security Review: minisign-rs

**Date:** 2026-01-28
**Version:** 0.12.0
**Reviewer:** Claude (Opus 4.5)
**Scope:** Full security review of architecture, code, and dependencies

---

## Executive Summary

The minisign-rs project is a well-architected, security-conscious implementation of the minisign cryptographic signing tool. The codebase demonstrates strong security practices including:

- **Zero unsafe code** - 100% safe Rust
- **Proper secret handling** with `Zeroize` and `ZeroizeOnDrop`
- **Constant-time comparisons** using the `subtle` crate
- **Atomic file operations** preventing TOCTOU race conditions
- **Comprehensive input validation** matching C implementation behavior
- **No known vulnerabilities** in dependencies (verified with `cargo audit`)

Overall assessment: **PRODUCTION READY** with minor recommendations.

---

## Table of Contents

1. [Architecture Assessment](#architecture-assessment)
2. [Cryptographic Implementation Review](#cryptographic-implementation-review)
3. [Secret Handling](#secret-handling)
4. [Input Validation](#input-validation)
5. [File Operations Security](#file-operations-security)
6. [Error Handling](#error-handling)
7. [Dependency Analysis](#dependency-analysis)
8. [Potential Security Issues](#potential-security-issues)
9. [Recommendations](#recommendations)
10. [Conclusion](#conclusion)

---

## Architecture Assessment

### Overall Structure

The project follows a clean separation of concerns:

```
src/
├── crypto.rs      # Low-level cryptographic primitives
├── keys.rs        # Key structures and encryption/decryption
├── signature.rs   # Signature structures and verification
├── validation.rs  # Input validation (C-compatible)
├── formats.rs     # Base64 and binary encoding
├── errors.rs      # Error types (no secret leakage)
├── ops/           # High-level operations
│   ├── generate.rs
│   ├── sign.rs
│   ├── verify.rs
│   └── ...
└── main.rs        # CLI entry point
```

### Strengths

1. **Layered Design**: Clear separation between cryptographic primitives (`crypto.rs`), data structures (`keys.rs`, `signature.rs`), and operations (`ops/`).

2. **Single Responsibility**: Each module has a well-defined purpose, reducing the attack surface within any single component.

3. **Type Safety**: Newtype wrappers (`SecretKey`, `PublicKey`, `Signature`, `KeyNum`) prevent accidental mixing of cryptographic values.

4. **No Global State**: Operations are stateless with all context passed explicitly.

### Assessment: ✅ Well-architected

---

## Cryptographic Implementation Review

### Algorithm Selection

| Component | Algorithm | Library | Status |
|-----------|-----------|---------|--------|
| Signatures | Ed25519 | ed25519-dalek 2.2.0 | ✅ Secure |
| Hashing | Blake2b-256/512 | blake2 0.10.6 | ✅ Secure |
| KDF | Scrypt (N=2²⁰, r=8, p=1) | scrypt 0.11.0 | ✅ Secure |
| RNG | OS CSPRNG | getrandom 0.3.4 | ✅ Secure |

All cryptographic libraries are from the well-audited RustCrypto ecosystem.

### Key Derivation Parameters

The default scrypt parameters match libsodium's SENSITIVE level:

```rust
// crypto.rs:23-27
pub const SCRYPT_LOG_N: u8 = 20;  // N = 2^20 = 1,048,576
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;
```

This provides ~128 MB memory usage and 1-5 seconds per derivation, which is appropriate for key protection.

### Encryption Scheme

Secret keys use XOR encryption with the scrypt-derived key:

```rust
// keys.rs:399-403
// Encrypt entire blob with XOR
let mut encrypted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
for i in 0..ENCRYPTED_BLOB_SIZE {
    encrypted_blob[i] = blob[i] ^ derived_key[i];
}
```

This is acceptable because:
1. The KDF output is uniformly random
2. The same key is never reused (unique salt per key)
3. This matches the C minisign implementation for compatibility

### Constant-Time Operations

Checksum verification uses constant-time comparison:

```rust
// keys.rs:490-491
if computed_checksum.ct_eq(&decrypted_checksum).into() {
```

This prevents timing side-channel attacks during password verification.

### Assessment: ✅ Cryptographically sound

---

## Secret Handling

### Automatic Zeroization

Secret keys implement automatic memory clearing:

```rust
// crypto.rs:41-42
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; SECRET_KEY_BYTES]);
```

### Debug Output Redaction

Secrets are redacted from debug output:

```rust
// crypto.rs:58-62
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}
```

### Password Handling

Passwords are wrapped in `Zeroizing<String>`:

```rust
// main.rs:396,425-426
fn prompt_password(...) -> Result<Zeroizing<String>> {
    ...
    rpassword::read_password()
        .map(Zeroizing::new)
```

### Derived Key Handling

All KDF outputs use `Zeroizing<Vec<u8>>`:

```rust
// crypto.rs:317-318
pub fn derive_key_with_params(...) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(vec![0u8; output_len]);
```

### Intermediate Values

Decryption blobs are zeroized:

```rust
// keys.rs:469
let mut decrypted_blob = Zeroizing::new([0u8; ENCRYPTED_BLOB_SIZE]);
```

### Assessment: ✅ Proper secret handling

---

## Input Validation

### Comment Validation

Comments are validated for:
1. **Printable characters** (matching C `is_printable()`)
2. **No control characters** (0x00-0x1F except tab, 0x7F)
3. **No C1 control characters** (U+0080-U+009F)
4. **No embedded carriage returns**
5. **Valid UTF-8 sequences**
6. **No overlong encodings**
7. **No surrogate pairs**

```rust
// validation.rs:56-146
pub fn is_printable(s: &str) -> Result<()> {
    // Comprehensive UTF-8 validation matching C implementation
}
```

This prevents display-based attacks via control characters.

### Length Limits

Comment lengths are enforced:

```rust
// signature.rs:18-21
pub const COMMENTMAXBYTES: usize = 1024;
pub const TRUSTEDCOMMENTMAXBYTES: usize = 8192;
```

### File Size Limits

Non-prehashed mode has a 1 GB limit to prevent DoS:

```rust
// constants.rs (via ops/sign.rs)
pub const MAX_MESSAGE_SIZE_BYTES: u64 = 1_073_741_824; // 1 GB
```

### Assessment: ✅ Thorough input validation

---

## File Operations Security

### Atomic File Creation

Files are created atomically to prevent TOCTOU races:

```rust
// file_utils.rs:54-56
// Normal mode: fail if file already exists (atomic check)
options.create_new(true);
```

### Secret Key Permissions

On Unix, secret keys are created with mode 0600:

```rust
// file_utils.rs:59-63
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(SECRET_KEY_FILE_PERMISSIONS);  // 0o600
}
```

### Secure File Overwriting

Force mode properly truncates before writing:

```rust
// file_utils.rs:50-52
if force {
    options.create(true).truncate(true);
}
```

### Assessment: ✅ Secure file handling

---

## Error Handling

### No Secret Leakage

Error messages do not contain secrets:

```rust
// errors.rs - Error types reveal no sensitive data
#[error("checksum verification failed")]
ChecksumFailed,

#[error("decryption failed: wrong password")]
DecryptionFailed,
```

### Consistent Error Types

All operations return `Result<T, Error>` with well-defined error variants.

### Assessment: ✅ Safe error handling

---

## Dependency Analysis

### Production Dependencies

| Crate | Version | Purpose | Security Notes |
|-------|---------|---------|----------------|
| ed25519-dalek | 2.2.0 | Ed25519 signatures | RustCrypto, audited |
| blake2 | 0.10.6 | Blake2b hashing | RustCrypto |
| scrypt | 0.11.0 | Key derivation | RustCrypto |
| subtle | 2.6.1 | Constant-time ops | RustCrypto |
| zeroize | 1.8.2 | Memory clearing | RustCrypto, critical |
| rand | 0.8.5 | CSPRNG | Well-maintained |
| getrandom | 0.3.4 | OS randomness | RustCrypto |
| clap | 4.5.55 | CLI parsing | No security impact |
| base64 | 0.22.1 | Encoding | No security impact |
| rpassword | 7.4.0 | Password input | Trusted crate |
| thiserror | 2.0.18 | Error handling | No security impact |
| dirs | 6.0.0 | Config directories | No security impact |
| is-terminal | 0.4.17 | TTY detection | No security impact |
| git-version | 0.3.9 | Version embedding | No security impact |

### Vulnerability Scan

```
$ cargo audit
    Fetching advisory database...
    Loaded 907 security advisories
    Scanning Cargo.lock for vulnerabilities (150 crate dependencies)
    No vulnerabilities found!
```

### rand Version Note

The project uses rand 0.8.5 instead of 0.9.x due to compatibility issues:

```toml
rand = "0.8"  # 0.9 available but causes compatibility issues
```

This is documented and intentional. rand 0.8.5 has no known vulnerabilities.

### Assessment: ✅ Dependencies are secure

---

## Potential Security Issues

### Issue 1: KDF Fallback Mechanism (By Design)

**Location:** `keys.rs:342-391`

**Description:** When memory is insufficient, the KDF parameters can be reduced by halving N repeatedly until key derivation succeeds.

**Mitigation Already In Place:**
- Fallback is **opt-in only** (`--allow-kdf-fallback` flag required)
- Clear warnings are displayed when fallback is used
- `is_weak_kdf()` function detects and warns on weak keys
- Minimum parameters are enforced

**Assessment:** ✅ Properly mitigated through opt-in design and warnings

### Issue 2: Unencrypted Keys Option

**Location:** `keys.rs:294-308`

**Description:** The `-W` flag allows creating unencrypted secret keys.

**Mitigation Already In Place:**
- Explicit opt-in required
- Clearly labeled in file comments as "minisign secret key" (vs "encrypted secret key")
- `--inspect` command warns about unencrypted keys

**Assessment:** ✅ Acceptable - matches C minisign behavior, user choice

### Issue 3: Password File Option

**Location:** `main.rs:401-409`

**Description:** `--password-file` option allows reading passwords from files.

**Mitigation Already In Place:**
```rust
#[cfg(not(debug_assertions))]
eprintln!(
    "Warning: --password-file is insecure and should only be used for testing purposes."
);
```

**Assessment:** ⚠️ Minor concern - warning is helpful, but option exists for automation needs

### Issue 4: Debug-Only Weak KDF Flag

**Location:** `generate.rs:39-41`, `main.rs:79-80`

```rust
#[cfg(debug_assertions)]
pub force_weak_kdf: bool,
```

**Assessment:** ✅ Safe - only available in debug builds, never in release

---

## Recommendations

### High Priority

None identified.

### Medium Priority

1. **Consider fsync() on key files**

   After writing secret key files, consider calling `sync_all()` to ensure data is durably written to disk before returning success:

   ```rust
   file.write_all(contents.as_bytes())?;
   file.sync_all()?;  // Ensure durability
   ```

   This prevents data loss if the system crashes immediately after key generation.

2. **Document password strength recommendations**

   Consider adding password strength guidance to the README or help output. The scrypt parameters are strong, but weak passwords still reduce security.

### Low Priority

1. **Consider umask interaction on Unix**

   While `mode(0o600)` is set, the effective permissions could be affected by umask in edge cases. The current implementation is correct for `create_new`, but documenting this behavior might be helpful.

2. **Add SBOM generation to CI**

   Consider adding Software Bill of Materials generation for supply chain security visibility.

3. **Pin dependencies more precisely**

   The Cargo.toml uses semver ranges (e.g., `blake2 = "0.10"`). For a security-critical project, consider using exact versions or narrower ranges to prevent unexpected updates.

---

## Test Coverage Analysis

The project has comprehensive testing:

| Category | Tests | Coverage |
|----------|-------|----------|
| Unit tests | 212 | Core functionality |
| Integration tests | 77 | CLI and cross-binary |
| Property tests | 30+ | Randomized input validation |
| Compatibility tests | 7 | C minisign interop |
| Slow security tests | 11 | Full KDF parameters |

Notable security-focused tests:
- `test_secret_key_debug()` - Verifies no secret leakage in debug output
- `test_decrypt_with_wrong_password()` - Verifies checksum validation
- `test_atomic_file_creation_prevents_race()` - Verifies TOCTOU prevention
- Property tests for constant-time behavior

---

## Conclusion

The minisign-rs project demonstrates excellent security practices for a cryptographic tool:

| Category | Rating |
|----------|--------|
| Architecture | ✅ Excellent |
| Cryptographic Implementation | ✅ Excellent |
| Secret Handling | ✅ Excellent |
| Input Validation | ✅ Excellent |
| File Operations | ✅ Excellent |
| Error Handling | ✅ Excellent |
| Dependencies | ✅ Excellent |

**Overall Assessment: PRODUCTION READY**

The codebase follows security best practices, uses well-audited cryptographic libraries, properly handles secrets, and has comprehensive test coverage. The identified issues are either by design (with appropriate mitigations) or low priority improvements.

---

## Appendix: Files Reviewed

- `src/crypto.rs` - Cryptographic primitives
- `src/keys.rs` - Key structures and encryption
- `src/signature.rs` - Signature handling
- `src/validation.rs` - Input validation
- `src/formats.rs` - Encoding helpers
- `src/errors.rs` - Error types
- `src/main.rs` - CLI entry point
- `src/ops/generate.rs` - Key generation
- `src/ops/sign.rs` - Signing operations
- `src/ops/verify.rs` - Verification operations
- `src/ops/file_utils.rs` - File operations
- `Cargo.toml` - Dependencies
- `Cargo.lock` - Locked dependency versions

## Appendix: Tools Used

- `cargo audit 0.22.0` - Vulnerability scanning
- Manual code review
- Static analysis via clippy (project maintains zero warnings in pedantic mode)
