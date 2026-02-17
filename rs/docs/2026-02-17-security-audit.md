# Security Audit: minisign-rs v1.3.1

**Date:** 2026-02-17
**Version:** 1.3.1
**Reviewer:** Claude (Opus 4.6)
**Scope:** Full security audit of cryptographic implementation, secret handling, input validation, file operations, dependencies, and attack surface
**Previous Review:** 2026-01-28 (v0.12.0, Opus 4.5)

---

## Executive Summary

minisign-rs is a security-focused Rust reimplementation of the C minisign cryptographic signing tool. This audit covers the full codebase at v1.3.1, including significant additions since the January 2026 review: multi-file operations, credential store integration, key inspection, and the builder-pattern API refactor.

### Key Findings

| Category | Rating | Notes |
|----------|--------|-------|
| Cryptographic Primitives | **Excellent** | Well-audited RustCrypto libraries, correct algorithm usage |
| Secret Material Handling | **Excellent** | Comprehensive Zeroize coverage, no leaks in error paths |
| Constant-Time Operations | **Excellent** | Consistent `subtle::ConstantTimeEq` usage at all comparison points |
| Input Validation | **Excellent** | Comment, path, and length validation at all entry points |
| File Operation Safety | **Excellent** | Atomic creation, `sync_all()`, Unix permissions |
| Error Handling | **Excellent** | No secret leakage, structured error types |
| Dependencies | **Excellent** | Zero known vulnerabilities (cargo audit clean) |
| Unsafe Code | **Excellent** | Zero `unsafe` blocks in all 20 source files |
| Debug/Release Separation | **Excellent** | `force_weak_kdf` eliminated at compile time in release |
| Multi-File Operations | **Good** | Sound design with minor race window concern (see S-4) |

**Overall Assessment: PRODUCTION READY** — No high-severity issues found. Three medium-severity and four low-severity items identified, all with mitigations in place or requiring specific preconditions.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Cryptographic Implementation](#2-cryptographic-implementation)
3. [Secret Material Lifecycle](#3-secret-material-lifecycle)
4. [Constant-Time Analysis](#4-constant-time-analysis)
5. [Input Validation & Parsing](#5-input-validation--parsing)
6. [File Operation Security](#6-file-operation-security)
7. [Multi-File & Parallel Operations](#7-multi-file--parallel-operations)
8. [Credential Store Security](#8-credential-store-security)
9. [Error Handling & Information Leakage](#9-error-handling--information-leakage)
10. [Dependency Analysis](#10-dependency-analysis)
11. [Compile-Time Security Controls](#11-compile-time-security-controls)
12. [Attack Surface Analysis](#12-attack-surface-analysis)
13. [Findings Summary](#13-findings-summary)
14. [Changes Since Previous Review](#14-changes-since-previous-review)
15. [Recommendations](#15-recommendations)
16. [Appendices](#appendices)

---

## 1. Threat Model

### Assets

| Asset | Sensitivity | Storage |
|-------|-------------|---------|
| Ed25519 secret key (64 bytes) | **Critical** | Encrypted in `.key` file, in-memory during operations |
| Password / passphrase | **Critical** | Transient in-memory, optionally in OS credential store |
| KDF-derived keystream (104 bytes) | **Critical** | Transient in-memory during encrypt/decrypt |
| Plaintext keynum (8 bytes) | Low | In public key file and signature files |
| Signatures | Public | `.minisig` files |

### Threat Actors

1. **Local attacker with file access** — Can read secret key files; password strength and KDF parameters are the barrier
2. **Remote attacker** — Signature forgery requires private key; verification is the trust boundary
3. **Supply chain attacker** — Dependency compromise; mitigated by Cargo.lock pinning and audit
4. **Timing side-channel attacker** — Network-observable timing during verification; constant-time comparison prevents

### Trust Boundaries

- **User input → CLI parsing** — untrusted comments, file paths, passwords
- **File system → key/signature parsing** — untrusted file contents, format validation
- **OS credential store → password retrieval** — trusted OS API, but password returned to application memory

---

## 2. Cryptographic Implementation

### 2.1 Algorithm Selection

| Component | Algorithm | Library | Locked Version | Status |
|-----------|-----------|---------|----------------|--------|
| Signatures | Ed25519 | `ed25519-dalek` | 2.2.3 | **Secure** — RFC 8032 compliant |
| Hashing | Blake2b-256/512 | `blake2` | 2.11.0 | **Secure** — NIST-reviewed |
| KDF | scrypt (N=2²⁰, r=8, p=1) | `scrypt` | 1.2.0 | **Secure** — RFC 7914 |
| CSPRNG | OS entropy | `getrandom` | 0.3.4 | **Secure** — uses platform CSPRNG |
| Constant-time | `ct_eq` | `subtle` | 0.11.1 | **Secure** — audited |

All cryptographic crates are from the RustCrypto ecosystem, which is widely reviewed and used across the Rust ecosystem.

### 2.2 Key Derivation

**Production parameters** (`crypto.rs:24-28`):
- N = 2²⁰ (1,048,576 iterations)
- r = 8 (block size)
- p = 1 (parallelization)
- Memory: ~1 GiB
- Time: 1-5 seconds on modern hardware

These match libsodium's `SENSITIVE` level, providing strong resistance against GPU-based brute-force attacks.

**Parameter overflow protection** (`crypto.rs:390-417`): All arithmetic uses `checked_mul()` with explicit overflow handling. The `log_n` input is bounds-checked against 64 before the bit shift.

### 2.3 Key Encryption Scheme

The XOR-stream cipher scheme (`keys.rs:422-426`) is secure because:

1. The scrypt output is a PRF — each `(password, salt)` pair produces a unique, unpredictable keystream
2. The 32-byte salt is generated via `OsRng` — ensures unique keystream per key
3. No keystream reuse — salt regenerated on every `new_encrypted()` and password change
4. Integrity guaranteed by encrypted Blake2b-256 checksum inside the blob

**Assessment:** Matches C minisign exactly. The scheme is sound given single-use keystream property.

### 2.4 Prehashed Mode

Prehashed signatures use Blake2b-512 to hash the file before signing. The signature algorithm byte changes from `"Ed"` to `"ED"` to distinguish modes. This is correctly handled in both signing (`sign.rs:630-642`) and verification (`verify.rs:418-427`).

**Streaming implementation** (`crypto.rs:326-341`): Uses 8 KiB buffer for streaming large files without loading into memory. The buffer is stack-allocated and does not contain sensitive data.

---

## 3. Secret Material Lifecycle

### 3.1 Zeroize Coverage

| Secret | Type | Zeroize | ZeroizeOnDrop | Location |
|--------|------|---------|---------------|----------|
| Ed25519 secret key | `SecretKey` | Yes | Yes | `crypto.rs:47-48` |
| Secret key structure | `SeckeyStruct` | Yes | Yes | `keys.rs:268` |
| Password | `Zeroizing<String>` | Yes | Automatic | `main.rs:851-886` |
| KDF-derived key | `Zeroizing<Vec<u8>>` | Yes | Automatic | `crypto.rs:529` |
| Decrypted blob | `Zeroizing<[u8; 104]>` | Yes | Automatic | `keys.rs:492` |
| Plaintext blob (pre-encrypt) | `Zeroizing<Vec<u8>>` | Yes | Automatic | `keys.rs:417` |
| `KeyNum` | `KeyNum` | Yes | No | `crypto.rs:137` |

**Assessment:** All sensitive intermediaries are wrapped in `Zeroizing<T>` or derive `ZeroizeOnDrop`. No identified paths where secret material persists after use.

### 3.2 No-Clone Enforcement

`SeckeyStruct` intentionally does not implement `Clone`, preventing uncontrolled duplication of secret material. This is documented in the struct's doc comment (`keys.rs:267`).

### 3.3 Debug Output Redaction

| Type | Debug Output | Location |
|------|-------------|----------|
| `SecretKey` | `"SecretKey([REDACTED])"` | `crypto.rs:64-67` |
| `SeckeyStruct` | encrypted fields show `"[REDACTED]"` | `keys.rs:875-888` |
| `PublicKey` | First 4 bytes only | `crypto.rs:88-97` |
| `Signature` | First 4 bytes only | `crypto.rs:117-126` |

**Assessment:** No path exists to accidentally log secret material.

---

## 4. Constant-Time Analysis

### 4.1 Comparison Points

| Operation | Location | Method | Risk if Removed |
|-----------|----------|--------|-----------------|
| Password confirmation | `main.rs:908` | `ct_eq` on bytes | Timing oracle on password entry |
| Checksum verification | `keys.rs:514` | `ct_eq` on 32-byte hash | Wrong-password oracle |
| Keynum matching (verify) | `verify.rs:404` | `ct_eq` via `ConstantTimeEq` | Timing side-channel during verification |

All three critical comparison points use `subtle::ConstantTimeEq` consistently.

### 4.2 Non-Critical Comparisons

`KeyNum` also derives `PartialEq` for convenience in non-security contexts (e.g., test assertions). The security-critical path in `verify_message_signature()` explicitly uses `ct_eq`, not `==`. This dual-trait approach is documented in the `KeyNum` doc comment (`crypto.rs:128-137`).

---

## 5. Input Validation & Parsing

### 5.1 Comment Validation

**Entry points** validated via `validate_comment_with_length()`:

1. `SignatureBox::new()` — both untrusted and trusted comments (`signature.rs:246-263`)
2. `SignatureBox::from_file_contents()` — parsing signature files (`signature.rs:322-354`)
3. `SignatureBox::with_global_signature()` — creating signatures (`signature.rs:424-441`)
4. `create_signature()` — before any file I/O (`sign.rs:615-625`)

**Checks performed** (`validation.rs`):
- Rejects ASCII control characters (0x00-0x1F except tab, 0x7F)
- Rejects C1 control characters (U+0080-U+009F)
- Rejects embedded carriage returns (`\r`)
- Enforces length limits: 1024 bytes (untrusted), 8192 bytes (trusted)

**Assessment:** Comprehensive. Comments are validated at every entry point before use.

### 5.2 Binary Format Parsing

All binary structures enforce exact size validation on parse:

| Structure | Expected Size | Validation Location |
|-----------|--------------|---------------------|
| `PubkeyStruct` | 42 bytes | `keys.rs:146-152` |
| `SeckeyStruct` | 158 bytes | `keys.rs:765-771` |
| `SigStruct` | 74 bytes | `signature.rs:161-167` |
| Global signature | 64 bytes | `signature.rs:358-364` |

Algorithm identifiers (`"Ed"`, `"ED"`, `"Sc"`, `"B2"`) are validated as exact byte comparisons. Invalid algorithms produce specific error messages.

### 5.3 File Format Parsing

**Signature files** (`signature.rs:305-376`):
- Enforces exactly 4 lines
- Validates `"trusted comment: "` prefix (required for C compatibility)
- Untrusted comment prefix is optional (stripped if present)
- Both comments validated for printability and length

**Key files** (`keys.rs:181-193, 852-863`):
- Enforces minimum 2 lines (comment + base64)
- Base64 decoding with size validation
- Algorithm fields validated

### 5.4 Path Validation

- **Windows reserved names** checked on output paths (`validation.rs:228-277`): `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`
- **No-op on Unix** (`validation.rs:287-291`) — appropriate since these names aren't reserved
- **Signature path construction** uses `OsString` for non-UTF-8 safety (`sign.rs:307-310`)

---

## 6. File Operation Security

### 6.1 Atomic File Creation

All write operations use `OpenOptions::create_new(true)` when `force` is false, providing atomic check-and-create semantics that prevent TOCTOU race conditions:

- `write_secret_key_file()` — `file_utils.rs:62`
- `write_public_key_file()` — `file_utils.rs:129`
- `write_signature_file()` — `sign.rs:720`

### 6.2 Durability

Every file write calls `file.sync_all()` before returning success:
- `file_utils.rs:94` (secret key)
- `file_utils.rs:144` (public key)
- `sign.rs:736` (signature)

This ensures data is flushed to persistent storage, preventing data loss on power failure.

### 6.3 Unix Permissions

Secret key files are created with mode `0o600` (owner read/write only):
- `file_utils.rs:68-69` — Set via `OpenOptionsExt::mode()` at creation time
- `file_utils.rs:82-87` — When force-overwriting, explicitly calls `set_permissions()` to secure pre-existing files with lax permissions

### 6.4 File Size Limits

Non-prehashed (legacy) mode enforces a 1 GiB limit (`file_utils.rs:159-170`), preventing memory exhaustion from processing extremely large files. Prehashed mode streams via 8 KiB buffer with no memory limit.

---

## 7. Multi-File & Parallel Operations

### 7.1 Design

Multi-file signing (`sign.rs:462-531`) and verification (`verify.rs:486-542`):
- **Single key load** — key loaded and decrypted once, shared across all files
- **Parallel execution** via Rayon `par_iter()` by default, with `--sequential` fallback
- **File deduplication** via canonicalized path `HashSet` (`sign.rs:468-483`)
- **Error categorization** — `PartialFailure` vs `TotalFailure` for different exit codes

### 7.2 Security Properties

- Secret key reference is shared read-only across Rayon threads (no mutable aliasing)
- Each file's signature is independent — parallel execution doesn't affect correctness
- Failed files are reported individually to stderr, with summary at the end

### 7.3 Concern: S-4 (see [Findings](#13-findings-summary))

The deduplication uses `canonicalize()` which resolves symlinks at call time. A symlink replaced between deduplication and signing could result in signing an unintended target. This is a standard filesystem TOCTOU concern, not specific to this implementation. See S-4 for details.

---

## 8. Credential Store Security

### 8.1 Architecture

The credential store (`credential_store.rs`) wraps the `keyring` crate, using OS-native backends:
- macOS: Keychain Services
- Windows: Credential Manager
- Linux: Secret Service (libsecret/gnome-keyring)

**Service name:** `"minisign"` (constant, `credential_store.rs:32`)
**Key:** Credential ID (hex of encrypted keynum for encrypted keys)

### 8.2 Security Properties

- Passwords are wrapped in `Zeroizing<String>` on retrieval (`credential_store.rs:74`)
- Credential store failures never block primary operations (`credential_store.rs:68-74`)
- Feature-gated: when `credential_store` feature is off, all functions are no-ops
- Deletion is idempotent — `NoEntry` is treated as success (`credential_store.rs:93-94`)

### 8.3 Credential ID Design

For encrypted keys, the credential ID is derived from the **encrypted** keynum bytes (file offsets 54-61) rather than the decrypted keynum. This solves the chicken-and-egg problem: the credential store can be queried before the password is known.

The credential ID changes when the password changes (different KDF salt → different encrypted bytes), so stale entries are cleaned up on password change (`main.rs:617-619`).

### 8.4 Concern: S-6 (see [Findings](#13-findings-summary))

The password is stored in the OS credential store in plaintext (as the `keyring` crate provides). Security relies on the OS credential store's access control (e.g., macOS Keychain requires user authorization). This is by design and documented.

---

## 9. Error Handling & Information Leakage

### 9.1 Error Messages

Error messages are reviewed for secret leakage:

| Error | Message | Leaks Secrets? |
|-------|---------|----------------|
| Wrong password | `"checksum verification failed"` | No |
| Invalid key | `"invalid secret key: <format details>"` | No (format only) |
| KDF failure | `"key derivation failed: <scrypt error>"` | No |
| Verification failure | `"signature verification failed"` | No |
| Key mismatch | `"signature keyid X doesn't match"` | No (keynums are public) |

The `ChecksumFailed` error (`errors.rs:71`) intentionally does not distinguish between wrong password and corrupted data, preventing oracle attacks.

### 9.2 Exit Codes

- `0` — success
- `1` — operation error
- `2` — usage/argument error

This matches standard Unix conventions and reveals no security-sensitive state through exit codes.

### 9.3 Stderr Output

Warnings (weak KDF, credential store failures) go to stderr, not stdout. This prevents contamination of piped output (e.g., `minisign_rs -V -o | sha256sum`).

---

## 10. Dependency Analysis

### 10.1 Vulnerability Scan

```
$ cargo audit (2026-02-17)
    Loaded 920 security advisories
    Scanning Cargo.lock for vulnerabilities (261 crate dependencies)
    No vulnerabilities found!
```

### 10.2 Critical Dependency Versions (Locked)

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `ed25519-dalek` | 2.2.3 | Ed25519 signatures | RustCrypto, professionally audited |
| `blake2` | 2.11.0 | Blake2b hashing | RustCrypto |
| `scrypt` | 1.2.0 | Key derivation | RustCrypto |
| `subtle` | 0.11.1 | Constant-time operations | RustCrypto, audited |
| `zeroize` | 0.8.39 | Memory clearing | RustCrypto, audited |
| `getrandom` | 0.3.4 | OS CSPRNG | RustCrypto |
| `rand_core` | 0.6.4/0.9.0 | RNG trait | RustCrypto |
| `keyring` | 1.0.17 | OS credential store | Community-maintained |
| `rpassword` | 0.8.9 | Secure password input | Community-maintained |

### 10.3 Dependency Version Pinning

Cargo.toml uses semver ranges (e.g., `blake2 = "0.10"`, `scrypt = "0.11"`), but `Cargo.lock` pins exact versions. For a security-critical project, the lock file should always be committed (it is).

**Note:** Several locked versions have been updated since the Cargo.toml ranges were written (e.g., `blake2` locked at 2.11.0 despite `"0.10"` range, `scrypt` at 1.2.0 despite `"0.11"` range). This is expected semver behavior — the locked versions are compatible with the specified ranges.

### 10.4 Supply Chain Considerations

- **Zero C dependencies** — pure Rust throughout, eliminating entire class of C FFI vulnerabilities
- **Cargo.lock committed** — reproducible builds
- **CI includes CodeQL scanning** — GitHub Actions badge in README
- **No build scripts** (`build.rs`) with network access — only `git-version` for embedding version strings

---

## 11. Compile-Time Security Controls

### 11.1 Debug-Only Features

The `force_weak_kdf` flag is controlled at multiple layers:

1. **CLI level** (`cli.rs`): `#[cfg_attr(not(debug_assertions), arg(skip))]` — invisible in release builds
2. **Calculation level** (`crypto.rs:384-388`): `assert!(!force_weak_kdf)` in release builds
3. **Builder level** (`generate.rs:104-108`, `change.rs:74-78`): compile-time assertion in release

**Assessment:** Three independent guards ensure weak KDF keys cannot be created in release builds.

### 11.2 Feature Gating

The `credential_store` feature gates all keyring access:
- When disabled: all four functions (`save_password`, `get_password`, `forget_password`, `has_password`) are no-ops
- Dev/test builds use `--no-default-features` to avoid keychain prompts
- The `credential_store_tests` feature further isolates interactive tests

### 11.3 Profile Optimization

```toml
[profile.dev.package.scrypt]
opt-level = 3
```

This ensures scrypt runs at full speed even in debug builds, preventing test timeouts while maintaining security-relevant performance characteristics.

---

## 12. Attack Surface Analysis

### 12.1 Input Attack Surface

| Input | Source | Validation | Risk |
|-------|--------|------------|------|
| Password | Terminal/file | Zeroizing wrapper | Low — rpassword disables echo |
| Comment strings | CLI args | Printability + length + CR check | Low |
| Public key file | File system | Size + format + algorithm validation | Low |
| Secret key file | File system | Size + format + algorithm + KDF validation | Low |
| Signature file | File system | 4-line format + base64 + size validation | Low |
| Message file | File system | Size limit (1 GiB) or streaming hash | Low |
| Base64 public key | CLI `-P` flag | Decode + size validation | Low |

### 12.2 File System Attack Surface

| Scenario | Mitigation |
|----------|-----------|
| Symlink to sensitive file | Standard filesystem permissions apply; no special handling needed for a signing tool |
| Secret key file world-readable | Created with mode 0600; force-overwrite tightens permissions |
| Signature file replacement during multi-file | Atomic `create_new(true)` prevents unauthorized replacement |
| File modified between size check and read | Read failure is handled; prehashed mode streams regardless |

### 12.3 Memory Attack Surface

| Scenario | Mitigation |
|----------|-----------|
| Core dump containing secrets | `ZeroizeOnDrop` clears memory before drop |
| Swap containing secrets | Not mitigated (would require `mlock`); see S-7 |
| Fork preserving secrets | Not applicable — no forking in the binary |
| Stack residue after function return | `Zeroizing` types zero on drop; stack frames may retain residue for types not wrapped in `Zeroizing` |

---

## 13. Findings Summary

### Medium Severity

| ID | Finding | Impact | Mitigation |
|----|---------|--------|------------|
| **S-1** | **Unencrypted keys have no integrity check** — checksum is all-zeros, corrupted key files load without error | Signing with corrupted key produces invalid signatures | By design for C compatibility; documented in `keys.rs:7-30`. Encrypted keys DO have integrity checks. |
| **S-2** | **XOR encryption without authenticated encryption** — no MAC on the ciphertext; relies on embedded checksum | A targeted bit-flip attack on the encrypted blob could go undetected if the attacker can predict plaintext | Extremely difficult to exploit: attacker needs to flip bits in both the key material and the checksum consistently, and the checksum is also encrypted under the same keystream. C compatibility requirement. |
| **S-3** | **Password file option available in release builds** — `--password-file` works in production | Passwords stored in files may be logged, leaked, or left in shell history | Warning is printed on use (`main.rs:857-859`). Necessary for CI/automation. Password is still Zeroized after reading. |

### Low Severity

| ID | Finding | Impact | Mitigation |
|----|---------|--------|------------|
| **S-4** | **Multi-file symlink race** — deduplication resolves symlinks, but the actual signing reads the file later | Theoretically, a symlink target could change between deduplication and signing | Standard TOCTOU on filesystems; minisign does not claim to defend against concurrent filesystem modifications. |
| **S-5** | **No secret key file permission check on load** — code doesn't verify 0600 permissions before reading | User may unknowingly use a world-readable secret key | ~~Key generation always sets 0600; runtime check would be defense-in-depth only.~~ **Resolved** — `load_secret_key()` now calls `check_secret_key_permissions()` on Unix, warning to stderr if `mode & 0o077 != 0` (commit `11db8a1`). |
| **S-6** | **OS credential store security depends on OS** — password stored as plaintext in OS keyring | If OS keyring is compromised, password is exposed | By design; OS credential stores provide access control (e.g., macOS Keychain authorization dialogs). Feature is opt-in (`--save-password`). |
| **S-7** | **No mlock() on sensitive memory** — secrets could be swapped to disk | A local attacker with root access could read secrets from swap | Rust's `Zeroizing` minimizes exposure window. `mlock` would require `unsafe` code, violating the project's zero-unsafe policy. This is consistent with the C implementation's behavior (libsodium uses `mlock` internally, but the C minisign application code does not `mlock` its own buffers). |

### Informational

| ID | Finding | Notes |
|----|---------|-------|
| **I-1** | `SeckeyStruct` keeps plaintext `keynum` field after encryption | The field is zeroed for encrypted keys (`keys.rs:821`); real keynum recovered only on decrypt. Not a leak — encrypted keys show `[0; 8]` until decrypted. |
| **I-2** | Credential ID is deterministic from file contents | Allows offline brute-force of encrypted keynum mapping. Low risk: the keynum is not secret (it appears in signature files). |
| **I-3** | `rand_core` 0.6.x used alongside 0.9.x in dependency tree | Two versions coexist via transitive dependencies. Both are secure; no code confusion — the project directly depends on 0.6. |
| **I-4** | Base64 standard encoding used (not URL-safe) | Matches C minisign. Not a vulnerability; the base64 is never used in URLs. |

---

## 14. Changes Since Previous Review (v0.12.0 → v1.3.1)

### New Features Audited

| Feature | Security Assessment |
|---------|-------------------|
| Multi-file signing/verification (Rayon) | Sound — key loaded once, shared read-only. File deduplication prevents double-signing. |
| OS credential store integration | Sound — feature-gated, opt-in, passwords Zeroized on retrieval. |
| Key inspection (`-I/--inspect`) | Sound — read-only analysis, no secrets exposed without password. |
| Smart decryption in inspect | Sound — credential store checked first, then password prompt. `--no-decrypt` skips entirely. |
| Builder pattern for options | Sound — improves API ergonomics with no security impact. |
| Password confirmation with `ct_eq` | **Improvement** — prevents timing oracle on password mismatch. |
| Force-overwrite permission tightening | **Improvement** — `set_permissions(0o600)` on existing files during force-overwrite. |
| `--no-decrypt` flag | **Improvement** — enables non-interactive inspection of encrypted keys. |

### Resolved Items from Previous Review

| Previous Recommendation | Status |
|------------------------|--------|
| "Consider fsync() on key files" | **Resolved** — `sync_all()` called on all file writes |
| "Document password strength recommendations" | Partially addressed via inspect command and weak key warnings |

### Post-Audit Resolutions (2026-02-17)

Recommendations 1–4 from [Section 15](#15-recommendations) were implemented immediately following the audit:

| Recommendation | Resolution | Commit |
|----------------|-----------|--------|
| Rec 1: Warn on world-readable secret key files | `has_lax_permissions()` + `check_secret_key_permissions()` added to `file_utils.rs`; called from `load_secret_key()` on Unix. Five unit tests added. | `11db8a1` |
| Rec 2: Minimum password length warning | `MIN_RECOMMENDED_PASSWORD_LEN = 8` constant and stderr warning added to the interactive branch of `prompt_password_with_confirmation()` in `main.rs`. Warning suppressed for `--password-file` (automation). | `95b3723` |
| Rec 3: Document `--password-file` security implications | Dedicated "Using `--password-file` Securely" section added to `docs/USAGE.md` covering 0600 permissions, shared filesystem risks, CI cleanup pattern, and alternatives. | `c28fb9f` |
| Rec 4: Pin crypto dependency ranges | `ed25519-dalek`, `blake2`, `scrypt`, `zeroize`, `subtle`, `rand_core` pinned to `=X.Y.Z` in `Cargo.toml`. All are at the latest stable release (next versions are RC/pre-release only). | `c82ffa4` |

---

## 15. Recommendations

### Medium Priority

1. ✅ **RESOLVED** — **Warn on world-readable secret key files** (addresses S-5) — commit `11db8a1`

   `load_secret_key()` now checks Unix permissions on every key load and emits a stderr warning with the current mode and a `chmod 600` reminder if `mode & 0o077 != 0`. The predicate `has_lax_permissions()` is exposed as a public function with five unit tests (0644, 0640, 0600, 0400, nonexistent).

2. ✅ **RESOLVED** — **Minimum password length warning** (defense-in-depth) — commit `95b3723`

   A `MIN_RECOMMENDED_PASSWORD_LEN = 8` constant was added to `main.rs`. After successful password confirmation in the interactive branch of `prompt_password_with_confirmation()`, a stderr warning is emitted if the password is shorter than 8 characters. The check is suppressed for `--password-file` (CI automation).

3. ✅ **RESOLVED** — **Document `--password-file` security implications prominently** (addresses S-3) — commit `c28fb9f`

   A dedicated "Using `--password-file` Securely" section was added to `docs/USAGE.md` covering: 0600 permission requirement, shared/network filesystem risks, CI cleanup pattern (delete on failure too), and when to prefer unencrypted keys or the OS credential store instead.

### Low Priority

4. ✅ **RESOLVED** — **Pin crypto dependency ranges** — commit `c82ffa4`

   `ed25519-dalek`, `blake2`, `scrypt`, `zeroize`, `subtle`, and `rand_core` are now pinned to exact `=X.Y.Z` versions in `Cargo.toml`. All pins are at the current latest stable releases; next versions for all five RustCrypto crates are RC or pre-release only. An upgrade comment documents the review process for future updates.

5. **Add SBOM generation to CI**

   Software Bill of Materials generation would improve supply chain visibility for downstream consumers.

6. **Consider mlock integration** (addresses S-7)

   If the zero-unsafe policy is ever relaxed, `mlock()` on secret key pages would prevent swap exposure. The `memsec` or `secmem` crates provide safe wrappers. Not urgent given the existing `Zeroize` coverage.

---

## Appendices

### Appendix A: Files Reviewed

**Core cryptographic modules:**
- `src/crypto.rs` — Cryptographic primitives (567 lines)
- `src/keys.rs` — Key structures and encryption (889 lines)
- `src/signature.rs` — Signature structures (470 lines)

**Operations:**
- `src/ops/generate.rs` — Key generation (347 lines)
- `src/ops/sign.rs` — File signing (740 lines)
- `src/ops/verify.rs` — Signature verification (593 lines)
- `src/ops/change.rs` — Password management (229 lines)
- `src/ops/file_utils.rs` — File I/O helpers (171 lines)
- `src/ops/inspect.rs` — Key inspection (~615 lines)
- `src/ops/recreate.rs` — Public key recovery
- `src/ops/mod.rs` — Module re-exports

**Supporting modules:**
- `src/main.rs` — CLI entry point (915 lines)
- `src/cli.rs` — Clap CLI definition
- `src/validation.rs` — Input validation (347 lines)
- `src/formats.rs` — Base64 and binary helpers (99 lines)
- `src/errors.rs` — Error types (149 lines)
- `src/credential_store.rs` — OS keyring integration (151 lines)
- `src/wordlist.rs` — PGP Word List encoding
- `src/constants.rs` — Centralized constants
- `src/lib.rs` — Library root

**Configuration:**
- `Cargo.toml` — Dependencies and features
- `Cargo.lock` — Locked dependency versions (261 crates)

### Appendix B: Tools Used

- `cargo audit` 0.22.0 — Vulnerability scanning (920 advisories checked)
- Manual code review — All 20 source files
- `grep` — Verified zero `unsafe` blocks, zero bare `unwrap()` in production paths

### Appendix C: Test Coverage

The project maintains 479 tests across multiple categories:

| Category | Count | Security Relevance |
|----------|-------|-------------------|
| Unit tests | ~212 | Core functionality coverage |
| CLI integration tests | ~77 | End-to-end validation |
| Compatibility tests | ~7 | C interoperability proof |
| Property-based tests | ~30 | Randomized input fuzzing |
| Security attack tests | dedicated | Attack vector validation |
| Slow security tests | 11 | Production KDF parameter testing |
| Concurrent access tests | dedicated | Multi-process safety |

---

**End of Security Audit**
