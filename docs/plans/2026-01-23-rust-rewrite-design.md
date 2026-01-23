# Minisign Rust Rewrite - Design Document

**Date:** 2026-01-23
**Status:** Approved
**Target Platforms:** macOS, Windows, Linux

## Overview

Complete rewrite of minisign in 100% Rust with identical CLI interface. The implementation uses pure Rust cryptography (no C dependencies), follows TDD methodology, and maintains byte-level compatibility with the C implementation.

---

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Crypto library | RustCrypto ecosystem | Pure Rust, audited, no C dependencies |
| CLI parsing | clap v4 | Industry standard, derive macros, excellent errors |
| Error handling | thiserror + anyhow | Clean library/application separation |
| Project structure | Single crate (lib + bin) | Simple, testable, matches minisign's focus |
| Test data | Generated from C implementation | Guarantees behavioral compatibility |
| Implementation order | Bottom-up | Natural TDD progression |

---

## Project Structure

```
minisign-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Public API exports
│   ├── main.rs         # CLI entry point
│   ├── crypto.rs       # Ed25519, Blake2b, Scrypt wrappers
│   ├── keys.rs         # Key types, generation, encryption
│   ├── signature.rs    # Signature creation and verification
│   ├── formats.rs      # Base64, file parsing, serialization
│   ├── errors.rs       # Error types with thiserror
│   └── cli.rs          # Clap definitions and handlers
├── tests/
│   ├── fixtures/       # Generated from C implementation
│   │   ├── keys/
│   │   ├── signatures/
│   │   └── edge_cases/
│   ├── integration/    # End-to-end CLI tests
│   └── compatibility.rs
└── scripts/
    └── generate_fixtures.sh
```

---

## Dependencies

```toml
[package]
name = "minisign"
version = "0.12.0"
edition = "2024"
rust-version = "1.90"
license = "ISC"
description = "A dead simple tool to sign files and verify signatures"

[dependencies]
ed25519-dalek = { version = "2", features = ["rand_core"] }
blake2 = "0.10"
scrypt = "0.11"
rand = "0.8"
base64 = "0.22"
clap = { version = "4", features = ["derive"] }
thiserror = "1"
anyhow = "1"
zeroize = { version = "1", features = ["derive"] }
rpassword = "7"
dirs = "5"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
proptest = "1"

[[bin]]
name = "minisign"
path = "src/main.rs"

[lib]
name = "minisign"
path = "src/lib.rs"
```

---

## Crypto Layer

### Constants

```rust
pub const SIGNATURE_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 64;
pub const KEYNUM_BYTES: usize = 8;
pub const KDF_SALT_BYTES: usize = 32;
pub const CHECKSUM_BYTES: usize = 32;
```

### Core Types

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_BYTES]);

pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);
pub struct Signature([u8; SIGNATURE_BYTES]);
pub struct KeyNum([u8; KEYNUM_BYTES]);
```

### Operations

| Function | Description |
|----------|-------------|
| `generate_keypair()` | Generate Ed25519 keypair with random keynum |
| `sign(sk, msg)` | Deterministic Ed25519 signature |
| `verify(pk, msg, sig)` | Verify Ed25519 signature |
| `derive_key(password, salt, ops, mem)` | Scrypt key derivation |
| `blake2b_256(data)` | Blake2b with 256-bit output (checksums) |
| `blake2b_512(data)` | Blake2b with 512-bit output (global sig) |

### Scrypt Parameters

Matching libsodium SENSITIVE level:
- `log_n = 20` (N = 2^20 = 1,048,576)
- `r = 8`
- `p = 1`
- Fallback: progressively reduce memory on allocation failure

---

## Data Structures

### Secret Key File (SeckeyStruct)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | sig_alg | "Ed" |
| 2 | 2 | kdf_alg | "Sc" or "\0\0" |
| 4 | 2 | chk_alg | "B2" |
| 6 | 32 | kdf_salt | Scrypt salt |
| 38 | 8 | kdf_opslimit | Little-endian u64 |
| 46 | 8 | kdf_memlimit | Little-endian u64 |
| 54 | 8 | keynum | Key identifier |
| 62 | 64 | secret_key | Ed25519 secret key (encrypted) |
| 126 | 32 | checksum | Blake2b-256 of keynum + sk |

**Total: 158 bytes**

### Public Key File (PubkeyStruct)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | sig_alg | "Ed" |
| 2 | 8 | keynum | Key identifier |
| 10 | 32 | public_key | Ed25519 public key |

**Total: 42 bytes**

### Signature (SigStruct)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | sig_alg | "Ed" or "ED" (prehashed) |
| 2 | 8 | keynum | Key identifier |
| 10 | 64 | signature | Ed25519 signature |

**Total: 74 bytes**

---

## File Formats

### Secret Key File (.key)

```
untrusted comment: minisign encrypted secret key
<base64-encoded SeckeyStruct>
```

### Public Key File (.pub)

```
untrusted comment: minisign public key <KEYNUM_HEX>
<base64-encoded PubkeyStruct>
```

### Signature File (.minisig)

```
untrusted comment: <freely modifiable>
<base64-encoded SigStruct>
trusted comment: <cryptographically bound comment>
<base64-encoded global signature>
```

The global signature signs: `SigStruct.signature || trusted_comment_text`

---

## CLI Interface

### Actions (mutually exclusive)

| Flag | Action | Description |
|------|--------|-------------|
| `-G` | Generate | Create new keypair |
| `-S` | Sign | Sign file(s) |
| `-V` | Verify | Verify signature |
| `-R` | Recreate | Recreate public key from secret key |
| `-C` | Change | Change/remove password |

### Common Options

| Flag | Argument | Description |
|------|----------|-------------|
| `-f` | - | Force overwrite |
| `-H` | - | Prehashed message |
| `-l` | - | Legacy format (sign only) |
| `-m` | file | Message file |
| `-o` | - | Output on verification |
| `-p` | file | Public key file |
| `-P` | key | Public key (base64) |
| `-q` | - | Quiet mode |
| `-Q` | - | Pretty quiet (trusted comment only) |
| `-s` | file | Secret key file |
| `-t` | text | Trusted comment |
| `-c` | text | Untrusted comment |
| `-x` | file | Signature file |
| `-W` | - | No password (generate/change) |
| `-h` | - | Help |
| `-v` | - | Version |

### Default Paths

| Type | Unix | Windows |
|------|------|---------|
| Secret key | `~/.minisign/minisign.key` | `%USERPROFILE%\.minisign\minisign.key` |
| Public key | `./minisign.pub` | `.\minisign.pub` |
| Signature | `<file>.minisig` | `<file>.minisig` |

---

## Platform Support

### Cross-Platform Considerations

| Concern | Solution |
|---------|----------|
| Home directory | `dirs` crate (`dirs::home_dir()`) |
| Path separators | `std::path::Path` handles this |
| File permissions | `std::os::unix::fs::PermissionsExt` on Unix, skip on Windows |
| Terminal password input | `rpassword` crate |
| Line endings | Read/write in binary mode, handle both |

### Unix-Specific

- Secret key files created with mode 0600
- Parent directories created with mode 0700
- Terminal echo disabled for password input via termios

### Windows-Specific

- Use `SetConsoleMode` for password input (handled by rpassword)
- No file permission enforcement (Windows ACLs differ)
- Handle both forward and backslashes in paths

---

## Testing Strategy

### Unit Tests

Each module has inline `#[cfg(test)]` tests:

- `crypto.rs`: sign/verify roundtrip, KDF output matching, checksums
- `keys.rs`: serialization roundtrip, encryption/decryption
- `signature.rs`: parsing, trusted comment validation
- `formats.rs`: base64, endianness, file parsing

### Integration Tests

Located in `tests/`:

| Test File | Coverage |
|-----------|----------|
| `compatibility.rs` | Verify C-generated fixtures |
| `generate_test.rs` | Key generation all modes |
| `sign_test.rs` | Signing with all options |
| `verify_test.rs` | Verification all modes |
| `cli_test.rs` | End-to-end CLI behavior |

### Test Fixtures

Generated from C implementation using `scripts/generate_fixtures.sh`:

```
fixtures/
├── keys/
│   ├── test.key           # Password: "test"
│   ├── test.pub
│   └── unencrypted.key    # -W flag
├── signatures/
│   ├── hello.txt
│   ├── hello.txt.minisig
│   ├── prehashed.minisig  # -H mode
│   └── legacy.minisig     # -l mode
└── edge_cases/
    ├── unicode_comment.minisig
    ├── empty_file.minisig
    └── large_file.minisig
```

### Compatibility Verification

1. Rust verifies all C-generated signatures
2. C minisign verifies all Rust-generated signatures
3. Cross-verify keys work interchangeably

### Property-Based Testing

Using `proptest` for:
- Base64 encode/decode roundtrips
- Signature file parsing with arbitrary input
- UTF-8 validation edge cases

---

## Staged Implementation Plan

### Phase 1: Foundation (Week 1)

**Deliverables:**
- Cargo project initialized
- `errors.rs`: All error types defined
- `formats.rs`: Base64, little-endian helpers

**Tests:**
- Base64 roundtrip (random data)
- Endianness correctness (known values)
- Error type coverage

**Exit Criteria:** All unit tests pass

---

### Phase 2: Crypto Layer (Week 2)

**Deliverables:**
- `crypto.rs`: Complete crypto wrapper
- Ed25519 sign/verify
- Blake2b (256 and 512)
- Scrypt with fallback

**Tests:**
- Sign/verify roundtrip
- KDF output matches C libsodium vectors
- Blake2b matches known test vectors

**Exit Criteria:** Crypto operations match C behavior exactly

---

### Phase 3: Key Structures (Week 3)

**Deliverables:**
- `keys.rs`: SeckeyStruct, PubkeyStruct
- Key file parsing and writing
- Password encryption/decryption
- Checksum validation

**Tests:**
- Parse C-generated keys
- Roundtrip serialization
- Encryption/decryption with known passwords

**Exit Criteria:** Can load and save keys compatible with C minisign

---

### Phase 4: Signature Structures (Week 4)

**Deliverables:**
- `signature.rs`: SigStruct, global signature
- Signature file parsing
- Trusted comment handling
- Prehash mode support

**Tests:**
- Parse C-generated signatures
- Trusted comment validation
- Global signature verification

**Exit Criteria:** Can parse all C-generated signature files

---

### Phase 5: Operations (Week 5-6)

**Deliverables:**
- `ops/verify.rs`: Complete verification
- `ops/sign.rs`: Complete signing
- `ops/generate.rs`: Key generation
- `ops/recreate.rs`: Public key recovery
- `ops/change.rs`: Password management

**Tests:**
- Verify C-generated signatures
- Sign and verify with C minisign (cross-check)
- Generate keys usable by C minisign

**Exit Criteria:** All operations work bidirectionally with C version

---

### Phase 6: CLI Integration (Week 7)

**Deliverables:**
- `cli.rs`: Complete clap interface
- `main.rs`: Wiring and error handling
- Output modes (-q, -Q, -o)
- Exit codes matching C

**Tests:**
- assert_cmd end-to-end tests
- All flag combinations
- Error message format matching

**Exit Criteria:** CLI behavior identical to C minisign

---

### Phase 7: Polish & Release (Week 8)

**Deliverables:**
- Cross-platform CI (Linux, macOS, Windows)
- Release binaries
- README updates
- COMPATIBILITY.md documenting any differences

**Tests:**
- Full test suite on all platforms
- Performance comparison with C version
- Memory safety verification (miri)

**Exit Criteria:** Ready for production use

---

## Compatibility Guarantees

### Must Match C Behavior

1. All file formats byte-identical
2. Same default paths
3. Same exit codes
4. Same error conditions
5. Keys and signatures interchangeable

### Documented Differences

If C bugs are found:
- Document in COMPATIBILITY.md
- Default to matching C behavior
- Consider `--strict` flag for correct behavior

### Not Guaranteed

- Exact error message wording
- Performance characteristics
- Memory usage patterns

---

## Security Considerations

### Memory Safety

- All secret material uses `#[derive(Zeroize, ZeroizeOnDrop)]`
- No secret data in error messages
- Explicit scope limiting for sensitive operations

### No Unsafe Code

- Pure safe Rust throughout
- No `unsafe` blocks
- Dependencies audited for unsafe usage

### Constant-Time Operations

- `ed25519-dalek` uses constant-time comparison
- Password comparison via `subtle` crate if needed

---

## Open Questions

1. **Should we support the Zig build's libzodium mode?**
   - Recommendation: No, pure Rust is sufficient

2. **MSRV policy?**
   - Recommendation: 1.90+, update yearly

3. **Async support?**
   - Recommendation: No, minisign operations are inherently blocking

---

## References

- [Original minisign](https://github.com/jedisct1/minisign)
- [ed25519-dalek](https://docs.rs/ed25519-dalek)
- [RustCrypto](https://github.com/RustCrypto)
- [Ed25519 RFC 8032](https://tools.ietf.org/html/rfc8032)
