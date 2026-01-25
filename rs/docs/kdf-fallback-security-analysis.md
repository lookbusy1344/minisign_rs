# KDF Fallback Security Analysis

**Status**: Security Issue
**Severity**: Medium
**Affected Versions**: C minisign (all versions), Rust minisign (mitigated in current version)
**Date**: 2026-01-25

## Executive Summary

The C implementation of minisign contains an automatic KDF parameter fallback mechanism that silently creates permanently weaker secret keys on memory-constrained systems. Users have **no way to detect** if their existing keys were created with reduced security parameters, potentially leaving keys 8-64x more vulnerable to brute-force attacks than intended.

The Rust rewrite addresses this by making fallback opt-in via the `--allow-kdf-fallback` flag, following a secure-by-default design principle.

---

## Background: How Key Encryption Works

Minisign encrypts secret keys using password-based encryption:

1. User provides a password
2. Scrypt KDF derives an encryption key from the password + salt
3. The derived key encrypts the secret key material via XOR
4. The KDF parameters are **stored in the encrypted key file**

### Key File Structure (158 bytes)

```
Offset  Size  Field           Description
------  ----  --------------  ------------------------------------
0-1     2     sig_alg         Signature algorithm ("Ed")
2-3     2     kdf_alg         KDF algorithm ("Sc" = scrypt)
4-5     2     chk_alg         Checksum algorithm ("B2" = Blake2b)
6-37    32    kdf_salt        Random salt for KDF
38-45   8     kdf_opslimit    CPU/time cost (u64 LE)  ← PERMANENT
46-53   8     kdf_memlimit    Memory cost (u64 LE)    ← PERMANENT
54-61   8     keynum          Key identifier (encrypted)
62-125  64    secret_key      Ed25519 secret key (encrypted)
126-157 32    checksum        Blake2b checksum (encrypted)
```

**Critical**: The `kdf_opslimit` and `kdf_memlimit` fields at bytes 38-53 are **baked into the file at creation time**. These determine the security level forever.

### Scrypt Parameters

Scrypt uses three parameters:
- **N**: Iterations (main work factor, always a power of 2)
- **r**: Block size (typically 8)
- **p**: Parallelization (typically 1)

Libsodium expresses these as:
- `opslimit = 4 × N × r`
- `memlimit = 128 × N × r` (bytes)

| Security Level | N | opslimit | memlimit | Memory | Attack Resistance |
|----------------|---|----------|----------|---------|-------------------|
| Production (SENSITIVE) | 2^20 | 33,554,432 | 1,073,741,824 | 1024 MB | Baseline (100%) |
| After 1 fallback | 2^19 | 16,777,216 | 536,870,912 | 512 MB | 50% weaker |
| After 2 fallbacks | 2^18 | 8,388,608 | 268,435,456 | 256 MB | 75% weaker |
| After 3 fallbacks | 2^17 | 4,194,304 | 134,217,728 | 128 MB | 87.5% weaker (8x) |
| Minimum (OPSLIMIT_MIN) | 2^14 | 131,072 | 16,777,216 | 16 MB | 98.4% weaker (64x) |

---

## The Problem: Silent Permanent Degradation

### C Implementation Behavior

**File**: `src/minisign.c:395-443`

```c
static void encrypt_key(SeckeyStruct *const seckey_struct) {
    unsigned long kdf_memlimit;
    unsigned long kdf_opslimit;

    // Start with production parameters
    kdf_opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;  // 33,554,432
    kdf_memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;  // 1,073,741,824

    // Automatic fallback loop - NO user consent required
    while (crypto_pwhash_scryptsalsa208sha256(stream, sizeof seckey_struct->keynum_sk, pwd,
                                              strlen(pwd), seckey_struct->kdf_salt,
                                              kdf_opslimit, kdf_memlimit) != 0) {
        kdf_opslimit /= 2;  // Halve parameters
        kdf_memlimit /= 2;

        if (kdf_opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN ||
            kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) {
            exit_err("Unable to complete key derivation - More memory would be needed");
        }
    }

    // Single-line warning if fallback occurred (line 431-435)
    if (kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE) {
        fprintf(stderr, "Warning: due to limited memory the KDF used less "
                        "memory than the default\n");
    }

    // Store the ACTUAL parameters used (possibly after multiple fallbacks)
    le64_store(seckey_struct->kdf_opslimit_le, kdf_opslimit);  // ← PERMANENT
    le64_store(seckey_struct->kdf_memlimit_le, kdf_memlimit);  // ← PERMANENT

    // Encrypt and save...
}
```

### Key Decryption (Uses Stored Parameters)

**File**: `src/minisign.c:370-393`

```c
static void decrypt_key(SeckeyStruct *const seckey_struct) {
    // Read parameters FROM the file (set at creation time)
    if (crypto_pwhash_scryptsalsa208sha256(stream, sizeof seckey_struct->keynum_sk, pwd,
                                           strlen(pwd), seckey_struct->kdf_salt,
                                           le64_load(seckey_struct->kdf_opslimit_le),  // ← From file
                                           le64_load(seckey_struct->kdf_memlimit_le)) != 0) {
        exit_err("Unable to complete key derivation...");
    }
    // ... decrypt and verify checksum
}
```

**Security implication**: Decryption ALWAYS uses the parameters from creation time. You cannot "upgrade" security later.

---

## Critical Security Issues

### 1. **Limited Inspection Capability in C Implementation**

The C implementation provides **zero** ways to inspect a key file's KDF parameters:

```bash
$ minisign --help
# No --inspect, --show-params, --info commands
```

**C minisign users cannot determine**:
- Whether their key was created with fallback parameters
- How weak their key might be (2x, 8x, or 64x weaker)
- Whether they should regenerate their keys

The only indication is a **single-line warning at creation time** that:
- May have scrolled off the screen
- Doesn't specify the reduction amount
- Isn't logged anywhere
- Can't be checked later

**✅ Rust Implementation Solution**: The `-I/--inspect` command (added in commit e8bceb3) provides comprehensive key inspection:

```bash
$ minisign_rs -I -s ~/.minisign/minisign.key

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

For weak keys, the inspect command displays:

```bash
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

The inspect command:
- Works with both secret and public keys
- Provides three-tier security classification (High/Medium/Low)
- Shows exact KDF parameters and weakness multiplier
- Offers actionable recommendations for weak keys
- Reads directly from bytes 38-53 of the key file (fully compatible with C-generated keys)

### 2. **Persistent Warning System**

**✅ Rust Implementation Enhancement** (added in commit 63fd712): The Rust implementation now displays warnings **every time** a weak key is used, not just at creation:

```rust
// Warning appears during both signing and decryption operations
if seckey.is_weak_kdf() {
    eprintln!("\n⚠️  WARNING: WEAK KEY DETECTED ⚠️");
    eprintln!("This key was created with reduced security parameters.");
    eprintln!("It is easier to brute-force than a production-strength key.");
    eprintln!("Consider regenerating this key on a system with more memory.");
    eprintln!("See rs/docs/kdf-fallback-security-analysis.md for details.\n");
}
```

This warning appears:
- **During signing operations** (in `ops/sign.rs`)
- **During key decryption** (in `keys.rs`)
- **Every time the key is used** (not just once at creation)
- **With actionable guidance** (links to this security analysis)

The `is_weak_kdf()` method checks if KDF parameters are below production strength:
- Production: `opslimit = 33,554,432`, `memlimit = 1,073,741,824`
- Weak: Any value below production thresholds
- Unencrypted keys return `false` (no KDF applied)

**Impact**: Users cannot unknowingly continue using weak keys. The persistent warnings ensure awareness of the security trade-off.

### 3. **Permanent Security Degradation**

Once created with weak parameters, the key is permanently compromised:

```
Key created on low-memory system (e.g., Raspberry Pi with 512MB RAM):
→ Fallback to N=2^17 (128MB)
→ Parameters stored: opslimit=4,194,304, memlimit=134,217,728
→ FOREVER 8x easier to brute-force than intended

Even when later used on high-memory system:
→ Still uses N=2^17 (parameters baked into file)
→ Cannot be "upgraded" without generating new key
→ Regenerating key requires re-signing all signatures
→ Distributing new public key to all verifiers
```

### 4. **Silent Compromise in C Implementation**

The automatic fallback occurs without explicit user acknowledgment:

```
User expectation: "I'm creating a secure cryptographic key"
Reality: "You're creating a key 8x weaker than production strength"

User feedback: "Warning: due to limited memory the KDF used less memory than the default"
                ↑ Vague, non-actionable, easily dismissed
```

### 5. **Attack Scenarios**

**Scenario 1: Targeted Attack on IoT Devices**

```
1. Attacker identifies keys created on IoT devices (Raspberry Pi, routers, etc.)
2. These devices typically have 256-512MB RAM
3. Keys likely created with N=2^17 or N^18 (1-3 fallbacks)
4. Attacker has 8-16x easier brute-force target
5. User has no idea their key is weaker
```

**Scenario 2: Cloud Environment Memory Limits**

```
1. Container with 512MB memory limit generates keys
2. Automatic fallback to N=2^18 (256MB)
3. Keys deployed to production
4. 4x weaker than intended, permanently
5. No audit trail or warning in logs
```

---

## Rust Implementation: Secure-by-Default Fix

**File**: `rs/src/keys.rs:338-387`

### Changes Made

1. **Opt-in fallback** via `--allow-kdf-fallback` flag
2. **Fail-by-default** if production parameters can't be met
3. **Explicit warnings** when fallback is used
4. **Clear security implications** communicated to user

### Implementation

```rust
/// Creates encrypted secret key with optional fallback
pub fn new_encrypted(
    keynum: KeyNum,
    secret_key: SecretKey,
    password: &[u8],
    allow_fallback: bool,  // ← Requires explicit consent
) -> Result<Self> {
    let mut kdf_opslimit = SCRYPT_OPSLIMIT_SENSITIVE;
    let mut kdf_memlimit = SCRYPT_MEMLIMIT_SENSITIVE;

    loop {
        match derive_key_with_limits(password, &kdf_salt, kdf_opslimit, kdf_memlimit) {
            Ok(derived_key) => {
                // Success with current parameters

                // Warn if fallback was used
                if kdf_memlimit < SCRYPT_MEMLIMIT_SENSITIVE {
                    eprintln!("⚠ WARNING: Key created with reduced security parameters!");
                    eprintln!("  Requested: 1024 MB, Actual: {} MB",
                              kdf_memlimit / 1_048_576);
                    eprintln!("  This key is {}x easier to brute-force than production strength.",
                              SCRYPT_MEMLIMIT_SENSITIVE / kdf_memlimit);
                    eprintln!("  Consider using a system with more memory for key generation.");
                }

                return Ok(Self { /* ... */ });
            }
            Err(_) if allow_fallback => {
                // Fallback only if explicitly allowed
                kdf_opslimit /= 2;
                kdf_memlimit /= 2;

                if kdf_opslimit < SCRYPT_OPSLIMIT_MIN ||
                   kdf_memlimit < SCRYPT_MEMLIMIT_MIN {
                    return Err(Error::ScryptParamError(
                        "Cannot meet minimum KDF requirements even with fallback. \
                         More memory is needed.".into()
                    ));
                }
            }
            Err(e) => {
                // Fail immediately if fallback not allowed
                return Err(Error::ScryptParamError(format!(
                    "Key derivation requires 1024 MB but system cannot allocate it. \
                     Use --allow-kdf-fallback to use reduced security parameters \
                     (NOT recommended). Error: {}", e
                )));
            }
        }
    }
}
```

### User Experience Comparison

| Action | C Version | Rust Version |
|--------|-----------|--------------|
| **Key gen on 256MB system** | Silent fallback → 4x weaker key | Hard error with explanation |
| **With `--allow-kdf-fallback`** | N/A (always allowed) | Fallback + loud warning with impact |
| **Inspect existing key** | Impossible | Possible (could add `--inspect` cmd) |
| **Security feedback** | "Warning: used less memory" | "⚠ Key is 4x easier to brute-force" |

---

## Compatibility Analysis

### Are Fallback Keys Compatible?

**Yes, fully compatible** between C and Rust implementations.

**Why**: Both versions:
1. Store KDF parameters in the file (bytes 38-53)
2. Read those parameters when decrypting
3. Use the same scrypt implementation (libsodium interface)

```
C key created with fallback (N=2^17):
→ File contains: opslimit=4,194,304, memlimit=134,217,728
→ Rust reads file: opslimit=4,194,304, memlimit=134,217,728
→ Rust decrypts with N=2^17 (converted from opslimit/memlimit)
→ ✓ Decryption succeeds

Rust key created with fallback (--allow-kdf-fallback):
→ File contains: opslimit=4,194,304, memlimit=134,217,728
→ C reads file: le64_load(kdf_opslimit_le) = 4,194,304
→ C decrypts with those exact parameters
→ ✓ Decryption succeeds
```

**The security weakness is in the parameters themselves, not compatibility.**

### Migration Path

Keys created with C minisign's automatic fallback can be used with Rust minisign, but:

1. **They remain permanently weaker** (parameters are in the file)
2. **Cannot be upgraded** without generating new keys
3. **Should be audited** if security is critical

---

## Recommendations

### For C Minisign Users

1. **Audit Existing Keys**

   Currently impossible without manual hex inspection. You can check by:

   ```bash
   # Read bytes 46-53 (kdf_memlimit in little-endian u64)
   hexdump -C ~/.minisign/minisign.key | head -5

   # Bytes 46-53:
   # 00 00 00 40 00 00 00 00 = 1,073,741,824 (1024 MB) ✓ Production strength
   # 00 00 00 20 00 00 00 00 =   536,870,912 (512 MB)  ⚠ 2x weaker
   # 00 00 00 10 00 00 00 00 =   268,435,456 (256 MB)  ⚠ 4x weaker
   # 00 00 00 08 00 00 00 00 =   134,217,728 (128 MB)  ⚠ 8x weaker
   # 00 00 00 01 00 00 00 00 =    16,777,216 (16 MB)   🔥 64x weaker
   ```

2. **Regenerate Weak Keys**

   If your key was created with fallback parameters:

   ```bash
   # Generate new key on high-memory system (≥2GB RAM)
   minisign -G -p newkey.pub -s newkey.key

   # Re-sign all previously signed files
   for file in *.tar.gz; do
       minisign -S -s newkey.key -m "$file"
   done

   # Distribute new public key to all verifiers
   # Revoke old public key if possible
   ```

3. **Document Key Provenance**

   If using keys in production, document:
   - System memory when key was generated
   - Whether warning appeared during generation
   - Security requirements for the use case

### For Rust Minisign Users

1. **Never Use `--allow-kdf-fallback` in Production**

   ```bash
   # BAD: Creates permanently weaker keys
   minisign -G --allow-kdf-fallback

   # GOOD: Use system with sufficient memory (≥2GB RAM)
   minisign -G
   ```

2. **Inspect Existing Keys**

   The `-I/--inspect` command allows you to audit your keys:

   ```bash
   # Inspect a secret key
   minisign_rs -I -s ~/.minisign/minisign.key

   # Inspect a public key
   minisign_rs -I -p ~/.minisign/minisign.pub

   # Output for production-strength key:
   # Security Level: HIGH ✓
   #
   # Key Information:
   # ├─ Key ID: RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa
   # ├─ Encrypted: Yes
   # ├─ KDF Algorithm: Scrypt
   # └─ KDF Parameters:
   #    ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
   #    ├─ memlimit: 1073741824 (1024 MB)
   #    └─ Creation: Normal (production parameters)

   # Output for weak key:
   # Security Level: LOW 🔥
   #
   # Key Information:
   # ├─ Key ID: RWQwpZXcv6r8MS...
   # ├─ Encrypted: Yes
   # ├─ KDF Algorithm: Scrypt
   # └─ KDF Parameters:
   #    ├─ opslimit: 4194304 (N=2^17, r=8, p=1)
   #    ├─ memlimit: 134217728 (128 MB)
   #    ├─ Creation: Fallback (reduced parameters)
   #    └─ Brute-force resistance: 8x weaker than production strength
   #
   # ⚠️  RECOMMENDATION: Regenerate this key on a system with ≥2GB RAM for full security.
   ```

   **Security levels**:
   - **HIGH**: Production parameters (N=2^20, 1024 MB)
   - **MEDIUM**: 1-2 fallbacks (N=2^19-18, 256-512 MB, 2-4x weaker)
   - **LOW**: 3+ fallbacks (N≤2^17, ≤128 MB, 8x+ weaker)
   - **NONE**: Unencrypted key (no KDF protection)

### For Security-Critical Deployments

1. **Enforce Key Generation Standards**

   ```bash
   # CI/CD pipeline check (pseudocode)
   if key_memlimit < 1_073_741_824:
       fail("Key was created with reduced security parameters")
   ```

2. **Automated Key Auditing**

   Build tooling to inspect all keys in your infrastructure and flag weak ones.

3. **Consider Hardware Security Modules**

   For critical signing keys, consider HSMs or YubiKeys that don't rely on software KDF.

---

## Attack Cost Analysis

### Brute-Force Attack Cost

Assumptions:
- Attacker has password candidate list (leaked database, dictionary, etc.)
- Modern GPU: ~1 million scrypt iterations/sec at N=2^20
- Password space: 10^9 candidates (moderate strength)

| Key Strength | N | Memlimit | Time per Password | Total Attack Time | Cost (AWS) |
|--------------|---|----------|-------------------|-------------------|------------|
| Production | 2^20 | 1024 MB | 1.0 ms | 11.6 days | $280 |
| After 1 fallback | 2^19 | 512 MB | 0.5 ms | 5.8 days | $140 |
| After 2 fallbacks | 2^18 | 256 MB | 0.25 ms | 2.9 days | $70 |
| After 3 fallbacks | 2^17 | 128 MB | 0.125 ms | 1.45 days | $35 |
| Minimum | 2^14 | 16 MB | 0.016 ms | 4.3 hours | $4.30 |

**Note**: Actual costs vary based on GPU availability and parallelization. The key point is the **relative** reduction in attack cost.

### Password Strength Requirements

To maintain equivalent security:

| Key Strength | Required Password Entropy (bits) |
|--------------|----------------------------------|
| Production (N=2^20) | 40 bits (e.g., 8 random chars) |
| After 3 fallbacks (N=2^17) | 43 bits (e.g., 9 random chars) |
| Minimum (N=2^14) | 46 bits (e.g., 10 random chars) |

Users would need **stronger passwords** to compensate for weaker KDF, but they aren't told this.

---

## Rust Implementation Security Enhancements

The Rust implementation provides comprehensive protection against weak KDF parameters through multiple layers:

### 1. **Creation-Time Protection**
- Fail-by-default when production parameters cannot be met
- Require explicit `--allow-kdf-fallback` flag for reduced parameters
- Display detailed warnings showing exact weakness multiplier

### 2. **Runtime Warnings** (commit 63fd712)
- Detect weak keys during signing and decryption operations
- Display warnings **every time** a weak key is used
- Provide actionable guidance and links to security documentation
- Cannot be silenced or dismissed (appears on stderr)

### 3. **Inspection Capability** (commit e8bceb3)
- New `-I/--inspect` command for auditing key security
- Works with both secret and public keys
- Three-tier security classification (High/Medium/Low)
- Displays exact KDF parameters and weakness calculations
- Fully compatible with C-generated keys (reads bytes 38-53)
- Provides recommendations for weak keys

### Implementation Details

**Warning Detection** (`keys.rs:512-553`):
```rust
pub fn is_weak_kdf(&self) -> bool {
    if !self.encrypted {
        return false;  // Unencrypted keys have no KDF
    }

    // Check if parameters are below production strength
    self.kdf_opslimit < PRODUCTION_OPSLIMIT
        || self.kdf_memlimit < PRODUCTION_MEMLIMIT
}
```

**Inspection** (`ops/inspect.rs`):
- 615 lines of code
- 12 unit tests covering all security levels
- 5 integration tests for CLI behavior
- Weakness multiplier calculation: `PRODUCTION_MEMLIMIT / actual_memlimit`
- Security level classification based on memory thresholds

**Test Coverage**:
- Weak key detection: 5 unit tests
- Warning display: 2 integration tests
- Inspection command: 12 unit tests, 5 CLI tests
- All following TDD principles (tests written first)

---

## Conclusion

The C implementation's automatic KDF fallback represents a **security vs. usability trade-off that prioritizes usability over security**, without informed user consent. This is problematic for a cryptographic tool where security is paramount.

The Rust implementation corrects this by:
1. **Failing loudly** when production parameters can't be met
2. **Requiring explicit opt-in** for fallback (`--allow-kdf-fallback`)
3. **Providing clear warnings** about security implications
4. **Enabling future auditing** (via potential `--inspect` command)

### Key Takeaways

✅ **Fallback keys ARE cryptographically valid and compatible**
✅ **Fallback keys WORK across C and Rust implementations**
⚠️ **Fallback keys are PERMANENTLY WEAKER (8-64x less secure)**
❌ **C implementation provides NO WAY to detect weak keys**
✅ **Rust implementation follows secure-by-default principles**

---

## References

- **C Implementation**: `src/minisign.c:395-443` (encrypt_key)
- **Rust Implementation**: `rs/src/keys.rs:338-387` (new_encrypted)
- **File Format**: `rs/src/keys.rs:231-243` (documentation)
- **Scrypt Spec**: RFC 7914 - https://tools.ietf.org/html/rfc7914
- **Libsodium Docs**: https://doc.libsodium.org/password_hashing/scrypt

---

**Last Updated**: 2026-01-25
**Version**: 1.0
**Authors**: Minisign Rust Project Contributors
