# Hardware-Backed Key Protection

## Overview

Minisign-rs supports optional hardware-backed key protection using platform security modules to protect Ed25519 signing keys. This feature provides defense-in-depth by requiring **both** the key file **and** physical device access with biometric/PIN authentication to perform signing operations.

## Security Model

### Threat Model

Hardware key protection defends against:

- **Key file theft without device**: An attacker who steals only the `.key` file cannot sign messages without also having the physical device and passing biometric/PIN authentication
- **Malware reading key files**: Even if malware exfiltrates the `.key` file, the hardware-backed private key never leaves the security module
- **Memory forensics**: The Ed25519 private key is only decrypted transiently in secure memory during signing operations

Hardware key protection does **not** defend against:

- **Device theft with the key file**: An attacker with both the physical device and the key file can attempt authentication (though biometric/PIN still provides a barrier)
- **Compromised OS with active signing session**: Malware running on a compromised system during a signing operation can potentially capture the decrypted key
- **Recovery password compromise**: The key file always includes a password-protected recovery slot for device loss scenarios

### Cryptographic Design

The system uses **ECIES (Elliptic Curve Integrated Encryption Scheme)** with P-256 keys:

1. **Hardware key generation**: A P-256 private key is generated in the platform security module (Secure Enclave, TPM 2.0) and never extracted
2. **ECIES encryption**: The Ed25519 private key is encrypted to the hardware public key
3. **Authentication gating**: Decryption requires device authentication (Touch ID, Face ID, Windows Hello, or TPM PIN)
4. **Dual-slot design**: A password-protected recovery slot (standard Scrypt encryption) is always present

### ECIES Flow

#### Encryption (Key Generation / Hardware Enrollment)

```
1. hw_private, hw_public ← HW.generate_p256_key(label)
2. ephemeral_secret, ephemeral_public ← generate_ephemeral_p256()
3. shared_secret ← ECDH(ephemeral_secret, hw_public)
4. wrapping_key ← HKDF-SHA256(shared_secret, salt="minisign-ecies-v1", len=32)
5. ciphertext, tag ← AES-256-GCM(wrapping_key, nonce, plaintext_blob)
6. Store: ephemeral_public ‖ nonce ‖ ciphertext ‖ tag ‖ hw_key_label
7. Zeroize: ephemeral_secret, shared_secret, wrapping_key
```

**Key insight**: The hardware private key never leaves the security module. The ephemeral public key and ciphertext are stored in the `.key` file.

#### Decryption (Signing Time)

```
1. [User authentication prompt: Touch ID / Face ID / Windows Hello / PIN]
2. shared_secret ← HW.ecdh(hw_private, ephemeral_public)  [computed inside hardware]
3. wrapping_key ← HKDF-SHA256(shared_secret, salt="minisign-ecies-v1", len=32)
4. plaintext_blob ← AES-256-GCM_decrypt(wrapping_key, nonce, ciphertext, tag)
5. ed25519_secret ← verify_checksum_and_extract(plaintext_blob)
6. Zeroize: shared_secret, wrapping_key, plaintext_blob
```

**Key insight**: The ECDH operation happens **inside** the hardware security module. The shared secret is derived without ever exposing the hardware private key.

## File Format

### Backward-Compatible Dual-Slot Layout

Hardware-enrolled keys use a **three-line format** that is **fully compatible** with the C minisign implementation:

```
untrusted comment: minisign encrypted secret key
<base64 of 158-byte SeckeyStruct>          ← password slot (C-compatible)
<base64 of hardware slot>                   ← hardware slot (ignored by C minisign)
```

**Compatibility guarantee**:
- C minisign reads only lines 1-2 and ignores line 3 (if present)
- Keys created **without** hardware enrollment have only 2 lines (identical to current format)
- Password-protected recovery is always available, even with hardware enrollment

### Hardware Slot Binary Format

| Offset | Size     | Field                                           |
|--------|----------|-------------------------------------------------|
| 0-1    | 2        | `hw_version` — `0x01 0x00` (little-endian)      |
| 2-34   | 33       | `ephemeral_pubkey` — compressed P-256 point     |
| 35-46  | 12       | `nonce` — AES-256-GCM nonce                     |
| 47-150 | 104      | `ciphertext` — encrypted blob (keynum + sk + checksum) |
| 151-166| 16       | `tag` — AES-256-GCM authentication tag         |
| 167-   | variable | `hw_key_label` — UTF-8 key reference (e.g., `minisign:a1b2c3d4e5f6g7h8`) |

**Total: 167 + label_length bytes** (base64-encoded on line 3)

**Format versioning**: The `hw_version` field (`0x0100` for version 1.0) allows future format evolution. Unknown versions are rejected with a clear error.

### Encrypted Blob Contents (104 bytes)

The ciphertext contains:

| Offset | Size | Field                                           |
|--------|------|-------------------------------------------------|
| 0-7    | 8    | `keynum` — Ed25519 key identifier               |
| 8-39   | 32   | `ed25519_secret` — Ed25519 private key          |
| 40-71  | 32   | `checksum` — Blake2b-256(keynum ‖ ed25519_secret) |
| 72-103 | 32   | `padding` — zeros (reserved for future use)     |

The checksum is verified after decryption to detect tampering or corruption.

## Platform Support

### Platform Comparison

| Platform | Hardware         | Auth Mechanism                     | Availability          | Key Storage Location |
|----------|------------------|------------------------------------|------------------------|----------------------|
| macOS    | Secure Enclave   | Touch ID / Face ID                 | All Apple Silicon Macs | Secure Enclave       |
| Windows  | TPM 2.0          | Windows Hello (fingerprint/face/PIN) | Most modern PCs      | TPM NV storage       |
| Linux    | TPM 2.0          | TPM PIN/password                   | Many laptops, servers | TPM persistent handle|

### macOS: Secure Enclave

**Hardware**: Dedicated security coprocessor on Apple Silicon (M1, M2, M3, etc.)

**Key generation**:
- Keys generated with `kSecAttrTokenIDSecureEnclave`
- Access control: `kSecAccessControlBiometryCurrentSet` (Touch ID / Face ID)
- Keys are hardware-bound and cannot be extracted

**ECDH operation**:
- Performed via `SecKeyCreateSharedSecret` API
- Biometric prompt: `"Authenticate to use your minisign signing key"`
- Shared secret returned to application, private key stays in Secure Enclave

**Key label format**: `minisign:<keynum_hex>` (stored in macOS Keychain)

**Rust implementation**: `security-framework` crate (mature, well-maintained)

**Fallback**: If Secure Enclave is unavailable (older Intel Macs), `is_available()` returns `false` and password-only mode is used

### Windows: TPM 2.0 + CNG

**Hardware**: TPM 2.0 chip (discrete or firmware-based)

**Key generation**:
- Via `NCryptCreatePersistedKey` with `MS_PLATFORM_CRYPTO_PROVIDER`
- Keys are TPM-backed and marked as non-exportable
- Windows Hello integration for biometric/PIN gating

**ECDH operation**:
- Performed via `NCryptSecretAgreement` + `NCryptDeriveKey`
- Windows Hello prompt for fingerprint, face, or PIN authentication
- Shared secret returned to application, private key stays in TPM

**Key label format**: `minisign:<keynum_hex>` (stored in Windows TPM NV storage)

**Rust implementation**: `windows` crate (Microsoft official bindings)

**Requirements**:
- Windows 10 build 1607+ (for TPM 2.0 + CNG support)
- Windows Hello must be set up (fingerprint reader, camera, or PIN)

**Fallback**: If TPM is unavailable or Windows Hello not enrolled, password-only mode is used

### Linux: TPM 2.0 + TSS

**Hardware**: TPM 2.0 chip (discrete or firmware-based)

**Key generation**:
- Via `tss-esapi` crate (TPM2 TSS ESAPI bindings)
- P-256 key created with `EccScheme::EcDh` and `EccCurve::NistP256`
- Key made persistent via `evict_control` (persistent handle)

**ECDH operation**:
- Performed via `ecdh_z_gen` (TPM2_ECDH_ZGen command)
- Auth policy: `PolicyAuthValue` (PIN/password prompt)
- Shared secret returned to application, private key stays in TPM

**Key label format**: `minisign:<keynum_hex>` (mapped to TPM persistent handle)

**Rust implementation**: `tss-esapi` crate (TPM2 TSS bindings)

**Requirements**:
- `tpm2-tss` library installed (`libtss2-esys`)
- TPM device accessible (`/dev/tpmrm0` or `/dev/tpm0`)
- User in `tss` group for TPM access (or root)

**Authentication**: Unlike macOS/Windows, Linux lacks a standard biometric framework at the TPM level. PIN/password is used for TPM auth, but the key is still hardware-bound (it cannot be extracted from the TPM).

**Fallback**: If TPM is unavailable or `tpm2-tss` not installed, password-only mode is used

## Command-Line Usage

### Generating Keys with Hardware Protection

```bash
# Generate a new key with hardware protection
minisign_rs -G --hardware-key

# Shorter alias
minisign_rs -G --hw

# With custom paths
minisign_rs -G --hw -s mykey.key -p mykey.pub
```

**Behavior**:
1. Prompts for recovery password (always required, even with hardware enrollment)
2. Generates P-256 key in platform security module
3. Encrypts Ed25519 private key using ECIES
4. Writes 3-line `.key` file (password slot + hardware slot)
5. Displays: `"Key protected by Secure Enclave + recovery password"` (or TPM 2.0)

**Error cases**:
- Hardware unavailable (no Secure Enclave/TPM): Error with clear message
- Biometric not enrolled (Windows): Prompts to set up Windows Hello
- TPM access denied (Linux): Suggests checking `/dev/tpmrm0` permissions

### Signing with Hardware-Protected Keys

```bash
# Sign a file (automatically uses hardware if enrolled)
minisign_rs -S -m file.txt

# Works exactly like password-protected keys - no special flags needed
minisign_rs -S -m file1.txt file2.txt file3.txt -t "v1.0.0 release"
```

**Behavior**:
1. Loads key file and detects hardware slot (if present)
2. If hardware available: Triggers biometric/PIN prompt, decrypts key silently
3. If hardware unavailable: Falls back to password prompt with explanation
4. Signs file using decrypted Ed25519 key
5. Zeroizes all secrets

**Fallback scenarios**:
- **Device changed**: Hardware key missing → password prompt with message: `"Hardware key not found (different device?). Enter recovery password:"`
- **Biometric denied**: User cancels Touch ID → password prompt
- **Platform changed**: Key created on macOS, signing on Linux → password prompt

### Managing Hardware Enrollment

#### Add hardware protection to existing key

```bash
# Add hardware enrollment to a password-protected key
minisign_rs -K --add-hardware-key

# Shorter alias
minisign_rs -K --add-hw
```

**Behavior**:
1. Prompts for current password to decrypt key
2. Generates hardware P-256 key
3. Encrypts Ed25519 key using ECIES
4. Rewrites key file with both slots (password + hardware)

#### Remove hardware protection

```bash
# Remove hardware enrollment, keep password only
minisign_rs -K --remove-hardware-key

# Shorter alias
minisign_rs -K --remove-hw
```

**Behavior**:
1. Decrypts key (tries hardware, falls back to password)
2. Deletes hardware P-256 key from security module
3. Rewrites key file with password slot only (2-line format)

### Inspecting Hardware-Enrolled Keys

```bash
# Inspect a key with hardware enrollment
minisign_rs -I -s mykey.key
```

**Output (hardware-enrolled key)**:
```
Inspecting: mykey.key (hardware-decrypted)

Security Level: HIGH [OK]

Key Information:
├─ Key ID: 31FCAABFDC95A530
├─ Key ID (words): physique aftermath edict lockup tactics Eskimo blockade commence
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt
├─ KDF Parameters:
│  ├─ opslimit: 33554432 (N=2^20, r=8, p=1)
│  ├─ memlimit: 1073741824 (1024 MB)
│  └─ Creation: Normal (production parameters)
├─ HW Protection: Enrolled (Secure Enclave)
├─ HW Key Label: minisign:31fcaabfdc95a530
└─ HW Key Status: Available
```

**Output (hardware-enrolled key, device changed)**:
```
Inspecting: mykey.key (password-decrypted)

Security Level: HIGH [OK]

Key Information:
├─ Key ID: 31FCAABFDC95A530
├─ Encrypted: Yes
├─ KDF Algorithm: Scrypt (production parameters)
├─ HW Protection: Enrolled (Secure Enclave)
├─ HW Key Label: minisign:31fcaabfdc95a530
└─ HW Key Status: Missing (device changed or hardware unavailable)
    ⚠ Recovery password required for signing on this device
```

## Security Considerations

### Threat Model Summary

**Hardware key protection is effective when**:
- Key file is stolen but device is not (attacker cannot sign without device + biometric)
- Malware exfiltrates key files (hardware key cannot be extracted)
- Device is shared but biometric/PIN is strong (unauthorized users blocked)

**Limitations**:
- **Device theft + key file**: Both stolen together → attacker can attempt biometric/PIN
- **Evil maid attack**: Physical access to unlocked device during signing → malware can capture decrypted key
- **Recovery password weakness**: Weak recovery password undermines hardware protection

### Best Practices

1. **Strong recovery password**: Use 20+ character passphrase. The recovery password is the fallback if the device is lost.
2. **Biometric enrollment**: macOS/Windows users should enable Touch ID/Face ID/Windows Hello for best UX.
3. **Key file backup**: Store `.key` file securely (encrypted backup). It contains the ciphertext and recovery password slot.
4. **Device loss procedure**: Use recovery password on new device, then re-enroll hardware protection.
5. **Multi-device scenarios**: Hardware keys are device-bound. Use recovery password on secondary devices, or enroll hardware on each device separately (requires separate key files per device).

### When NOT to Use Hardware Protection

- **Headless servers**: No biometric enrollment, password-only is simpler
- **CI/CD pipelines**: Automated signing requires password-only keys
- **Shared signing keys**: Multiple users/devices need access (hardware keys are device-bound)
- **Containers/VMs**: Hardware security modules typically not available in virtualized environments

### Recovery Scenarios

| Scenario | Solution |
|----------|----------|
| Device lost/broken | Use recovery password on new device, re-enroll hardware if desired |
| Hardware key deleted accidentally | Use recovery password, re-enroll with `-K --add-hw` |
| Moved key to different device | Use recovery password (hardware keys are device-bound) |
| Biometric enrollment changed | Hardware key invalid, use recovery password, re-enroll if needed |
| OS reinstalled | Hardware keys lost, use recovery password, re-enroll with `-K --add-hw` |

## Implementation Details

### Cryptographic Primitives

**Dependencies** (from RustCrypto):
- `p256` - P-256 elliptic curve operations (ECDH, ephemeral key generation)
- `aes-gcm` - AES-256-GCM authenticated encryption
- `hkdf` - HKDF-SHA256 key derivation
- `sha2` - SHA-256 hash function

**HKDF parameters**:
- Hash: SHA-256
- Salt: `"minisign-ecies-v1"` (UTF-8 bytes)
- Info: empty
- Output length: 32 bytes (256-bit AES key)

**AES-GCM parameters**:
- Key size: 256 bits
- Nonce size: 12 bytes (96 bits, recommended)
- Tag size: 16 bytes (128 bits, full tag)

**P-256 point compression**: Ephemeral public keys are stored in compressed format (33 bytes: 0x02/0x03 prefix + x-coordinate).

### Platform Backend Selection (Compile-Time)

The appropriate hardware backend is selected at compile time via Cargo features:

```toml
[features]
default = []
hw-keystore-macos = ["dep:security-framework"]
hw-keystore-windows = ["dep:windows"]
hw-keystore-linux = ["dep:tss-esapi"]
```

**Automatic platform detection**:
```toml
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = { version = "3", optional = true }

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.58", optional = true, features = [...] }

[target.'cfg(target_os = "linux")'.dependencies]
tss-esapi = { version = "8", optional = true }
```

If no hardware backend is compiled in, an `UnsupportedHardwareKeyStore` stub is used that returns `is_available() = false` for all operations.

### HardwareKeyStore Trait

All platform backends implement a common trait:

```rust
pub trait HardwareKeyStore {
    /// Generate a new P-256 key pair in hardware, gated by device auth.
    fn generate_key(&self, label: &str) -> Result<p256::PublicKey>;

    /// Perform ECDH inside hardware: shared_secret = ECDH(hw_private, peer_public).
    fn ecdh(&self, label: &str, peer_public: &p256::PublicKey) -> Result<SharedSecret>;

    /// Check if a key with this label exists in hardware.
    fn key_exists(&self, label: &str) -> Result<bool>;

    /// Delete a key from hardware.
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Returns true if hardware key store is available on this platform.
    fn is_available(&self) -> bool;

    /// Human-readable name for UI messages.
    fn display_name(&self) -> &'static str;
}
```

**Key insight**: The `ecdh()` method performs the operation **inside** the hardware security module. The shared secret is returned to the application, but the hardware private key never leaves the module.

### Zeroization

All cryptographic secrets are wrapped in `Zeroizing<T>` from the `zeroize` crate:

- Ephemeral P-256 secret key
- ECDH shared secret
- HKDF-derived wrapping key
- Decrypted Ed25519 private key blob

This ensures secrets are wiped from memory when dropped, even in the presence of panics.

## Testing

### Unit Tests (Automated)

**Mock `HardwareKeyStore`**: In-memory implementation for automated testing:
- Simulates hardware key generation and ECDH
- Configurable: can simulate auth denial, missing keys, hardware failure
- Enables full test coverage without real hardware

**Test coverage**:
- ECIES round-trip (encrypt → decrypt → verify plaintext matches)
- Tampered ciphertext → GCM tag verification failure
- Tampered ephemeral public key → ECDH produces wrong secret → GCM failure
- Wrong hardware key label → error
- Biometric denial (mock) → error propagation
- Zeroization of intermediates (verified via memory inspection)

### Integration Tests (Manual)

**Platform-specific tests** (gated by `#[cfg(target_os = "...")]` and `MINISIGN_TEST_HW_KEYSTORE=1`):

```bash
# macOS: Test with real Secure Enclave
MINISIGN_TEST_HW_KEYSTORE=1 cargo test --features hw-keystore-macos -- --ignored

# Windows: Test with real TPM 2.0
$env:MINISIGN_TEST_HW_KEYSTORE=1; cargo test --features hw-keystore-windows -- --ignored

# Linux: Test with real TPM 2.0
MINISIGN_TEST_HW_KEYSTORE=1 cargo test --features hw-keystore-linux -- --ignored
```

**Manual test checklist** (per platform):
1. Generate key with hardware enrollment → verify 3-line file
2. Sign file → verify biometric prompt appears → signature created
3. Verify signature → works correctly
4. Move key to different device → password fallback works
5. Change: add hardware to password-only key → verify 3-line file
6. Change: remove hardware from enrolled key → verify 2-line file
7. Inspect: shows hardware status correctly

## Compatibility

### C Minisign Compatibility

**Forward compatibility**: C minisign can read and use keys created by Rust minisign with hardware enrollment:

- C reads lines 1-2 only (untrusted comment + password slot)
- Line 3 (hardware slot) is ignored
- Password-protected recovery works on any platform
- Signatures created by either implementation verify correctly

**File format guarantee**: The 3-line format is an additive extension. Removing line 3 makes the file identical to a standard C minisign key.

### Cross-Platform Key Portability

| Scenario | Result |
|----------|--------|
| Key created on macOS with `--hw`, used on Linux | Password prompt (hardware slot ignored) |
| Key created on Windows with `--hw`, used on macOS | Password prompt (different hardware) |
| Key created on Linux (password only), used on macOS | Password prompt (no change) |
| Key created with `--hw`, used on same device | Biometric prompt (hardware decryption) |

**Key insight**: Hardware keys are **device-bound by design**. Cross-device usage requires the recovery password.

## Future Work (Out of Scope)

The following features are **not** implemented in the current version but could be added in the future:

- **Android StrongBox / TEE**: Same trait interface, different backend implementation
- **Hardware-only keys (no password slot)**: Requires alternative recovery strategy (e.g., key escrow, Shamir secret sharing)
- **Multiple hardware enrollments**: Encrypt to N devices simultaneously (requires N hardware slots in file format)
- **Key migration between devices**: Requires secure out-of-band key transfer protocol
- **Cross-device sync**: Fundamentally incompatible with hardware-bound keys (by design)

## References

### Specifications

- [ECIES (Elliptic Curve Integrated Encryption Scheme)](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme)
- [NIST SP 800-56A Rev. 3: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://tools.ietf.org/html/rfc5869)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

### Platform Documentation

- **macOS**: [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- **Windows**: [TPM 2.0 and Platform Crypto Provider](https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-fundamentals)
- **Linux**: [TPM 2.0 TSS (Trusted Computing Group)](https://trustedcomputinggroup.org/resource/tss-overview-common-structures-specification/)

### Rust Crates

- [p256](https://docs.rs/p256/) - NIST P-256 elliptic curve (RustCrypto)
- [aes-gcm](https://docs.rs/aes-gcm/) - AES-GCM authenticated encryption (RustCrypto)
- [hkdf](https://docs.rs/hkdf/) - HKDF key derivation (RustCrypto)
- [security-framework](https://docs.rs/security-framework/) - macOS Security framework bindings
- [windows](https://docs.rs/windows/) - Windows API bindings (Microsoft official)
- [tss-esapi](https://docs.rs/tss-esapi/) - TPM 2.0 TSS ESAPI bindings

## Glossary

- **ECIES**: Elliptic Curve Integrated Encryption Scheme - a hybrid encryption system combining ECDH key agreement with symmetric encryption
- **ECDH**: Elliptic Curve Diffie-Hellman - a key agreement protocol allowing two parties to establish a shared secret
- **HKDF**: HMAC-based Key Derivation Function - a cryptographic key derivation function
- **GCM**: Galois/Counter Mode - an authenticated encryption mode for block ciphers
- **Secure Enclave**: Apple's dedicated security coprocessor on Apple Silicon Macs
- **TPM**: Trusted Platform Module - a hardware security module standard (version 2.0 used)
- **CNG**: Cryptography Next Generation - Windows cryptographic API
- **TSS**: TCG Software Stack - standard API for TPM 2.0 interaction
- **P-256**: NIST elliptic curve (also known as secp256r1 or prime256v1)
- **Ephemeral key**: A temporary cryptographic key used once and then discarded
- **Zeroization**: Secure erasure of sensitive data from memory
