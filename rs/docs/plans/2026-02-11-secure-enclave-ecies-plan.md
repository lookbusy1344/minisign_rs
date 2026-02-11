# Hardware-Backed ECIES Key Protection

## Overview

Add optional hardware-backed key protection using ECIES (Elliptic Curve
Integrated Encryption Scheme). The Ed25519 signing key is encrypted using a
P-256 key held in a platform hardware security module, accessible only via
biometric or device authentication.

| Platform | Hardware         | Auth Mechanism                     |
|----------|------------------|------------------------------------|
| macOS    | Secure Enclave   | Touch ID / Face ID                 |
| Windows  | TPM 2.0          | Windows Hello (fingerprint/face/PIN) |
| Linux    | TPM 2.0          | TPM auth policy (PIN/password)     |

This is an **optional alternative** to password-based encryption. Standard
password-encrypted keys remain the default and are fully compatible with the
legacy C minisign implementation.

### Security Model

To decrypt the Ed25519 private key, an attacker needs **both**:

1. The `.key` file (contains ciphertext + ephemeral P-256 public key)
2. Authenticated access to the device's hardware key store (holds the P-256
   private key)

A recovery password slot (standard Scrypt encryption) is always present for
break-glass recovery if the device is lost.

### ECIES Flow

**Encryption (key generation / HW enrollment):**

```
1. Hardware generates P-256 key pair (private stays in hardware, auth-gated)
2. Generate ephemeral P-256 key pair (e, E = eG)
3. shared_secret = ECDH(e, HW_public)          -- outside hardware, ephemeral key available
4. wrapping_key  = HKDF-SHA256(shared_secret, salt="minisign-ecies-v1", len=32)
5. ciphertext    = AES-256-GCM(wrapping_key, nonce, keynum ‖ ed25519_sk ‖ checksum)
6. Store in file: E ‖ nonce ‖ ciphertext ‖ tag ‖ HW key label
7. Zeroize: e, shared_secret, wrapping_key
```

**Decryption (signing time):**

```
1. Auth prompt (biometric/PIN) → hardware access granted
2. shared_secret = ECDH(HW_private, E)          -- computed INSIDE hardware
3. wrapping_key  = HKDF-SHA256(shared_secret, salt="minisign-ecies-v1", len=32)
4. plaintext     = AES-256-GCM_decrypt(wrapping_key, nonce, ciphertext, tag)
5. Verify Blake2b-256 checksum over (keynum ‖ ed25519_sk)
6. Zeroize: shared_secret, wrapping_key
```

---

## File Format

### Backward-Compatible Dual-Slot Layout

```
untrusted comment: minisign encrypted secret key
<base64 of 158-byte SeckeyStruct>          ← standard password slot (C-compatible)
<base64 of HW-encrypted payload>           ← HW slot (ignored by C minisign)
```

The C implementation reads only lines 1-2, so the third line is invisible to it.
Keys created without HW enrollment have no third line (identical to current
format).

### HW Slot Binary Layout

| Offset | Size     | Field                                           |
|--------|----------|-------------------------------------------------|
| 0-1    | 2        | `hw_version` — `0x01 0x00`                      |
| 2-34   | 33       | `ephemeral_pubkey` — compressed P-256 point     |
| 35-46  | 12       | `nonce` — AES-256-GCM nonce                     |
| 47-150 | 104      | `ciphertext` — encrypted blob (keynum + sk + checksum) |
| 151-166| 16       | `tag` — AES-256-GCM auth tag                   |
| 167-   | variable | `hw_key_label` — UTF-8 key reference (e.g. `minisign:<keynum_hex>`) |

**Total: 167 + label length bytes** (base64-encoded on line 3)

The `hw_version` field allows future format evolution without breaking existing
HW-encrypted keys. The format is **platform-agnostic** — only the label
identifies which hardware backend created the key.

---

## Dependencies (new crates)

| Crate                | Purpose                            | Platform  | Notes                   |
|----------------------|------------------------------------|-----------|-------------------------|
| `p256`               | P-256 ECDH + ephemeral key gen     | All       | RustCrypto              |
| `aes-gcm`            | AES-256-GCM authenticated encrypt  | All       | RustCrypto              |
| `hkdf`               | HKDF-SHA256 key derivation         | All       | RustCrypto              |
| `sha2`               | SHA-256 (for HKDF)                 | All       | RustCrypto              |
| `security-framework` | Keychain / Secure Enclave          | macOS     | Mature, well-maintained |
| `windows`            | CNG / TPM via Platform Crypto      | Windows   | Microsoft official      |
| `tss-esapi`          | TPM 2.0 TSS bindings               | Linux     | Requires `tpm2-tss` lib |

ECIES crypto crates are from the RustCrypto project for consistency and audit
trail. Platform crates are conditionally compiled per target.

---

## Phased Implementation

### Phase 1: ECIES Crypto Primitives

Pure-Rust cryptographic building blocks with no platform dependencies.

**New file: `src/ecies.rs`**

Implement and test:

- `generate_ephemeral_p256() → (EphemeralSecret, PublicKey)` — P-256 keypair
- `ecdh(secret, peer_public) → SharedSecret` — ECDH key agreement
- `derive_wrapping_key(shared_secret) → [u8; 32]` — HKDF-SHA256 with fixed
  context string `"minisign-ecies-v1"`
- `ecies_encrypt(wrapping_key, plaintext) → (nonce, ciphertext, tag)` —
  AES-256-GCM
- `ecies_decrypt(wrapping_key, nonce, ciphertext, tag) → plaintext` —
  AES-256-GCM
- All outputs wrapped in `Zeroizing<>` where appropriate

**Tests:**

- Round-trip encrypt/decrypt with known test vectors
- Wrong key → decryption failure (tag verification)
- Nonce uniqueness (statistical test over N encryptions)
- Zeroization of intermediate secrets

**Acceptance criteria:**

- All primitives work independently of any platform API
- Can encrypt/decrypt a 104-byte blob (matching `ENCRYPTED_BLOB_SIZE`)
- Full test coverage of happy path and error cases

---

### Phase 2: Platform Abstraction + Hardware Backends

Define a trait for hardware key store operations and implement per platform.

#### Phase 2a: Trait Definition + Mock + macOS Secure Enclave

**New file: `src/hw_keystore/mod.rs`**

```rust
pub trait HardwareKeyStore {
    /// Generate a new P-256 key pair in hardware, gated by device auth.
    /// Returns the public key (private key stays in hardware).
    fn generate_key(&self, label: &str) -> Result<p256::PublicKey>;

    /// Perform ECDH inside hardware: shared_secret = ECDH(hw_private, peer_public).
    /// Triggers auth prompt (biometric/PIN).
    fn ecdh(&self, label: &str, peer_public: &p256::PublicKey) -> Result<SharedSecret>;

    /// Check if a key with this label exists in hardware.
    fn key_exists(&self, label: &str) -> Result<bool>;

    /// Delete a key from hardware.
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Returns true if hardware key store is available on this platform.
    fn is_available(&self) -> bool;

    /// Human-readable name for UI messages (e.g. "Secure Enclave", "TPM 2.0").
    fn display_name(&self) -> &'static str;
}
```

**New file: `src/hw_keystore/mock.rs`**

- In-memory `HashMap<String, (SecretKey, PublicKey)>` implementing the trait
- Configurable: can simulate biometric denial, missing keys, hardware failure
- Used for all automated testing in phases 3-5

**New file: `src/hw_keystore/macos.rs`**

- Implement `HardwareKeyStore` for macOS using `security-framework`
- Key generation with `kSecAttrTokenIDSecureEnclave` +
  `kSecAccessControlBiometryCurrentSet`
- ECDH via `SecKeyCreateSharedSecret`
- Key label format: `minisign:<keynum_hex>` for deterministic lookup
- Biometric prompt string: `"Authenticate to use your minisign signing key"`

**New file: `src/hw_keystore/unsupported.rs`**

- Stub implementation returning `Error::HardwareKeyStoreUnavailable` for all
  ops
- Fallback for platforms with no backend compiled in
- `is_available()` returns `false`

**Feature flags:**

```toml
[features]
default = []
hw-keystore-macos = ["dep:security-framework"]
hw-keystore-windows = ["dep:windows"]
hw-keystore-linux = ["dep:tss-esapi"]
```

Enabled automatically via platform-conditional defaults in `Cargo.toml`:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = { version = "3", optional = true }

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.58", optional = true, features = ["..."] }

[target.'cfg(target_os = "linux")'.dependencies]
tss-esapi = { version = "8", optional = true }
```

**Tests:**

- Unit tests for the unsupported stub (always returns errors)
- Unit tests for the mock (configurable success/failure)
- Integration tests for macOS SE (gated by `#[cfg(target_os = "macos")]` and
  an environment variable `MINISIGN_TEST_HW_KEYSTORE=1` since they require
  hardware + biometric enrollment)
- Mock implementation enables full automated testing of phases 3-5

**Acceptance criteria:**

- Trait compiles on all platforms
- macOS implementation can generate keys and perform ECDH (manual verification)
- Unsupported platforms get a clear error message
- Mock implementation enables full automated testing

#### Phase 2b: Windows TPM Backend

**New file: `src/hw_keystore/windows.rs`**

- Implement `HardwareKeyStore` using Windows CNG (Cryptography Next Generation)
- Key generation via `NCryptCreatePersistedKey` with
  `MS_PLATFORM_CRYPTO_PROVIDER` (TPM-backed)
- ECDH via `NCryptSecretAgreement` + `NCryptDeriveKey`
- Windows Hello integration for biometric/PIN gating via
  `NCRYPT_PIN_CACHE_PIN_PROPERTY` or `NCRYPT_WINDOW_HANDLE_PROPERTY` for
  UI prompt
- Key label format: same `minisign:<keynum_hex>` convention
- `display_name()` returns `"TPM 2.0 (Windows Hello)"`

**Platform considerations:**

- Requires Windows 10 build 1607+ (TPM 2.0 + CNG support)
- Not all Windows machines have TPM — `is_available()` must probe for TPM
  presence via `NCryptOpenStorageProvider` with platform provider
- Windows Hello enrollment is a prerequisite — if not set up, prompt user to
  enroll via Windows Settings
- The `windows` crate from Microsoft provides safe bindings; features needed:
  `Win32_Security_Cryptography`, `Win32_Security_Credentials`

**Tests:**

- Integration tests gated by `#[cfg(target_os = "windows")]` +
  `MINISIGN_TEST_HW_KEYSTORE=1`
- Same test matrix as macOS: generate, ECDH, key existence, deletion
- TPM not present → `is_available()` returns false, clear error message

**Acceptance criteria:**

- Full `HardwareKeyStore` trait implementation for Windows
- Works with Windows Hello (fingerprint, face, or PIN)
- Graceful degradation when TPM not available
- Manual end-to-end test on a Windows machine with TPM

#### Phase 2c: Linux TPM Backend

**New file: `src/hw_keystore/linux.rs`**

- Implement `HardwareKeyStore` using `tss-esapi` (TPM2 TSS bindings)
- Key generation via `create_primary` + `create` with `EccScheme::EcDh` and
  `EccCurve::NistP256`
- ECDH via `ecdh_z_gen` (TPM2_ECDH_ZGen command)
- Auth policy: `PolicyAuthValue` (PIN/password) — Linux lacks a standard
  biometric framework at the TPM level
- Key persistence: store in TPM NV index or use persistent handle
  (`evict_control` to make transient key persistent)
- `display_name()` returns `"TPM 2.0"`

**Platform considerations:**

- Requires `tpm2-tss` library installed on the system (`libtss2-esys`)
- TPM device must be accessible (`/dev/tpmrm0` or `/dev/tpm0`)
- User may need to be in `tss` group for TPM access
- Auth model differs from macOS/Windows: PIN/password rather than biometric.
  This is still a security improvement because key material is hardware-bound
  (the PIN protects TPM access, the key never leaves the TPM)
- `is_available()` checks for TPM device node + library presence
- Some VMs and cloud instances lack TPM — `is_available()` handles this

**Tests:**

- Integration tests gated by `#[cfg(target_os = "linux")]` +
  `MINISIGN_TEST_HW_KEYSTORE=1`
- Same test matrix as macOS/Windows
- swtpm (software TPM emulator) can be used for CI testing if needed,
  but hardware tests are preferred for confidence

**Acceptance criteria:**

- Full `HardwareKeyStore` trait implementation for Linux
- Works with physical TPM 2.0
- Graceful degradation when TPM not available
- Manual end-to-end test on a Linux machine with TPM

---

### Phase 3: HW Slot Format + Key File Extension

Extend the key file format to support an optional HW-encrypted slot.

**Modify: `src/keys.rs`**

- New struct `HwSlot`:
  ```rust
  pub struct HwSlot {
      hw_version: u16,
      ephemeral_pubkey: [u8; 33],   // compressed P-256
      nonce: [u8; 12],              // AES-256-GCM nonce
      ciphertext: [u8; 104],        // encrypted blob
      tag: [u8; 16],                // GCM auth tag
      hw_key_label: String,         // hardware key reference
  }
  ```
- `HwSlot::to_bytes() → Vec<u8>` / `HwSlot::from_bytes(&[u8]) → Result<Self>`
- Extend key file parsing: after reading the standard 2-line format, check for
  an optional third base64 line → parse as `HwSlot`
- Extend key file writing: if HW slot present, append third line

**Modify: `src/constants.rs`**

- `HW_SLOT_VERSION: u16 = 1`
- `HW_SLOT_FIXED_SIZE: usize = 167` (excluding variable-length label)
- `HW_KEY_LABEL_MAX_BYTES: usize = 64`

**Modify: `src/formats.rs`**

- Extend `read_secret_key_file()` to return `(SeckeyStruct, Option<HwSlot>)`
- Extend `write_secret_key_file()` to accept optional `HwSlot`

**Tests:**

- Round-trip serialization of `HwSlot`
- Key file with HW slot: write → read → verify both slots present
- Key file without HW slot: backward-compatible (no third line)
- Invalid HW slot data → clear error
- C-compatible key files still parse correctly (no third line)
- Reject HW slot with unknown version (forward compatibility)

**Acceptance criteria:**

- Existing key files load without any change in behavior
- New key files with HW slot write a third base64 line
- `HwSlot` serialization is fully tested with known byte sequences

---

### Phase 4: ECIES Wrapping Integration

Connect the crypto primitives (Phase 1) with the platform layer (Phase 2)
and the file format (Phase 3).

**New file: `src/ecies_wrap.rs`**

Two high-level functions:

```rust
/// Encrypt the Ed25519 secret key blob using ECIES with hardware key store.
pub fn ecies_wrap(
    hw: &dyn HardwareKeyStore,
    hw_key_label: &str,
    plaintext_blob: &[u8; ENCRYPTED_BLOB_SIZE],
) -> Result<HwSlot>

/// Decrypt the HW slot to recover the Ed25519 secret key blob.
pub fn ecies_unwrap(
    hw: &dyn HardwareKeyStore,
    hw_slot: &HwSlot,
) -> Result<Zeroizing<[u8; ENCRYPTED_BLOB_SIZE]>>
```

**Flow (wrap):**
1. Retrieve HW public key for label (or error if not found)
2. Generate ephemeral P-256 keypair
3. ECDH(ephemeral_secret, HW_public) → shared_secret
4. HKDF → wrapping_key
5. AES-256-GCM encrypt → (nonce, ciphertext, tag)
6. Build `HwSlot` with ephemeral public (compressed), nonce, ciphertext, tag,
   label
7. Zeroize ephemeral secret, shared_secret, wrapping_key

**Flow (unwrap):**
1. Decompress ephemeral public key from `HwSlot`
2. `hw.ecdh(label, ephemeral_public)` → shared_secret (triggers auth prompt)
3. HKDF → wrapping_key
4. AES-256-GCM decrypt → plaintext_blob
5. Zeroize shared_secret, wrapping_key
6. Return plaintext blob (caller verifies checksum)

**Modify: `src/keys.rs`**

- `SeckeyStruct::decrypt_with_hw(hw, hw_slot) → Result<(SecretKey, KeyNum)>`:
  calls `ecies_unwrap`, then verifies Blake2b checksum, extracts keynum +
  secret key — mirrors the existing `decrypt()` flow

**Tests (using mock `HardwareKeyStore`):**

- Round-trip: wrap → unwrap → verify plaintext matches
- Tampered ciphertext → GCM tag failure
- Tampered ephemeral public key → ECDH produces wrong secret → GCM failure
- Wrong HW key label → error
- Auth denied (mock) → error propagation
- Zeroization of intermediates (check memory after drop)

**Acceptance criteria:**

- Full ECIES wrap/unwrap cycle works with mock hardware
- All error paths produce clear, distinct errors
- No secret material leaks (Zeroizing on all intermediates)

---

### Phase 5: CLI + Operation Integration

Wire everything into the existing operations and CLI.

**Modify: `src/errors.rs`**

New error variants:
- `HardwareKeyStoreUnavailable` — platform has no supported hardware
- `HardwareKeyStoreAuthDenied` — biometric/PIN auth failed or cancelled
- `HardwareKeyNotFound { label }` — HW key missing (device changed?)
- `HwSlotCorrupted` — decryption/format failure
- `HardwareKeyStoreError { detail }` — other hardware errors

**Modify: `src/cli.rs`**

New flags:
- `--hardware-key` / `--hw` — enroll hardware key protection during generation
- No flag needed for signing/verification — HW slot is auto-detected

**Modify: `src/ops/generate.rs`**

- Extend `GenerateOptionsBuilder` with `.hardware_key(bool)`
- When HW requested:
  1. Check `hw.is_available()` — error early if no hardware
  2. Generate Ed25519 keypair as usual
  3. Prompt for recovery password (always required for dual-slot)
  4. Create standard Scrypt-encrypted `SeckeyStruct` (password slot)
  5. Generate HW P-256 key with label `minisign:<keynum_hex>`
  6. ECIES-wrap the plaintext blob → `HwSlot`
  7. Write key file with both slots
  8. Display: `"Key protected by <hw.display_name()> + recovery password"`
- When HW not requested: existing behavior (no change)

**Modify: `src/ops/sign.rs`**

- In `load_and_decrypt_key()`:
  1. Load key file (may have HW slot)
  2. If HW slot present AND `hw.is_available()` → attempt `decrypt_with_hw()`
  3. If HW decrypt succeeds → use key (no password needed)
  4. If HW decrypt fails (denied, unavailable, missing key) → fall back to
     password prompt with message explaining why
  5. If no HW slot → existing password flow (no change)

**Modify: `src/ops/change.rs`**

- Extend `ChangeOptionsBuilder` with:
  - `.add_hardware_key(bool)` — enroll HW on an existing password-protected key
  - `.remove_hardware_key(bool)` — remove HW slot, keep password only
- Add HW enrollment:
  1. Decrypt with existing password
  2. Generate HW key + ECIES wrap
  3. Rewrite key file with both slots
- Remove HW enrollment:
  1. Decrypt with password or HW
  2. Rewrite key file with password slot only
  3. Delete HW key from hardware store

**Modify: `src/ops/inspect.rs`**

- Show HW enrollment status:
  ```
  HW protection:     enrolled (label: minisign:a1b2c3d4e5f6g7h8)
  HW backend:        Secure Enclave / TPM 2.0 / unavailable
  HW key available:  yes / no (device changed?)
  ```
- If HW slot present but hardware unavailable, show warning

**Modify: `src/main.rs`**

- Instantiate appropriate `HardwareKeyStore` based on platform
  (compile-time dispatch via `cfg`)
- Pass to operations that need it
- Display appropriate messages for HW operations

**Tests:**

- CLI integration test: `--hardware-key` flag accepted during generate
- CLI integration test: `--hardware-key` flag rejected when HW unavailable
  (unsupported platform stub)
- Generate with HW → key file has 3 lines
- Generate without HW → key file has 2 lines (unchanged)
- Sign with HW key → no password prompt (mock auth success)
- Sign with HW key, auth denied → falls back to password prompt
- Sign with HW key on different device (HW key missing) → falls back to
  password
- Change: add HW to existing key → key file gains third line
- Change: remove HW from key → key file loses third line, HW key deleted
- Inspect: shows HW status correctly
- All existing tests pass unchanged (no regression)

**Acceptance criteria:**

- Existing workflow is completely unchanged when `--hardware-key` is not used
- HW enrollment works end-to-end on each platform (manual test)
- Fallback to password works when HW is unavailable
- Key files with HW slot are readable by C minisign (it ignores line 3)
- All 466+ existing tests pass

---

### Phase 6: Documentation + Polish

- Update `README.md` with hardware key usage instructions and platform matrix
- Add `docs/hardware-key-protection.md` explaining the security model, ECIES
  scheme, file format, and platform-specific details
- Ensure `--help` text for new flags is clear and concise
- Verify cross-compilation still works (HW code compiles to no-op on
  platforms without the feature flag)

---

## Implementation Order

Phases 1, 3, and 2a can proceed in parallel (no dependencies between them).
Phase 2b and 2c can proceed in parallel after 2a (they follow the same trait).
Phase 4 requires 1 + 2a + 3. Phase 5 requires 4. Phase 6 is last.

```
Phase 1 (ECIES crypto) ──────────────────┐
Phase 2a (trait + mock + macOS) ──────────┤
Phase 3 (file format) ───────────────────→├→ Phase 4 (wrapping) → Phase 5 (CLI) → Phase 6 (docs)
                                          │
Phase 2b (Windows TPM) ──────────────────→┘  (can land independently after 2a)
Phase 2c (Linux TPM) ────────────────────→┘  (can land independently after 2a)
```

---

## Platform Comparison

| Capability              | macOS Secure Enclave      | Windows TPM 2.0           | Linux TPM 2.0             |
|-------------------------|---------------------------|---------------------------|---------------------------|
| P-256 key generation    | Yes                       | Yes                       | Yes                       |
| ECDH in hardware        | Yes                       | Yes                       | Yes                       |
| Key never extracted     | Yes                       | Yes                       | Yes                       |
| Biometric gating        | Touch ID / Face ID        | Windows Hello             | No (PIN/password only)    |
| Auth UX                 | OS-managed, polished      | OS-managed, polished      | CLI prompt (less seamless)|
| Prevalence              | All Apple Silicon Macs    | Most modern PCs           | Many laptops, some servers|
| Rust crate maturity     | Mature                    | Solid (Microsoft-backed)  | Functional, less polished |
| System library needed   | None (built-in)           | None (built-in)           | `libtss2-esys` required  |
| CI testability          | macOS runners only        | Windows runners only      | Needs TPM or swtpm       |

---

## Out of Scope (Future Work)

- **Android StrongBox / TEE** — same trait, different backend
- **HW-only keys (no password slot)** — requires alternative recovery strategy
- **Multiple HW enrollments** — encrypt to N devices simultaneously
- **Key migration between devices** — requires out-of-band key transfer
- **Cross-device sync** — HW keys are inherently device-bound by design

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| macOS SE API needs Objective-C bridging | `security-framework` crate handles FFI |
| Biometric prompt UX varies by OS version | Use standard platform APIs, defer UX to OS |
| HW key orphaned if key file deleted | Inspect command can list/clean HW keys |
| CI can't test HW (no hardware) | Mock `HardwareKeyStore` for automated tests; manual test gate for release |
| `security-framework` crate lags macOS API | Pin version; SE APIs stable since macOS 10.12.1 |
| Compressed P-256 point encoding edge cases | Use `p256` crate's `CompressedPoint` type |
| Windows CNG API complexity | `windows` crate provides safe bindings; CNG is well-documented |
| Linux `tpm2-tss` not installed | `is_available()` checks for library; clear error message with install instructions |
| Linux TPM permissions (`/dev/tpmrm0`) | Document required group membership (`tss`); `is_available()` checks access |
| No biometric on Linux | Document that Linux uses PIN/password for TPM auth; still hardware-bound |
| Key file created on Mac used on Linux | Password slot works everywhere; HW slot is device-bound (by design) |
