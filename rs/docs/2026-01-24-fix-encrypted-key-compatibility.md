# Fix C/Rust Key Encryption Compatibility

**Date:** 2026-01-24
**Status:** Planned

## Root Cause

The Rust implementation has a **key derivation length mismatch** with C minisign:

- **C minisign:** Derives **72 bytes** (keynum 8 + secret_key 64) and encrypts both together
- **Rust implementation:** Derives **64 bytes** (secret_key only) and stores keynum unencrypted

This causes C-generated encrypted keys to fail checksum validation when decrypted in Rust.

### Evidence

From diagnostic output:
```
Expected checksum: [a9, a7, 17, d1, 28, 96, 22, 4e]
Computed checksum: [1a, 0a, 1a, 88, 18, 2e, 94, 4a]
Parameters: opslimit=33554432, memlimit=1073741824, log_n=20, r=8, p=1
```

Parameters are correct, but decrypted data is wrong because:
1. C encrypted: `keynum (8 bytes) + secret_key (64 bytes)` with 72-byte derived key
2. Rust decrypts: Only `secret_key (64 bytes)` with 64-byte derived key
3. The keynum bytes remain encrypted, corrupting the decrypted secret key

### C Implementation Reference

From [minisign.c](https://github.com/jedisct1/minisign/blob/master/src/minisign.c):

```c
crypto_pwhash_scryptsalsa208sha256(stream, sizeof seckey_struct->keynum_sk, ...)
xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
        sizeof seckey_struct->keynum_sk);
```

Where `keynum_sk` = 8-byte keynum + 64-byte secret key = **72 bytes total**.

## Algorithm Compatibility Note

**scryptsalsa208sha256 IS RFC 7914 scrypt** - they are the same algorithm:
- Both use Salsa20/8 for block mixing
- Both use PBKDF2-HMAC-SHA-256
- The RustCrypto `scrypt 0.11` crate implements RFC 7914 correctly

The issue is NOT the algorithm - it's the **output length parameter** (64 vs 72 bytes).

## Implementation Plan

### Critical Files

1. **`src/keys.rs`** - SeckeyStruct encryption/decryption (HIGH impact)
2. **`src/crypto.rs`** - No changes needed (KDF function is correct)
3. **Tests** - All encrypted key tests will start passing

### Detailed Changes

#### 1. Fix `SeckeyStruct::new_encrypted()` (src/keys.rs:260-293)

**Current code (WRONG):**
```rust
// Line 272-273: Derives only 64 bytes
let derived_key =
    derive_key_with_params(password, &kdf_salt, log_n, r, p, SECRET_KEY_BYTES)?;

// Line 277-278: Only encrypts secret_key
for i in 0..SECRET_KEY_BYTES {
    secret_key_encrypted[i] = secret_key.as_bytes()[i] ^ derived_key[i];
}
```

**Fixed code:**
```rust
// Derive 72 bytes (keynum + secret_key) to match C implementation
const ENCRYPTED_BLOB_SIZE: usize = KEYNUM_BYTES + SECRET_KEY_BYTES; // 8 + 64 = 72
let derived_key =
    derive_key_with_params(password, &kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)?;

// Create combined blob: keynum + secret_key
let mut blob = Vec::with_capacity(ENCRYPTED_BLOB_SIZE);
blob.extend_from_slice(keynum.as_bytes());
blob.extend_from_slice(secret_key.as_bytes());

// Encrypt entire blob with XOR
let mut encrypted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
for i in 0..ENCRYPTED_BLOB_SIZE {
    encrypted_blob[i] = blob[i] ^ derived_key[i];
}

// Split back into encrypted keynum and encrypted secret_key
let mut encrypted_keynum = [0u8; KEYNUM_BYTES];
encrypted_keynum.copy_from_slice(&encrypted_blob[0..KEYNUM_BYTES]);

let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
secret_key_encrypted.copy_from_slice(&encrypted_blob[KEYNUM_BYTES..]);
```

#### 2. Update SeckeyStruct to store encrypted keynum (src/keys.rs:214-222)

**Current structure:**
```rust
pub struct SeckeyStruct {
    encrypted: bool,
    kdf_salt: [u8; KDF_SALT_BYTES],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum: KeyNum,  // ← Stored unencrypted (WRONG for encrypted keys)
    secret_key_encrypted: [u8; SECRET_KEY_BYTES],
    checksum: [u8; CHECKSUM_BYTES],
}
```

**Two options:**

**Option A: Add encrypted_keynum field** (Recommended - cleaner separation)
```rust
pub struct SeckeyStruct {
    encrypted: bool,
    kdf_salt: [u8; KDF_SALT_BYTES],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum: KeyNum,  // Plaintext keynum (for unencrypted keys)
    encrypted_keynum: [u8; KEYNUM_BYTES],  // Encrypted keynum (for encrypted keys)
    secret_key_encrypted: [u8; SECRET_KEY_BYTES],
    checksum: [u8; CHECKSUM_BYTES],
}
```

**Option B: Store combined blob** (Matches C more closely)
```rust
pub struct SeckeyStruct {
    encrypted: bool,
    kdf_salt: [u8; KDF_SALT_BYTES],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum_sk_encrypted: [u8; 72],  // Combined keynum+sk (matches C)
    checksum: [u8; CHECKSUM_BYTES],
}
```

**Recommendation:** Use Option A - maintains cleaner separation and matches current API.

#### 3. Fix `SeckeyStruct::decrypt()` (src/keys.rs:303-328)

**Current code (WRONG):**
```rust
// Line 312-313: Derives only 64 bytes
let derived_key =
    derive_key_with_params(password, &self.kdf_salt, log_n, r, p, SECRET_KEY_BYTES)?;

// Line 317-318: Only decrypts secret_key
for i in 0..SECRET_KEY_BYTES {
    secret_key_bytes[i] = self.secret_key_encrypted[i] ^ derived_key[i];
}
```

**Fixed code:**
```rust
// Derive 72 bytes (keynum + secret_key) to match C implementation
const ENCRYPTED_BLOB_SIZE: usize = KEYNUM_BYTES + SECRET_KEY_BYTES;
let derived_key =
    derive_key_with_params(password, &self.kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)?;

// Reconstruct encrypted blob
let mut encrypted_blob = Vec::with_capacity(ENCRYPTED_BLOB_SIZE);
encrypted_blob.extend_from_slice(&self.encrypted_keynum);
encrypted_blob.extend_from_slice(&self.secret_key_encrypted);

// Decrypt entire blob
let mut decrypted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
for i in 0..ENCRYPTED_BLOB_SIZE {
    decrypted_blob[i] = encrypted_blob[i] ^ derived_key[i];
}

// Extract decrypted keynum
let mut decrypted_keynum = [0u8; KEYNUM_BYTES];
decrypted_keynum.copy_from_slice(&decrypted_blob[0..KEYNUM_BYTES]);

// Verify keynum matches (catches wrong password early)
if decrypted_keynum != self.keynum.as_bytes() {
    return Err(Error::ChecksumFailed); // Wrong password corrupts keynum
}

// Extract decrypted secret_key
let mut secret_key_bytes = [0u8; SECRET_KEY_BYTES];
secret_key_bytes.copy_from_slice(&decrypted_blob[KEYNUM_BYTES..]);

// Validate checksum (using unencrypted keynum from struct)
let computed_checksum = Self::compute_checksum(self.keynum, &secret_key_bytes);
if computed_checksum != self.checksum {
    return Err(Error::ChecksumFailed);
}
```

#### 4. Update serialization methods (src/keys.rs:433-549)

**`to_bytes()`** - Write encrypted_keynum to bytes 54-61 (if encrypted)
**`from_bytes()`** - Read encrypted_keynum from bytes 54-61 (if encrypted)

**Current:** Reads/writes plaintext keynum
**Fixed:** For encrypted keys, read/write encrypted_keynum; decrypt on load is separate

#### 5. Update helper methods

- `keynum()` - Returns plaintext keynum (no change)
- `encrypted_secret_key()` - Consider renaming to `encrypted_blob()` or keep as-is
- Debug impl - Redact encrypted_keynum

### Constants to Add

```rust
// In src/crypto.rs or src/keys.rs
/// Size of encrypted blob (keynum + secret key)
/// Matches C minisign: sizeof(seckey_struct->keynum_sk)
const ENCRYPTED_BLOB_SIZE: usize = KEYNUM_BYTES + SECRET_KEY_BYTES; // 8 + 64 = 72
```

## Testing Strategy

### Tests That Will Start Passing

1. **`keys::tests::test_decrypt_c_generated_encrypted_key`** - C fixture decryption ✓
2. **`keys::tests::test_decrypt_c_generated_encrypted_key_wrong_password`** - Already passing ✓
3. **`ops::sign::tests::test_sign_encrypted_key`** - Uses C fixture ✓

### Tests That Need Updates

1. **`keys::tests::test_seckey_encryption_decryption_fast`** - Update to verify encrypted keynum
2. **`ops::generate::tests::test_generate_encrypted_key_fast`** - Already compatible (generates with Rust)
3. Any tests using `SeckeyStruct` serialization - Verify encrypted_keynum field

### New Tests to Add

```rust
#[test]
fn test_encrypted_keynum_roundtrip() {
    // Verify keynum gets encrypted and decrypted correctly
    let (secret_key, _, keynum) = generate_keypair();
    let password = b"test";

    let encrypted = SeckeyStruct::new_encrypted(...);
    let serialized = encrypted.to_bytes();

    // Verify bytes 54-61 are encrypted (not plaintext keynum)
    assert_ne!(&serialized[54..62], keynum.as_bytes());

    let decrypted_sk = encrypted.decrypt(password).unwrap();
    // Decryption should succeed with correct password
}

#[test]
fn test_c_rust_cross_encryption() {
    // Generate key with Rust, verify C can decrypt
    // (Requires C minisign binary for cross-validation)
}
```

## Verification Steps

After implementation:

1. **Run ignored tests:**
   ```bash
   cargo test --lib -- --ignored
   ```
   Expected: 5/5 tests passing (currently 3/5)

2. **Run all tests:**
   ```bash
   gtimeout 60 cargo test
   ```
   Expected: All 123 tests passing (currently 121/123)

3. **Cross-validate with C minisign:**
   ```bash
   # Generate key with Rust
   ./target/debug/minisign -G -p test.pub -s test.key
   # Sign with C minisign
   echo "test message" > msg.txt
   echo "password" | minisign -S -s test.key -m msg.txt
   # Verify signature
   ./target/debug/minisign -V -p test.pub -m msg.txt
   ```

4. **Verify C-generated fixture decrypts:**
   ```bash
   cargo test keys::tests::test_decrypt_c_generated_encrypted_key -- --exact --ignored
   ```
   Expected: PASS

## Risk Assessment

### Low Risk
- Changes are isolated to `SeckeyStruct` encryption/decryption
- Unencrypted keys unchanged
- Public key operations unchanged
- Signature verification unchanged

### Testing Coverage
- Existing fast tests verify logic correctness
- C fixtures verify byte-level compatibility
- Cross-binary tests verify end-to-end compatibility

### Backward Compatibility
- ⚠️ **BREAKING:** Keys generated by current Rust implementation won't work with C minisign
- ✅ **FIXED:** C-generated keys will now work with Rust implementation
- **Migration:** Users with Rust-generated encrypted keys must regenerate them

## Documentation Updates

Update `/COMPATIBILITY.md`:
```markdown
### Known Issues (Fixed in v0.12.1)

**Previous versions (≤v0.12.0):** Encrypted keys generated by Rust were incompatible with C minisign due to incorrect KDF output length (64 bytes instead of 72 bytes). This has been fixed in v0.12.1.

**Migration:** If you generated encrypted keys with Rust minisign v0.12.0, regenerate them with v0.12.1 for full compatibility.
```

## Implementation Order

1. Add `ENCRYPTED_BLOB_SIZE` constant
2. Add `encrypted_keynum` field to `SeckeyStruct`
3. Update `new_encrypted()` to encrypt keynum+secretkey
4. Update `decrypt()` to decrypt keynum+secretkey
5. Update `to_bytes()` and `from_bytes()` serialization
6. Update `Debug` impl to redact encrypted_keynum
7. Run tests and verify C compatibility
8. Update documentation

## Timeline

- **Implementation:** 30-45 minutes
- **Testing:** 15 minutes
- **Documentation:** 10 minutes
- **Total:** ~1 hour

## Success Criteria

- [ ] All 5 ignored slow tests pass
- [ ] All 123 total tests pass
- [ ] C-generated encrypted keys decrypt successfully in Rust
- [ ] Rust-generated encrypted keys work with C minisign
- [ ] No clippy warnings
- [ ] Documentation updated
