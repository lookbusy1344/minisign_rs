# Code Review: Data Structures and Code Simplification

**Date:** 2026-02-01
**Scope:** Data structures, code structure, idiomatic Rust, cloning optimization

---

## Executive Summary

The minisign-rs codebase is well-structured with strong security practices, but there are opportunities for simplification and optimization. Key findings:

1. **Code duplication** - Two functions and two constants are duplicated across modules
2. **Excessive cloning** - Options structs use owned `String` forcing clones at call sites
3. **Inconsistent path types** - Mix of `String` and `PathBuf` across options structs
4. **Multi-file signing inefficiency** - Secret key is reloaded for each file
5. **Minor structural improvements** - Could use enums and fixed arrays more effectively

---

## Priority 1: Code Duplication (HIGH)

### 1.1 Duplicated Function: `opslimit_memlimit_to_params`

**Location:**
- `src/keys.rs:664-716` - method on `SeckeyStruct`
- `src/ops/inspect.rs:320-366` - standalone function

**Problem:** Identical logic duplicated with explicit comment acknowledging it:
> "This is a copy of the logic from `SeckeyStruct::opslimit_memlimit_to_params` but made available for inspection purposes."

**Solution:** Extract to a shared location (e.g., `crypto.rs` or a new `kdf.rs`) and call from both places.

```rust
// In crypto.rs (or new kdf.rs)
pub fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)>

// In keys.rs - delegate
impl SeckeyStruct {
    pub fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
        crate::crypto::opslimit_memlimit_to_params(opslimit, memlimit)
    }
}
```

**Files to modify:** `src/keys.rs`, `src/ops/inspect.rs`, `src/crypto.rs`

---

### 1.2 Duplicated Function: `check_file_size_limit`

**Location:**
- `src/ops/sign.rs:411-422`
- `src/ops/verify.rs:201-212`

**Problem:** Identical implementation in both files.

**Solution:** Extract to `src/ops/file_utils.rs` (already exists for other file helpers).

```rust
// In ops/file_utils.rs
pub fn check_file_size_limit(path: &str) -> Result<()>
```

**Files to modify:** `src/ops/sign.rs`, `src/ops/verify.rs`, `src/ops/file_utils.rs`

---

### 1.3 Duplicated Constants: Production KDF Parameters

**Location:**
- `src/keys.rs:283-285` - `SeckeyStruct::PRODUCTION_OPSLIMIT/MEMLIMIT`
- `src/ops/inspect.rs:184-186` - module-level constants

**Problem:** Same magic numbers defined in two places.

**Solution:** Define once in `src/constants.rs` (central constants file already exists).

```rust
// In constants.rs
pub const PRODUCTION_OPSLIMIT: u64 = 33_554_432;
pub const PRODUCTION_MEMLIMIT: u64 = 1_073_741_824;
```

**Files to modify:** `src/constants.rs`, `src/keys.rs`, `src/ops/inspect.rs`

---

## Priority 2: Cloning Optimization (MEDIUM)

### 2.1 Options Structs Use Owned Strings

**Problem:** All options structs use `String` for paths, forcing clones:

```rust
// Current - forces clone
pub struct SignOptions {
    pub secret_key_file: String,
    pub message_file: String,
    pub signature_file: Option<String>,
    // ...
}

// In main.rs - cloning required
let options = SignOptions {
    secret_key_file: secret_key_file.to_string_lossy().to_string(),
    message_file: message_file.to_string_lossy().to_string(),
    // ...
};
```

**Impact:** ~15 string clones in `main.rs` alone.

**Solution A (Conservative):** Use `Cow<'a, str>` for zero-copy when possible:

```rust
pub struct SignOptions<'a> {
    pub secret_key_file: Cow<'a, str>,
    pub message_file: Cow<'a, str>,
    pub signature_file: Option<Cow<'a, str>>,
    // ...
}
```

**Solution B (Simpler):** Use `&Path` references with lifetime parameters:

```rust
pub struct SignOptions<'a> {
    pub secret_key_file: &'a Path,
    pub message_file: &'a Path,
    pub signature_file: Option<&'a Path>,
    // ...
}
```

**Recommendation:** Solution B is simpler and idiomatic for Rust CLI tools. Paths are always borrowed from CLI parsing and live for the duration of the operation.

**Trade-off:** Adds lifetime parameters which may complicate some patterns, but eliminates all cloning.

**Files to modify:**
- `src/ops/sign.rs`
- `src/ops/verify.rs`
- `src/ops/generate.rs`
- `src/ops/change.rs`
- `src/ops/recreate.rs`
- `src/ops/inspect.rs`
- `src/main.rs`

---

### 2.2 Inconsistent Path Types Across Modules

**Current State:**
| Options Struct | Path Type |
|----------------|-----------|
| `GenerateOptions` | `PathBuf` |
| `SignOptions` | `String` |
| `VerifyOptions` | `String` |
| `RecreateOptions` | `PathBuf` |
| `ChangeOptions` | `PathBuf` |
| `InspectOptions` | `String` |

**Problem:** Inconsistency forces conversions like `to_string_lossy().to_string()` in `main.rs`.

**Solution:** Standardize on `&Path` (see 2.1) or consistently use `PathBuf` everywhere.

---

### 2.3 SignatureBox Stores Owned Strings

**Current:**
```rust
pub struct SignatureBox {
    pub untrusted_comment: String,
    pub trusted_comment: String,
    // ...
}
```

**Problem:** `from_file_contents` must allocate/clone the comment strings.

**Potential Solution:** Use `Cow<'a, str>`:
```rust
pub struct SignatureBox<'a> {
    pub untrusted_comment: Cow<'a, str>,
    pub trusted_comment: Cow<'a, str>,
    // ...
}
```

**Assessment:** Low priority. The strings are typically small (<1KB), and the current design is simpler. Only pursue if benchmarks show this matters.

---

## Priority 3: Multi-File Signing Inefficiency (MEDIUM)

### 3.1 Secret Key Reloaded Per File

**Location:** `src/ops/sign.rs:171-213`

**Problem:** `sign_multiple_files` calls `sign_single_file` for each file, which re-reads and re-decrypts the secret key every time.

```rust
// Current - key loaded N times
files.par_iter().map(|file| {
    let result = sign_single_file(file, options, password);  // loads key inside
    // ...
})
```

**Solution:** Refactor to load key once, pass to signing function:

```rust
// Load and decrypt once
let (secret_key, keynum) = load_and_decrypt_key(&options.secret_key_file, password)?;

// Sign all files with the loaded key
files.par_iter().map(|file| {
    sign_file_with_key(file, &secret_key, keynum, options)
})
```

**Impact:** For N files, saves:
- N-1 file reads
- N-1 base64 decodes
- N-1 scrypt derivations (expensive - ~1-2 seconds each for encrypted keys!)

**Files to modify:** `src/ops/sign.rs`

---

## Priority 4: Structural Improvements (LOW)

### 4.1 SeckeyStruct Stores Redundant Fields

**Current:**
```rust
pub struct SeckeyStruct {
    encrypted: bool,
    keynum: KeyNum,           // Zero if encrypted
    encrypted_keynum: [u8; 8], // Unused if unencrypted
    // ...
}
```

**Problem:** Two mutually exclusive fields waste 8 bytes and create confusing semantics.

**Potential Solution:** Use an enum:
```rust
enum KeynumState {
    Plaintext(KeyNum),
    Encrypted([u8; KEYNUM_BYTES]),
}

pub struct SeckeyStruct {
    keynum_state: KeynumState,
    // ...
}
```

**Assessment:** Low priority. The current design works correctly and the 8-byte overhead is negligible. Only pursue if major refactoring is planned.

---

### 4.2 Vec Allocations for Fixed-Size Data

**Location:** `src/keys.rs:593-598`

```rust
// Current
let mut data = Vec::with_capacity(2 + KEYNUM_BYTES + SECRET_KEY_BYTES);
data.extend_from_slice(SIG_ALG);
data.extend_from_slice(keynum.as_bytes());
data.extend_from_slice(secret_key);
```

**Problem:** Heap allocation for known fixed-size data.

**Solution:** Use fixed array:
```rust
const CHECKSUM_INPUT_SIZE: usize = 2 + KEYNUM_BYTES + SECRET_KEY_BYTES;
let mut data = [0u8; CHECKSUM_INPUT_SIZE];
data[0..2].copy_from_slice(SIG_ALG);
data[2..10].copy_from_slice(keynum.as_bytes());
data[10..].copy_from_slice(secret_key);
```

**Assessment:** Low priority. This is a one-time allocation in a function that's already doing expensive crypto operations.

---

### 4.3 SignatureAlgorithm Enum Location

**Current:** `SignatureAlgorithm` is defined in `ops/inspect.rs:265-271` but logically belongs with signature types.

**Problem:** `SigStruct` exposes `is_prehashed() -> bool` instead of returning a proper enum.

**Solution:** Move enum to `signature.rs`, add method:
```rust
// In signature.rs
pub enum SignatureAlgorithm {
    Normal,
    Prehashed,
}

impl SigStruct {
    pub fn algorithm(&self) -> SignatureAlgorithm {
        if self.prehashed { SignatureAlgorithm::Prehashed }
        else { SignatureAlgorithm::Normal }
    }
}
```

**Files to modify:** `src/signature.rs`, `src/ops/inspect.rs`

---

## Priority 5: Minor Issues (LOW)

### 5.1 Debug Assertions in formats.rs

**Location:** `src/formats.rs:27-36, 44-51`

```rust
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    debug_assert!(bytes.len() >= 8, ...);  // Only checks in debug builds
    // ...
}
```

**Problem:** In release builds, if called with wrong-sized slice, no panic occurs - just silent incorrect behavior (reading garbage).

**Options:**
1. **Keep as-is** - Callers are trusted, all call sites are validated
2. **Change to runtime check** - Panic on invalid input
3. **Take fixed array** - `fn read_u64_le(bytes: &[u8; 8]) -> u64`

**Recommendation:** Option 3 is most idiomatic. The function is only called in controlled contexts where the slice is always the right size, but taking a fixed array makes the API self-documenting and prevents misuse.

---

### 5.2 Timestamp Fallback in Sign

**Location:** `src/ops/sign.rs:349-354`

```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0);
```

**Assessment:** Correct behavior. Using `0` as fallback for the impossible case of time before epoch is reasonable. No change needed.

---

## Implementation Plan

### Phase 1: Code Duplication (Estimated: 2-3 hours)
1. Extract `opslimit_memlimit_to_params` to shared location
2. Extract `check_file_size_limit` to `file_utils.rs`
3. Move production KDF constants to `constants.rs`
4. Run tests to verify no regressions

### Phase 2: Multi-File Signing Optimization (Estimated: 1-2 hours)
1. Refactor `sign_multiple_files` to load key once
2. Add internal `sign_file_with_key` function
3. Update tests for new structure
4. Verify parallel signing still works

### Phase 3: Path Type Standardization (Estimated: 3-4 hours)
1. Decide on `&Path` vs `PathBuf` approach
2. Update all Options structs consistently
3. Update `main.rs` to remove unnecessary cloning
4. Run clippy and fix any new warnings

### Phase 4: Minor Improvements (Optional, Estimated: 1-2 hours)
1. Move `SignatureAlgorithm` to `signature.rs`
2. Consider fixed arrays for formats.rs functions
3. Review any remaining Vec allocations

---

## Files Summary

| File | Changes |
|------|---------|
| `src/constants.rs` | Add production KDF constants |
| `src/crypto.rs` | Add shared `opslimit_memlimit_to_params` |
| `src/keys.rs` | Remove duplicated constants/function, delegate |
| `src/signature.rs` | Add `SignatureAlgorithm` enum |
| `src/ops/file_utils.rs` | Add `check_file_size_limit` |
| `src/ops/sign.rs` | Remove duplicate, refactor multi-file signing |
| `src/ops/verify.rs` | Remove duplicate, update imports |
| `src/ops/inspect.rs` | Remove duplicates, update imports |
| `src/ops/generate.rs` | Standardize path types |
| `src/ops/change.rs` | Standardize path types |
| `src/ops/recreate.rs` | Standardize path types |
| `src/main.rs` | Remove unnecessary clones |
| `src/formats.rs` | Optional: change to fixed arrays |

---

## Risk Assessment

| Change | Risk | Mitigation |
|--------|------|------------|
| Extract shared functions | Low | Comprehensive test suite |
| Multi-file signing refactor | Medium | Existing parallel signing tests |
| Path type changes | Medium | May affect API; compile-time errors guide |
| Lifetime parameters | Medium | May complicate some patterns |

---

## Conclusion

The codebase is well-designed with good security practices. The recommended changes focus on:

1. **Eliminating code duplication** (highest priority) - straightforward and low-risk
2. **Optimizing multi-file signing** (high value) - significant performance improvement for batch operations
3. **Reducing unnecessary cloning** (medium priority) - cleaner code, minor performance benefit

Total estimated effort: 7-11 hours for phases 1-3.
