# C-Rust Implementation Parity Plan

**Date**: 2026-01-25
**Status**: Planning
**Priority**: High (Security + Compatibility)

## Executive Summary

Deep comparison of the C and Rust implementations reveals several gaps where the C version includes validation and security checks not present in Rust. While the Rust implementation benefits from memory safety guarantees, it lacks explicit character validation that the C version performs.

## Critical Gaps Identified

### 1. UTF-8 Printability Validation (HIGH PRIORITY - Security)

**Issue**: The C implementation validates that trusted comments contain only printable characters through the `is_printable()` function (minisign.c:76-125). Rust relies solely on UTF-8 type system guarantees but doesn't validate the character content.

**C Implementation** (minisign.c:253-258):
```c
if (is_printable(trusted_comment) == 0) {
    exit_msg("Signature file contains unprintable characters");
}
```

The `is_printable()` function validates:
- Printable ASCII (0x20-0x7E)
- Tab character (0x09)
- Valid UTF-8 multi-byte sequences
- Rejects control characters
- Validates UTF-8 continuation bytes

**Current Rust**: No equivalent validation

**Impact**:
- Security: Potential for control characters or malformed UTF-8 sequences in trusted comments
- Compatibility: Rust may accept signatures that C would reject
- File format integrity: Trusted comments could contain unprintable data

**Proposed Solution**:
1. Create `validation.rs` module in `rs/src/`
2. Implement `is_printable()` function matching C behavior
3. Add validation in `signature.rs::SignatureBox::from_string()` after parsing trusted comment
4. Add validation in `ops/sign.rs` before creating signature

**Files to Modify**:
- `rs/src/validation.rs` (new file)
- `rs/src/lib.rs` (add module)
- `rs/src/signature.rs` (add validation call)
- `rs/src/ops/sign.rs` (add validation call)

**Test Requirements**:
- Valid UTF-8 multi-byte sequences (emoji, accented characters)
- Invalid UTF-8 sequences (should reject)
- Control characters (should reject)
- Tab character (should accept)
- Printable ASCII range (should accept)
- Boundary cases (0x1F, 0x20, 0x7E, 0x7F)

---

### 2. Carriage Return Detection (MEDIUM PRIORITY - Compatibility)

**Issue**: The C implementation's `trim()` function explicitly detects embedded carriage returns ('\r') within comments and rejects them (helpers.c:174-175).

**C Implementation**:
```c
if (memchr(str, '\r', len) != NULL) {
    return 0;  // Indicates error
}
```

**Current Rust**: No explicit '\r' detection in comment strings

**Impact**:
- Compatibility: Rust may accept signatures with embedded '\r' that C would reject
- Cross-platform: Windows-style line endings could sneak into comment fields
- File format consistency: Different handling of line-ending characters

**Proposed Solution**:
1. Add carriage return check to `validation.rs`
2. Apply check to both untrusted and trusted comments
3. Return error if embedded '\r' found

**Files to Modify**:
- `rs/src/validation.rs` (add function)
- `rs/src/signature.rs` (add validation)
- `rs/src/ops/sign.rs` (add validation)

**Test Requirements**:
- Comment with embedded '\r' (should reject)
- Comment ending with '\n' (should accept after trim)
- Comment with '\r\n' at end (should reject embedded '\r')
- Empty comment (should accept)

---

### 3. Scrypt Parameter Fallback (LOW PRIORITY - Robustness)

**Issue**: The C implementation has a fallback mechanism that reduces scrypt parameters if key derivation fails due to memory constraints (minisign.c:416-425).

**C Implementation**:
```c
while (crypto_pwhash_scryptsalsa208sha256(...) != 0) {
    kdf_opslimit /= 2;
    kdf_memlimit /= 2;
    if (kdf_opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN ||
        kdf_memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN) {
        exit_msg("scrypt failed");
    }
}
```

**Current Rust**: Fixed parameters only (crypto.rs, keys.rs)

**Impact**:
- Memory-constrained systems: May fail to decrypt keys on low-memory devices
- Embedded/IoT: Less flexible deployment
- Error handling: Rust fails immediately rather than attempting fallback

**Proposed Solution**:
1. Add fallback logic to `keys.rs::SecretKeyEncrypted::decrypt()`
2. Define minimum parameter thresholds
3. Attempt derivation with reduced parameters on failure
4. Log warnings when using reduced parameters

**Files to Modify**:
- `rs/src/keys.rs` (modify `decrypt()` method)
- `rs/src/crypto.rs` (add minimum parameter constants)

**Test Requirements**:
- Successful decryption with standard parameters
- Simulated memory pressure (challenging to test)
- Minimum parameter threshold validation
- Warning messages for fallback usage

---

### 4. Constants Organization (LOW PRIORITY - Code Quality)

**Issue**: Constants are scattered across multiple modules in Rust, while C has them centralized in `minisign.h`.

**Current State**:
- `crypto.rs`: Cryptographic constants (SIGNATURE_BYTES, etc.)
- `signature.rs`: Signature-related constants (COMMENTMAXBYTES, etc.)
- `keys.rs`: Key-related constants (PUBKEY_STRUCT_SIZE, etc.)

**Impact**:
- Developer experience: Harder to find all constants in one place
- Maintenance: Need to search multiple files for related values
- Documentation: No single source of truth for limits and sizes

**Proposed Solution** (Optional):
1. Create `rs/src/constants.rs` module
2. Re-export constants from specialized modules
3. Add documentation comments for each constant
4. Maintain module-specific constants but also expose via central module

**Files to Create/Modify**:
- `rs/src/constants.rs` (new file)
- `rs/src/lib.rs` (add module and re-exports)

**Benefits**:
- Single import point for all constants
- Better documentation discoverability
- Easier comparison with C implementation

---

## Implementation Priority

### Phase 1: Critical Security (Week 1)
1. Implement UTF-8 printability validation
2. Add carriage return detection
3. Comprehensive test suite for validation

**Estimated Effort**: 8-12 hours
**Risk**: Low (additive changes, no breaking changes)

### Phase 2: Robustness Enhancement (Week 2)
1. Implement scrypt parameter fallback
2. Test on constrained environments
3. Add warning/logging for fallback usage

**Estimated Effort**: 4-6 hours
**Risk**: Medium (changes key derivation logic)

### Phase 3: Code Quality (Optional)
1. Centralize constants
2. Documentation improvements
3. Cross-reference with C implementation

**Estimated Effort**: 2-4 hours
**Risk**: Low (refactoring only)

---

## Testing Strategy

### Unit Tests
- Each validation function isolated
- Boundary condition testing
- UTF-8 edge cases (surrogate pairs, overlong sequences)
- Control character ranges

### Integration Tests
- End-to-end signature verification with validated comments
- Cross-compatibility with C implementation
- File format roundtrip (C sign → Rust verify, Rust sign → C verify)

### Compatibility Tests
- Generate signatures with Rust, verify with C
- Generate signatures with C, verify with Rust
- Test with known-good signature files from C implementation
- Test rejection cases (should fail in both implementations)

### Regression Tests
- Existing test suite must pass
- No breaking changes to public API
- Backward compatibility with existing Rust-generated signatures

---

## Success Criteria

1. ✓ Rust rejects same invalid inputs as C implementation
2. ✓ All validation functions have >90% code coverage
3. ✓ Cross-compatibility tests pass (C ↔ Rust)
4. ✓ No breaking changes to existing Rust API
5. ✓ Performance impact <5% on signing/verification operations
6. ✓ Documentation updated with new validation behavior

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing Rust signatures | Low | High | Comprehensive testing, validation only on input |
| Performance degradation | Low | Medium | Benchmark before/after, optimize UTF-8 validation |
| Over-validation (stricter than C) | Medium | Medium | Exact matching of C behavior, cross-validation tests |
| UTF-8 validation bugs | Low | High | Extensive edge case testing, fuzzing |
| Memory constraints with scrypt fallback | Low | Low | Document minimum system requirements |

---

## Future Considerations

### Potential Additional Validations
1. **Maximum file size limits**: C doesn't explicitly check message file sizes; neither does Rust
2. **Path traversal protection**: Both implementations assume valid file paths
3. **Signature file structure validation**: Both parse line-by-line; additional structural checks could help
4. **Key file permission checks**: C doesn't validate; Rust could add chmod warnings

### Compatibility Notes
- Rust's memory safety eliminates entire classes of bugs present in C (buffer overflows, use-after-free)
- Type system provides stronger guarantees than C's runtime checks
- Trade-off: Rust must explicitly implement validation that C does incidentally

---

## References

### C Implementation Files
- `src/minisign.h` - Constants and definitions
- `src/minisign.c` - Main logic, validation functions
- `src/helpers.c` - `trim()` and utility functions
- Lines of interest: 76-125 (is_printable), 159-178 (trim), 416-425 (scrypt fallback)

### Rust Implementation Files
- `rs/src/crypto.rs` - Cryptographic primitives
- `rs/src/signature.rs` - Signature structures
- `rs/src/keys.rs` - Key handling
- `rs/src/ops/sign.rs` - Signing operations (recent comment validation added)
- `rs/src/ops/verify.rs` - Verification operations

### Related Commits
- `77fa106` - feat: add comment length validation for C compatibility
- `ce51b5e` - fix: use cryptographically secure RNG for KDF salt generation

---

## Next Steps

1. **Review this plan** with stakeholders/maintainers
2. **Create issues** for each implementation phase
3. **Set up test infrastructure** for cross-compatibility testing
4. **Implement Phase 1** (critical security validations)
5. **Run full test suite** including C interoperability tests
6. **Document changes** in CHANGELOG and migration guide

---

## Appendix: Detailed Function Specifications

### A. `is_printable()` Function Specification

**Purpose**: Validate that a string contains only printable characters and valid UTF-8

**Input**: `&str` - String slice to validate

**Output**: `Result<(), Error>` - Ok if valid, Err with details if invalid

**Validation Rules**:
1. Single-byte characters:
   - Allow: 0x20-0x7E (printable ASCII)
   - Allow: 0x09 (tab)
   - Reject: 0x00-0x08, 0x0A-0x1F, 0x7F+ (control characters)

2. Multi-byte UTF-8:
   - Validate leading byte (0xC2-0xF4 ranges)
   - Validate continuation bytes (0x80-0xBF)
   - Reject overlong encodings
   - Reject surrogate pair ranges (U+D800-U+DFFF)
   - Reject values > U+10FFFF

3. Edge cases:
   - Empty string: valid
   - String with only whitespace: valid
   - String with tab characters: valid
   - String with newlines: invalid

**C Reference**: minisign.c:76-125

### B. `validate_no_embedded_cr()` Function Specification

**Purpose**: Ensure comment strings don't contain embedded carriage returns

**Input**: `&str` - String slice to validate

**Output**: `Result<(), Error>` - Ok if no embedded '\r', Err otherwise

**Validation Rules**:
1. Scan string for '\r' character (0x0D)
2. If found anywhere in string, return error
3. Empty string: valid

**Rationale**: Prevents mixing of line ending styles within comment fields

**C Reference**: helpers.c:174-175

### C. `decrypt_with_fallback()` Function Specification

**Purpose**: Attempt key derivation with parameter fallback on memory constraints

**Input**:
- `password: &[u8]` - Password bytes
- `salt: &[u8; 32]` - KDF salt
- `initial_opslimit: u64` - Starting opslimit
- `initial_memlimit: u64` - Starting memlimit

**Output**: `Result<[u8; N], Error>` - Derived key or error

**Algorithm**:
1. Attempt derivation with initial parameters
2. If derivation fails:
   a. Divide both opslimit and memlimit by 2
   b. Check if below minimum thresholds (opslimit < 32768, memlimit < 8192)
   c. If below minimums, return error
   d. Otherwise, retry with reduced parameters (goto step 1)
3. Log warning if fallback used

**C Reference**: minisign.c:416-425

---

**Document Version**: 1.0
**Last Updated**: 2026-01-25
**Author**: Automated Analysis
**Review Status**: Pending
