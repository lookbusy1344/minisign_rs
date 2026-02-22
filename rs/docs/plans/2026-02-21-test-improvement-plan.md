# Test System Improvement Plan

**Date:** 2026-02-21
**Scope:** All test code under `rs/tests/`
**Metrics:** ~10k test lines, ~4k production lines (2.5:1 ratio)

---

## Priority 1: Delete Redundant Code

### P1.1 — Remove `phase2_h5_only.rs` entirely

Both tests (`h5_constant_time_comparison_uses_subtle` and `h5_verify_returns_error_not_panic_on_mismatch`) are exact duplicates of tests in `phase2_security_tests.rs`. Delete the file and remove the `mod phase2_h5_only` declaration from `unit.rs`.

**Files:** `tests/unit/phase2_h5_only.rs`, `tests/unit.rs`

### P1.2 — Deduplicate cross-file test overlap

| Duplicate | Location A | Location B | Keep |
|-----------|-----------|-----------|------|
| `write_public_key_file` roundtrip | `ops/generate.rs` | `ops/recreate.rs` | generate.rs |
| `check_file_size_limit` | `ops/sign.rs` | `ops/verify.rs` | file_utils tests (new) |
| T1.3 / T1.6 signature reuse vs modified message | `security_attacks.rs` | `security_attacks.rs` | Merge into one parameterized test |

---

## Priority 2: Fix Broken / Always-Passing Tests

### P2.1 — `h3_kdf_params_error_on_u32_truncation` always passes

```rust
// Current: accepts BOTH outcomes — can never fail
match result {
    Ok(_) => { /* acceptable */ }
    Err(_) => { /* acceptable */ }
}
```

**Fix:** Determine the correct behavior for the platform and assert specifically. If the function should handle overflow gracefully, assert `Ok` with valid params. If it should reject, assert a specific error variant.

### P2.2 — `m1_calculate_kdf_params_handles_overflow_safely` always passes

Same pattern as P2.1. Both `Ok` and `Err` are accepted. Pick the correct invariant and assert it.

### P2.3 — `test_force_weak_kdf_with_change_password` is an empty placeholder

```rust
// cli_test.rs — empty test body
```

**Fix:** Either implement the test or delete it. An empty `#[test]` silently inflates the pass count.

### P2.4 — `test_null_byte_in_path` tests wrong variable

The test constructs a path with a null byte but then operates on a different (valid) path variable. The null byte string is never used.

**Fix:** Pass the null-byte path to the function under test and assert the expected error.

---

## Priority 3: Fix Silently Skipped Tests

### P3.1 — Cross-binary tests should use `#[ignore]` instead of silent `return`

Both `cross_binary_test.rs` and `compatibility.rs` use a `require_c_minisign!()` macro that prints to stderr and returns early when the C binary isn't found. This means CI reports these as "passed" when they were never executed.

**Fix:** Replace the macro pattern with `#[ignore]` attribute and a helper that panics if the binary is missing. Run ignored tests explicitly in CI when the C binary is available:

```rust
#[test]
#[ignore] // Requires C minisign binary
fn test_cross_binary_sign_verify() {
    let c_bin = find_c_minisign().expect("C minisign not found");
    // ...
}
```

This gives honest reporting: "X passed, Y ignored" instead of "X+Y passed".

---

## Priority 4: Strengthen Weak Assertions

### P4.1 — Assert specific error variants, not just `is_err()`

These tests confirm failure but not *which* failure:

| Test | File | Should assert |
|------|------|--------------|
| `test_change_with_wrong_old_password_fails` | `ops/change.rs` | `Error::PasswordRequired` or `Error::ChecksumFailed` |
| `test_verify_with_wrong_key_fails` | `ops/verify.rs` | `Error::KeyMismatch` |
| `test_sign_nonexistent_file` | `ops/sign.rs` | `Error::FileRead` |

Pattern to adopt:

```rust
let err = result.unwrap_err();
assert!(matches!(err, Error::ChecksumFailed), "got: {err}");
```

### P4.2 — Security attack tests T1.4/T1.5 check structure but never verify

These tests create forged/tampered signatures and check structural properties (byte positions, algorithm markers) but never call `verify()` to confirm the signature is actually rejected.

**Fix:** Add `assert!(verify(...).is_err())` after the structural assertions.

### P4.3 — `test_read_during_write` uses arbitrary threshold

The test checks `contents.len() > 50` to detect partial reads. This is a magic number with no justification.

**Fix:** Either remove the threshold and check for atomic-or-empty behavior, or document the rationale and use a named constant.

---

## Priority 5: Fix Misleading Names

### P5.1 — `test_multiprocess_signing_same_key` uses threads, not processes

The test spawns `std::thread` handles, not separate processes. Rename to `test_concurrent_signing_same_key` or `test_multithreaded_signing_same_key`.

### P5.2 — Phase-numbered test files obscure purpose

`phase1_security_tests.rs` and `phase2_security_tests.rs` are named after implementation phases, not what they test. Consider renaming:
- `phase1_security_tests.rs` → `security_hardening.rs`
- `phase2_security_tests.rs` → `constant_time_and_kdf.rs`

Or merge both into a single `security_properties.rs`.

---

## Priority 6: Add Missing Coverage

### P6.1 — Ed25519 signature malleability (HIGH)

No test verifies that malleable signatures (S-value negation: `S' = L - S mod L`) are rejected. This is a known Ed25519 weakness. Test that verification fails when the S component is replaced with its negation modulo the group order.

### P6.2 — Small subgroup attacks (HIGH)

No test sends a public key on a small subgroup point. Verify that the implementation rejects or handles these correctly.

### P6.3 — Correct global signature + incorrect primary signature (MEDIUM)

Tests cover tampered global signatures, but no test checks the case where the global signature is valid but the primary signature is forged. Verify that verification fails.

### P6.4 — Password change → sign → verify roundtrip (MEDIUM)

No test changes a password and then uses the re-encrypted key to sign and verify. This exercises the full lifecycle.

### P6.5 — Invalid comment during key generation (LOW)

`ops/generate.rs` tests valid comments but not rejection of invalid ones (embedded CR, overlong, non-printable characters).

### P6.6 — Process-level atomicity (LOW)

`concurrent_access.rs` tests thread-level atomicity only. True process-level atomicity testing would require spawning child processes. This is harder to test but more realistic.

---

## Priority 7: Structural Improvements

### P7.1 — Extract shared test helpers

Many test files duplicate helper patterns:
- Temporary directory setup with keypair generation
- Loading C fixture files
- Creating a signed file for verification tests

Extract these into a `tests/helpers/` module to reduce duplication and make tests more readable.

### P7.2 — Add `#[cfg(test)]` compile-time checks

Consider adding a test that verifies `EVEN_WORDS` and `ODD_WORDS` have exactly 256 entries each at compile time using `const` assertions, rather than only at runtime.

### P7.3 — Property-based test coverage for crypto roundtrips

`fuzzing.rs` has good proptest coverage for formats and validation, but no property-based tests for the core sign → verify roundtrip with random messages and keys. Add:

```rust
proptest! {
    #[test]
    fn sign_verify_roundtrip_arbitrary_message(msg in prop::collection::vec(any::<u8>(), 0..10000)) {
        let (pk, sk) = generate_keypair();
        let sig = sign(&sk, &msg);
        assert!(verify(&pk, &sig, &msg).is_ok());
    }
}
```

---

## Summary

| Priority | Items | Effort | Impact |
|----------|-------|--------|--------|
| P1: Delete redundant | 3 | Low | Reduces noise, fewer false confidence signals |
| P2: Fix broken | 4 | Low | Tests that pass honestly |
| P3: Fix skipped | 1 | Low | Honest CI reporting |
| P4: Strengthen assertions | 3 | Low | Catch regressions to specific error types |
| P5: Fix names | 2 | Low | Readability |
| P6: Add coverage | 6 | Medium-High | Cryptographic correctness guarantees |
| P7: Structural | 3 | Medium | Maintainability |

**Recommended order:** P1 → P2 → P3 → P4 → P5 → P6 → P7

P1–P5 are all low-effort fixes that improve test honesty. P6 adds genuine security coverage. P7 is ongoing hygiene.
