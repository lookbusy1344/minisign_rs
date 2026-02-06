# Code Review & Remediation Plan — 2026-02-06

## Overview

Full code review of the minisign Rust implementation (v1.1.1) covering all 41 source
files (~12,000 LOC) and 15 integration/unit test files (~5,700 LOC).

**Review methodology:** Five parallel review passes covering crypto/keys, signatures/validation,
ops (sign/verify/generate), ops (change/recreate/inspect/CLI), and test quality. Each finding
was then manually verified against the source to eliminate false positives.

**Codebase stats:**
- 12,073 lines of Rust code across 41 files
- 348+ tests across 15 test files
- 7 direct dependencies, 7 dev dependencies
- Zero `unsafe`, zero `unwrap`/`expect` in production paths

---

## Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| HIGH     | 6     | Security or correctness issues requiring immediate fix |
| MEDIUM   | 10    | Quality, robustness, or minor security concerns |
| LOW      | 4     | Code quality, consistency, style |
| TESTING  | 6     | Test coverage gaps |

---

## HIGH Severity Findings

### H1. `SignatureBox::new()` accepts unvalidated comments — Newline injection

**File:** `src/signature.rs:234-246`

**Issue:** The public constructor performs zero validation on `untrusted_comment` or
`trusted_comment`. Callers can construct a `SignatureBox` with newlines embedded in
comments, breaking the 4-line file format invariant. `from_file_contents()` (line 280)
validates via `validate_comment()`, but construction paths don't.

**Impact:** Format corruption, parser confusion across implementations, potential
display-based attacks via ANSI escape sequences in untrusted comments.

**Evidence:**
```rust
pub fn new(
    untrusted_comment: String,  // no validation
    sig_struct: SigStruct,
    trusted_comment: String,    // no validation
    global_signature: Signature,
) -> Self {
    Self { untrusted_comment, sig_struct, trusted_comment, global_signature }
}
```

**Remediation:**
- Add `validate_comment()` calls inside `SignatureBox::new()`, or
- Make `new()` return `Result<Self>` with validation, or
- Make `new()` private and force all construction through validated paths

**Effort:** Small (< 1 hour)

---

### H2. `with_global_signature()` bypasses all validation

**File:** `src/signature.rs:375-395`

**Issue:** Like `new()`, the `with_global_signature()` constructor creates a
`SignatureBox` without validating comment lengths or content. This is a library-level
API that callers can use directly, bypassing the length checks in `ops/sign.rs:441-446`.

**Impact:** Library users constructing signatures outside `ops::sign` can create
oversized or malformed signature files.

**Remediation:**
- Add comment validation (printability + length) inside `with_global_signature()`
- This is the defense-in-depth layer — `ops/sign.rs` validates too, but the
  signature module should enforce its own invariants

**Effort:** Small (< 1 hour)

---

### H3. Silent fallback in `opslimit_memlimit_to_params()` — `unwrap_or(r)`

**File:** `src/crypto.rs:406-418`

**Issue:** When opslimit/memlimit don't match expected values, the function derives
`r` from opslimit. If the derivation fails (division overflow or u32 truncation),
it silently falls back to default `r=8` via `unwrap_or(r)`:

```rust
let derived_r = opslimit
    .checked_div(LIBSODIUM_OPSLIMIT_MULTIPLIER.checked_mul(n).ok_or_else(|| ...)?  )
    .and_then(|v| u32::try_from(v).ok())
    .unwrap_or(r);  // ← silent fallback
```

**Impact:** A corrupted or malicious secret key file with non-standard KDF parameters
could be processed with weaker-than-intended parameters, with no error or warning.

**Remediation:**
Replace `unwrap_or(r)` with explicit error:
```rust
.ok_or_else(|| Error::ScryptParamError("failed to derive r from opslimit".into()))?;
```

**Effort:** Small (< 30 minutes)

---

### H4. Missing `sync_all()` in signature file write

**File:** `src/ops/sign.rs:531-534`

**Issue:** `write_signature_file()` calls `write_all()` but does NOT call `sync_all()`
before returning success. Both `write_secret_key_file()` (file_utils.rs:78) and
`write_public_key_file()` (file_utils.rs:124) correctly call `sync_all()`.

```rust
file.write_all(contents.as_bytes())
    .map_err(|e| Error::file_write(path, e))?;
Ok(())  // missing sync_all()
```

**Impact:** If the system crashes immediately after signing, the signature file may
be lost or corrupted despite the function returning `Ok(())`. Breaks durability
guarantee.

**Remediation:**
Add `file.sync_all().map_err(|e| Error::file_write(path, e))?;` before `Ok(())`.

**Effort:** Trivial (< 15 minutes)

---

### H5. `KeyNum` comparison uses non-constant-time `!=` in verification

**File:** `src/ops/verify.rs:268`

**Issue:** The verification path compares key numbers using the derived `PartialEq`
(standard byte comparison), which is not constant-time:

```rust
if pubkey.keynum() != sig_box.sig_struct().keynum() {
    return Err(Error::KeyMismatch { ... });
}
```

`KeyNum` at `crypto.rs:118` derives `PartialEq, Eq` with standard (non-constant-time)
equality. The codebase correctly uses `ct_eq()` from the `subtle` crate for checksum
comparison (keys.rs:508), but not for keynum comparison in the verification path.

**Impact:** Timing side-channel could leak information about valid key numbers.
Practical exploitability is low (keynums are 8 bytes, and the comparison is early-exit
only), but this contradicts the project's security posture.

**Remediation:**
Either use `subtle::ConstantTimeEq` for `KeyNum`, or document that keynums are
non-secret (they appear in plaintext in signature files) and the timing leak is
acceptable. The C implementation also uses non-constant-time comparison here, so
this may be acceptable for compatibility.

**Effort:** Small (< 30 minutes)

---

### H6. No comment length validation during parsing — DoS vector

**File:** `src/signature.rs:280-337`

**Issue:** `from_file_contents()` validates comments for printability but NOT length.
Constants `COMMENTMAXBYTES` (1024) and `TRUSTEDCOMMENTMAXBYTES` (8192) are defined
but not enforced during parsing. A malicious signature file with a multi-gigabyte
comment would be fully allocated into memory.

**Impact:** Denial of service. An attacker crafts a `.minisig` file with an enormous
first line and feeds it to the verifier.

**Remediation:**
Add length checks in `from_file_contents()` after extracting each comment:
```rust
if untrusted_comment.len() > COMMENTMAXBYTES {
    return Err(Error::InvalidComment("untrusted comment too long".into()));
}
```

**Effort:** Small (< 30 minutes)

---

## MEDIUM Severity Findings

### M1. `calculate_kdf_params()` unchecked arithmetic for large `log_n`

**File:** `src/crypto.rs:351-356`

**Issue:** `log_n` is `u8` (0-255). For values >= 64, `1u64 << log_n` panics in
debug mode and wraps in release. For values 32-63, the subsequent multiplications
(`n * r * MULTIPLIER`) can overflow without checked arithmetic.

```rust
let n = 1u64 << log_n;  // UB for log_n >= 64
(LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r, LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r)
```

**Current callers** only pass `log_n <= 20` (production) or fallback values, but the
function signature accepts any `u8`.

**Remediation:**
Add bounds check: `if log_n >= 64 { return error }` and use `checked_mul` chains.

**Effort:** Small (< 30 minutes)

---

### M2. `formats.rs` functions panic on short slices

**File:** `src/formats.rs:27-51`

**Issue:** `read_u64_le()` and `write_u64_le()` use `debug_assert!` for length
validation, then `copy_from_slice()` which panics in release if the slice is too short.

**Current callers** all pass correctly-sized buffers, but the API is fragile.

**Remediation:**
Return `Result<u64>` or use `bytes.get(..8)?.try_into()` pattern.

**Effort:** Small (< 30 minutes), but requires updating all call sites.

---

### M3. Inconsistent error handling for comment length violations

**File:** `src/ops/sign.rs:441-446`

**Issue:** Untrusted comment length violation produces an `eprintln!` warning
(non-fatal), while trusted comment violation returns `Err`. This asymmetry means
oversized untrusted comments silently produce incompatible signature files.

```rust
if untrusted_comment.len() >= COMMENTMAXBYTES - COMMENT_PREFIX_SIZE {
    eprintln!("Warning: ...");  // continues!
}
if trusted_comment.len() >= TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE {
    return Err(Error::Other("Trusted comment too long".into()));  // aborts!
}
```

**Remediation:**
Make both fatal errors, or at minimum document the asymmetry. The C implementation
also only warns for untrusted, so this may be intentional for compatibility.

**Effort:** Trivial (< 15 minutes)

---

### M4. `validate_comment()` doesn't enforce length

**File:** `src/validation.rs:128-132`

**Issue:** The validation module checks printability and carriage returns but not
length. Length validation is only in `ops/sign.rs`, creating scattered validation
logic and making it easy for future callers to forget length checks.

**Remediation:**
Add optional length parameter to `validate_comment()` or create
`validate_comment_with_length()` that centralizes all checks.

**Effort:** Small (< 30 minutes)

---

### M5. `Error::Other` used for trusted comment length error

**File:** `src/ops/sign.rs:446`

**Issue:** Uses generic `Error::Other("Trusted comment too long")` instead of the
dedicated `Error::InvalidComment` variant.

**Remediation:**
Replace with `Error::InvalidComment("trusted comment exceeds maximum length".into())`.

**Effort:** Trivial (< 5 minutes)

---

### M6. Crypto operations before validation in `create_signature()`

**File:** `src/ops/sign.rs:427-447`

**Issue:** The signing operation (line 427) happens before comment validation
(lines 441-451). If comments are invalid, cryptographic work is wasted.

**Remediation:**
Move all validation to the beginning of `create_signature()`, before any crypto.

**Effort:** Small (< 30 minutes)

---

### M7. `.display()` used for signature file path construction

**File:** `src/ops/sign.rs:182-184`, `src/ops/verify.rs:307`

**Issue:** Path construction uses `format!("{}.minisig", message_file.display())`
which can produce incorrect results for non-UTF8 paths (replacement characters) or
platform-specific separators.

**Remediation:**
Use `OsString` manipulation or `Path::with_extension()` pattern instead.

**Effort:** Small (< 30 minutes)

---

### M8. No duplicate file detection in parallel operations

**File:** `src/ops/sign.rs:341-352`

**Issue:** If a user passes the same file multiple times to multi-file signing, parallel
threads race to write the same `.minisig` file. In force mode, this can corrupt output.

**Remediation:**
Deduplicate the file list before processing, or document the limitation.

**Effort:** Small (< 30 minutes)

---

### M9. CLI `-W` flag semantics in change/recreate operations

**File:** `src/main.rs:337-368`

**Issue:** `-W` (no_password) is documented as "generate and change only" in
`cli.rs:115-116`. In `handle_change()`, `-W` skips ALL password prompts (both old
and new), making it impossible to remove a password from an encrypted key via the
CLI (you need the old password to decrypt, then no new password to remove encryption).

In `handle_recreate()`, `-W` is checked despite the CLI docs saying it's for
generate/change only.

**Remediation:**
- `handle_change`: Separate the concern — always prompt for old password if key is
  encrypted, treat `-W` as "desired end state has no password"
- `handle_recreate`: Either reject `-W` or document its behavior

**Effort:** Medium (2-4 hours, requires careful testing of password flows)

---

### M10. Missing API exports in `ops/mod.rs`

**File:** `src/ops/mod.rs:16`

**Issue:** `InspectPrivateOptions`, `inspect_private`, and `inspect_signature` are
used by `main.rs` but not exported from the public `ops` module. `main.rs` reaches
directly into `ops::inspect::` submodule.

**Remediation:**
Add missing types to the `pub use` statement in `ops/mod.rs`.

**Effort:** Trivial (< 10 minutes)

---

## LOW Severity Findings

### L1. Hardcoded magic string for encrypted key detection

**File:** `src/main.rs:416, 525`

**Issue:** Uses hardcoded `"0000000000000000"` to detect encrypted keys whose keynum
hasn't been decrypted yet. Should be a named constant.

**Effort:** Trivial

---

### L2. `PublicKey` Debug shows first byte — inconsistent with `SecretKey`

**File:** `src/crypto.rs:89`

**Issue:** `SecretKey` Debug prints `"[REDACTED]"` but `PublicKey` prints `"PublicKey(ab..)"`.
Public keys are not secret, so this is cosmetic. But `Signature` at line 113 also
shows first byte — consider consistency.

**Effort:** Trivial

---

### L3. Clippy nursery: many `const fn` opportunities

**Clippy output:** 12+ functions could be `const fn` (crypto.rs, keys.rs, cli.rs).

**Effort:** Small (mechanical changes)

---

### L4. `derive_key_with_params()` has no output length cap

**File:** `src/crypto.rs:442-463`

**Issue:** Accepts arbitrary `output_len`. Current callers always pass
`ENCRYPTED_BLOB_SIZE` (104). A misuse could request enormous allocations.

**Effort:** Trivial (add a const bound)

---

## Test Coverage Gaps

### T1. No signature forgery / malleability attack tests

**Severity:** HIGH

**Missing scenarios:**
- Signature with correct keynum but forged signature bytes
- Tampered global signature (trusted comment binding)
- Signature reuse across messages
- Algorithm confusion ("Ed" vs "ED" marker swaps)

**Remediation:** Create `tests/security_attacks.rs` with dedicated forgery tests.

---

### T2. Weak error message assertions in CLI tests

**Severity:** MEDIUM

**Issue:** ~15 CLI tests only check `.failure()` without verifying the error message
content. Tests pass even if the wrong error is returned.

**Example:** `cli_test.rs:71` — `minisign_cmd().arg("-G").assert().failure()` — doesn't
verify WHY it failed.

**Remediation:** Add `.stderr(predicate::str::contains("expected message"))` to all
failure assertions.

---

### T3. No malicious path traversal tests

**Severity:** MEDIUM

**Missing:** Tests for `../../../etc/passwd`, null bytes in paths, overlong paths,
Windows reserved names (`CON`, `NUL`).

**Remediation:** Add path traversal tests to `tests/edge_cases.rs`.

---

### T4. Password-protected workflow tests are all slow/ignored

**Severity:** MEDIUM

**Issue:** All password tests use production scrypt params (N=2^20) and are `#[ignore]`.
No fast password tests exist using `--force-weak-kdf`.

**Remediation:** Add fast password workflow tests using debug-mode weak KDF.

---

### T5. Concurrent tests use timing-dependent sleeps

**Severity:** LOW

**File:** `tests/concurrent_access.rs`

**Issue:** Tests use `thread::sleep(Duration::from_micros(10..100))` for synchronization,
making them potentially flaky on slow CI.

**Remediation:** Replace sleeps with synchronization primitives (`Barrier`, channels)
where possible.

---

### T6. No key uniqueness / RNG quality verification tests

**Severity:** LOW

**Issue:** No test generates multiple keys and verifies they're all distinct.

**Remediation:** Add test generating N keys and asserting uniqueness.

---

## Remediation Plan — Execution Order

### Phase 1: Critical Security (Estimated: 1 day)

| ID  | Finding | Action |
|-----|---------|--------|
| H1  | `SignatureBox::new()` validation | Add `validate_comment()` calls, make fallible |
| H2  | `with_global_signature()` validation | Add comment validation + length checks |
| H3  | `unwrap_or(r)` silent fallback | Replace with explicit error |
| H4  | Missing `sync_all()` | Add to `write_signature_file()` |
| H6  | Comment length in parsing | Add length checks in `from_file_contents()` |

### Phase 2: Security Hardening (Estimated: 1 day)

| ID  | Finding | Action |
|-----|---------|--------|
| H5  | `KeyNum` timing | Use `ct_eq` or document as acceptable |
| M1  | `calculate_kdf_params` overflow | Add bounds check + checked arithmetic |
| M6  | Validation before crypto | Reorder `create_signature()` |
| T1  | Forgery attack tests | Create `tests/security_attacks.rs` |

### Phase 3: Robustness (Estimated: 1-2 days)

| ID  | Finding | Action |
|-----|---------|--------|
| M2  | `formats.rs` panics | Make functions return `Result` |
| M3  | Comment length asymmetry | Make both errors or document |
| M4  | Centralize validation | Add length to `validate_comment()` |
| M5  | `Error::Other` → `InvalidComment` | Simple replacement |
| M7  | Path construction | Use `OsString` manipulation |
| M8  | Duplicate file detection | Deduplicate before parallel ops |
| T2  | Error message assertions | Add stderr predicates to ~15 tests |
| T3  | Path traversal tests | Add to `tests/edge_cases.rs` |

### Phase 4: Polish (Estimated: 1 day)

| ID  | Finding | Action |
|-----|---------|--------|
| M9  | `-W` flag semantics | Rework password change CLI flow |
| M10 | Missing exports | Add to `ops/mod.rs` |
| L1  | Magic string | Extract constant |
| L2  | Debug consistency | Align PublicKey/Signature Debug impls |
| L3  | `const fn` | Apply clippy nursery suggestions |
| L4  | KDF output length | Add const bound |
| T4  | Fast password tests | Add weak-KDF test variants |
| T5  | Sleep-based tests | Replace with barriers/channels |
| T6  | Key uniqueness test | Add uniqueness assertion |

---

## Findings NOT Included (False Positives)

The following items were flagged by reviewers but rejected after manual verification:

1. **"Missing unit tests"** — All 15 unit test files exist in `tests/unit/`. The reviewer's
   glob pattern was incorrect.

2. **"SecretKey not zeroized in change.rs"** — `crypto::SecretKey` already derives
   `#[derive(Zeroize, ZeroizeOnDrop)]` at `crypto.rs:46`. The type automatically
   zeroizes on drop.

3. **"XOR encryption reuses key stream without nonce"** — This matches the C minisign
   specification. Security depends on unique salts, which are randomly generated.
   Documented as intentional.

4. **"Secret key path exposure in error messages"** — Secret key file paths are not
   themselves secret (they're user-specified CLI arguments). The path `/home/user/.minisign/minisign.key`
   is the well-known default location documented in the README. Sanitizing this would
   reduce debuggability without meaningful security gain.

---

## Positive Observations

The codebase demonstrates strong security engineering:

- All secrets use `Zeroize + ZeroizeOnDrop` (SecretKey, Zeroizing<Vec>)
- Checksum comparison uses constant-time `ct_eq()` via `subtle`
- Zero `unsafe` code enforced
- Zero clippy warnings in standard pedantic mode
- Comprehensive integration testing with 348+ tests
- Atomic file creation (`create_new(true)`) prevents TOCTOU races
- Restrictive permissions (0600) for secret key files on Unix
- Streaming hash support prevents loading large files into memory
- Well-structured error types with `thiserror`
- Clear module boundaries and separation of concerns
