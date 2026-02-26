# Code Review: minisign-rs v1.4.0

**Date:** 2026-02-26
**Scope:** Full Rust codebase under `rs/`
**Reviewers:** Automated multi-agent review (crypto, operations, CLI/validation, test quality)

---

## Executive Summary

The minisign Rust implementation is a well-structured, production-grade cryptographic tool with 4,208 lines of production code, 10,515 lines of tests (2.5:1 ratio), zero `unsafe` blocks, and clean clippy-pedantic compliance. The architecture is sound with clear module boundaries, no circular dependencies, and correct use of audited cryptographic libraries.

However, four parallel review passes uncovered **32 issues** across security, correctness, usability, and test quality. The most critical findings relate to **non-atomic key file writes** (data loss risk), **unzeroized secret key material in serialization temporaries**, and **several tests that assert the opposite of their stated purpose**.

### Issue Distribution

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 1 | File I/O atomicity |
| Important/High | 12 | Memory safety, TOCTOU, validation, test integrity |
| Medium | 10 | UX, API design, test gaps |
| Low/Info | 9 | Cosmetics, naming, documentation |

---

## Part 1: Security & Cryptographic Review

### S1. Unzeroized secret key in `to_bytes()` temporary buffer — Important

**File:** `src/keys.rs:708-747, 862-865`

`SeckeyStruct::to_bytes()` allocates a `[u8; 158]` on the stack containing plaintext secret key material (for unencrypted keys). This array is returned by value and passed to `encode_base64()`, which copies it into a heap `String`. Neither the stack array nor the `String` are wrapped in `Zeroizing`, creating two locations where secret key material persists after the struct's `ZeroizeOnDrop` has no reach.

**Fix:**
```rust
pub fn to_file_contents(&self, comment: &str) -> String {
    let bytes = Zeroizing::new(self.to_bytes());
    let base64 = Zeroizing::new(encode_base64(&*bytes));
    format!("untrusted comment: {comment}\n{base64}\n")
}
```

### S2. `ScryptParams.len` mismatch relies on undocumented crate behavior — Important

**File:** `src/crypto.rs:529-537`

`ENCRYPTED_BLOB_SIZE` is 104 bytes but `ScryptParams::new()` caps `len` at 64. The code passes `len=64` to `Params` but a 104-byte output buffer to `scrypt()`. This works because scrypt-0.11.0's low-level function uses `output.len()` directly, ignoring `Params.len`. A future version that validates output size against `Params.len` would silently truncate key material or error.

**Fix:** Add a defensive assertion:
```rust
// Verified against scrypt-0.11.0 — low-level scrypt() ignores Params.len for output size
debug_assert_eq!(output.len(), output_len);
```

### S3. `compute_checksum` intermediate Vec not zeroized — Medium

**File:** `src/keys.rs:612-618`

A `Vec` containing 64 bytes of raw secret key material is allocated for checksum computation but not wrapped in `Zeroizing`.

**Fix:**
```rust
let mut data = Zeroizing::new(Vec::with_capacity(2 + KEYNUM_BYTES + SECRET_KEY_BYTES));
```

### S4. `set_permissions(path)` TOCTOU race — High

**File:** `src/ops/file_utils.rs:101-106`

`std::fs::set_permissions` operates on the path, not the file descriptor. Between `open()` and `set_permissions()`, an attacker could swap the file via rename, causing mode 0600 to be applied to the wrong file. Should use `fchmod` on the fd.

**Fix:** Use `libc::fchmod` on the file descriptor, or restructure to set permissions via `OpenOptions` before writing.

### S5. Non-crypto dependencies not pinned — Low

**File:** `Cargo.toml:22-28`

`rpassword` (handles raw password input) and `pico-args` (parses CLI flags including security-relevant ones) use semver ranges while crypto crates are pinned to exact versions. A supply-chain compromise of `rpassword` could exfiltrate passwords at the point of entry.

**Fix:** Pin `rpassword` to an exact version at minimum.

### S6. `force_weak_kdf` panics in release builds via `assert!` — Low

**File:** `src/crypto.rs:382-386`

`calculate_kdf_params` is a public library API that returns `Result`, but uses `assert!` instead of `Err` when `force_weak_kdf=true` in release builds. A downstream caller would get a panic instead of a recoverable error.

**Fix:** Return `Err(Error::ScryptParamError(...))` instead of `assert!`.

---

## Part 2: Operations & Application Logic Review

### O1. Non-atomic secret key rewrite in `change.rs` — Critical

**File:** `src/ops/change.rs:184`

`write_secret_key_file` opens the existing file with `create(true).truncate(true)`, which truncates before writing. If the process is killed or the OS crashes mid-write, the secret key is permanently lost with no backup.

**Fix:** Implement write-to-temp → fsync → rename pattern:
```rust
fn atomic_write(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| Error::FileWrite(...))?;
    let tmp = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
    std::fs::write(&tmp, contents)?;
    // fsync the file
    let f = std::fs::File::open(&tmp)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
```

### O2. Orphaned secret key on partial generate failure — High

**File:** `src/ops/generate.rs:256-270`

`write_secret_key_file` is called before `write_public_key_file`. If the public key write fails (e.g., file already exists due to race), the user is left with a secret key file but no corresponding public key. No cleanup of the secret key occurs.

**Fix:** Delete the secret key file if public key write fails:
```rust
write_secret_key_file(options.secret_key_file, &seckey_contents, options.force)?;
if let Err(e) = write_public_key_file(options.public_key_file, &pubkey_contents, options.force) {
    let _ = std::fs::remove_file(options.secret_key_file);
    return Err(e);
}
```

### O3. Comment validation off-by-one — High

**File:** `src/validation.rs:176-184`

`validate_comment_with_length` uses `>= max_len` (strict) while `SignatureBox::new` uses `> COMMENTMAXBYTES` (lenient). This rejects valid comments 20 bytes earlier than necessary. A comment of exactly `COMMENTMAXBYTES - COMMENT_PREFIX_SIZE` bytes is incorrectly rejected.

**Fix:** Change `>= max_len` to `> max_len` in `validate_comment_with_length`.

### O4. `KeyMismatch` error captures `pub_keynum` but never displays it — Medium

**File:** `src/errors.rs:64-68`

The `#[error]` format string only interpolates `sig_keynum`. The `pub_keynum` field is constructed and silently discarded in display.

**Fix:**
```rust
#[error("key mismatch: signature keyid {sig_keynum} doesn't match public keyid {pub_keynum}")]
```

### O5. `eprintln!("Working...")` in sign never cleared — Medium

**File:** `src/main.rs:260`

Uses `eprintln!` (with newline) unlike `handle_generate` which uses `eprint!` + `\r\x1b[K` to clear the line.

**Fix:** Match the pattern used in `handle_generate`.

### O6. Password file not verified as regular file — Medium

**File:** `src/main.rs:860-872`

`std::fs::read_to_string` on a FIFO, device, or `/dev/stdin` will block or produce unexpected behavior. Should stat the path and verify it's a regular file.

### O7. Implicit coupling: encrypted keynum ↔ `ENCRYPTED_KEYNUM_PLACEHOLDER` — Medium

**File:** `src/ops/inspect.rs:324-325`

For encrypted keys, `seckey.keynum()` returns zeroed bytes, which happen to match `ENCRYPTED_KEYNUM_PLACEHOLDER`. This works by coincidence, not explicit design. If either side changes, the coupling breaks silently.

**Fix:** Use a named constant or explicit check: `if seckey.is_encrypted()` rather than comparing keynum strings.

### O8. Batch failure summary suppressed in quiet mode — Medium

**File:** `src/ops/sign.rs:452-465`, `src/ops/verify.rs:476-487`

Per-file errors are shown in quiet mode, but the grouped summary of which files failed is suppressed — inconsistent behavior.

---

## Part 3: CLI, Validation & Error Handling Review

### C1. Multiple action flags accepted silently — Important

**File:** `src/cli.rs:182-187`

`minisign_rs -G -S -s my.key -m file.txt` silently runs only `Generate`, ignoring `-S`. No mutual-exclusion check exists.

**Fix:** Count action flags after parsing and return `Err(Error::Usage(...))` if more than one is set.

### C2. `\r` in `validate_comment` produces wrong error variant — Important

**File:** `src/validation.rs:55-75, 105-112`

`is_printable()` catches `\r` as a generic control character before `validate_no_embedded_cr()` is reached. The specific CR error message is dead code. Either allow `\r` through `is_printable` or remove the redundant `validate_no_embedded_cr` call.

### C3. `-q` and `-Q` not rejected as conflicting — Important

**File:** `src/cli.rs:194-195`

Help text documents `-q|-Q` as mutually exclusive, but both can be passed simultaneously. `-Q` is silently ignored when `-q` is also present.

**Fix:** Add usage error when both are set.

### C4. Windows reserved name check incorrectly rejects `COM0`/`LPT0` — Medium

**File:** `src/validation.rs:254-274`

`is_ascii_digit()` matches `'0'`, but `COM0`/`LPT0` are not Windows reserved device names.

**Fix:** Replace `is_ascii_digit()` with `matches!(c, '1'..='9')`.

### C5. `save_password` no-op stub silently succeeds without credential store feature — Medium

**File:** `src/credential_store.rs:123-126`

User passes `--save-password`, sees success message, but nothing was saved. Should return an error when the feature is disabled.

### C6. `default_signature_path` corrupts non-UTF-8 filenames — Low

**File:** `src/cli.rs:326-336`

`to_string_lossy()` replaces invalid UTF-8 with U+FFFD. Use `OsString::push` instead:
```rust
let mut sig_name = file_name.to_os_string();
sig_name.push(".minisig");
```

### C7. `password_file` flag silently ignored for verify/inspect — Low

**File:** `src/main.rs`

No validation rejects `--password-file` for operations that don't use passwords.

---

## Part 4: Test Quality Review

### T1. `test_concurrent_key_generation_with_force` — false confidence — High

**File:** `tests/concurrent_access.rs:197`

Five threads race to write the same key file. Test only asserts `exists()`, never validates the resulting file is a parsable, non-corrupt key. A corrupt file from interleaved writes would pass this test.

**Fix:** Parse and validate the resulting key file after all threads join.

### T2. `test_read_during_write` atomicity check is vacuous — High

**File:** `tests/concurrent_access.rs:484-491`

The reader thread almost never reads during the write window on fast machines. The atomicity assertion loop never executes, providing zero coverage of the stated invariant.

**Fix:** Assert at least one successful read occurred, or restructure to guarantee overlap.

### T3. `test_sign_file_too_large_fails` tests opposite of its name — High

**File:** `tests/unit/ops/sign.rs:484-506`

Named "too large fails" but actually asserts a small file succeeds. Same issue in `test_verify_file_too_large_fails`. These are documentation masquerading as tests.

**Fix:** Rename to reflect actual behavior, or test the size-limit code path via `check_file_size_limit` with synthetic metadata.

### T4. Property tests contradict on CR handling — High

**File:** `tests/fuzzing.rs:207, 229`

`prop_control_chars_in_comments` excludes `0x0d` from rejected characters, but `prop_carriage_return_injection` expects `\r` to be rejected. One of them is wrong.

**Fix:** Remove the `0x0d` exclusion from `prop_control_chars_in_comments`.

### T5. `test_zero_length_password` tests comment validation, not passwords — Low

**File:** `tests/fuzzing.rs:337-343`

Copy-paste error: name says "password", body calls `validate_comment("")`.

### T6. `test_blake2b_512_hello` hex string is 127 chars (odd) — Low

**File:** `tests/unit/crypto.rs:79-87`

127-character hex string either panics on decode or produces a 63-byte slice that can never match Blake2b-512's 64-byte output. Likely a truncated KAT.

**Fix:** Verify against the canonical Blake2b-512 test vector and use the full 128-character hex string.

### T7. Summary output tests assert nothing about output format — Medium

**Files:** `tests/unit/ops/sign.rs:751`, `tests/unit/ops/verify.rs:527`

Both `test_*_summary_shows_only_filenames_not_error_details` tests end with a comment saying "would need stderr capture" and assert nothing about the summary format.

### T8. `h6_parse_accepts_maximum_length_comments` tests MAX-1, not MAX — Medium

**File:** `tests/unit/security_hardening.rs:264-268`

Uses `COMMENTMAXBYTES - 1` instead of `COMMENTMAXBYTES`. The exact boundary is untested.

### T9. No integration test for `-o` (output) verify flag — Medium

No test in `cli_test.rs` or `ops/verify.rs` verifies that `-o` causes message content to be written to stdout.

### T10. No property test for `SignatureBox` text round-trip — Medium

Only `SigStruct` binary round-trips are property-tested. No proptest covers full `SignatureBox` serialization under arbitrary valid comments.

---

## Part 5: Remediation Plan

### Phase 1: Critical & Security (Immediate)

| # | Issue | Priority | Effort | Files to Modify |
|---|-------|----------|--------|-----------------|
| 1 | O1: Atomic key file writes | Critical | Medium | `ops/file_utils.rs`, `ops/change.rs` |
| 2 | S1: Zeroize `to_bytes()` temporaries | Important | Small | `keys.rs` |
| 3 | S3: Zeroize `compute_checksum` Vec | Medium | Small | `keys.rs` |
| 4 | S4: `fchmod` instead of `set_permissions(path)` | High | Medium | `ops/file_utils.rs` |
| 5 | O2: Cleanup orphaned secret key on generate failure | High | Small | `ops/generate.rs` |

**Approach for O1 (atomic writes):**
1. Create an `atomic_write_file` function in `file_utils.rs` that writes to a `.tmp` sibling, fsyncs, then renames.
2. Use it in `change.rs` for secret key updates.
3. Consider using it for all key file writes in `generate.rs`.
4. Add tests for crash-recovery scenarios using the temp file pattern.

**Approach for S1 + S3 (zeroization):**
1. Wrap `to_bytes()` return in `Zeroizing::new()` at all call sites.
2. Wrap `compute_checksum`'s intermediate `Vec` in `Zeroizing`.
3. Audit all paths where `SecretKey` bytes leave the `Zeroizing` wrapper.

### Phase 2: Correctness & Validation (Soon)

| # | Issue | Priority | Effort | Files to Modify |
|---|-------|----------|--------|-----------------|
| 6 | O3: Comment validation off-by-one | High | Small | `validation.rs` |
| 7 | C1: Reject multiple action flags | Important | Small | `cli.rs` |
| 8 | C2: Fix `\r` error variant in `validate_comment` | Important | Small | `validation.rs` |
| 9 | C3: Reject conflicting `-q`/`-Q` | Important | Small | `cli.rs` or `main.rs` |
| 10 | C4: Fix COM0/LPT0 false rejection | Medium | Small | `validation.rs` |
| 11 | O4: Include `pub_keynum` in `KeyMismatch` display | Medium | Small | `errors.rs` |
| 12 | S2: Add `debug_assert` for scrypt output len | Important | Small | `crypto.rs` |

### Phase 3: Test Quality (Next Sprint)

| # | Issue | Priority | Effort | Files to Modify |
|---|-------|----------|--------|-----------------|
| 13 | T1: Validate key integrity in concurrent test | High | Small | `tests/concurrent_access.rs` |
| 14 | T3: Rename/fix "too large" stub tests | High | Small | `tests/unit/ops/sign.rs`, `verify.rs` |
| 15 | T4: Reconcile CR property test contradiction | High | Small | `tests/fuzzing.rs` |
| 16 | T6: Fix Blake2b hex KAT | Low | Small | `tests/unit/crypto.rs` |
| 17 | T5: Fix password/comment test naming | Low | Small | `tests/fuzzing.rs` |
| 18 | T8: Test exact MAX boundary | Medium | Small | `tests/unit/security_hardening.rs` |
| 19 | T9: Add `-o` integration test | Medium | Medium | `tests/cli_test.rs` |
| 20 | T10: Add SignatureBox round-trip proptest | Medium | Medium | `tests/fuzzing.rs` |

### Phase 4: Polish & UX (When Convenient)

| # | Issue | Priority | Effort | Files to Modify |
|---|-------|----------|--------|-----------------|
| 21 | C5: Error on `--save-password` without feature | Medium | Small | `credential_store.rs` |
| 22 | O5: Fix "Working..." not cleared in sign | Medium | Small | `main.rs` |
| 23 | C6: Use `OsString` for signature paths | Low | Small | `cli.rs` |
| 24 | O6: Verify password file is regular file | Medium | Small | `main.rs` |
| 25 | S5: Pin `rpassword` to exact version | Low | Small | `Cargo.toml` |
| 26 | S6: Return `Err` instead of `assert!` for `force_weak_kdf` | Low | Small | `crypto.rs`, `generate.rs`, `change.rs` |
| 27 | C7: Reject `--password-file` for non-password ops | Low | Small | `main.rs` |
| 28 | O7: Explicit encrypted key check in inspect | Medium | Small | `ops/inspect.rs` |
| 29 | O8: Show failure summary even in quiet mode | Medium | Small | `ops/sign.rs`, `ops/verify.rs` |

### Estimated Total Effort

- **Phase 1:** ~4 hours (atomic writes is the bulk)
- **Phase 2:** ~2 hours (all small, self-contained fixes)
- **Phase 3:** ~3 hours (test restructuring)
- **Phase 4:** ~2 hours (incremental polish)

---

## Appendix: What's Working Well

These aspects deserve recognition and should be preserved:

- **Zero `unsafe` code** — entire codebase is safe Rust
- **Clean module boundaries** — no circular dependencies, clear separation of concerns
- **Builder pattern consistency** — all operation options use the same pattern
- **Error type design** — comprehensive, structured, no stringly-typed errors
- **Test-to-code ratio of 2.5:1** — significantly above industry norms
- **Crypto dependency pinning** — exact versions for all security-critical crates
- **Constant-time comparison** for keynum via `subtle::ConstantTimeEq`
- **`Zeroize` + `ZeroizeOnDrop`** on secret key structures
- **Release profile optimization** — LTO, strip, panic=abort, size-optimized
- **Feature-gated credential store tests** — avoids OS prompts in CI
