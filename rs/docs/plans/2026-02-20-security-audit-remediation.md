# Security Audit Remediation Plan

**Date:** 2026-02-20
**Source:** `rs/docs/2026-02-20-rust-security-audit.md`
**Findings to address:** RS-1 through RS-9 (8 actionable, RS-7 and RS-8 are informational/no-action)

---

## Context

A security audit of the Rust minisign implementation identified 9 findings (2 Medium, 4 Low, 2 Informational, 1 Medium shared with C). The Critical and High classes from the C audit are structurally absent. This plan addresses the 7 actionable findings in priority order.

---

## Step 1: RS-9 — Add `O_NOFOLLOW` to force-overwrite path

**Priority:** High (Medium severity, straightforward fix)
**File:** `src/ops/file_utils.rs`

The `write_file` function's force path uses `.create(true).truncate(true)` which follows symlinks. Add `O_NOFOLLOW` via `OpenOptionsExt::custom_flags`.

**Changes:**
- In `write_file()`, when `force` is true on Unix, add `libc::O_NOFOLLOW` via `custom_flags()`
- `libc` is already a transitive dependency (via `scrypt` → `libc 0.2.182`) but we need it as a direct dependency for the constant
- Alternative: use the raw integer value `0x0100` on Linux / `0x0020` on macOS — but `libc` is cleaner

**Implementation:**
```rust
#[cfg(unix)]
if force {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}
```

**Dependency:** Add `libc = "0.2"` to `[dependencies]` in `Cargo.toml`.

**Tests:**
- Unit test: create a symlink, attempt force-write, assert it returns an error (not follows the symlink)
- Existing tests must still pass

---

## Step 2: RS-1 — Add scrypt output-length regression test

**Priority:** High (Medium severity, test-only change)
**File:** `tests/` (new or existing crypto test file)

The `derive_key_with_params` function passes a capped `params_len` (64) to `ScryptParams::new` but a full 104-byte buffer to `scrypt()`. This works due to crate internals. A regression test with a known-good test vector will catch breakage on crate upgrades.

**Changes:**
- Add an integration test that calls `derive_key_with_params` with `output_len = 104` (matching `ENCRYPTED_BLOB_SIZE`), a fixed password, salt, and known scrypt parameters
- Assert the output matches a pre-computed expected value (compute once, hardcode)
- This test should be `#[ignore]` tagged since scrypt is slow

**No production code changes.** The existing comment documents the coupling adequately.

---

## Step 3: RS-4 — Replace `.expect()` with infallible operations

**Priority:** Medium (Low severity, CLAUDE.md violation)
**Files:** `src/keys.rs`, `src/crypto.rs`, `src/formats.rs`

Three `.expect()` calls in production paths violate the project's "no `.expect()` in production" rule, even though they are structurally unreachable.

**Changes in `src/keys.rs` (lines 731-740):**
Replace `write_u64_le(...).expect(...)` with direct `copy_from_slice`:
```rust
bytes[SECKEY_KDF_OPSLIMIT_OFFSET..opslimit_end]
    .copy_from_slice(&self.kdf_opslimit.to_le_bytes());
bytes[SECKEY_KDF_MEMLIMIT_OFFSET..memlimit_end]
    .copy_from_slice(&self.kdf_memlimit.to_le_bytes());
```

**Changes in `src/crypto.rs` (line 197):**
Replace `read_u64_le(&self.0).expect(...)` with direct conversion:
```rust
let value = u64::from_le_bytes(self.0);
```

**Changes in `src/formats.rs` (line 40):**
The `.expect("slice is exactly 8 bytes")` in `read_u64_le` is inside a fallible function that already returns `Result` — the `.get(..8)` guard makes the `.expect()` unreachable. But since the function returns `Result`, we can use `map_err` instead:
```rust
let buf: [u8; 8] = bytes
    .get(..8)
    .ok_or_else(|| Error::Other(...))?
    .try_into()
    .map_err(|_| Error::Other("slice conversion failed".into()))?;
```

**Tests:** Existing tests cover these paths. Run full suite to verify no regressions.

---

## Step 4: RS-5 — Add release profile hardening flags

**Priority:** Medium (Low severity, build config)
**File:** `Cargo.toml`

**Changes:**
```toml
[profile.release]
strip = true
overflow-checks = true
lto = true
panic = "abort"
codegen-units = 1
```

**Verification:** Build a release binary and verify it functions correctly:
```bash
cargo build --release
./target/release/minisign_rs -G -f -p /tmp/test.pub -s /tmp/test.key
echo "test" > /tmp/test.txt
./target/release/minisign_rs -Sm /tmp/test.txt -s /tmp/test.key
./target/release/minisign_rs -Vm /tmp/test.txt -p /tmp/test.pub
```

---

## Step 5: RS-2 — Enforce untrusted comment prefix on parse

**Priority:** Low (Low severity, consistency fix)
**File:** `src/signature.rs`

**Changes (line 307-310):**
Replace `unwrap_or(lines[0])` with `.ok_or_else()` matching the trusted comment pattern:
```rust
let untrusted_comment = lines[0]
    .strip_prefix("untrusted comment: ")
    .ok_or_else(|| {
        Error::InvalidSignatureFormat(
            "untrusted comment must start with \"untrusted comment: \"".to_string(),
        )
    })?
    .to_string();
```

**Compatibility concern:** The C minisign also requires this prefix (it checks `COMMENT_PREFIX`). Verify no existing test fixtures lack the prefix. If any do, they are already malformed.

**Tests:** Add a test with a missing prefix, assert it returns `Error::InvalidSignatureFormat`.

---

## Step 6: RS-3 — Warn on timestamp fallback to zero

**Priority:** Low (Low severity)
**File:** `src/ops/sign.rs`

**Changes (lines 573-576):**
```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or_else(|_| {
        eprintln!("Warning: system clock error, using timestamp 0");
        0
    });
```

**Tests:** Existing tests unaffected (system clock works in CI).

---

## Step 7: RS-6 — Document `MINISIGN_CONFIG_DIR` trust model

**Priority:** Low (Low severity, documentation only)
**File:** `src/cli.rs`

**Changes:** Add a doc comment above the `MINISIGN_CONFIG_DIR` usage:
```rust
// MINISIGN_CONFIG_DIR is trusted input — it determines the default key path.
// Users are responsible for ensuring this environment variable is not set by
// untrusted processes (e.g., SUID wrappers, CI pipeline injection).
```

**No code changes, no tests needed.**

---

## Excluded (No Action Required)

| Finding | Reason |
|---------|--------|
| RS-7 (Info) | Inherent to multi-threaded signing; no mitigation possible without single-threading |
| RS-8 (Info) | Inherent OS keyring API limitation; Rust-side copy is already `Zeroizing` |

---

## Verification

After all changes, run the full pre-commit checklist:
```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
cargo test --no-default-features
cargo test --no-default-features -- --ignored
```

Then verify release build:
```bash
cargo build --release
# Run a sign/verify round-trip with the release binary
```
