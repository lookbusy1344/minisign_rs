# minisign-rs Security Code Review & Remediation Plan

**Date:** 2026-02-28  
**Scope:** `rs/` Rust implementation (`src/`, tests, and docs under `rs/docs/`)  
**Reviewer:** Codex (fresh-pass, security-focused review)

---

## Executive Summary

The Rust implementation is generally strong in cryptographic hygiene and safety posture: no `unsafe` usage under `src/`, strong use of `Zeroizing`/`ZeroizeOnDrop`, constant-time checks on security-critical comparisons, and solid test coverage.

I did not identify an immediate signature forgery or key exfiltration bug in core cryptographic flows.  
I did identify **three security-relevant hardening gaps** (1 medium, 2 low/medium) that should be addressed to reduce denial-of-service and local race/interference risk.

---

## Review Method

1. Baseline quality gate run:
   - `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
   - `cargo fmt -- --check`
   - `cargo test --no-default-features`
   - `cargo test --no-default-features -- --ignored`
2. Manual review of high-risk modules:
   - `src/crypto.rs`, `src/keys.rs`, `src/signature.rs`
   - `src/ops/{file_utils,sign,verify,generate,change,inspect}.rs`
   - `src/main.rs`, `src/cli.rs`, `src/credential_store.rs`
3. Focused pattern scans for panic/command execution/symlink handling/secret handling paths.

All baseline gates completed successfully.

---

## Positive Security Observations

- **No unsafe code in runtime modules** (`src/`) and crate-level `#![forbid(unsafe_code)]` in `src/lib.rs`.
- **Secret handling is mature**: `SecretKey` and sensitive buffers use `Zeroize`/`Zeroizing` (`src/crypto.rs`, `src/keys.rs`, `src/main.rs`).
- **Key/Checksum comparisons use constant-time operations**:
  - keynum compare in verify path (`src/ops/verify.rs:286-294`)
  - checksum compare during key decrypt (`src/keys.rs:512-518`)
- **File overwrite hardening exists**:
  - `O_NOFOLLOW` and fd-based permission setting for secret-key overwrite (`src/ops/file_utils.rs:133-176`).

---

## Findings

| ID | Severity | Area | Summary |
|---|---|---|---|
| CR-2026-02-28-1 | **Medium** | File parsing/input handling | Multiple unbounded `read_to_string()` paths allow memory DoS from oversized key/signature/password files. |
| CR-2026-02-28-2 | **Medium** | KDF parameter handling | Decryption accepts file-supplied KDF cost parameters without policy cap, enabling attacker-selected expensive scrypt work. |
| CR-2026-02-28-3 | **Low** | Atomic overwrite temp strategy | Secret-key temp overwrite path uses predictable temp names with `create(true)+truncate(true)`, allowing local interference in writable dirs. |

---

## Detailed Findings and Remediation

### CR-2026-02-28-1 — Unbounded file reads in key/signature/password paths (Medium)

**Evidence**
- Secret key load: `src/ops/file_utils.rs:61`
- Public key load: `src/ops/verify.rs:239-245`
- Signature load: `src/ops/verify.rs:260-264`
- Inspect key/signature loads: `src/ops/inspect.rs:200-201`, `301-302`, `437-438`
- Password file read: `src/main.rs:872-889`

All of these use `read_to_string()` without an upper bound prior to allocation.

**Impact**
- A maliciously large file can trigger excessive memory allocation and process termination or severe slowdown.
- Most relevant for consumers using this as a verification library against untrusted files.

**Remediation Plan**
1. Introduce explicit maximum sizes for each input class:
   - key files (small, fixed-layout base64 content),
   - signature files (4-line format with bounded comment lengths),
   - password files (very small; e.g., a few KiB cap).
2. Replace unbounded reads with bounded I/O:
   - metadata pre-check + bounded read (`take(max+1)` pattern),
   - fail with explicit error if over limit.
3. For signature parsing, prefer line-based bounded parsing (`BufRead::read_line`) instead of whole-file read.
4. Add tests for oversized files to assert deterministic rejection.

---

### CR-2026-02-28-2 — No explicit policy cap on decryption KDF costs from file (Medium)

**Evidence**
- Encrypted key decryption derives parameters directly from on-disk fields:
  - `src/keys.rs:477-484`
- Parameter conversion currently checks arithmetic validity, not policy ceilings:
  - `src/crypto.rs:437-487`
- Derived values then drive scrypt work:
  - `src/crypto.rs:514-539`

**Impact**
- Crafted encrypted key files can request very high KDF work factors and force expensive CPU/memory operations.
- This can be used as a denial-of-service vector in automated workflows or services.

**Remediation Plan**
1. Add policy bounds for accepted decryption parameters (e.g., max `log_n`, max derived memory cost).
2. Reject over-budget keys by default with a clear error.
3. Optionally allow explicit override flag (similar to existing fallback controls), but default to safe refusal.
4. Add unit tests with crafted high-parameter key metadata ensuring bounded failure behavior.

---

### CR-2026-02-28-3 — Predictable temp file path in atomic overwrite flow (Low)

**Evidence**
- Temp file name uses deterministic counter:
  - `src/ops/file_utils.rs:143-152`
- Temp file open uses `.create(true).truncate(true)` (not exclusive create):
  - `src/ops/file_utils.rs:155-161`

**Impact**
- In attacker-writable/shared directories, pre-creation or collision with predictable temp names can cause interference or unintended truncation of a pre-existing temp path.
- Does not directly expose secret key material, but can affect integrity/availability.

**Remediation Plan**
1. Use unpredictable temp names (CSPRNG nonce) and **exclusive create** (`create_new(true)`).
2. Keep `O_NOFOLLOW` and same-directory rename semantics.
3. Add tests for concurrent overwrite and pre-existing temp-path collision handling.

---

## Prioritized Remediation Plan

### Phase 1 (Immediate hardening)
1. Implement bounded input reads for keys/signatures/password files (CR-1).
2. Add regression tests for oversized input rejection.

### Phase 2 (DoS resistance)
1. Introduce decryption KDF policy ceilings with explicit error path (CR-2).
2. Add malformed/extreme KDF metadata tests.

### Phase 3 (Integrity hardening)
1. Make temp-file creation exclusive and non-predictable in secret-key overwrite path (CR-3).
2. Add collision/interference tests.

---

## Exit Criteria

Remediation can be considered complete when:

1. Oversized key/signature/password inputs are rejected before large allocation.
2. Decryption path refuses attacker-selected KDF costs above policy limits by default.
3. Secret-key overwrite temp files are created with exclusive, collision-resistant strategy.
4. Full existing quality gate suite remains green.

