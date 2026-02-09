# Code Review: minisign-rs (Rust implementation)
**Date:** 2026-02-09  
**Scope:** `rs/src` (CLI, crypto, keys, ops, file utilities)

---

## Executive Summary

The Rust implementation is well-structured and security-conscious (zeroize usage, constant-time comparisons, tight parsing, and size limits). I found a small set of correctness and UX regressions that are easy to fix, plus one security hardening gap around file permissions when overwriting secret keys. None of the issues appear to compromise cryptographic correctness, but they do affect CLI behavior, user safety guarantees, and audit clarity.

---

## Notable Strengths

- **Memory hygiene and side‑channel awareness:** `Zeroize`/`Zeroizing` is used consistently for secrets, and constant‑time comparisons protect key IDs and checksums (`src/crypto.rs`, `src/keys.rs`, `src/ops/verify.rs`).
- **Compatibility and validation discipline:** binary formats, comment validation, and file size limits are all explicit and cross‑referenced to C minisign behavior (`src/signature.rs`, `src/validation.rs`, `src/ops/file_utils.rs`).
- **Operational resilience:** atomic file creation and fsync are used for key/signature writes, reducing TOCTOU and durability risks (`src/ops/file_utils.rs`, `src/ops/sign.rs`).

---

## Findings (Prioritized)

### 1) Secret key permissions are not enforced when overwriting (HIGH)

**Location:** `src/ops/file_utils.rs:65-70, 72-86`  
**Issue:** When `--force` is used, `OpenOptions::create(true)` opens an existing file but does **not** reset permissions. If a secret key file was previously created with lax permissions, it remains world‑readable after overwrite.  
**Risk:** Secret key disclosure on misconfigured file systems.  
**Recommendation:** After opening the file, explicitly `set_permissions(0o600)` on Unix when `force` is true (or always), mirroring the intent of the current `mode()` call.

---

### 2) `--output` flag is wired but unused (MEDIUM)

**Location:** `src/cli.rs:76-78`, `src/ops/verify.rs:18-98`, `src/main.rs:279-318`  
**Issue:** `VerifyOptions::output` is stored and exposed but never used in verification or CLI output paths.  
**Impact:** CLI behavior does not match documentation; `-o` is effectively a no‑op.  
**Recommendation:** Implement a single‑line output mode (e.g., `ok|fail`, or the trusted comment only) or remove the flag to avoid misleading users. Add a CLI test to lock behavior.

---

### 3) Quiet mode is ignored for multi‑file signing (MEDIUM)

**Location:** `src/ops/sign.rs:488-519, 523-546`  
**Issue:** `report_file_result` and `print_summary` always print, even when `SignOptions::quiet` is true.  
**Impact:** `-q` does not behave consistently across single‑file and multi‑file signing.  
**Recommendation:** Gate per‑file output and summaries on `options.quiet()` similar to verification.

---

### 4) File size limit error message references wrong flag (LOW)

**Location:** `src/ops/file_utils.rs:150-157`  
**Issue:** Error message suggests `--prehashed (-p)` but the CLI flag is `-H` (and `-p` is public key).  
**Impact:** Confusing guidance when non‑prehashed file size limits are hit.  
**Recommendation:** Change the message to `--prehashed (-H)` to match CLI.

---

### 5) `--prehashed` flag in signing path is effectively a no‑op (LOW)

**Location:** `src/cli.rs:60-63`, `src/main.rs:176-181`  
**Issue:** The sign path sets `prehashed(!cli.legacy)` and never consumes `cli.prehashed`, so `-H` does not alter signing behavior.  
**Impact:** Users cannot tell if `-H` is required or meaningful, and the flag appears nonfunctional.  
**Recommendation:** Either (a) wire `-H` to explicitly select prehashed mode (and consider rejecting `-H` with `-l`), or (b) document that prehashed is default and treat `-H` as an alias with a warning.

---

### 6) Comment in KDF parameter conversion is inconsistent with behavior (LOW)

**Location:** `src/crypto.rs:464-482`  
**Issue:** The comment states “explicit error instead of silent fallback,” but the code derives `r` and returns `Ok(...)` when `opslimit` mismatches.  
**Impact:** Audit confusion; readers expect a hard failure but the function proceeds.  
**Recommendation:** Either change the comment to describe the derived‑`r` path or convert the mismatch into a hard error (with tests) if that was the intended policy.

---

## Staged Remediation Plan

### Stage 1: Correctness and Safety Fixes (Immediate)

1. **Enforce 0600 on secret key overwrite**  
   - Add `set_permissions` after opening secret key files when `force` is true (or always).  
   - Add a unit test or CLI integration test asserting permissions on Unix.
2. **Honor `-q` during multi‑file signing**  
   - Gate `report_file_result` and `print_summary` on `options.quiet()`.  
   - Add a CLI test for `-q` with multiple files.
3. **Fix file size limit guidance**  
   - Update the error message to `--prehashed (-H)`.

### Stage 2: CLI Behavior Alignment (Short‑Term)

1. **Implement `--output` behavior**  
   - Define expected output format and add tests (single‑file + multi‑file).  
   - Ensure `pretty-quiet` and `--output` interactions are explicit.
2. **Clarify `--prehashed` on signing**  
   - Decide whether `-H` is a functional toggle or a documented alias; update CLI docs and tests accordingly.

### Stage 3: Documentation and Audit Clarity (Later)

1. **Resolve KDF conversion comment mismatch**  
   - Align comment with behavior or make mismatch fatal; update related docs/tests.  
2. **Add a small CLI regression suite**  
   - Focus on flags that are easy to regress: `-q`, `-Q`, `-o`, `-H`, `-l`, `-W`.

---

## Summary

The core cryptographic and format handling is solid and defensive. Addressing the small CLI inconsistencies and the secret‑key permission edge case would materially improve user safety and trust without touching cryptographic primitives. The staged plan above keeps changes low‑risk and testable.
