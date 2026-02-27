# minisign-rs Fresh Code Review & Remediation Plan

**Date:** 2026-02-27  
**Scope:** `rs/` Rust implementation (`src/`, tests, and developer docs)  
**Reviewer:** Codex (fresh-pass static and behavioral review)

---

## Executive Summary

The codebase is generally strong (clean clippy pedantic run, formatting check, and full no-default-features test suite including ignored tests all passed), but this review found one confirmed high-severity correctness issue and several policy/process drifts that increase future security and maintenance risk.

The highest-priority issue is in key generation overwrite flow: when public-key write fails, the secret key can be removed, causing key material loss. This is reproducible now and should be fixed first.

---

## Review Method

1. Read project constraints from `rs/CLAUDE.md` and implementation docs.
2. Ran repository checks:
   - `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
   - `cargo fmt -- --check`
   - `cargo test --no-default-features`
   - `cargo test --no-default-features -- --ignored`
3. Reviewed core operation paths (`ops/generate.rs`, `ops/file_utils.rs`, `main.rs`, CLI/options models, key handling).
4. Reproduced suspected key-loss path with a forced generate command targeting an invalid public-key destination.

---

## Findings

| ID | Severity | Area | Summary |
|---|---|---|---|
| CR-1 | **High** | `src/ops/generate.rs` | Forced key generation can delete secret key when public-key write fails. |
| CR-2 | **Medium** | `src/ops/file_utils.rs` | Production `unsafe` block exists despite project-level “zero unsafe” requirement and docs claim. |
| CR-3 | **Medium** | `src/cli.rs`, `src/ops/{generate,change}.rs` | Multiple `#[allow(clippy::struct_excessive_bools)]` suppressions conflict with project guidance and hide complexity debt. |
| CR-4 | **Low** | `docs/DEVELOPMENT.md` | Dependency section is stale (`clap`, `git-version`) and no longer matches `Cargo.toml` (`pico-args`, no `git-version`). |
| CR-5 | **Medium (Coverage Gap)** | `tests/unit/ops/generate.rs` | Missing regression tests for force-overwrite partial-failure rollback/preservation behavior. |

---

## Detailed Findings and Remediation

### CR-1 — Forced generate can remove secret key on partial failure (High)

**Evidence**
- Code path in `src/ops/generate.rs` writes secret key first, then on public key write failure runs:
  - `let _ = std::fs::remove_file(options.secret_key_file);`
- Reproduction (executed during this review): forced generate with `-p` pointing to a directory failed and left the directory without `secret.key`.

**Impact**
- Key loss / availability failure in an operation that is expected to be recoverable.
- In force mode this can destroy the only copy of a secret key if the destination path is misconfigured or temporarily invalid.

**Remediation Plan**
1. Replace current best-effort delete logic with transactional behavior for force flow.
2. Preferred implementation:
   - Stage new secret/public key files to temp siblings.
   - `fsync` temps.
   - Commit with rename sequence.
   - On any failure, keep existing files unchanged.
3. If full dual-file transaction is too invasive, implement immediate safety patch:
   - never delete secret key in force mode;
   - return explicit partial-failure error with actionable recovery guidance.
4. Add structured error context so users know whether secret key changed, stayed unchanged, or needs manual recreate.

**Validation**
- New regression tests for:
  - force=true + invalid public destination => pre-existing secret key preserved;
  - force=false + public write failure => cleanup semantics explicitly asserted;
  - no accidental secret key deletion in any error branch.

---

### CR-2 — Unsafe usage violates project safety contract (Medium)

**Evidence**
- `src/ops/file_utils.rs` contains `unsafe { libc::fchmod(...) }`.
- `rs/CLAUDE.md` and README state zero-unsafe policy/claims.

**Impact**
- Policy drift weakens trust in project guarantees and security narrative.
- Future contributors may assume `unsafe` is acceptable and expand it.

**Remediation Plan**
1. Replace raw `libc::fchmod` with a safe wrapper crate API (`rustix`/`nix`) to preserve TOCTOU protections without local unsafe.
2. Add a CI guard that fails if `unsafe` appears under `src/` (except explicit, documented allowlist if absolutely necessary).
3. If zero-unsafe cannot be maintained, update policy/docs immediately and justify exception with threat model and invariants.

**Validation**
- `rg "unsafe" src/` returns zero results.
- Clippy/test suite pass unchanged.

---

### CR-3 — Clippy suppression for bool-heavy structs hides design debt (Medium)

**Evidence**
- `#[allow(clippy::struct_excessive_bools)]` present in:
  - `src/cli.rs`
  - `src/ops/change.rs`
  - `src/ops/generate.rs`
- Project guidance in `rs/CLAUDE.md` explicitly discourages this suppression and prefers builders/typed options.

**Impact**
- Increased invalid-state combinations and readability cost.
- Harder to reason about action-specific flags and future extension safety.

**Remediation Plan**
1. Refactor large boolean groups into typed enums/newtypes:
   - action mode enum,
   - password mode enum,
   - overwrite policy enum,
   - KDF strategy enum.
2. Keep builders, but enforce invariants at build time (or parse-time) so invalid combinations are unrepresentable.
3. Remove suppression attributes after refactor.

**Validation**
- No `struct_excessive_bools` allows remain.
- Existing CLI behavior tests still pass; add explicit invalid-combination tests where needed.

---

### CR-4 — Development docs drift from actual dependency stack (Low)

**Evidence**
- `docs/DEVELOPMENT.md` lists `clap` and `git-version` as key dependencies.
- `Cargo.toml` uses `pico-args` and does not include `git-version`.

**Impact**
- Onboarding friction and incorrect assumptions during review/auditing.
- Security and supply-chain review can target the wrong crates.

**Remediation Plan**
1. Update dependency section in `docs/DEVELOPMENT.md` to match `Cargo.toml` exactly.
2. Add a brief note that dependency truth source is `Cargo.toml`/`Cargo.lock`.
3. Add doc maintenance check item to release checklist.

**Validation**
- Manual doc review against current manifest.

---

### CR-5 — Missing regression tests for partial-failure force semantics (Medium Coverage Gap)

**Evidence**
- `tests/unit/ops/generate.rs` has strong happy-path and existence tests, but no test asserts behavior when secret write succeeds and public write fails in force mode.

**Impact**
- CR-1 class regressions can reappear undetected.

**Remediation Plan**
1. Add targeted unit/integration tests that inject public-key write failure after secret-key write.
2. Assert file preservation/rollback behavior for both `force=true` and `force=false`.
3. Add one CLI-level regression test mirroring real user invocation (`-G -f ...`) with invalid public target path.

**Validation**
- New tests fail on current behavior and pass after fix.

---

## Prioritized Execution Plan

### Phase 1 (Immediate)
1. Implement CR-1 safety fix (or full transactional write path).
2. Add CR-5 regression tests to lock in behavior.
3. Run full quality suite and re-test the manual reproduction scenario.

### Phase 2 (Short-term hardening)
1. Eliminate CR-2 unsafe via safe syscall wrapper.
2. Add CI guard for `unsafe` contract enforcement.

### Phase 3 (Design and maintainability)
1. Address CR-3 boolean-struct refactor incrementally (CLI first, then ops options).
2. Remove clippy suppression attributes.

### Phase 4 (Docs alignment)
1. Apply CR-4 docs correction.

---

## Exit Criteria

Remediation is complete when all are true:

1. No reproducible key-loss path remains for forced generation failures.
2. Regression tests cover force and non-force partial-failure semantics.
3. `src/` contains no undocumented `unsafe` usage.
4. CLI/options model no longer relies on `struct_excessive_bools` suppression.
5. Development docs reflect actual dependencies and current workflow.
