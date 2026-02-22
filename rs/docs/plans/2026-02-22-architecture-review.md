# Architecture Review — 2026-02-22

**Scope:** Full architectural assessment of `rs/src/` (4,011 production lines)
**Baseline commit:** `b918854` (preparing for v1.3.6)
**Branch:** `lb_rust`

---

## Overall Assessment

The codebase is architecturally sound. The design decisions are deliberate and the
security posture is strong: zero unsafe blocks, comprehensive zeroization, constant-time
comparisons throughout, and a 2.6:1 test-to-code ratio. No fundamental restructuring is
warranted.

The outstanding work is in three categories:

1. **Structural consistency** — a few modules don't conform to established conventions
2. **Deduplication** — identified duplications in file_utils, main.rs, and inspect.rs
3. **Test quality** — a comprehensive plan exists but hasn't been executed

Each category references the prior plan that documented it.

---

## Part 1: What Is Working Well

These are architectural strengths that must not regress:

- **Module boundaries are clean.** `crypto.rs`, `keys.rs`, `signature.rs`, and `ops/`
  each have a single, well-defined responsibility. There is no significant coupling leakage.
- **Error handling is comprehensive.** 27 typed error variants, `?`-propagation throughout,
  no silent failures, no `.unwrap()` in production paths.
- **Security fundamentals are solid.** Every C/Zig vulnerability class identified in
  `2026-02-20-c-zig-security-audit.md` is resolved. All 9 Rust-specific findings (RS-1
  through RS-9) are closed.
- **Builder pattern reduces API surface risk.** `SignOptions`, `GenerateOptions`,
  `ChangeOptions` all use the builder pattern, preventing boolean argument confusion.
- **Streaming I/O is implemented.** `blake2b_512_stream` processes files in 8 KB chunks,
  enabling signing of arbitrarily large files.
- **Rayon parallel batch operations.** Multi-file sign/verify are parallelised with a
  `--sequential` escape hatch for constrained environments.

---

## Part 2: Open Items from Prior Plans

These items were identified in prior reviews but are not yet reflected in the current
codebase (verified against the `b918854` baseline). Each has a clear owner plan.

### 2.1 Structural Consistency

**Source:** `2026-02-16-full-code-review.md` (Q1, Q7, L1, L2)

| # | Issue | Location | Impact |
|---|-------|----------|--------|
| A | `VerifyOptions::new()` takes 6 params (3 booleans) without a builder | `ops/verify.rs:33-61` | Violates CLAUDE.md builder policy; inconsistent with all other operation options |
| B | `ChangeResult`, `RecreateResult`, `SignResult`, `VerifyResult` use public fields | `ops/change.rs`, `recreate.rs`, `sign.rs`, `verify.rs` | Inconsistent with `GenerateResult`/`InspectResult` which use private fields + getters |
| C | `cli` module is `pub` in `lib.rs` | `lib.rs:19` | Leaks CLI parsing types into the library API surface; not useful to library consumers |
| D | Deprecated `new()` methods still compiled on `SignOptions`, `GenerateOptions`, `ChangeOptions` | `ops/sign.rs`, `generate.rs`, `change.rs` | Dead code; safe to remove as this is a single-binary project with no external consumers |

**Recommended action:** Address A and B together in one commit; C and D in a second.
Effort: ~2 hours.

### 2.2 Duplication

**Source:** `2026-02-20-code-reduction-plan.md` (Phases 1–3)

The code reduction plan identified ~410–530 lines of removable duplication. The items
below are the highest-value, lowest-risk subset:

| # | Issue | Location | Estimated savings |
|---|-------|----------|-------------------|
| E | `write_secret_key_file`, `write_public_key_file`, `write_signature_file` are near-identical | `ops/file_utils.rs` | ~80 lines |
| F | `inspect_private` duplicates body of `inspect_private_with_key` | `ops/inspect.rs` | ~20 lines |
| G | `recreate()` duplicates body of `recreate_with_key()` | `ops/recreate.rs` | ~15 lines |
| H | Boolean builder guards `if cli.force { builder = builder.force(true) }` appear ~16 times | `main.rs` | ~16 lines |
| I | Credential-store lookup pattern inlined in `handle_recreate`, `handle_change`, `handle_inspect` despite `get_password_with_credential_store` helper existing | `main.rs` | ~25 lines |

Items F, G, H, I are low-risk delegation refactors. Item E is a slightly larger extract
that requires care around the `unix_mode` parameter.

The Options/Builder merger (Phase 1.2, ~130 lines) is the largest item and carries
medium risk. Defer until after the smaller items are done.

**Recommended action:** Tackle G → F → I → H → E in order (ascending risk). Each is
an independent commit. Effort: ~3 hours.

### 2.3 Dependency Hygiene

**Source:** `2026-02-16-full-code-review.md` (D1)

`getrandom` appears in the dependency tree twice (0.2.x via `ed25519-dalek` and 0.3.x
direct). Similarly `rand_core` 0.6 and a newer version co-exist. The fix is to remove
the direct `getrandom` dependency and replace `getrandom::fill()` calls with
`OsRng.fill_bytes()` from the already-imported `rand_core::OsRng`. This eliminates one
direct dependency and one transitive duplicate. Effort: ~20 minutes.

### 2.4 Test Quality

**Source:** `2026-02-21-test-improvement-plan.md`

This plan is comprehensive and entirely unexecuted. The highest-value items are:

| Priority | Item | Why it matters |
|----------|------|----------------|
| P1 | Delete `phase2_h5_only.rs` (exact duplicate of tests in `phase2_security_tests.rs`) | Removes false confidence from duplicated passes |
| P2.1/P2.2 | Fix always-passing KDF overflow tests that accept both Ok and Err | These tests can never fail |
| P2.4 | Fix `test_null_byte_in_path` — operates on wrong variable | Test is structurally broken |
| P3.1 | Replace `require_c_minisign!()` silent-return with `#[ignore]` | CI reports skipped tests as passing |
| P4.2 | Security attack tests T1.4/T1.5 never call `verify()` | Structural assertions without actual rejection verification |
| P6.1 | Add Ed25519 signature malleability test | Known attack class with no current coverage |
| P6.2 | Add small subgroup attack test | Known attack class with no current coverage |

The full plan covers P1–P7. **P1–P4 should be done first** (test honesty); P6 is the
highest-value new coverage addition.

---

## Part 3: New Observations

These are issues not captured in prior plans.

### 3.1 `VerifyResult.valid` Field Is Dead Code

**Source:** `2026-02-16-full-code-review.md` (Q3) — listed but not yet removed.

`VerifyResult` has a `valid: bool` field that is always `true` at construction; a failed
verification returns `Err`, so the field carries no information. Remove it. The `Result`
type already encodes success/failure for all callers.

### 3.2 Three Dead Error Variants

**Source:** `2026-02-16-full-code-review.md` (Q5) — listed but not yet removed.

`UnsupportedSigAlg`, `UnsupportedKdfAlg`, `UnsupportedChkAlg` are defined in `errors.rs`
but never constructed in production code. The current code handles unknown algorithm bytes
via `InvalidSecretKey`/`InvalidSignatureFormat`. Remove the three dead variants.

### 3.3 `handle_sign` Suppresses a Valid Clippy Warning

**Source:** `2026-02-16-full-code-review.md` (Q6) — listed but not yet addressed.

`#[allow(clippy::too_many_lines)]` at `main.rs:218` suppresses a lint on a 136-line
function. The two branches (single-file vs multi-file) are already logically separable.
Extract into `handle_sign_single` and `handle_sign_multiple` and remove the allow.

### 3.4 Stream Buffer Size Is Conservative

`blake2b_512_stream` in `crypto.rs` uses an 8 KB buffer. This is well below what modern
systems benefit from for sequential file I/O — Linux and macOS read-ahead works best with
multiples of 64 KB–128 KB. For minisign's use case (signing large release artefacts),
increasing this to 64 KB would reduce syscall count and improve throughput with negligible
memory cost. This is a performance tuning item, not a correctness issue.

Named constant: rename `STREAM_BUFFER_SIZE` from `8192` to `65536`.

**Effort:** 5 minutes. Verify with `hyperfine` on a large file.

### 3.5 `InspectPrivateOptions` Is Structurally Identical to `InspectOptions`

**Source:** `2026-02-20-code-reduction-plan.md` (2.3) — listed but not yet removed.

Both structs wrap a single `&Path`. Delete `InspectPrivateOptions` and update
`inspect_private` / `inspect_private_with_key` to accept `&InspectOptions` or `&Path`
directly. Update callers in `main.rs`. Effort: ~20 minutes.

### 3.6 `DecryptionFailed` Error Variant Is Unreachable

**Source:** `2026-02-20-code-reduction-plan.md` (2.1) — listed but not yet removed.

`Error::DecryptionFailed` is defined but never constructed; the wrong-password path uses
`Error::ChecksumFailed`. Remove it. Effort: 5 minutes.

---

## Part 4: Prioritised Implementation Roadmap

Ordered by impact/effort ratio. Each item should be a separate commit following the
pre-commit checklist (`clippy` → `fmt` → `test`).

### Phase 1: Dead Code Removal (Low risk, ~1 hour)

1. Remove `VerifyResult.valid` (Section 3.1 / Q3)
2. Remove `UnsupportedSigAlg`, `UnsupportedKdfAlg`, `UnsupportedChkAlg` (Section 3.2 / Q5)
3. Remove `DecryptionFailed` (Section 3.6 / plan 2.1)
4. Remove `InspectPrivateOptions` (Section 3.5 / plan 2.3)
5. Remove deprecated `new()` methods from Sign/Generate/ChangeOptions (Section 2.1 D)
6. Remove `read_u16_le` / `write_u16_le` from `formats.rs` (plan 2.2)

### Phase 2: Consistency (Medium risk, ~2 hours)

7. Add builder to `VerifyOptions` (Section 2.1 A)
8. Make `ChangeResult`, `RecreateResult`, `SignResult`, `VerifyResult` fields private + add getters (Section 2.1 B)
9. Make `cli` module `pub(crate)` in `lib.rs` (Section 2.1 C)
10. Fix dependency duplicate: replace `getrandom::fill()` with `OsRng.fill_bytes()` (Section 2.3)

### Phase 3: Deduplication (Medium risk, ~3 hours)

11. Delegate `recreate()` → `recreate_with_key()` (Section 2.2 G)
12. Delegate `inspect_private()` → `inspect_private_with_key()` (Section 2.2 F)
13. Route `handle_recreate`, `handle_change`, `handle_inspect` through `get_password_with_credential_store` (Section 2.2 I)
14. Simplify boolean builder guards in `main.rs` (Section 2.2 H)
15. Unify `write_secret_key_file` / `write_public_key_file` / `write_signature_file` (Section 2.2 E)
16. Extract `handle_sign_single` / `handle_sign_multiple`, remove `#[allow]` (Section 3.3)

### Phase 4: Test Quality (Medium risk, ~4 hours)

17. Execute `2026-02-21-test-improvement-plan.md` in priority order: P1 → P2 → P3 → P4 → P6
    - P6.1 (Ed25519 malleability) and P6.2 (small subgroup) are new security coverage; treat as highest priority within P6

### Phase 5: Performance Tuning (Low risk, ~30 minutes)

18. Increase `STREAM_BUFFER_SIZE` from 8 KB to 64 KB; benchmark with `hyperfine` (Section 3.4)
19. Options/Builder merger (plan Phase 1.2, ~130 lines) — do last, highest churn

---

## Metrics After Completion

Based on estimates from the code reduction plan:

| Metric | Current | Expected after Phase 1–3 |
|--------|---------|--------------------------|
| Production code lines | ~4,011 | ~3,600–3,700 |
| Dead error variants | 4+ | 0 |
| `#[allow(clippy::...)]` suppressions | 3+ | 1 (struct_excessive_bools, justified) |
| Deprecated public methods | 3 | 0 |
| Duplicate dependency trees | 2 | 1 |

---

## What Is Explicitly Out of Scope

- **`wordlist.rs`** — 256-entry lookup tables. Cannot be meaningfully reduced without code
  generation that would harm readability.
- **`crypto.rs`** — security-critical. No reduction attempts.
- **`keys.rs`** — binary serialization with cryptographic invariants. Changes require extreme care.
- **Test deletion** — no tests should be removed unless they are exact duplicates (P1) or
  demonstrably broken in a way that produces false confidence (P2).
- **New features** — this plan is strictly maintenance and cleanup.
