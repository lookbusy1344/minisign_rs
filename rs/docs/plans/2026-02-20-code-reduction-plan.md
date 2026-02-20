# Code Reduction Plan — Target ~10% of src/ Lines

**Date:** 2026-02-20
**Branch:** `lb_rust`
**Baseline:** 5,304 lines (tokei), 4,226 code lines
**Target reduction:** ~530 lines (~10%)

## Methodology

Only source code (`src/`) is in scope. Test code is excluded — tests should not be deleted or simplified. Each item includes estimated line savings (code lines, not total) and risk level.

---

## Phase 1: Structural Deduplication (~200–240 lines)

### 1.1 Unify file-write functions (~80 lines saved) — LOW RISK

**Files:** `src/ops/file_utils.rs`, `src/ops/sign.rs`

`write_secret_key_file`, `write_public_key_file`, and `write_signature_file` are near-identical. The only difference is that `write_secret_key_file` sets Unix 0600 permissions. All three:
- Validate Windows path
- Build `OpenOptions` with force/create_new logic
- Map `AlreadyExists` to `Error::FileExists`
- `write_all` + `sync_all`

**Action:** Extract a single `write_file(path, contents, force, unix_mode: Option<u32>)` in `file_utils.rs`. Replace all three functions with thin wrappers (or inline calls). Delete `write_signature_file` from `sign.rs`.

### 1.2 Collapse Options/Builder duplication (~130 lines saved) — MEDIUM RISK

**Files:** `src/ops/sign.rs`, `src/ops/verify.rs`, `src/ops/generate.rs`, `src/ops/change.rs`

Each module declares an `XxxOptions` struct and an `XxxOptionsBuilder` struct with identical fields. The builder's `build()` method copies every field into the options struct. The options struct then re-declares getters.

**Action:** For each pair, merge into a single struct that implements `Default` where possible, and make the builder *be* the options struct. The pattern:
- Struct with private fields + `new()` for required params, setter methods returning `Self`
- Remove the separate `Builder` struct entirely
- The `build()` method becomes unnecessary — callers chain setters directly on the options struct

Estimated per-module: SignOptions (~40), VerifyOptions (~30), GenerateOptions (~35), ChangeOptions (~25).

### 1.3 Deduplicate `recreate` / `recreate_with_key` (~15 lines saved) — LOW RISK

**File:** `src/ops/recreate.rs`

`recreate()` (lines 116–143) duplicates the body of `recreate_with_key()` (lines 166–194). The only added step is `load_secret_key`.

**Action:** `recreate()` should load the key and delegate to `recreate_with_key()`.

---

## Phase 2: Eliminate Dead Code & Wrappers (~30–40 lines)

### 2.1 Remove `DecryptionFailed` error variant (~3 lines saved) — LOW RISK

**File:** `src/errors.rs`

`Error::DecryptionFailed` is defined but never constructed. The wrong-password path uses `Error::ChecksumFailed`.

**Action:** Remove the variant. If a more descriptive name is desired, rename `ChecksumFailed` to `DecryptionFailed` in a separate commit (touching callers).

### 2.2 Remove `read_u16_le` / `write_u16_le` (~20 lines saved) — LOW RISK

**File:** `src/formats.rs`

Neither function has production callers — only test code exercises them. They were added speculatively.

**Action:** Remove both functions from `src/formats.rs`. Update or remove corresponding tests.

### 2.3 Remove `InspectPrivateOptions` (~20 lines saved) — LOW RISK

**File:** `src/ops/inspect.rs`

`InspectPrivateOptions` is structurally identical to `InspectOptions` (both wrap a single `&Path`). There is no reason to have two types.

**Action:** Delete `InspectPrivateOptions`. Change `inspect_private` and `inspect_private_with_key` to accept `&InspectOptions` or just `&Path` directly. Update callers in `main.rs`.

---

## Phase 3: Reduce Boilerplate in main.rs (~80–100 lines)

### 3.1 Deduplicate credential-store password lookup (~25 lines saved) — LOW RISK

**File:** `src/main.rs`

The pattern "check credential store → fall back to prompt" is inlined in `handle_recreate` (lines 507–519), `handle_change` (lines 570–583), and `handle_inspect` (lines 814–823). The helper `get_password_with_credential_store` already exists (line 172) but is only called once.

**Action:** Route all three through `get_password_with_credential_store`.

### 3.2 Deduplicate credential-store save block in `handle_change` (~12 lines saved) — LOW RISK

**File:** `src/main.rs`

`handle_change` (lines 629–644) re-implements the save-password match block instead of calling `save_password_to_credential_store`.

**Action:** Replace with a call to `save_password_to_credential_store`.

### 3.3 Deduplicate `SignOptions` builder block (~12 lines saved) — LOW RISK

**File:** `src/main.rs`

`handle_sign_single` (lines 307–318) and `handle_sign_multiple` (lines 362–373) contain identical builder conditionals for trusted_comment, untrusted_comment, force, quiet.

**Action:** Extract `fn apply_sign_options(builder: SignOptionsBuilder, cli: &Cli) -> SignOptionsBuilder`. Or, after Phase 1.2, pass booleans unconditionally: `.force(cli.force).quiet(cli.quiet)` — no guard needed since `false` is the default.

### 3.4 Simplify boolean builder guards (~16 lines saved) — LOW RISK

**File:** `src/main.rs`

The pattern `if cli.force { builder = builder.force(true); }` appears ~16 times. Since `.force(false)` is a no-op (matches default), this can always be written unconditionally as `.force(cli.force)`.

**Action:** Replace all guarded boolean setters with unconditional calls.

---

## Phase 4: Reduce Verbose Doc Comments (~80–100 lines)

### 4.1 Trim redundant doc blocks — LOW RISK

**Files:** Multiple across `src/`

Many getter methods have 5–8 line doc comments for single-line functions like `pub const fn force(&self) -> bool`. The `#[must_use]` attribute and the method name are self-documenting.

**Action:** Reduce trivial getter docs to a single `///` line or remove entirely where the method name is unambiguous. Keep doc comments on public API entry points (`sign`, `verify`, `generate`, etc.) and anything with non-obvious semantics.

Similarly, builder setter docs like "Set the trusted comment" on `fn trusted_comment(...)` add no information.

Estimated: ~80–100 lines of doc comments can be removed from getter/setter boilerplate without losing any meaningful documentation.

---

## Summary

| Phase | Description | Est. Savings | Risk |
|-------|-------------|-------------|------|
| 1.1 | Unify file-write functions | ~80 lines | Low |
| 1.2 | Collapse Options/Builder pairs | ~130 lines | Medium |
| 1.3 | Deduplicate recreate functions | ~15 lines | Low |
| 2.1 | Remove dead `DecryptionFailed` | ~3 lines | Low |
| 2.2 | Remove unused `u16_le` functions | ~20 lines | Low |
| 2.3 | Remove duplicate `InspectPrivateOptions` | ~20 lines | Low |
| 3.1 | Deduplicate credential-store lookups | ~25 lines | Low |
| 3.2 | Deduplicate credential-store save | ~12 lines | Low |
| 3.3 | Extract sign options builder helper | ~12 lines | Low |
| 3.4 | Simplify boolean builder guards | ~16 lines | Low |
| 4.1 | Trim redundant doc comments | ~80 lines | Low |
| **Total** | | **~410–530 lines** | |

Against the 5,304-line baseline, this represents an **8–10% reduction**.

---

## Execution Order

1. **Phase 2 first** (dead code removal) — zero behavioral change, simple to verify
2. **Phase 3** (main.rs deduplication) — consolidates existing helpers
3. **Phase 1.1** (file-write unification) — moderate refactor, clear pattern
4. **Phase 4** (doc trimming) — cosmetic, no behavior change
5. **Phase 1.2 last** (Options/Builder merge) — largest refactor, most test updates needed
6. **Phase 1.3** (recreate dedup) — small, can slot in anywhere

Each phase should be a separate commit. Run the full pre-commit checklist after each:
```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
cargo test --no-default-features
cargo test --no-default-features -- --ignored
```

## Items Explicitly NOT in Scope

- **Test code** — not to be reduced or simplified
- **`wordlist.rs`** — 536 code lines, but it's a static lookup table (PGP Word List). Cannot be meaningfully reduced without code generation or `include!()` which would hurt readability.
- **`crypto.rs`** — security-critical pure implementations. No reduction should be attempted.
- **`keys.rs`** — binary serialization with crypto invariants. Tread carefully.
- **Adding new dependencies** (e.g., `derive_builder`) — the project favors minimal deps. Phase 1.2 uses manual consolidation only.
