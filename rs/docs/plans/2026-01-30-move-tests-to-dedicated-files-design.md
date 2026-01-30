# Design: Move Inline Tests to Dedicated Test Files

**Date:** 2026-01-30
**Status:** Approved
**Author:** Design collaboration (Claude Code + User)

## Primary Motivation

CodeQL flags 25+ alerts for hardcoded test passwords/salts in `#[cfg(test)]` modules within source files. CodeQL cannot distinguish `#[cfg(test)]` blocks from production code, treating all code in `rs/src/**` equally.

Moving tests to dedicated files in `rs/tests/unit/**` will allow our existing CodeQL configuration to automatically suppress these false positives without requiring blanket query suppressions that could hide real security issues.

## Secondary Benefits

- Cleaner source files (no test code mixed with production)
- Faster compilation in release mode (tests not compiled into source)
- Standard Rust project structure
- Easier code review (tests separated from implementation)
- Better alignment with Rust community conventions

## Current State

- **14 source files** with inline `#[cfg(test)]` modules
- **213 unit tests** across these modules
- **~4,534 lines** of test code
- CodeQL alerts in: `crypto.rs`, `keys.rs`, `ops/inspect.rs`, `ops/sign.rs`, `ops/recreate.rs`, and others

## File Structure & Organization

Create new `rs/tests/unit/` directory to hold extracted unit tests, mirroring the source structure:

```
rs/tests/
├── unit/                    # NEW: Unit tests extracted from src/
│   ├── crypto.rs           # From src/crypto.rs #[cfg(test)]
│   ├── keys.rs             # From src/keys.rs #[cfg(test)]
│   ├── signature.rs        # From src/signature.rs #[cfg(test)]
│   ├── validation.rs       # From src/validation.rs #[cfg(test)]
│   ├── formats.rs          # From src/formats.rs #[cfg(test)]
│   ├── errors.rs           # From src/errors.rs #[cfg(test)]
│   ├── constants.rs        # From src/constants.rs #[cfg(test)]
│   ├── cli.rs              # From src/cli.rs #[cfg(test)]
│   └── ops/                # NEW: Operations unit tests
│       ├── generate.rs     # From src/ops/generate.rs #[cfg(test)]
│       ├── sign.rs         # From src/ops/sign.rs #[cfg(test)]
│       ├── verify.rs       # From src/ops/verify.rs #[cfg(test)]
│       ├── change.rs       # From src/ops/change.rs #[cfg(test)]
│       ├── recreate.rs     # From src/ops/recreate.rs #[cfg(test)]
│       └── inspect.rs      # From src/ops/inspect.rs #[cfg(test)]
├── cli_test.rs             # Existing integration tests
├── compatibility.rs        # Existing integration tests
└── ...                     # Other existing integration tests
```

Each unit test file will import from the main crate using `use minisign_rs::*;` instead of `use super::*;`.

## Migration Phases

### Phase 1: Core Cryptography (3 files, ~1,314 lines) ✅ COMPLETED

- ✅ `crypto.rs` - 17 tests, ~272 lines (derive_key, blake2b, signing primitives)
- ✅ `keys.rs` - 37 tests, ~790 lines (key encryption, parsing, serialization)
- ✅ `signature.rs` - 15 tests, ~252 lines (signature parsing, validation)

**Rationale:** These are the foundation - all other modules depend on them. Moving these first ensures crypto correctness is maintained.

**Completion Notes:**
- All 69 unit tests (17+37+15) successfully moved to `tests/unit/`
- Made necessary items `pub` for external testing (fields, methods)
- All tests passing (66 passed, 3 ignored slow tests)
- Zero clippy warnings
- Completed commits: 774d507, d582c5d, 107ba8a

### Phase 2: Operations (6 files, ~2,356 lines)

- `ops/generate.rs` - 19 tests, ~485 lines
- `ops/sign.rs` - 22 tests, ~631 lines
- `ops/verify.rs` - 7 tests, ~108 lines
- `ops/change.rs` - 8 tests, ~353 lines
- `ops/recreate.rs` - 12 tests, ~356 lines
- `ops/inspect.rs` - 15 tests, ~423 lines

**Rationale:** High-level operations that use the core modules. Moving second ensures we catch integration issues.

### Phase 3: Utilities & CLI (5 files, ~864 lines)

- `validation.rs` - 29 tests, ~266 lines
- `formats.rs` - 11 tests, ~164 lines
- `cli.rs` - 10 tests, ~263 lines
- `errors.rs` - 3 tests, ~42 lines
- `constants.rs` - 8 tests, ~129 lines

**Rationale:** Supporting utilities and CLI parsing. Moving last as they're least likely to have issues.

## Per-File Migration Process

For each source file being migrated, follow these steps:

### 1. Extract test module

- Copy entire `#[cfg(test)] mod tests { ... }` block from source file
- Create corresponding file in `rs/tests/unit/` (or `rs/tests/unit/ops/`)
- Remove the `#[cfg(test)]` wrapper and `mod tests {` - tests are standalone now
- Change `use super::*;` to `use minisign_rs::module_name::*;`

### 2. Make private items accessible

- Identify which private items the tests access
- Change visibility from private to `pub(crate)` in the source file
- Add comment: `// pub(crate) for unit tests`

**Rationale:** This preserves comprehensive test coverage (213 unit tests) while keeping items private to external users. The project emphasizes "ZERO clippy warnings" and comprehensive testing, and security-critical crypto code benefits from thorough internal testing.

### 3. Remove original test module

- Delete the entire `#[cfg(test)] mod tests { ... }` block from source file
- Clean up any unused test-only imports

### 4. Verify

- Run `cargo test` to ensure all tests still pass
- Run `cargo clippy` to ensure no new warnings
- Verify test count matches (148 fast tests should remain 148)

### 5. Update documentation

- The test module's doc comments move with the tests
- Ensure any module-level test documentation is preserved

## Handling Edge Cases & Challenges

### Challenge 1: Test-only helper functions

Some `#[cfg(test)]` modules contain helper functions used by multiple tests.

**Solution:**
- Move helpers to the new test file along with the tests
- Keep them as regular functions (not `#[test]`)
- If helpers are used across multiple test files, create `rs/tests/unit/test_helpers.rs`

### Challenge 2: Test constants and fixtures

Tests often define constants like `TEST_LOG_N = 14` for reduced scrypt parameters.

**Solution:**
- Move test constants to the new test file
- If shared across files, put in `rs/tests/unit/test_helpers.rs`
- Existing `rs/tests/fixtures/` directory can continue to be used

### Challenge 3: Conditional compilation attributes

Some tests use `#[ignore]` for slow tests, or platform-specific `#[cfg(...)]`.

**Solution:**
- Preserve all attributes when moving tests
- Keep the same test organization (fast vs slow tests marked with `#[ignore]`)

### Challenge 4: Module path changes in error messages

When tests move, panic messages or assertion failures may show different paths.

**Solution:**
- Acceptable - test failures will now show `tests::unit::crypto::test_name` instead of `crypto::tests::test_name`
- Update any hardcoded path expectations if they exist

## Verification & Testing Strategy

**After each phase, run this verification checklist:**

### 1. Test Suite Integrity

```bash
cargo test                    # Fast tests (~9s, should still be 148 tests)
cargo test -- --ignored       # Slow tests (~16s, should still be 11 tests)
```

Total should remain 159 tests (or current total of 213+ if counting all unit tests)

### 2. Code Quality

```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt                     # Format code automatically
```

Must pass with ZERO warnings per CLAUDE.md

### 3. Build Verification

```bash
cargo build --release
cargo build                   # Debug build
```

### 4. Git Status

```bash
git diff --stat               # Review scope of changes
git status                    # Ensure no untracked test files
```

### Success Criteria

- All tests pass in same time as before
- Zero clippy warnings
- Test count unchanged
- No compilation errors
- CodeQL will suppress alerts in `rs/tests/unit/**` automatically

## CodeQL Integration & Benefits

### Current CodeQL Configuration

Our existing CodeQL configuration already excludes:

```yaml
paths-ignore:
  - rs/tests/**
  - rs/target/**
```

And has query filters:

```yaml
query-filters:
  - exclude:
      id: rust/hard-coded-cryptographic-value
      paths:
        - rs/tests/**
```

### How This Migration Fixes CodeQL Alerts

Once tests are in `rs/tests/unit/**`, they'll be automatically suppressed - **no config changes needed!**

### Expected Results

- All 25 `rust/hard-coded-cryptographic-value` alerts in source files → ✅ Suppressed
- 4 existing alerts in `rs/tests/edge_cases.rs` → ✅ Already suppressed
- 6 `rust/cleartext-logging` false positives in `main.rs` → ✅ Already suppressed with inline comments

**Post-Migration Alert Count: 0 open alerts**

## Implementation Commits

Each phase should be a single commit:

1. `refactor(tests): move Phase 1 core crypto tests to dedicated files`
2. `refactor(tests): move Phase 2 operations tests to dedicated files`
3. `refactor(tests): move Phase 3 utilities tests to dedicated files`

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Tests fail after move | High | Run full test suite after each file, revert if issues |
| Clippy warnings introduced | Medium | Run clippy after each phase, fix before continuing |
| Breaking `pub(crate)` changes | Low | Items already used internally, just changing visibility |
| Test execution time increases | Low | Integration tests are already external, no change expected |
| Forgotten test helpers | Medium | Careful review of each test module before deleting |

## Success Metrics

- ✅ All 213 unit tests moved successfully
- ✅ Zero CodeQL alerts remaining
- ✅ Zero clippy warnings
- ✅ No test failures
- ✅ Clean separation of test and production code
- ✅ Maintainable mirror structure for easy navigation
