# Clone Optimization Plan

**Date**: 2026-02-02
**Status**: ✅ Complete
**Priority**: Medium (Performance & Memory Efficiency)
**Completed**: 2026-02-02

## Executive Summary

Analysis of the codebase revealed excessive cloning operations, particularly in CLI argument handling and file path management. While the cryptographic hot paths are efficient, the CLI layer performs ~15+ unnecessary heap allocations per invocation. This plan addresses high-impact optimizations while preserving thread safety in parallel operations.

## Problem Statement

### Identified Issues

1. **Option<PathBuf> Clones in main.rs** (15+ occurrences)
   - Pattern: `cli.field.clone().unwrap_or_else(default)`
   - Impact: Unnecessary heap allocations for path buffers
   - Files: main.rs lines 56, 62, 66, 137, 160, 168-169, 197-198, 229, 248, 301, 307, 340, 498, 507

2. **Vec<PathBuf> Clone in cli.rs** (1 occurrence)
   - Location: `all_message_files()` at line 184
   - Impact: Clones entire Vec + all contained PathBufs for N files
   - Affects: Multi-file signing and verification operations

3. **Option<String> Comment Clones** (2 occurrences)
   - Files: generate.rs:163, recreate.rs:72
   - Impact: Minor, but easily avoidable

### Non-Issues (Do Not Change)

- **Parallel iterator clones** (sign.rs:221, verify.rs:289): Required for thread safety
- **Error message to_string()**: In error paths, negligible impact
- **Result to_string()**: Necessary for owned return types

## Goals

1. Eliminate unnecessary heap allocations in CLI argument processing
2. Reduce memory footprint for multi-file operations
3. Maintain zero unsafe code and thread safety
4. Preserve existing API compatibility where reasonable
5. No performance regression in hot paths (cryptographic operations)

## Implementation Plan

### Phase 1: Main.rs Option<PathBuf> Optimization (High Priority)

**Estimated Impact**: ~15 heap allocations eliminated per CLI invocation

#### Step 1.1: Refactor handle_generate()

**Current Pattern** (main.rs:52-86):
```rust
let secret_key_file = cli.secret_key_file.clone()
    .unwrap_or_else(Cli::default_secret_key_path);
```

**Optimized Pattern**:
```rust
let default_sk = Cli::default_secret_key_path();
let secret_key_file = cli.secret_key_file.as_ref()
    .unwrap_or(&default_sk);
```

**Files to Modify**:
- `src/main.rs`: handle_generate() lines 52-122

**Testing**:
- Run existing CLI tests: `cargo test cli_test`
- Test with explicit paths: `minisign_rs -G -s custom.key -p custom.pub`
- Test with default paths: `minisign_rs -G`

#### Step 1.2: Refactor handle_sign()

**Files to Modify**:
- `src/main.rs`: handle_sign() lines 124-212
- Handle both single-file and multi-file code paths

**Testing**:
- Single file: `cargo test -- sign::test_sign_single_file`
- Multi-file: `cargo test -- sign::test_sign_multiple_files`
- Default signature path: `minisign_rs -S -m test.txt`
- Custom signature path: `minisign_rs -S -m test.txt -x custom.sig`

#### Step 1.3: Refactor handle_verify()

**Files to Modify**:
- `src/main.rs`: handle_verify() lines 214-295

**Testing**:
- Single file verification
- Multi-file verification
- Both -p (file) and -P (base64) public key sources

#### Step 1.4: Refactor remaining handlers

**Files to Modify**:
- `src/main.rs`: handle_recreate() lines 297-334
- `src/main.rs`: handle_change() lines 336-382
- `src/main.rs`: handle_inspect() lines 474-553

**Testing**:
- Full test suite: `cargo test`
- CLI integration tests

### Phase 2: cli.rs all_message_files() Optimization (Medium Priority)

**Estimated Impact**: Avoid N PathBuf clones for N-file operations

#### Option A: Return Cow<'_, [PathBuf]> (Recommended)

**Implementation**:
```rust
pub fn all_message_files(&self) -> Cow<'_, [PathBuf]> {
    match &self.message_file {
        Some(first) => {
            let mut files = Vec::with_capacity(1 + self.extra_files.len());
            files.push(first.clone());  // Only one clone now
            files.extend_from_slice(&self.extra_files);
            Cow::Owned(files)
        }
        None => Cow::Borrowed(&self.extra_files),  // No clone
    }
}
```

**Files to Modify**:
- `src/cli.rs`: all_message_files() lines 176-186
- Call sites in main.rs (convert from Vec to slice as needed)

**Testing**:
- Multi-file operations: `cargo test -- test_sign_multiple_files`
- Single file: ensure no regression
- No files: error handling

#### Option B: Accept Current Overhead

**Justification**:
- Clone occurs once at CLI boundary
- Overhead is small compared to cryptographic operations
- Current code is clear and maintainable

**Decision**: Defer to implementation phase based on benchmark results

### Phase 3: Comment Clone Optimization (Low Priority)

**Estimated Impact**: 2 heap allocations per key generation/recreation

**Files to Modify**:
- `src/ops/generate.rs`: Line 163
- `src/ops/recreate.rs`: Line 72

**Pattern Change**:
```rust
// Before
let comment = options.comment.clone()
    .unwrap_or_else(|| format!("minisign public key {keynum_hex}"));

// After
let default_comment = format!("minisign public key {keynum_hex}");
let comment = options.comment.as_deref()
    .unwrap_or(&default_comment);
```

**Testing**:
- `cargo test -- test_generate_with_comment`
- `cargo test -- test_generate_without_comment`
- `cargo test -- test_recreate`

## Testing Strategy

### Pre-Implementation
1. Run full test suite: `cargo test && cargo test -- --ignored`
2. Document baseline performance metrics
3. Create specific test cases for edge cases

### During Implementation
1. TDD approach: Write/update tests before code changes
2. Run clippy after each change: `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
3. Verify no new warnings introduced
4. Test each handler individually before proceeding

### Post-Implementation
1. Full test suite must pass: `cargo test && cargo test -- --ignored`
2. Run compatibility tests: `cargo test -- compatibility`
3. CLI integration tests: `cargo test cli_test`
4. Manual testing of all CLI operations
5. Memory profiling (optional): Verify reduced allocations

### Benchmark Validation
Optional but recommended:
```bash
# Before changes
cargo build --release
hyperfine './target/release/minisign_rs -G -W -f' --warmup 3

# After changes
hyperfine './target/release/minisign_rs -G -W -f' --warmup 3
```

## Success Criteria

1. ✅ All tests pass (fast + slow)
2. ✅ Zero clippy warnings (pedantic mode)
3. ✅ No performance regression in cryptographic operations
4. ✅ Reduced heap allocations in CLI layer (measurable via profiling)
5. ✅ Code remains idiomatic Rust
6. ✅ No unsafe code introduced
7. ✅ Compatibility with C minisign preserved

## Risk Assessment

### Low Risk
- **Scope**: Changes confined to CLI argument processing
- **Hot paths**: Cryptographic operations untouched
- **Tests**: Comprehensive test coverage exists
- **Reversibility**: Easy to revert individual optimizations

### Potential Issues
1. **Lifetime complexity**: Adding references may complicate code
   - Mitigation: Accept some clones if lifetimes become unwieldy

2. **API changes**: Some internal APIs may need signature updates
   - Mitigation: Only internal APIs affected, no public crate API changes

3. **Clippy conflicts**: Reference patterns may trigger new warnings
   - Mitigation: Address or explicitly allow case-by-case

## Implementation Order

1. **Phase 1, Step 1.1**: handle_generate() - Smallest handler, good starting point
2. **Phase 1, Step 1.4**: handle_recreate() and handle_change() - Simple cases
3. **Phase 1, Step 1.2**: handle_sign() - Most complex, multi-file logic
4. **Phase 1, Step 1.3**: handle_verify() - Similar to sign
5. **Phase 1, Step 1.4**: handle_inspect() - Special cases with base64 keys
6. **Phase 2**: cli.rs optimization (if benchmarks warrant it)
7. **Phase 3**: Comment optimizations (polish)

## Commit Strategy

Follow conventional commit format:

```
perf(cli): eliminate Option<PathBuf> clones in handle_generate
perf(cli): eliminate Option<PathBuf> clones in handle_sign
perf(cli): eliminate Option<PathBuf> clones in handle_verify
perf(cli): optimize all_message_files to use Cow
perf(ops): eliminate comment clones in generate/recreate
```

## Post-Implementation

### Documentation Updates
- Update CLAUDE.md if new patterns emerge
- Add performance notes to README if significant improvement

### Follow-up Opportunities
- Profile real-world usage with `cargo flamegraph`
- Consider String vs &str optimizations in error types (future)
- Evaluate Cow<str> for comments in public API (future)

## Approval

**Reviewers**: Senior engineer approval recommended
**Estimated Effort**: 2-4 hours
**Complexity**: Low-Medium

---

**Next Steps**:
1. Review and approve plan
2. Create branch: `git checkout -b perf/clone-optimization`
3. Implement Phase 1, Step 1.1
4. Run tests and clippy
5. Iterate through remaining phases

---

## ✅ Implementation Complete - 2026-02-02

### Summary

All three phases successfully implemented with 6 focused commits:

1. `3485c2f` - perf(cli): eliminate PathBuf clones in handle_generate
2. `18f1cb6` - perf(cli): eliminate PathBuf clones in handle_recreate and handle_change
3. `1ef92f4` - perf(cli): eliminate PathBuf clones in handle_sign and handle_verify
4. `b670a47` - perf(cli): eliminate PathBuf clones in handle_inspect
5. `ba15406` - perf(cli): optimize all_message_files to use Cow to avoid clones
6. `866a813` - perf(ops): eliminate comment clones in generate and recreate

### Results

**Heap Allocations Eliminated**: 12-15+ per CLI invocation
- Phase 1: ~10 PathBuf allocations (main.rs handlers)
- Phase 2: Vec/PathBuf clones when applicable (cli.rs Cow optimization)
- Phase 3: 2 String allocations (generate/recreate comments)

**Quality Metrics**:
- ✅ All 254 tests pass (249 fast + 5 slow security tests)
- ✅ Zero clippy warnings (pedantic mode)
- ✅ No unsafe code introduced
- ✅ API backward compatible
- ✅ Conventional commit messages

### Verification

```bash
# Tests
cargo test                    # 249 passed
cargo test -- --ignored       # 5 passed (security-critical)

# Code Quality
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic  # 0 warnings
cargo fmt --check             # clean

# Compatibility
cargo test compatibility      # C minisign interop verified
```

### Impact

The optimization successfully reduced memory pressure in the CLI layer while:
- Maintaining identical behavior and API
- Preserving thread safety in parallel operations
- Keeping cryptographic hot paths unchanged
- Following Rust idioms and best practices

**Recommendation**: No further clone optimizations needed at this time. The remaining clones (parallel iterator, error paths, result types) are either necessary for correctness or have negligible performance impact.
