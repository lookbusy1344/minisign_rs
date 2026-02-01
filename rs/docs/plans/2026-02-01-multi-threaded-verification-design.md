# Multi-threaded Signature Verification

**Date:** 2026-02-01
**Status:** Design approved, ready for implementation

## Overview

Add parallel signature verification to match the existing multi-threaded signing capability. This allows users to verify multiple files efficiently using the same CLI pattern as signing: `-V -m file1 file2 file3 --sequential`.

## Use Case

Verify multiple signature files in parallel, where each message file has its own `.minisig` signature file. All files are verified against a single public key.

## Architecture

Mirror the existing `sign_multiple_files` pattern:

- **Load once, verify many**: Load the public key once, reuse it across all verifications
- **Parallel by default**: Use Rayon's `par_iter()` for concurrent verification
- **Continue on failure**: Verify all files, collect results, report summary
- **CLI compatibility**: Same pattern as signing (`-V -m file1 file2 file3 --sequential`)

## Implementation Components

### 1. Core Function (`ops/verify.rs`)

Add `verify_multiple_files()` function:

```rust
pub fn verify_multiple_files(
    files: Vec<PathBuf>,
    options: &VerifyOptions<'_>,
    sequential: bool,
) -> Result<()>
```

**Behavior:**
- Takes vector of message files to verify
- Loads public key once (avoid N-1 redundant I/O operations)
- For each file, discovers signature at `{file}.minisig`
- Verifies in parallel using Rayon (unless `sequential=true`)
- Returns `Error::PartialFailure` if any verifications failed

**Fast path optimization:** Single file continues to use existing `verify()` function directly.

### 2. Result Types

Add new result type matching `FileSignResult`:

```rust
pub struct FileVerifyResult {
    pub file: PathBuf,
    pub result: Result<VerifyResult>,
}
```

Stores per-file verification outcome for batch processing.

### 3. Signature File Discovery

For each message file in the batch, automatically locate signature at `{message_file}.minisig`. This matches signing behavior where signatures are written to `{message_file}.minisig`.

**Limitation:** The explicit `-x` signature file option only works for single-file verification (same constraint as signing). Batch operations require the `.minisig` naming convention.

### 4. Output Format

**Per-file output (success):**
```
Verified: file1
  Trusted comment: timestamp:1738454123
  Key ID: ABCD1234... (alpha-bravo-charlie-delta...)
```

**Per-file output (failure):**
```
Failed: file2 (Invalid signature)
```

**Summary:**
```
Summary: 2 verified, 1 failed
Failed files:
  - file2: Invalid signature
```

The `-q` and `-Q` flags affect per-file output verbosity, same as single-file verification.

### 5. CLI Integration

Modify verification handler in `main.rs`:

- Detect when multiple files are provided via `all_message_files()`
- Call `verify_multiple_files()` for batch operations
- Call `verify()` for single-file operations (fast path)
- Pass `cli.sequential` flag to control parallel vs sequential execution

The CLI already supports multiple files through `all_message_files()` which merges `-m` and positional arguments.

### 6. Public Key Handling

All files verified against a single public key specified via `-p` (file) or `-P` (base64). This is the simplest approach and mirrors signing behavior (single secret key signs all files).

Each file can still have been signed by different keys historically - the verification will succeed or fail based on whether the provided public key matches the signature's keynum.

## Error Handling

Use "continue on failure" semantics (matching signing):

- All files processed regardless of individual failures
- Per-file errors reported immediately via stderr
- Final summary shows aggregate results
- Returns `Error::PartialFailure` if any verifications failed (non-zero exit code)

This allows users to see all failures at once rather than fixing them iteratively.

## Testing Strategy

### Unit Tests
- Test `verify_multiple_files()` with 2-3 files
- Success case: all files verify correctly
- Mixed case: some files succeed, some fail
- Failure case: all files fail
- Test with different key mismatches

### Integration Tests
- Parallel safety: verify no race conditions with concurrent file I/O
- Sequential flag: test `--sequential` disables parallelism
- CLI integration: test `-V -m file1 file2 file3` parsing
- Compatibility: ensure single-file verification unchanged

### Performance Tests
- Benchmark parallel vs sequential for N files (N=5, 10, 50)
- Test with various file sizes (small, medium, large)
- Profile to confirm Rayon overhead acceptable for typical workloads

## Performance Characteristics

### Expected Benefits
- **Best case**: Large files with fast signatures benefit most (I/O bound operations overlap)
- **I/O bound**: Prehashed mode with streaming benefits from parallel file reads
- **CPU bound**: Ed25519 verification is fast (~60k/sec), but Rayon parallelism still helps

### Limitations
- **Diminishing returns**: Very small files may see minimal speedup due to thread scheduling overhead
- **Memory usage**: Parallel mode loads multiple files simultaneously (acceptable for typical workloads)

## Signature Algorithm Consideration

Ed25519 verification is fast (~60,000 verifications/second on modern hardware). The parallelism mainly benefits I/O-bound scenarios:

- Reading large files (especially in prehashed mode with streaming)
- Multiple concurrent file operations
- Network-mounted filesystems where I/O latency is high

For small files, speedup will be modest, but the ergonomics improvement (batch CLI) is valuable regardless.

## Dependencies

**Rayon** - Already a dependency (used for signing), reuse for verification parallelism.

## Migration Path

**Backwards compatibility:** Single-file verification behavior unchanged. New batch capability is purely additive.

**CLI compatibility:** Matches existing signing CLI pattern exactly (`-V -m file1 file2 file3 --sequential`).

## Future Enhancements (Out of Scope)

- Multiple public keys with automatic key matching by keynum
- Key discovery from `.minisig.pub` companion files
- Configurable fail-fast vs continue-on-failure modes
- Progress indicators for large batch operations

## Summary

This design adds parallel signature verification by mirroring the successful `sign_multiple_files` architecture. Key decisions:

1. **Single public key** for all files (simplest, matches signing)
2. **Continue on failure** error handling (matches signing)
3. **Full per-file output** plus summary (each file may have different key ID)
4. **Rayon parallelism** by default, `--sequential` flag to disable
5. **Automatic signature discovery** at `{file}.minisig` (matches signing)

Implementation follows established patterns, reuses existing infrastructure (Rayon, error handling, CLI parsing), and maintains full backwards compatibility.
