# Multi-File Signing with Parallel Execution Design

**Date:** 2026-01-31
**Status:** Approved

## Overview

Add support for signing multiple files in a single command with parallel execution by default. This brings feature parity with C minisign's `file [file ...]` syntax while adding modern parallelization for improved performance.

## Goals

- Sign multiple files in one command invocation
- Parallel execution by default (scales to CPU core count)
- Fail gracefully with partial success reporting
- Backwards compatible with single-file usage
- Optional sequential mode for edge cases

## CLI Changes

### Current (Single File)
```rust
message_file: Option<PathBuf>
```

### New (Multiple Files)
```rust
message_files: Vec<PathBuf>
```

### New Flag
- `--sequential` (long-form only, `-S` conflicts with sign flag)
  - Forces single-threaded execution
  - Use cases: huge files, embedded systems, debugging
  - Default: parallel execution enabled

### Example Usage

```bash
# Sign multiple files (parallel by default)
minisign_rs -S -m file1.txt file2.bin release.tar.gz

# Force sequential processing
minisign_rs -S -m file1.txt file2.txt --sequential

# Single file still works (backwards compatible)
minisign_rs -S -m file.txt
```

### Backwards Compatibility
- Single file usage unchanged
- All existing flags work the same
- Output format preserved for single files

## Implementation Approach

### Parallel Execution Strategy

Use Rayon's parallel iterator to process files concurrently:

```rust
use rayon::prelude::*;

struct SignResult {
    file: PathBuf,
    result: Result<(), Error>,
}

fn sign_multiple_files(files: Vec<PathBuf>, opts: SignOptions, sequential: bool) -> Result<()> {
    // Fast path for single file - skip parallel overhead
    if files.len() == 1 {
        let file = &files[0];
        sign_single_file(file, &opts)?;
        println!("Signed: {} → {}.minisig", file.display(), file.display());
        return Ok(());
    }

    // Multi-file path
    let results: Vec<SignResult> = if sequential {
        files.into_iter()
            .map(|file| {
                let result = sign_single_file(&file, &opts);
                report_file_result(&file, &result);
                SignResult { file, result }
            })
            .collect()
    } else {
        files.par_iter()
            .map(|file| {
                let result = sign_single_file(file, &opts);
                report_file_result(file, &result);
                SignResult { file: file.clone(), result }
            })
            .collect()
    };

    print_summary(&results)?;
    Ok(())
}

fn report_file_result(file: &Path, result: &Result<(), Error>) {
    match result {
        Ok(_) => println!("Signed: {} → {}.minisig", file.display(), file.display()),
        Err(e) => eprintln!("Failed: {} ({})", file.display(), e),
    }
}

fn print_summary(results: &[SignResult]) -> Result<()> {
    let failures: Vec<_> = results.iter()
        .filter_map(|r| r.result.as_ref().err().map(|e| (&r.file, e)))
        .collect();

    let success_count = results.len() - failures.len();

    if !failures.is_empty() {
        eprintln!("\nSummary: {} signed, {} failed", success_count, failures.len());
        eprintln!("Failed files:");
        for (file, err) in failures {
            eprintln!("  - {}: {}", file.display(), err);
        }
        return Err(Error::PartialFailure);
    }

    Ok(())
}
```

### Key Design Points

1. **Rayon's default thread pool** - sized to CPU cores automatically
2. **Continue on error** - collect all failures, report at end
3. **No locking needed** - each file gets independent `.minisig` output
4. **Sequential fallback** - simple flag check, no complex logic
5. **Single file optimization** - skip parallel overhead for one file

### Memory Characteristics
- Max concurrent operations = number of CPU cores
- Memory usage = `cores × average_file_size`
- Typical case (8 cores × 50MB files) = ~400MB
- No automatic fallback - trust Rayon's scheduler

## Error Handling

### Strategy
Continue processing on errors, collect failures, report summary with non-zero exit code.

### Progress Output

```
Signed: file1.txt → file1.txt.minisig
Signed: file2.txt → file2.txt.minisig
Failed: file3.txt (Permission denied)
Signed: file4.txt → file4.txt.minisig
...
Summary: 98 signed, 2 failed
Failed files:
  - file3.txt: Permission denied
  - file17.txt: File not found
```

### Exit Codes
- **Exit 0:** All files signed successfully
- **Exit 1:** One or more files failed (after attempting all)

### Rationale
- Files are independent operations
- Better to sign 90/100 files than stop at file 10
- User can fix errors and re-run for failures only
- More resilient for release workflows
- Avoids confusing partial signature sets

## Output Format

### Progress Reporting

Each file reports immediately upon completion (success or failure):
```
Signed: file1.txt → file1.txt.minisig
Signed: file2.txt → file2.txt.minisig
Failed: file3.txt (Permission denied)
Signed: file4.txt → file4.txt.minisig
```

### Output Ordering

With parallel execution, output lines may appear in non-deterministic order. This is acceptable because:
- Each line is atomic (single `println!`)
- Order doesn't affect correctness
- Users care about "which files succeeded" not "in what order"

### Thread Safety
- `println!` uses stdout mutex internally - safe for concurrent use
- `eprintln!` uses stderr mutex - safe for concurrent use
- Each file operation is independent (no shared state)
- No custom locking needed

### Single File Behavior

When only one file is provided:
- Skip Rayon overhead entirely
- Direct call to `sign_single_file()`
- Identical performance to current implementation

## Performance Expectations

- **Single file:** Identical to current implementation (no overhead)
- **Multiple files:** Scales linearly up to core count
- **100 files on 8-core CPU:** ~8× faster than sequential
- **Bottleneck:** Disk I/O (reading files) and CPU (Ed25519 signing)

## Dependencies

### New Dependency

Add to `Cargo.toml`:
```toml
rayon = "~1.10.0"
```

### Justification
- Industry-standard parallelism library
- Zero-cost when sequential path is used
- Well-tested, maintained by trusted authors
- Minimal API surface (just `par_iter()`)
- Used by ripgrep, fd, and other high-performance CLI tools

## Code Changes

### 1. `src/cli.rs`

**Change:**
```rust
// Before
message_file: Option<PathBuf>

// After
#[arg(short = 'm', long = "input", value_name = "FILE")]
message_files: Vec<PathBuf>
```

**Add:**
```rust
/// Process files sequentially instead of in parallel
#[arg(long)]
sequential: bool
```

### 2. `src/ops/sign.rs`

**Extract function:**
```rust
/// Sign a single file (pure function, no side effects)
fn sign_single_file(file: &Path, opts: &SignOptions) -> Result<()>
```

**Add functions:**
```rust
pub struct SignResult {
    pub file: PathBuf,
    pub result: Result<(), Error>,
}

/// Sign multiple files (parallel or sequential)
pub fn sign_multiple_files(
    files: Vec<PathBuf>,
    opts: SignOptions,
    sequential: bool,
) -> Result<()>

/// Report result for a single file
fn report_file_result(file: &Path, result: &Result<(), Error>)

/// Print summary of all signing operations
fn print_summary(results: &[SignResult]) -> Result<()>
```

### 3. `src/main.rs`

**Update:**
```rust
fn handle_sign(cli: &Cli) -> Result<()> {
    // Validate files provided
    if cli.message_files.is_empty() {
        return Err(Error::MissingMessageFile);
    }

    // Build SignOptions
    let opts = SignOptions {
        secret_key_file: cli.secret_key_file.clone(),
        signature_file: cli.signature_file.clone(),
        // ... other fields
    };

    // Call multi-file signing
    sign_multiple_files(cli.message_files.clone(), opts, cli.sequential)
}
```

### 4. `src/error.rs`

**Add error variant:**
```rust
#[error("No message files provided")]
MissingMessageFile,

#[error("Partial failure: some files could not be signed")]
PartialFailure,
```

## Testing Strategy (TDD)

### Test Files

1. `tests/unit/ops/sign.rs` - Unit tests for multi-file signing logic
2. `tests/cli_test.rs` - Integration tests for CLI behavior

### Unit Test Cases

**Core functionality:**
```rust
#[test] fn sign_multiple_files_sequential_success()
#[test] fn sign_multiple_files_parallel_success()
#[test] fn sign_single_file_uses_fast_path()
```

**Error handling:**
```rust
#[test] fn continue_on_error_collects_all_failures()
#[test] fn reports_partial_success_with_failures()
#[test] fn exit_code_nonzero_when_any_fail()
#[test] fn all_files_attempted_even_with_early_failures()
```

**Edge cases:**
```rust
#[test] fn empty_file_list_returns_error()
#[test] fn handles_duplicate_filenames()
#[test] fn sequential_flag_disables_parallelism()
```

### Integration Tests (CLI)

```rust
#[test] fn cli_sign_multiple_files_creates_all_signatures()
#[test] fn cli_sequential_flag_processes_files()
#[test] fn cli_shows_progress_for_each_file()
#[test] fn cli_summary_shows_success_and_failure_counts()
#[test] fn cli_nonzero_exit_on_partial_failure()
#[test] fn cli_backwards_compatible_single_file()
```

### Test Data

- Create multiple small test files (10-100 bytes each)
- Test with 1, 5, 20, 100 files
- Include permission-denied scenarios (read-only directories)
- Test with existing `.minisig` files (overwrite behavior)

### TDD Workflow

1. Write failing tests first (one test at a time)
2. Implement minimal code to pass
3. Refactor for clarity
4. Run full test suite (fast + slow)
5. Run clippy (pedantic mode)
6. Run `cargo fmt`
7. Repeat

## Success Criteria

- [ ] All unit tests pass (fast + slow)
- [ ] All integration tests pass
- [ ] Zero clippy warnings (pedantic mode)
- [ ] `cargo fmt` clean
- [ ] Backwards compatible with single-file usage
- [ ] Parallel execution verified with 100+ files
- [ ] Sequential flag verified to disable parallelism
- [ ] Error handling tested with partial failures
- [ ] Exit codes correct (0 = success, 1 = any failure)
- [ ] Performance scales linearly up to core count
- [ ] No memory issues with large file counts

## Future Considerations

**Not in scope for this design:**

- Progress bars or percentage indicators
- Retry logic for failed files
- Glob pattern expansion (use shell: `minisign -S -m *.txt`)
- Signature verification for multiple files (separate feature)
- Custom thread pool sizing (trust Rayon's defaults)

**Potential future enhancements:**

- Verbose mode (`-v`) to show detailed signing info per file
- Quiet mode (`-q`) to suppress progress, show only summary
- JSON output format for tooling integration
