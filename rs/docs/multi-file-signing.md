# Multi-File Signing

As of version 1.1.0, minisign_rs supports signing multiple files in a single command with parallel execution for improved performance.

## Basic Usage

Sign multiple files by specifying the `-m` flag multiple times:

```bash
minisign_rs -S -m file1.txt -m file2.bin -m release.tar.gz
```

Each file will get its own `.minisig` signature file:
- `file1.txt.minisig`
- `file2.bin.minisig`
- `release.tar.gz.minisig`

## Parallel Execution (Default)

By default, files are signed in parallel using all available CPU cores for improved performance:

```bash
# Signs files in parallel
minisign_rs -S -m file1.txt -m file2.txt -m file3.txt
```

## Sequential Mode

Force single-threaded execution with `--sequential`:

```bash
minisign_rs -S -m file1.txt -m file2.txt --sequential
```

Use sequential mode when:
- Signing very large files (>1GB each)
- Running on memory-constrained systems
- Debugging signing issues

## Progress Output

Each file reports its status as it completes:

```
Signed: file1.txt → file1.txt.minisig
Signed: file2.txt → file2.txt.minisig
Failed: file3.txt (No such file or directory)
Signed: file4.txt → file4.txt.minisig

Summary: 3 signed, 1 failed
Failed files:
  - file3.txt: No such file or directory
```

## Error Handling

If any files fail to sign:
- Processing continues for remaining files
- Failed files are reported to stderr
- A summary shows success/failure counts
- Exit code is 1 (failure) even if some files succeeded

This allows you to fix errors and re-run signing for only the failed files.

## Backwards Compatibility

Single-file signing behavior is unchanged:

```bash
# Same as before
minisign_rs -S -m file.txt
```

Output format remains identical for single files.

## Limitations

- Custom signature path (`-x`) is not supported with multiple files
  - Each file automatically gets `<filename>.minisig`
- Verification still supports only one file at a time
- All files use the same trusted/untrusted comments

## Performance

Parallel execution scales linearly up to the number of CPU cores:

- 8-core CPU signing 100 files: ~8× faster than sequential
- Memory usage: `cores × average_file_size`
- Typical usage (8 cores × 50MB files): ~400MB
