# Multi-file signing API remediation plan

Date: 2026-05-11

Scope: Rust implementation under `rs/` only.

## Review Summary

The fresh-eyes review found the sign/verify and key-management paths to be generally
well hardened: safe Rust, bounded reads, zeroization for secret material, C/Rust
compatibility coverage, post-sign verification, and clean clippy/test results.

This plan intentionally excludes low-priority cleanup and cosmetic output issues.
The only substantial issue worth scheduling from this review is an API-level
correctness hole in multi-file signing.

Verification performed during review:

- `gtimeout 300 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic` passed.
- `gtimeout 300 ./run_all_tests.sh` passed: 529 tests, 529 passed.

## Finding

### CR-2026-05-11-1: Multi-file signing API can target one custom signature path

Severity: Medium

Files:

- `src/ops/sign.rs:192`
- `src/ops/sign.rs:211`
- `src/ops/sign.rs:403`
- `src/main.rs:385`

`sign_multiple_files()` is public API and accepts a `SignOptions` value whose
`signature_file` field may be set. Internally, every file is signed through
`sign_file_with_key()`, which uses `options.signature_file` when present. That means
library callers can ask multi-file signing to write every signature to the same
destination.

The CLI already rejects `-x` with multiple message files, but the API itself does
not enforce that invariant. With `force=false`, one file may succeed and the rest
fail with `FileExists`. With `force=true` and parallel signing, the result is
last-writer-wins and nondeterministic. Either behavior is a footgun in a signing
tool because callers reasonably expect one signature per input file.

Remediation:

1. Add a regression test in `tests/unit/ops/sign.rs` that calls
   `sign_multiple_files()` with two files and a custom `signature_file`, and asserts
   the call fails before writing any signature.
2. Add an API-level guard in `sign_multiple_files()`:
   - If `files.len() > 1` and `options.signature_file` is `Some(_)`, return
     `Error::Usage` or a more specific existing error before loading/decrypting the
     secret key.
   - Keep the CLI-level validation in `main.rs`; it is still useful for producing a
     CLI-specific message.
3. Preserve the single-file behavior: `sign_multiple_files()` with exactly one input
   and a custom `signature_file` should continue to work.
4. Ensure the guard runs after deduplication or explicitly tests duplicate inputs so
   `["file", "file"]` does not get rejected as a false multi-file case.

Acceptance tests:

- New unit test proves multi-file API rejects a shared custom signature path.
- New or existing test proves single-file API use with a custom signature path still
  succeeds.
- Existing CLI test for `-x` with multiple files remains green.
- Full suite remains green with `gtimeout 300 ./run_all_tests.sh`.

Implementation notes:

- Prefer exposing a small helper on `SignOptions` only if tests need it; otherwise
  keep the invariant local to `sign_multiple_files()`.
- Do not change default per-file signature path behavior.
- Do not add locking or atomic-write work as part of this remediation; the defect is
  the invalid shared-output API state, not signature-file durability.

Status: planned.
