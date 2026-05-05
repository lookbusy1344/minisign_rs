# Fresh Code Review Remediation Plan

Date: 2026-05-05

Scope: Rust implementation under `rs/` only. The C and Zig sources remain read-only
compatibility references.

## Review Summary

The project is in strong shape for a security-sensitive rewrite: production code is
safe Rust with `#![forbid(unsafe_code)]`, the primary sign/verify paths stream or
bound large inputs, and C/Rust cross-binary compatibility is covered by integration
tests.

This pass found no immediate signature-forgery issue. The main residual risks are
around transactional file replacement, parser strictness, and small untrusted-input
resource edges that are easy to harden with tests first.

Verification performed during review:

- `gtimeout 300 cargo test --lib --tests` passed.
- `gtimeout 300 cargo clippy --lib --bins --tests --all-features -- -D warnings -W clippy::pedantic` completed without diagnostics.

## Findings

### CR-2026-05-05-1: Key generation is not transactional across secret/public files

Severity: Medium

Files:

- `src/ops/generate.rs:286`
- `src/ops/generate.rs:287`
- `src/ops/generate.rs:293`
- `src/ops/generate.rs:294`

`generate_with_log_n()` writes the secret key first and then writes the public key.
In `--force` mode, if the secret key overwrite succeeds but the public key write
fails, the command returns an error after leaving a new secret key on disk while the
public key path may still contain an old key, be missing, or be otherwise unusable.

Existing tests intentionally verify that the secret key is preserved on this failure
path, which avoids key deletion, but the operation is still not atomic as a keypair
replacement. The user-visible result is an error plus a partially updated keypair
state. For a signing tool, that is a real operational hazard: subsequent signing may
use a secret key whose matching public key was never written.

Remediation:

1. Add a regression test that creates an existing matching keypair, forces a
   public-key write failure, and asserts that the original secret/public keypair
   remains usable and matched after the failed operation.
2. Introduce a keypair write transaction for generation:
   - Write both new files to sibling temporary files.
   - Use secret-key temp mode `0600`.
   - Sync file contents before rename.
   - Rename the public key and secret key only after both writes have succeeded.
   - Prefer preserving the old keypair on any failure before the commit point.
3. On Unix, also sync the parent directory after renames if the existing fsync
   expectations are meant to cover crash consistency, not just application-level
   partial writes.
4. Keep the current Windows refusal for forced secret-key overwrite until equivalent
   safe semantics exist there.

Acceptance tests:

- New force-generation transaction test covering public-key write failure.
- Existing `test_force_pubkey_fail_preserves_secret_key` should be revised to assert
  preserved matched keypair semantics, not just file existence.
- Full test suite and cross-binary tests remain green.

Status: completed.
Implemented in `src/ops/generate.rs` with transactional temp-file staging,
rollback/restore handling, and a force-overwrite lock for concurrent writers.
Regression coverage lives in `tests/unit/ops/generate.rs` and `tests/concurrent_access.rs`.

### CR-2026-05-05-2: Small-file bounded reads use metadata before unbounded read

Severity: Medium-Low

Files:

- `src/ops/file_utils.rs:70`
- `src/ops/file_utils.rs:71`
- `src/ops/file_utils.rs:79`

`read_file_bounded()` checks path metadata before calling `std::fs::read_to_string()`.
That bounds normal key/signature/password files, but the actual read is performed by
a second path lookup with no `take(max_bytes + 1)` cap. A concurrent replacement
between metadata and read can turn this into an avoidable memory-DoS edge.

The project already fixed this pattern for message files in `read_message_file()`.
The same single-fd pattern should be used here.

Remediation:

1. Add a unit test using a custom helper or race-oriented fixture that proves the
   function enforces the cap during the read, not only before allocation.
2. Rewrite `read_file_bounded()` to:
   - Open the file once.
   - Check metadata on that file descriptor.
   - Read through `file.take(max_bytes + 1)`.
   - Reject if the collected byte length exceeds `max_bytes`.
   - Decode UTF-8 explicitly and return the existing file-read style error on
     invalid UTF-8.
3. Keep the external API unchanged.

Acceptance tests:

- Existing oversized key/signature/password tests remain green.
- New test demonstrates post-open/read-time size enforcement.

Status: completed.
Implemented in `src/ops/file_utils.rs` with a single-fd bounded reader and
coverage in `tests/unit/ops/file_utils.rs`.

### CR-2026-05-05-3: Public and secret key file parsers ignore trailing lines

Severity: Low

Files:

- `src/keys.rs:181`
- `src/keys.rs:182`
- `src/keys.rs:191`
- `src/keys.rs:845`
- `src/keys.rs:846`
- `src/keys.rs:855`

`PubkeyStruct::from_file_contents()` and `SeckeyStruct::from_file_contents()` accept
any file with at least two lines and parse only line 2. `SignatureBox` parsing is
stricter and requires exactly four lines.

This is not a direct cryptographic bypass because the decoded binary structures are
still length-checked. It is still undesirable in a security-sensitive format parser:
trailing data can hide operator mistakes, confused-deputy inputs, or appended content
that other tools may interpret differently.

Compatibility note: confirm C minisign behavior before changing this. If C accepts
trailing lines for key files, preserve compatibility and document the intentional
tolerance instead of tightening the parser.

Remediation:

1. Add explicit compatibility tests with C minisign for key files containing trailing
   lines after the base64 payload.
2. If C rejects trailing lines, require exactly two lines for key files.
3. If C accepts trailing lines, keep behavior but:
   - Rename tests to document this as compatibility behavior.
   - Reject non-empty trailing lines in any Rust-only strict mode if such a mode is
     introduced later.

Acceptance tests:

- Parser behavior for key files with trailing blank and non-blank lines is explicitly
  tested.
- C/Rust behavior is either matched or the deliberate divergence is documented.

Status: completed.
Compatibility coverage lives in `tests/unit/keys.rs`, documenting the accepted
trailing-line behavior.

### CR-2026-05-05-4: KDF parameter conversion is permissive for malformed inputs

Severity: Low

Files:

- `src/crypto.rs:455`
- `src/crypto.rs:463`
- `src/crypto.rs:480`
- `src/crypto.rs:484`
- `src/crypto.rs:498`

`opslimit_memlimit_to_params()` derives `N` with integer division from `memlimit`,
then uses `ilog2(N)`. If `memlimit` is not an exact libsodium-formula multiple or
if `N` is not a power of two, the conversion floors to a smaller `log_n`.

The subsequent scrypt call will reject some invalid combinations, but the conversion
itself is more permissive than the stored parameter format implies. For untrusted key
files, it is better to fail early and predictably unless C compatibility requires
accepting a specific non-standard encoding.

Remediation:

1. Add table tests for malformed `(opslimit, memlimit)` pairs:
   - `memlimit` not divisible by `128 * r`.
   - derived `N` not a power of two.
   - derived `r == 0`.
   - derived `r` that exceeds scrypt crate limits.
2. Compare behavior against C minisign for any historically accepted non-standard
   fixtures before rejecting them.
3. Tighten conversion to reject malformed inputs before KDF allocation.
4. Keep the `MAX_SCRYPT_LOG_N` denial-of-service cap.

Acceptance tests:

- Standard production, weak-test, and known C fixture parameters still parse.
- Malformed parameter pairs fail before `derive_key_with_params()`.

Status: completed.
Implemented in `src/crypto.rs` with exact-encoding validation and table coverage in
`tests/unit/security_hardening.rs` and `tests/unit/keys.rs`.

## Implementation Order

1. Transactional keypair generation tests and implementation.
2. Single-fd bounded read hardening.
3. Key parser trailing-line compatibility tests and either strict parsing or explicit
   documented tolerance.
4. KDF parameter strictness tests and conversion hardening.
5. Run:
   - `gtimeout 300 cargo test --lib --tests`
   - `gtimeout 300 cargo clippy --lib --bins --tests --all-features -- -D warnings -W clippy::pedantic`
   - Cross-binary tests when C minisign is available.

## Completion

All remediation items in this plan have been implemented and verified with the
relevant test coverage, including the concurrent force-overwrite case and the full
`cargo nextest run --no-default-features` pass.
