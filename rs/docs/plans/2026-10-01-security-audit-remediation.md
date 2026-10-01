# Rust Security Audit Remediation Plan

**Date:** 2026-10-01  
**Scope:** `rs/` production code, CLI boundaries, cryptographic verification,
secret handling, untrusted file parsing, and destructive file operations  
**Baseline:** commit `f2b9fc697add160f26e33462ea416d4edf786d96`

## Objective

Close the reproduced findings with the smallest changes that remove each root
cause. Match C minisign behaviour where C is stricter. Keep C's behaviour where
C is permissive and the permissiveness carries no risk once Rust's own output is
correct. Signatures and keys from legitimate C minisign releases must stay
compatible.

## Audit baseline

The following checks passed before remediation:

- `./run_all_tests.sh`: 532 tests passed.
- `cargo nextest run --no-default-features --features parallel`: 536 tests
  passed.
- `gtimeout 300 cargo clippy --all-targets --all-features -- -D clippy::all
  -D clippy::pedantic`: passed with no warnings.
- `cargo audit`: no known vulnerabilities in 210 locked dependencies using the
  advisory database updated on 2026-10-01.
- C compatibility probes used `/opt/homebrew/bin/minisign` 0.12.

Each reproduced exploit uses synthetic data and succeeded against the audited
Rust binary.

## Threat model

minisign trusts the public key the user supplies. An attacker who controls that
key can sign any message with an ordinary key pair. Severity below reflects
this: a finding that requires the attacker to supply the trusted public key,
the key-generation arguments, or write access to the key directory ranks lower
than one that breaks verification under an honest key.

## Findings and intended fixes

| ID | Severity | Finding | Status |
|---|---:|---|---|
| SA-01 | Medium | A constructible signature under an identity public key verifies any message; C rejects it | Reproduced |
| SA-02 | Low–Medium | Newlines in a generation comment inject a substitute key line | Reproduced |
| SA-03 | Low | Force-writing through a hard-link alias overwrites the aliased secret key | Reproduced |
| SA-04 | Low–Medium | A key file can request 32 GiB of scrypt memory; allocation failure aborts | Confirmed from parser and policy |
| SA-05 | Low | dalek zeroization is disabled; some secret temporaries are unguarded | Confirmed from feature graph and data flow |
| SA-06 | Low | A password FIFO blocks before the regular-file check runs | Reproduced on Unix |

SA-04 is Low for a manually invoked CLI and potentially Medium for automation
that processes attacker-supplied files. Its impact is resource exhaustion, not
signature forgery. Restricting requests to 1 GiB bounds the work but cannot
guarantee allocation succeeds on a memory-constrained host.

## SA-01: Use strict Ed25519 verification

### Evidence

`crypto::verify()` (`src/crypto.rs:271`) calls dalek's permissive
`Verifier::verify()`. With the identity point as public key, the identity point
as `R`, and scalar zero as `S`, Rust accepts both the message signature and the
global signature for arbitrary content. C minisign 0.12 rejects the same input:
libsodium refuses small-order public keys and small-order `R`.

The forgery needs an attacker-supplied public key. It matters because Rust
diverges from C, and because a weak key verifies every message, which breaks any
system that binds a key ID to one signer.

### TDD sequence

1. Unit test: identity public key with identity/zero signature is rejected for
   several distinct messages.
2. Integration test: a complete four-line `.minisig` using the forged value
   fails CLI verification and prints no trusted comment.
3. Unit tests for the other small-order public-key encodings from dalek's
   weak-key fixtures.
4. Keep the existing cross-binary tests proving valid C signatures verify.

### Remediation

1. Change `crypto::verify()` to call `VerifyingKey::verify_strict()`. It rejects
   small-order `A` and `R`, matching libsodium.
2. Add an explicit `is_weak()` check before verification and map it to
   `InvalidPublicKey`. `verify_strict()` already covers this case; the explicit
   check gives a distinct error and keeps the policy visible in this crate.
3. Map signature failure under a valid key to `VerificationFailed`.
4. All callers already go through the central wrapper. Keep it that way.

### Acceptance criteria

- The forged `.minisig` fails before any trusted comment is printed.
- Rust-to-Rust, Rust-to-C, and C-to-Rust compatibility tests pass.
- No production code calls dalek's permissive `verify()`.

## SA-02: Validate key comments before serialization

### Evidence

`PubkeyStruct::to_file_contents()` (`src/keys.rs:231`) and
`SeckeyStruct::to_file_contents()` (`src/keys.rs:862`) embed the comment
without validation. A generation comment of
`"synthetic metadata\n<attacker public key>"` writes a three-line public-key
file. The parser reads `lines[1]`, which is the injected key.

Exploitation requires control of the `-c` argument at generation time, for
example a wrapper that passes untrusted input to `-G`. C's assertion against
`\r` and `\n` (`../src/minisign.c:627`) belongs to signature creation, not
key generation. C generation writes the supplied secret-key comment without
that assertion and writes a fixed public-key comment through `write_pk_file()`.
Rust embeds the supplied comment in the generated public-key file. Validation
is required to prevent field injection regardless of C's comment handling.

### Parser policy

C reads key files with two `fgets` calls, ignores the comment content and any
trailing lines, and does not check the `untrusted comment: ` prefix. The Rust
parser keeps the same two-line read. Once the serializer rejects line breaks,
Rust cannot produce a multi-line comment, and a third party who hands over a
crafted key file already controls the key. Strictly rejecting extra lines does
not close the reproduced serializer injection and would reject files C accepts.
Retain that parser compatibility for this remediation and add fixtures for
ignored trailing lines and arbitrary first-line comments to make it explicit.

### TDD sequence

1. Unit tests: public- and secret-key serializers reject comments containing LF,
   CR, NUL, or other C0 control characters, and comments over the
   `COMMENTMAXBYTES`-derived limit.
2. Integration test: `-G` with an injected public-key line fails and creates
   neither output file.
3. Keep positive fixtures for canonical C public and secret keys.

### Remediation

1. Reuse the comment validation in `validation.rs`. Extract a key-comment
   helper if the key and signature limits differ.
2. Make key serialization fallible: `Result<String>` for public keys and
   `Result<Zeroizing<String>>` for secret keys.
3. Validate the comment in generation and recreation before directory creation,
   KDF work, or any write.

### Acceptance criteria

- No user-supplied comment can add a line to a key file.
- Failed comment validation leaves both output paths untouched.
- Key files accepted by C minisign 0.12 parse unchanged.

## SA-03: Replace in-place truncation with atomic rename

### Evidence

The force path for public keys and signatures opens the destination with
`truncate(true)` (`src/ops/file_utils.rs:289`). `O_NOFOLLOW` blocks a symlink
in the final component but not a hard link. With the public-key output
hard-linked to an unencrypted secret key, `recreate --force` truncated the
shared inode and destroyed the secret key.

Exploitation needs influence over the output path or a user mistake. Write
access to the key's own directory already permits deletion, but access to a
separate output directory does not necessarily permit deleting the original
key pathname. The demonstrated impact is destructive aliasing and data loss;
the audit did not demonstrate privilege escalation.

### Approach

`rename(2)` replaces a directory entry and never writes into the inode the old
entry pointed to. Writing to a sibling temp file and renaming it over the
destination therefore leaves every hard-link alias intact. The crate already has
this pattern (`src/ops/file_utils.rs:320-363`). Routing public-key and
signature writes through it closes the hard-link case without a file-identity
layer.

One alias remains: the output path and an input path naming the same file. For
signing, the message is read before the write, so the rename replaces the
message with its signature; for recreation, the secret key is replaced with the
public key. Both require `--force`, but a direct check is cheap.

### TDD sequence

1. Unix integration tests for `recreate --force` where the public output is a
   hard link to the secret key: assert success and byte-for-byte preservation of
the secret key through its own path.
2. Unix integration tests where the output is the input itself (same path,
   relative alias, symlink to it): assert failure and preservation of the input.
3. The same pair for signing: signature output versus message and secret-key
   inputs.
4. Generation tests: secret and public output paths naming the same destination
   fail before KDF work, whether that destination exists or not. Include
   identical paths, relative aliases, `.` and `..` components, and symlinked
   parent directories.
5. Failure-injection tests: failures before replacement preserve existing
   outputs and remove staged temp files. Cover both Unix and Windows writers.

### Remediation

1. Extract a non-secret atomic replacement helper from the existing sibling-temp
   pattern; do not reuse the secret-key helper's fixed 0600 permissions for
   public outputs. Stage with exclusive creation, write and flush, then replace
   the destination entry and sync its parent where supported. Define and test
   the Windows replacement behavior rather than assuming Unix rename semantics.
2. Reject output paths that resolve to a protected input pathname. Compare
   canonical paths for existing files. Reject final-component output symlinks
   explicitly, retaining the existing public/signature force-write policy.
3. Allow a distinct hard-link output name: atomic replacement detaches that
   name and leaves the input name and its inode untouched. Do not reject solely
   because the output and input share `(dev, ino)`; that would contradict the
   hard-link success tests above.
4. For generation, compare destinations before KDF work even if neither exists.
   Create parent directories, canonicalise each parent, append the file name,
   and compare the results. Canonicalisation resolves `.`, `..`, and symlinked
   parents. Case aliases on case-insensitive filesystems are not detected;
   document this limit.
5. On Windows, stable `std` has no file-identity API: `volume_serial_number` and
   `file_index` require the unstable `windows_by_handle` feature. Use pathname
   comparison for protected destinations; atomic replacement protects distinct
   hard-link names on both platforms.
6. State the concurrency boundary: pathname checks cannot guarantee protection
   against an attacker swapping writable parent directories after validation.
   Atomic replacement must never truncate or write into the old target inode,
   including when the final destination changes during staging.

### Acceptance criteria

- No successful operation writes into an input file's inode.
- Direct and resolved pathname aliases to an input are rejected; distinct
  hard-link output names are allowed and preserve the input bytes.
- Equivalent generation destinations are rejected even when they do not exist,
  except case aliases, which are documented as uncovered.
- Failures before commit preserve all pre-existing input and output bytes.
- No `truncate(true)` open remains on public-key or signature output paths.
- No new dependency.

## SA-04: Cap scrypt cost at the production limit

### Evidence

Encrypted key files carry `opslimit` and `memlimit`. The parser accepts up to
`MAX_SCRYPT_LOG_N = 25` (`src/crypto.rs:47`), about 32 GiB at `r = 8`.
`scrypt` allocates its working buffer with `vec!`; allocation failure aborts the
process rather than returning an error, so the `KdfMemoryError` fallback cannot
run. `inspect` reports such a key as `Security Level: HIGH`.

### TDD sequence

1. Policy tests at the maximum accepted parameters and one step above.
2. A synthetic over-budget key is rejected before password prompting,
   credential-store access, and any scrypt call. Test the policy helper
   directly, then the sign, recreate, change-password, and decrypting-inspect
   CLI paths with no password source: each must exit with the budget error,
   not a prompt or a password-source error. This ordering proves rejection
   precedes password retrieval without a new injection seam. Do not allocate
   large buffers in tests.
3. Inspection tests: standard parameters are `High`, weaker values `Medium` or
   `Low`, over-budget values `Unsupported`.
4. Keep fixtures for production and documented fallback parameters.

### Remediation

1. Separate structurally valid parameter decoding from execution-policy
   validation. Decoding checks canonical encoding and arithmetic bounds without
   allocating scrypt working memory. Inspection can then describe valid
   over-budget parameters instead of failing in the shared converter.
2. Set the decryption budget to `PRODUCTION_MEMLIMIT` (1 GiB), which equals
   libsodium's SENSITIVE limit used by C minisign. Derive the execution limit
   from that constant; do not retain a separate hard-coded `log_n` ceiling.
3. Validate the budget in every decrypting operation before password retrieval,
   credential-store access, or KDF allocation. Also validate at the library
   decryption boundary so callers cannot bypass it by skipping CLI loading.
4. Report structurally valid over-budget parameters as `Unsupported` in
   non-decrypting inspection, without consulting the credential store. Malformed
   encodings remain parse errors. Decrypting inspection fails before prompting.
5. Document the budget in `COMPATIBILITY.md`.

The fallback mechanism (`--allow-kdf-fallback`, `KdfMemoryError`,
`kdf_fallback_used`) is dead code under this backend, but removing it is not
needed to close SA-04. That cleanup is the separate follow-up below.

### Acceptance criteria

- No key file can request more than the named memory budget.
- Rejection occurs before allocation or credential prompt.
- Standard C minisign keys and supported reduced-cost keys remain usable.
- Inspection can report `Unsupported` without allocating KDF working memory or
  accessing credentials. Execution refuses that key before password retrieval.

## Follow-up: Remove the unreachable KDF fallback

Not a security fix. Commit separately after SA-04.

`scrypt` allocates with `vec!`, so allocator exhaustion aborts the process and
never returns an error. The `--allow-kdf-fallback` branches and the
`KdfMemoryError` mapping cannot run.

1. Remove the fallback branches. Map `scrypt()` invalid-output errors to
   `KdfError`.
2. Keep `--allow-kdf-fallback` as an accepted no-op that prints a deprecation
   warning to stderr. Scripts that pass it keep working; the warning states
   that the flag has no effect.
3. Keep the library builder option and the `kdf_fallback_used` result field for
   source compatibility, marked `#[deprecated]`. The field is always false.
4. Keep the `KdfMemoryError` variant and exit code 3, documented as not
   produced by this backend.
5. Update CLI help, API documentation, and `COMPATIBILITY.md` together.

Tests: passing the flag succeeds, exits 0, and emits the warning; the result
field is false.

## SA-05: Enable dalek zeroization and guard secret temporaries

### Evidence

`Cargo.toml` builds `ed25519-dalek` with `default-features = false` and only
`rand_core`; `cargo tree -e features -i ed25519-dalek` confirms `zeroize` is
off, so `SigningKey` and its expanded state are not wiped. Within this crate:

- `read_file_bounded()` returns a plain `String` holding the whole secret-key
  file.
- Base64 decoding returns a plain `Vec<u8>` holding plaintext secret key bytes
  for unencrypted keys.
- `inspect()` and `inspect_private()` read key-file contents directly and bypass
  `load_secret_key()`, so changing that loader alone leaves plaintext behind.
- `decrypt()` copies the plaintext secret key into a plain stack array, which is
  dropped unwiped on checksum failure.

scrypt's internal buffers are outside this crate's control.

### TDD sequence

1. A test that fails unless dalek's `zeroize` feature is enabled, for example a
   compile-time bound `fn assert_zod<T: ZeroizeOnDrop>() {}` applied to
   `SigningKey`.
2. A wrong-password test covering the checksum-failure path of `decrypt()`.
3. Exercise secret-key loading through sign, recreate, password change,
   `inspect()`, and `inspect_private()`, including nonstandard-comment detection,
   invalid UTF-8, and decode failures. Check that all paths use the guarded
   reader/decoder and preserve established parsing and error behavior.

The wrong-password test proves rejection, not erasure. Verify ownership and
drop guarantees through type bounds and a data-flow review of every named
caller; do not infer wiping from a functional test or inspect freed memory.

### Remediation

1. Enable dalek's `zeroize` feature, keeping `default-features = false`.
2. Wrap the plaintext array in `decrypt()` in `Zeroizing` before filling it.
   Recreation already receives a guarded `SecretKey` and constructs a dalek
   `SigningKey`; enabling dalek zeroization covers that owned copy. Inspect the
   actual data flow instead of introducing a new plaintext array there.
3. Add a bounded reader returning `Zeroizing<Vec<u8>>` for secret-key files and
   parse lines by borrowing from it. Route `load_secret_key()`, `inspect()`, and
   `inspect_private()` through it, including fallback type detection. Preallocate
   capacity for the maximum read plus the overflow-detection byte before reading
   secret data so growth cannot abandon an unwiped allocation. Borrow UTF-8
   views; do not transfer secret bytes into an owned UTF-8 error payload.
4. Decode secret-key base64 into a preallocated guarded destination, preferably
   `Zeroizing<[u8; SECKEY_STRUCT_SIZE]>` with `decode_slice`. Validate decoded
   length and reject oversized input without growing a buffer containing
   secrets. Keep the public decoder unchanged. Review ordinary scratch arrays
   in `SeckeyStruct::from_bytes()` as well as the decoded buffer.
5. Remove password `to_owned()` copies where the receiving API accepts a borrow.
6. Document that zeroization covers buffers this crate owns and dalek's signing
   state, not scrypt internals, allocator copies, or swap. Memory locking needs
   unsafe code and is out of scope.

### Acceptance criteria

- `SigningKey` implements `ZeroizeOnDrop` in the built dependency graph.
- Secret storage this crate owns is guarded by `Zeroizing` or a type implementing
  `Zeroize` and `ZeroizeOnDrop` from the moment it receives secret bytes,
  including error paths. This is checked across all loading and inspection paths.
- Bounded reads and decoding do not reallocate after receiving secrets, and
  error objects do not retain unguarded secret-file contents.
- Documentation states the zeroization boundary.

## SA-06: Open password files without blocking

### Evidence

`prompt_password()` (`src/main.rs:933`) calls `File::open(path)` before
`metadata().is_file()`. Opening a FIFO for reading blocks until a writer
connects, so the check never runs.

### TDD sequence

1. Unix integration test: a FIFO passed as `--password-file` is rejected within
   a bounded time.
2. Tests for a directory, an empty file, and the maximum permitted length.
3. A test that a symlink to a regular file is accepted.
4. Keep the existing bounded-read and invalid-UTF-8 tests.

### Remediation

1. On Unix, open with `O_NONBLOCK` via `OpenOptionsExt::custom_flags`, then
   check that the open handle is a regular file. `O_NONBLOCK` does not affect
   regular-file reads.
2. Follow symlinks. Container secret mounts (Docker, Kubernetes `..data/`)
   present password files as symlinks; rejecting them breaks that usage. The
   handle check applies to the resolved file.
3. Retain the Windows open-then-check path. Optionally add Windows tests for
   named-pipe and device paths; they are not required to close this Unix
   finding.
4. Keep the `MAX_PASSWORD_FILE_BYTES + 1` read bound and the `Zeroizing` buffer.

### Acceptance criteria

- FIFO, socket, directory, and device inputs fail promptly on Unix.
- A symlink to a regular file works.
- The file is opened once and read from that handle.
- No password bytes appear in errors.

## Implementation order

Implement each phase as a separate conventional commit. Write and observe
failing tests before each production change.

1. **SA-01:** strict verification.
2. **SA-05 step 1 and SA-02:** dalek `zeroize` feature and comment validation.
   Both are small and independent.
3. **SA-03:** atomic rename for all force writes, then the same-file check.
4. **SA-04:** scrypt budget and inspection output.
5. **SA-05 remainder:** zeroizing reader, decoder, and `decrypt()` buffer.
6. **SA-06:** non-blocking password-file open.
7. **Follow-up:** remove the unreachable KDF fallback.

Suggested commits:

- `fix(crypto): use strict Ed25519 verification`
- `build(deps): enable ed25519-dalek zeroize feature`
- `fix(keys): reject line breaks in key comments`
- `fix(files): replace force truncation with atomic rename`
- `fix(kdf): cap key file scrypt cost at production limit`
- `fix(secrets): zeroize transient key material`
- `fix(password): open password files without blocking`
- `refactor(kdf): remove unreachable memory fallback`

Each commit body states the threat, the affected path, and the resulting
behaviour.

## Verification

Run after each phase and on the final tree:

```sh
./run_all_tests.sh
gtimeout 300 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo audit
```

Also:

- release-mode tests;
- `--no-default-features` and default-feature test runs;
- an explicit `--no-default-features --features parallel` test run, since
  `run_all_tests.sh` disables both default features;
- C minisign 0.12 cross-binary generation, signing, verification, password
  change, and public-key recreation;
- regression tests for the three reproduced exploits;
- a search confirming no permissive dalek `verify()` call and no `truncate(true)`
  on public-key or signature output paths.

Windows validation is required for SA-03, which changes the writer used on that
platform. Run Windows CI tests for replacement of an existing regular file,
preservation through distinct hard-link names, direct input/output aliases,
and preservation on failures before replacement. Verify the same-directory
replacement primitive actually used by the Windows writer; do not equate moving
the old file aside and installing a new file with atomic replacement. If a safe
supported replacement cannot be implemented, reject that operation explicitly
rather than falling back to truncation.

Broader parser fuzzing is a separate work item. It is not a completion criterion
for these targeted fixes.

## Completion criteria

- All six finding-specific test sets pass.
- The verification steps above pass without warnings.
- C-generated keys and signatures remain compatible.
- Over-budget and invalid-comment cases fail before KDF work, credential access,
  or writes.
- Security documentation states the zeroization and KDF resource limits.
- Windows replacement and alias tests pass; unsupported operations fail
  explicitly without damaging existing files.
- The release binary cannot reproduce the three demonstrated effects:
  verification forgery, comment-based key substitution, or destructive
  hard-link writes. The hard-link command may succeed by safely replacing only
  the output directory entry.
