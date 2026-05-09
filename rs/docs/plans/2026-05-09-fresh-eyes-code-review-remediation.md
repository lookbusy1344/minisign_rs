# Fresh-eyes code review — remediation plan

**Date:** 2026-05-09
**Branch:** lb_rust
**Scope:** entire `rs/` crate (8 kLOC), cross-referenced against C reference at `../src/minisign.c`

## Method

Three independent passes were combined: a manual reading of every security-critical file, a fresh-eyes review by `code-reviewer`, and a focused `silent-failure-hunter` sweep. Each finding below is cited to a specific `file:line` in the working tree. `cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic` is clean at the time of review.

The codebase is in good shape overall: `forbid(unsafe_code)` holds, no naked `unwrap`/`expect` in production paths, secrets are wrapped in `Zeroize`/`Zeroizing`, constant-time comparisons (`subtle::ConstantTimeEq`) are used in every keynum / checksum / password / passwords-match comparison, scrypt log_n is capped at 25 before any KDF work runs, file-size caps are enforced via single-fd `metadata().len()` + `take(limit+1)`, and the `--force` keypair commit pipeline is correctly write-temp → fsync → swap → fsync-parent. The findings below are real but none break signature verification or key encryption outright.

The single most consequential class of issue is silent error swallowing — particularly around the credential store, the KDF fallback loop, and rollback paths in `generate.rs` — which can produce keys with weaker-than-requested parameters or leave on-disk state in an inconsistent place without ever telling the user.

## Severity legend

- **High** — security or data-loss impact, or a clear correctness gap with the C reference.
- **Medium** — robustness, durability, defence-in-depth, or non-obvious operational hazards.
- **Low** — UX, output-formatting, code-smell, or upstream-dependent risks.

## Findings

### High

#### H1. Scrypt-fallback loop conflates programmer/parameter bugs with memory pressure
- **Location:** `src/keys.rs:372-403` (`SeckeyStruct::new_encrypted` derive loop)
- **Problem:** `derive_key_with_params` returns `Error::KdfError` for at least three distinct conditions: `output_len > MAX_KDF_OUTPUT_LEN` (programmer bug), `ScryptParams::new()` rejected the parameters (parameter bug), and `scrypt()` itself failed (memory). The current `if let Ok(key) = derive_key_with_params(...)` discards the error variant. With `--allow-kdf-fallback`, a non-memory error halves opslimit/memlimit and retries, eventually succeeding at the smaller size and emitting "REDUCED SECURITY PARAMETERS" — for a reason that had nothing to do with memory.
- **Risk:** Generates a key with weaker-than-requested KDF parameters whose only signal is a stderr warning the user may not see (CI logs, redirected stderr).
- **Fix:** Introduce a distinct error path for memory-allocation failures (`scrypt::errors::InvalidOutputLen`-style) and only retry on that. Programmer/parameter errors must propagate immediately.

#### H2. Credential-store lookups collapse all errors to "no password saved"
- **Location:** `src/credential_store.rs:63-67` (`get_password`), `src/credential_store.rs:100-102` (`has_password`)
- **Problem:** `entry.get_password().ok()?` flattens `keyring::Error::NoEntry` (legitimate "nothing saved") with `PlatformFailure`, `BadEncoding`, `NoStorageAccess`, locked-keychain prompts the user denied, broken D-Bus, etc. The caller then prompts the user as if no password were ever saved. Worse, `inspect` reads `password_saved: has_password(&id)` which becomes `false` whenever the keychain is locked or unreachable — actively misleading the user about whether they have a stored credential.
- **Risk:** On a non-interactive run (CI) the user gets a confusing "Cannot prompt for password in non-interactive mode" instead of "your keychain is locked"; on an interactive run, every operation re-prompts and the user assumes saving never worked.
- **Fix:** Change `get_password` to return `Result<Option<Zeroizing<String>>>`. Map only `keyring::Error::NoEntry` to `Ok(None)`; surface every other variant. `inspect`'s display should distinguish "Yes / No / Unknown — credential store unavailable".

#### H3. Rollback failures during keypair commit are silent
- **Location:** `src/ops/generate.rs:518-535, 565-606, 614-618, 700-718` (22+ `let _ = std::fs::*` calls in rollback paths)
- **Problem:** The keypair commit pipeline (write tmp → fsync → hard_link/rename → fsync parent → swap backups) has many error paths. Each unwinds with `let _ = std::fs::remove_file(...)` / `let _ = std::fs::rename(backup, ...)` and returns the original error. If a rollback step itself fails — backup-rename to `<keyfile>.bak.<nonce>` succeeded but the rename-back failed — the user's existing secret key has just disappeared and they are told only "the operation failed". They have no idea their old key is now at `.minisign.key.<nonce>.bak`.
- **Risk:** Silent partial-state on disk for the user's most sensitive file.
- **Fix:** Collect rollback errors into a wrapping `Error::PartialState { primary, rollback_errors: Vec<...> }` whose `Display` lists exactly which paths now contain stale state. At minimum, `eprintln!("CRITICAL: rollback failed: ...; recover manually")` for each failing step before returning the primary error.

#### H4. `recreate` trusts the stored public-key half of an unencrypted secret key
- **Location:** `src/ops/recreate.rs:163-171` (`extract_public_key_from_secret`)
- **Problem:** For unencrypted secret keys the file checksum is hard-coded zeros (intentional C compatibility, see `src/keys.rs:329`). `extract_public_key_from_secret` simply slices bytes 32..64 of the stored secret key and writes them out as the public key. An attacker who can flip those bytes gets `recreate` to emit an attacker-chosen public key whose scalar half does not match. Encrypted keys are protected by the Blake2b-256 checksum and so are immune; unencrypted keys are the live path.
- **Risk:** Tampered unencrypted key file produces a public key that does not actually match the signing scalar — confusing the user, and breaking trust if the recreated public key is published.
- **Fix:** Re-derive the public key from the 32-byte scalar via `ed25519_dalek::SigningKey::from_bytes(...)` then `.verifying_key()`, and compare against the stored half before emitting. A mismatch is a hard error.

#### H5. Off-by-one vs C in comment-length validation
- **Location:** `src/signature.rs:245, 257, 332, 357, 434, 444` (`SignatureBox::new`, `from_file_contents`, `with_global_signature`)
- **Problem:** Rust uses `untrusted.len() > COMMENTMAXBYTES` (1024) and `trusted.len() > TRUSTEDCOMMENTMAXBYTES` (8192). C uses `>=` against `MAX - sizeof(prefix)` (i.e. 1024-20 and 8192-18) because the prefix and newline must fit in C's fgets buffer. `create_signature` already applies the C-compat length at `src/ops/sign.rs:542-552`; the public constructors and the parser do not.
- **Risk:** Rust signs files whose comments would be rejected (or truncated) by C-side verifiers — a real interop break, not a theoretical one.
- **Fix:** Replace the strict `>` checks with `>= COMMENTMAXBYTES - COMMENT_PREFIX_SIZE` and `>= TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE` consistently in all six call sites.

#### H6. TOCTOU on prehashed `verify -o` output
- **Location:** `src/ops/verify.rs:386-395`
- **Problem:** Prehashed verify with `--output` does: open file → stream-hash → verify signature on hash → rewind fd → `io::copy` to stdout. An attacker with write access to the message file can modify its content *after* hashing/verification but *before* the bytes are emitted (open fd sees in-place truncate/rewrite). The `verify` succeeds against pre-tamper content; stdout receives post-tamper content. Pure mode buffers the file fully and is safe.
- **Risk:** `minisign_rs -V -o file.bin | tar x` (or similar pipe-after-verify) cannot trust the bytes that emerge.
- **Fix (pick one):** (a) memory-map the file with `MAP_PRIVATE` so subsequent writes are not visible; (b) advisory-flock the fd before hashing; (c) at minimum, document the gap in the `--output` help text and refuse to combine `-H -o` for files exceeding a "buffer it instead" threshold.

### Medium

#### M1. `atomic_overwrite_secret_key` does not fsync the parent directory after rename
- **Location:** `src/ops/file_utils.rs:274` (and the same gap exists implicitly for the `change-password` write path)
- **Problem:** POSIX guarantees rename is atomic with respect to other observers, but durability of the directory entry against a crash requires an explicit `fsync` of the directory inode. `generate.rs::commit_keypair_files` does this; `atomic_overwrite_secret_key` does not.
- **Fix:** Append a `sync_parent_directory(path)` call (move the helper out of `generate.rs` into a shared module) after the rename succeeds.

#### M2. Non-`force` secret-key write is not atomic
- **Location:** `src/ops/file_utils.rs:286-302` (`write_secret_key_file_impl` non-force branch routes to `write_file`)
- **Problem:** Initial key creation under `--no-password`-like fast paths and the change-password output on Windows both go through `write_file`, which `OpenOptions::create_new(true).write(true)` then `write_all`. No fsync, no temp, no atomic rename. A crash mid-write leaves an empty or partial-base64 secret key file. The `change` operation always passes `force=true` so on Unix it gets `atomic_overwrite_secret_key` — but on Windows it falls through to truncate+write with the same risk. `generate.rs` catches the Windows case and refuses; `change.rs` does not.
- **Fix:** Route both create-new and overwrite secret-key writes through a shared atomic-write helper (write tmp → fsync → rename → fsync parent). On Windows, refuse the change-password path until a Windows atomic-rename equivalent (`MoveFileEx(..., MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`) is implemented, mirroring generate.rs.

#### M3. Scrypt API misuse: `Params::new(.., 64)` vs `output.len() == 104`
- **Location:** `src/crypto.rs:556-572` (`derive_key_with_params`)
- **Problem:** `Params::new` rejects `len > 64`, so we pass `params_len = output_len.min(64)`, but call `scrypt(..., &mut output)` with a 104-byte output. This relies on the undocumented (in the `scrypt` crate's public docs) behaviour that the low-level `scrypt()` ignores `Params.len` and uses `output.len()`. The pin to `scrypt = "=0.11.0"` mitigates today; an upgrade that starts honoring `Params.len` would silently produce a 64-byte derived key with the trailing 40 bytes left zero — XORing zero into the encrypted blob exposes 40 bytes of plaintext (8 bytes of secret-key tail + 32-byte checksum) on disk. The `debug_assert_eq!` only catches it in debug builds and only checks length.
- **Fix:** Convert the debug assert into a runtime check (`return Err` if length differs), and add a regression test that asserts `derived_key[64..]` is non-zero for a realistic password+salt — pinning the contract. Long-term: derive in two 64-byte rounds with a counter to remove the dependency on the implementation detail.

#### M4. Post-sign self-verification missing (parity gap with C)
- **Location:** `src/ops/sign.rs:521-589` (`create_signature`)
- **Problem:** C minisign re-verifies a freshly produced signature against its corresponding public key (`minisign.c:657-663`) and aborts with "Verification would fail with the given public key". Rust does not. ed25519-dalek does not produce silently bad signatures in safe Rust, so this is unlikely to fire today — but it would catch a future bug in our crypto wrapper layer or memory corruption from another crate.
- **Fix:** After computing both signatures in `create_signature`, derive the public key from the secret scalar (the fixed version of finding H4) and call `crypto_verify` on both signatures before serializing the `.minisig`.

#### M5. `read_message_file` allocates from metadata-derived size, no parallel-OOM guard
- **Location:** `src/ops/file_utils.rs:375` and parallel sign/verify in `src/ops/sign.rs:330-376`, `src/ops/verify.rs:266-312`
- **Problem:** Non-prehashed mode buffers the full file (up to `MAX_MESSAGE_SIZE_BYTES = 1 GB`) into memory. With the `parallel` feature enabled, rayon may run as many workers as cores — peak RSS becomes `cores × 1 GB` on a multi-file legacy-mode batch. Default mode is prehashed, so users have to opt in via `-l`, but it is a real footgun.
- **Fix:** Either reduce per-worker concurrency for legacy-mode batches (limit to a single in-flight buffer) or enforce a smaller limit when the parallel feature is active. At minimum, document the memory cost in the `-l` help text.

#### M6. KDF fallback warning is post-hoc and stderr-only
- **Location:** `src/keys.rs:351-414` (warning emitted *after* successful derivation)
- **Problem:** When `--allow-kdf-fallback` succeeds at reduced parameters, the only signal is `eprintln!("*** WARNING: REDUCED SECURITY PARAMETERS ***")`. In CI/non-interactive use, stderr may be swallowed or never read; the resulting key has up to 64× weaker brute-force resistance with no machine-readable signal.
- **Fix:** Add a `fallback_used` field to `GenerateResult` / `ChangeResult` and a CLI exit code (e.g. 3) when fallback was used. Optionally, require a second flag `--accept-weak-kdf` in addition to `--allow-kdf-fallback` before actually writing a weakened key.

#### M7. Best-effort secret/public parsing in `inspect` hides the real parse error
- **Location:** `src/ops/inspect.rs:204-215, 304-316`
- **Problem:** `inspect` tries `SeckeyStruct::from_file_contents`, then `PubkeyStruct::from_file_contents`, then returns the generic "File is not a valid minisign key". A truncated-by-one-byte secret key gets the generic error instead of the specific "expected 158 bytes, got 157", erasing useful diagnostic information.
- **Fix:** Sniff the `untrusted comment:` line ("minisign encrypted secret key" / "minisign secret key" / "minisign public key") and route to the matching parser, surfacing its specific error.

#### M8. `MINISIGN_CONFIG_DIR` silently ignored on non-UTF8 values
- **Location:** `src/cli.rs:325` (`default_secret_key_path`)
- **Problem:** `std::env::var("MINISIGN_CONFIG_DIR")` returns `Err(NotUnicode)` for env values that aren't UTF-8 (rare but realistic on locale-mangled systems). The code falls through to `~/.minisign/`, so the user thinks they are operating on the env-var path but is actually on the default — silently signing/generating keys in the wrong location.
- **Fix:** Use `std::env::var_os` and treat presence-but-not-readable (or empty string) as a hard error rather than silent fallback.

#### M9. Empty `--comment ""` bypasses the default comment
- **Location:** `src/ops/generate.rs:271`, `src/ops/recreate.rs:146`
- **Problem:** `cli.untrusted_comment.as_deref()` returns `Some("")` for `--comment ""`, not `None`. The default comment is bypassed and the public key file gets a literal `untrusted comment: ` line with nothing after the space. Some downstream tools may strip empty-comment lines.
- **Fix:** Treat `Some("")` as `None` in the comment-resolution helper, or reject explicitly with `Error::InvalidComment`.

#### M10. `change-password` `remove_password` flag is logically dead
- **Location:** `src/main.rs:586`
- **Problem:** `.remove_password(cli.no_password && new_password.is_none())` — but `new_password` is `None` iff `cli.no_password` is true (lines 577-583), so the condition is just `cli.no_password`. A future refactor that decouples them silently keeps the password instead of removing it.
- **Fix:** Drop the redundant `&& new_password.is_none()` and add a precondition assertion that `cli.no_password` implies `new_password.is_none()`.

#### M11. `keyring` returns secrets through a non-Zeroized String
- **Location:** `src/credential_store.rs:64-67`
- **Problem:** Wrapping the returned `String` in `Zeroizing` reuses the same heap buffer (correct), but the `keyring` crate's backend wire-protocol buffers (D-Bus message body, `SecKeychainItemCopyContent` output, Windows credential blob) are not zeroized and may live as duplicates in process memory. Conflicts with the "all secrets use Zeroize" rule.
- **Fix:** Document the residual exposure in `credential_store.rs` (one paragraph). Optionally migrate to `keyring::Entry::get_secret()` which returns `Vec<u8>` we can zeroize, plus consider a defence-in-depth re-keying with an OS-derived secret.

### Low

#### L1. Best-effort tmp/lock cleanups silently leak files
- **Locations:** `src/ops/file_utils.rs:278`, `src/ops/generate.rs:507-540, 565-624, 673-676`
- **Problem:** Cleanup of `.<name>.<nonce>.tmp` and `.<keyfile>.force.lock` files uses `let _ = std::fs::remove_file(...)`. On failure (transient FS error, AV scanner holding the handle), an orphan tmp file containing the encrypted secret key remains in the user's `~/.minisign/` directory; an orphan lock file blocks all future `--force` invocations until 30 s of timeout (and indefinitely after that, every run).
- **Fix:** Surface cleanup failures via `eprintln!("Warning: temp file <path> could not be removed: <e>; delete manually")`. For the lock, in `acquire_force_overwrite_lock` examine the lock file's mtime; if older than `2 × timeout`, treat it as stale and forcibly remove.

#### L2. `check_secret_key_permissions` silently no-ops when stat fails
- **Location:** `src/ops/file_utils.rs:43-58`
- **Problem:** The world-readable-secret-key warning depends on `std::fs::metadata(path)` succeeding. If it fails (EACCES on parent dir, symlink loop), the check is skipped silently — the user proceeds without ever learning the check did not run.
- **Fix:** Move the check to operate on the open file descriptor (after `File::open` in `load_secret_key`), so that whenever the key load succeeded the check has the metadata it needs. Log a stderr warning if the check itself fails.

#### L3. Path display is not control-character sanitised
- **Locations:** `src/ops/sign.rs:457`, `src/ops/verify.rs:519`
- **Problem:** A crafted filename like `evil.txt\033[1A\033[2KVerified ok` rewrites earlier terminal output. Modern terminals are largely hardened against the worst forms but ANSI rewriting and CR-line-overwrite are still viable spoofs.
- **Fix:** Add a small `sanitised_display(&Path) -> String` helper that escapes ASCII controls, 0x7F, and C1 codes, and route every user-facing print through it.

#### L4. Default trusted comment differs from C minisign
- **Location:** `src/ops/sign.rs:611-621` (`generate_default_trusted_comment`)
- **Problem:** Rust emits `timestamp:<unix_seconds>`. C emits `timestamp:<unix_seconds>\tfile:<basename>` and appends `\thashed` for prehashed. Both are valid (the trusted comment is just signed text) but tools that parse the trusted comment to extract the file name will misbehave on Rust-signed files.
- **Fix:** Match the C format byte-for-byte. Sanitise the basename per L3.

#### L5. Pre-1970 system clock silently produces `timestamp:0`
- **Location:** `src/ops/sign.rs:615-622`
- **Problem:** If the clock is before UNIX_EPOCH, an `eprintln!` warning fires but the signature is still produced with `timestamp:0`. The trusted comment is signed, so the bogus timestamp propagates indefinitely.
- **Fix:** Treat clock failure as a hard error — refuse to sign. Optionally also refuse if the clock is before a sanity floor (e.g. 2020-01-01) since systems with sub-2020 clocks are misconfigured by definition.

#### L6. `rpassword::read_password()` failure mode flattens SIGINT and termios state
- **Location:** `src/main.rs:925-927`
- **Problem:** All rpassword errors collapse to `Error::Io(...)`. SIGINT during the prompt (which rpassword catches and re-emits) is indistinguishable from real I/O failure; if rpassword's termios restoration fails the user's terminal can be left with `ECHO` disabled, and we don't try to recover.
- **Fix:** Distinguish `e.kind() == io::ErrorKind::Interrupted` to a dedicated `Error::Interrupted` and exit 130. After any password prompt error, attempt to restore termios (e.g. via `nix::sys::termios` or running `stty echo` as a fallback hint to the user).

#### L7. `read_to_string` for password files may orphan reallocations
- **Location:** `src/main.rs:898-900`
- **Problem:** `String::with_capacity(size)` is an estimate; `read_to_string` may resize and reallocate, orphaning earlier buffers that `Zeroizing` cannot wipe (it only zeroes the *current* buffer).
- **Fix:** Read into a `Zeroizing<Vec<u8>>` of fixed `MAX_PASSWORD_FILE_BYTES` capacity, then UTF-8-validate into a `String`, to guarantee no reallocations during the read.

#### L8. Batch sign canonicalisation falls back to user-supplied path
- **Location:** `src/ops/sign.rs:411` (`unwrap_or_else(|_| file.clone())`)
- **Problem:** Deduplication keys on `canonicalize()` to handle `./foo` vs `foo`. When canonicalisation fails the literal user path is used as the dedup key, so `./foo` and `foo` (both not-yet-canonicalisable) signal as distinct inputs and sign in parallel — both writing to the same target `.minisig` and racing.
- **Fix:** When `canonicalize` fails return `Error::file_read(path, e)` immediately — the file doesn't exist and signing it would fail anyway; failing earlier is less surprising.

#### L9. `default_pk` deferred-init in `handle_verify`
- **Location:** `src/main.rs:400-415`
- **Problem:** `let default_pk;` is declared outside the if-else, assigned only in the `else if` branch, then borrowed. Works today because the borrow only fires in that arm, but a future edit that moves the borrow outside breaks it.
- **Fix:** Hoist the path computation unconditionally above the match.

#### L10. Single-file vs multi-file verify outputs differ
- **Location:** `src/ops/verify.rs:474-486` vs `:489-503`
- **Problem:** One-file path prints "Verified: ... Trusted comment: ... Key ID: ..."; the multi-file branch prints `Verifying with key: ...` first, then per-file results. Scripts parsing this output break when file count crosses 1 → 2.
- **Fix:** Unify the format across both paths.

#### L11. Comment validation duplicated between `SignatureBox::new` and `with_global_signature`
- **Location:** `src/signature.rs:241-260, 425-448`
- **Problem:** Identical 7-line validation blocks appear twice. Easy to drift.
- **Fix:** Extract `validate_comments(untrusted, trusted)` helper.

#### L12. Duplicate code comment in `prompt_password`
- **Location:** `src/main.rs:877-878`
- **Problem:** "Open once; derive metadata from the fd to avoid TOCTOU races." appears verbatim twice.
- **Fix:** Delete one.

#### L13. `--save-password` may store a password the keyring cannot retrieve
- **Location:** `src/main.rs:178-204` (`save_password_to_credential_store`)
- **Problem:** The save path reports failure correctly, but does not verify a subsequent `get_password` returns the expected value. Some keyring backends silently drop secrets larger than implementation limits.
- **Fix:** After save, call `get_password(credential_id)` and compare ct_eq; if mismatch, surface a hard error so the user knows their save did not actually persist.

## Recommended ordering

1. **Wave 1 (correctness/data-loss):** H1 (KDF fallback), H2 (credential store error mapping), H3 (rollback visibility), H5 (C-compat off-by-one), M2 (non-force atomic write), M1 (parent-dir fsync). These are the cluster of issues that can produce silently-wrong on-disk state.
2. **Wave 2 (parity/robustness):** H4 (recreate trust), H6 (prehashed -o TOCTOU), M3 (scrypt API), M4 (post-sign verify), L4/L5 (timestamp parity), M11 (keyring zeroize doc).
3. **Wave 3 (UX/operational):** the remaining M and L items, batched by file.

Each wave should land with tests: bit-flip corruption tests for H4, a deliberate scrypt-truncation test for M3, a synthetic keyring-error injector for H2, and a crash-injection test for the rollback paths in H3 (the existing debug-only `inject_commit_failure_*` infrastructure in `generate.rs` is the model).

## Out of scope / not investigated

- Behaviour under filesystem-full conditions during multi-step keypair commit.
- Whether `keyring` 3.x caches the password in process memory beyond the explicit `get_password` call.
- Coverage of corruption-bit-flipping the encrypted blob (any single-bit flip in encrypted_keynum / sk / checksum *should* produce `ChecksumFailed`, not a crash; worth a property test).
- Windows path handling beyond reserved names — long-path / UNC behaviour, ADS streams.
