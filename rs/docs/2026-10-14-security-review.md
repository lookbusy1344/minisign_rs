# Security Review: minisign-rs

**Date:** 2026-10-14
**Scope:** Rust production code in `rs/src/`, compared against the C reference in `src/minisign.c`
**Baseline:** `bd9d6ff4` (`lb_rust`, "chore: updating dependencies")
**Reviewer:** Claude Code (claude-opus-5-5)
**Current security model:** [`../SECURITY.md`](../SECURITY.md)

## Summary

The review found no critical or high-severity issues. The cryptographic core matches C minisign. It found four defects and one risky default inherited from C. All five are fixed, one commit each, and each fix starts with a failing test.

| # | Severity | Finding | Fix |
|---|----------|---------|-----|
| 1 | Medium | `-K --password-file` read the current and the new password from the same file | `0682f480` |
| 2 | Low | `-G` created missing secret key directories with mode `0755` | `95f7bb61` |
| 3 | Low | Bytes from a signature file reached the terminal unescaped in an error message | `be103dea` |
| 4 | Low | Multi-file signing read the secret key file twice | `b5ac372c` |
| 5 | Low (inherited) | `-V` falls back to `./minisign.pub` without notice | `b684de37` |

After the fixes, pedantic clippy, the `unsafe_code` clippy pass and the full suite (609 tests, `--no-default-features`) pass. The suite includes the C cross-binary tests.

## Method

The review read every production module on these paths:

- parsing of signature, public key and secret key files
- verification and signing
- key encryption and the KDF
- file reading and writing
- password input and the credential store
- the CLI handlers in `main.rs`

Each security-relevant behaviour was compared with `src/minisign.c`. The review assumes these inputs are untrusted:

- signature files
- public keys
- secret key files from third parties
- the current working directory
- names of files being signed

## Findings

### 1. `-K --password-file` keeps the old password (Medium)

**Location:** `src/main.rs`, `handle_change`

`handle_change` passed `cli.password_file` both to the prompt for the current password and to `prompt_password_with_confirmation` for the new password. The key was re-encrypted with a fresh salt under the same password, and the command printed "Password changed". A script rotating a leaked password left the key under the leaked password.

An existing cross-binary test documented the behaviour in a comment ("we need to use the same file since `--password-file` is used for both current and new password") rather than flagging it.

**Fix:**
- `--password-file` now holds the current password only. `--new-password-file` supplies the new one.
- `-K --password-file` without `--new-password-file` or `-W` is a usage error, and so is `-K --password-file` on an unencrypted key. In both cases the key file is unchanged.
- `--new-password-file` is rejected with any action other than `-K`, and together with `-W`.

**Tests:** `tests/change_password.rs`. The C-to-Rust cross-binary test now also checks that the old password fails after the change.

### 2. Secret key directory created world-readable (Low)

**Location:** `src/ops/generate.rs`, `ensure_parent_directory`

`create_dir_all` applies the umask, so a missing `~/.minisign` was created `0755`. The key file itself is `0600`, so the exposure is limited to the directory listing. C creates the directory `0700` (`basedir_create_useronly`).

**Fix:** `ensure_secret_key_directory` creates missing directories with `DirBuilder` and mode `0700`. Existing directories keep their mode. The public key's directory is unchanged.

**Tests:** `tests/key_directory.rs`.

### 3. Unescaped signature bytes in an error message (Low)

**Location:** `src/signature.rs`, `SigStruct::from_bytes`

An unknown signature algorithm produced an error that embedded the two `sig_alg` bytes through `String::from_utf8_lossy`. A crafted `.minisig` could send `ESC c` (terminal reset) or the UTF-8 encoding of U+009B (CSI) to stderr. Comments and paths were already escaped everywhere else.

**Fix:** the bytes are printed with `escape_ascii`.

**Tests:** `tests/unit/signature.rs`, with ESC, C1 CSI, and printable ASCII.

### 4. Multi-file signing read the key file twice (Low)

**Location:** `src/main.rs`, `handle_sign`; `src/ops/sign.rs`, `sign_multiple_files`

`handle_sign` loaded the secret key, checked its KDF budget and looked up its password in the credential store. `sign_multiple_files` then read the key file again. If the file was replaced between the two reads, the password stored for the first key was used to decrypt the second, and the budget check did not apply to the second read. Exploiting this needs write access to the key file. The single-file path already passed the loaded key through.

**Fix:** `sign_multiple_files_with_key` takes the loaded `SeckeyStruct`, and `main.rs` uses it. `sign_multiple_files` remains as a wrapper that loads the key once.

**Tests:** `tests/unit/ops/sign.rs`. The key file named in the options holds a different key from the one passed in, and every signature must verify against the key passed in. The tests fail when the re-read is restored.

### 5. Default public key from the working directory (Low, inherited)

**Location:** `src/main.rs`, `handle_verify`

Without `-p` or `-P`, `-V` reads `./minisign.pub`, as C does. Inside an unpacked download, that file can come from the same source as the message and the signature, and verification then proves nothing.

**Fix:** the fallback still works, for C compatibility, but now prints a warning to stderr unless `-q` is given.

**Tests:** `tests/default_public_key.rs`.

## Checked, no issue found

- **Verification:**
  - `verify_strict` plus an `is_weak` check rejects small-order public keys, small-order `R` and non-canonical `S`.
  - The key ID is compared in constant time before any message I/O.
  - The trusted comment and `-o` output are released only after both the message signature and the global signature verify.
  - `-o` hashes and emits the same buffer, so the file cannot change between check and output.
- **KDF parameters from key files:**
  - Only the exact minisign encoding is accepted: r = 8, p = 1, N a power of two.
  - `memlimit` is capped at 1 GiB before any password prompt or credential-store access.
  - A runtime guard detects a `scrypt` crate change that would leave derived bytes past index 64 as zero.
- **Key decryption:**
  - The checksum is compared in constant time.
  - Decrypted buffers are zeroized on both the success and the failure path.
  - `SigningKey::from_keypair_bytes` rejects a secret key whose public half does not match its scalar.
  - Signing re-verifies both signatures against a public key derived from the scalar.
- **File writes:**
  - Secret keys are created `0600` with `O_NOFOLLOW`.
  - Creation uses `hard_link` from a temporary file, so an existing file is never overwritten.
  - `--force` replaces files by atomic rename.
  - An output path that resolves to an input file or the secret key is rejected.
- **Input bounds:**
  - Key files are capped at 4 KiB, signature files at 16 KiB and password files at 1 KiB.
  - Non-prehashed messages are capped at 1 GiB.
  - Password files must be regular files and are read without blocking.
- **Comments and paths:** trusted and untrusted comments reject C0 and C1 control characters. Displayed paths are escaped.
- **Credential store:**
  - Entries are keyed by the encrypted keynum.
  - A crafted key file that reuses another key's credential ID gets that password run through its own salt. The command only reports a checksum failure, which reveals nothing about the password.

## Not covered

- `cargo audit` was not run for this review. The 2026-10-01 audit recorded no known vulnerabilities.
- Windows code paths were read but not run.
- Fuzzing was not extended.
