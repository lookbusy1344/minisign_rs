# Security Review: minisign-rs

**Date:** 2026-11-10
**Scope:** Rust production code in `rs/src/`
**Baseline:** `d23bc0a1` (`lb_rust`)
**Reviewer:** Claude Code (claude-opus-5-5)
**Current security model:** [`../SECURITY.md`](../SECURITY.md)

## Summary

The review found no critical or high-severity issues. It found three defects, all fixed with a failing test first, and two inherited behaviours, now documented under known limitations.

| # | Severity | Finding | Outcome |
|---|----------|---------|---------|
| 1 | Low–Medium | File names reached the terminal unescaped in UTF-8 errors | Fixed |
| 2 | Low | `-K` read the secret key file twice | Fixed |
| 3 | Low | `--password-file` stripped all trailing whitespace | Fixed |
| 4 | Low (inherited) | Special files stall verification | Documented |
| 5 | Info (inherited) | Trusted comments may hold bidi and zero-width characters | Documented |

## Findings

### 1. Unescaped file names in UTF-8 errors (Low–Medium)

**Location:** `src/ops/file_utils.rs`, `read_bounded_string_from_reader` and `utf8_text`

`Error::InvalidUtf8` carried `path.display()`, and its message printed it raw. All other path errors escape control characters.

An archive can hold a file whose name contains escape sequences, next to a `.minisig` with invalid UTF-8. `minisign -V -p key.pub -m *` then wrote the raw bytes to stderr. In batch mode the `Failed:` prefix escaped the name and the error after it did not, so a name with `\r` and `ESC [2K` could erase the failure line and draw a fake `Verified:` line. The exit code stayed non-zero.

**Fix:** the error context uses `sanitised_path_display`.

**Tests:** `tests/unit/ops/file_utils.rs`, `utf8_error_path_escaping`, with ESC, BEL and C1 CSI in the name, through both the signature and the secret key read.

### 2. `-K` read the key file twice (Low)

**Location:** `src/main.rs`, `handle_change`; `src/ops/change.rs`

`handle_change` loaded the key, checked its KDF budget and fetched its password from the credential store. `change` then read the file again. If the file was replaced in between, the password for the first key was tried on the second, and the credential entry deleted afterwards belonged to the first key. `decrypt` applies the KDF budget itself, so the second read could not bypass it. Exploiting it needs write access to the key directory. This is finding 4 of the 2026-10-14 review, on the `-K` path.

**Fix:** `change_with_key` takes the loaded `SeckeyStruct`, and `main.rs` uses it.

**Tests:** `tests/unit/ops/change.rs`, `test_change_with_key_uses_held_key_not_file`. The key file holds a different key from the one passed in, and the written file must decrypt to the key passed in.

### 3. `--password-file` stripped trailing whitespace (Low)

**Location:** `src/main.rs`, `prompt_password`

The file contents went through `trim_end`, which removes spaces and tabs as well as the line ending. The interactive prompt keeps them. A password ending in a space gave different keys depending on how it was entered, and a key encrypted from a file got a shorter password than the one written.

**Fix:** one trailing `\n` or `\r\n` is stripped, and nothing else.

**Tests:** `tests/password_file.rs`, `only_one_line_ending_is_stripped`.

### 4. Special files stall verification (Low, inherited)

`read_file_bounded` and the streamed prehash path open files without a regular-file check. A FIFO named `file.minisig` blocks, and a message that is a symlink to `/dev/zero` makes prehashed verification run without end. C behaves the same. Documented in `SECURITY.md` under known limitations.

### 5. Bidi and zero-width characters in trusted comments (Info, inherited)

`is_printable` rejects C0, C1 and DEL, as C does, and accepts characters such as U+202E. The default trusted comment embeds the signed file's base name, and a tab in that name adds a second `file:` field. Rejecting these would break compatibility with C. Documented in `SECURITY.md` under known limitations.

## Not covered

- `cargo audit` was not run.
- Windows code paths were read but not run.
