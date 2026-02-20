# Security Audit: minisign Rust Implementation (with C/Zig Comparison)

**Date:** 2026-02-20
**Scope:** All Rust source files in `rs/` — 18 production source files, `Cargo.toml`, `Cargo.lock`
**Auditor:** Claude Code (claude-opus-4-6)
**Companion report:** `2026-02-20-c-zig-security-audit.md` (same date)

---

## Audit Scope

Files examined:

- `src/main.rs` — CLI entry point, password prompting, orchestration
- `src/lib.rs` — public API re-exports
- `src/cli.rs` — argument parsing (clap derive)
- `src/constants.rs` — named constants (sizes, limits, prefixes)
- `src/errors.rs` — error types
- `src/crypto.rs` — Ed25519 signing/verification, Blake2b, scrypt KDF, KeyNum
- `src/keys.rs` — `PubKey`, `SecretKey`, `SeckeyStruct`, serialization/deserialization
- `src/signature.rs` — `SignatureBox` parsing and serialization
- `src/formats.rs` — base64 encoding/decoding helpers
- `src/validation.rs` — input validation functions
- `src/wordlist.rs` — BIP39-style mnemonic wordlist
- `src/credential_store.rs` — OS keyring integration
- `src/ops/mod.rs` — operation module exports
- `src/ops/sign.rs` — single-file and multi-file signing
- `src/ops/verify.rs` — signature verification
- `src/ops/generate.rs` — keypair generation
- `src/ops/change.rs` — password change
- `src/ops/recreate.rs` — public key recreation from secret key
- `src/ops/inspect.rs` — key/signature inspection
- `src/ops/file_utils.rs` — file I/O helpers
- `Cargo.toml` — dependencies and build configuration
- `Cargo.lock` — pinned dependency versions

---

## Key Structural Properties

Before the detailed findings, three properties dominate the security posture:

1. **Zero `unsafe` blocks.** A sweep of all 18 source files found no `unsafe` keyword. The entire Rust memory safety guarantee applies without caveat — no buffer overflows, no use-after-free, no double-free, no uninitialized memory reads are possible in this codebase.

2. **Zero `.unwrap()` in production code.** All `Option`/`Result` handling uses `unwrap_or`, `unwrap_or_else`, `?`, or pattern matching. The only `.expect()` calls are three structurally-unreachable assertions (RS-4 below).

3. **Cryptographic dependencies pinned to exact versions.** `ed25519-dalek`, `blake2`, `scrypt`, `zeroize`, `subtle`, and `rand_core` all use `=version` pinning in `Cargo.toml`, significantly reducing supply-chain risk.

---

## Part 1 — Comparison: C/Zig Findings vs. Rust Implementation

### C-1 (Critical): `sodium_malloc`/`sodium_free` — No Secret Zeroization

**Rust status: RESOLVED**

The Rust implementation uses the `zeroize` crate with Rust's RAII model:

| Type | Location | Protection |
|------|----------|------------|
| `SecretKey` | `crypto.rs:47-48` | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| `SeckeyStruct` | `keys.rs:268` | `#[derive(Zeroize, ZeroizeOnDrop)]` |
| `KeyNum` | `crypto.rs:137` | `#[derive(Zeroize)]` |
| KDF output | `crypto.rs:529` | `Zeroizing<Vec<u8>>` |
| Decrypted blob | `keys.rs:492` | `Zeroizing<[u8; 104]>` |
| Passwords | `main.rs` (all prompts) | `Zeroizing<String>` |

The compiler enforces that `Drop` (and therefore `ZeroizeOnDrop`) runs on all exit paths — including early returns, `?` propagation, and panics (with default unwinding). The C code relied on manual `sodium_free` calls that could be missed; Rust makes this structurally impossible.

---

### C-2 (High): `crypto_generichash_state` Opaque Buffer — No Compile-Time Size Assertion

**Rust status: RESOLVED**

The Rust implementation uses the `blake2` crate's generic types:

- `Blake2b::<U32>` for checksums (`crypto.rs:288`)
- `Blake2b512` for prehashed signing (`crypto.rs:306`)

Output sizes are type-level constants (`U32`, `U64`) enforced at compile time. There is no opaque buffer, no manual size tracking, and no alignment forwarding. The streaming path uses `Digest::finalize()` which returns a correctly-sized `GenericArray`. This problem class does not exist in Rust's type system.

---

### C-3 (High): `memcmp` for Checksum Comparison — Non-Constant-Time

**Rust status: RESOLVED**

All security-sensitive comparisons use the `subtle` crate (pinned to `=2.6.1`):

| Comparison | Location | Method |
|-----------|----------|--------|
| Checksum after KDF | `keys.rs:514` | `computed_checksum.ct_eq(&decrypted_checksum)` |
| KeyNum during verify | `ops/verify.rs:321` | `pubkey.keynum().ct_eq(sig_box.sig_struct().keynum())` |
| Password confirmation | `main.rs:873` | `ct_eq` |

No `==` or `memcmp`-equivalent comparisons were found for any security-sensitive data.

---

### C-4 (High): `unsigned long` for KDF Params — Type Width Mismatch

**Rust status: RESOLVED**

All KDF parameters are `u64` throughout. Conversions from `opslimit`/`memlimit` to scrypt-native parameters use `checked_mul`, `checked_div`, and `u8::try_from`/`u32::try_from` with explicit error propagation (`crypto.rs:438-488`). Rust's `u64` is exactly 8 bytes on all targets — no architecture-dependent width variation exists.

---

### C-5 (High): `trim()` Return Value Discarded for Global Signature Line

**Rust status: RESOLVED**

The Rust parser uses `str::lines()` which strips `\n` and `\r\n` terminators automatically. The four-line structure is enforced by:

```rust
// signature.rs:299-303
if lines.len() != 4 {
    return Err(Error::InvalidSignatureFormat(...));
}
```

No manual trim calls exist that could have return values discarded.

---

### C-6 (Medium): `xfprintf` 4096-byte Buffer vs. 8192-byte `TRUSTEDCOMMENTMAXBYTES`

**Rust status: RESOLVED**

There are no fixed-size formatting buffers. Rust's `String` grows dynamically. Comment lengths are checked against named constants (`COMMENTMAXBYTES` = 1024, `TRUSTEDCOMMENTMAXBYTES` = 8192) defined consistently in `signature.rs:18,21` and enforced in all code paths.

---

### C-7 (Medium): KDF Error Path Does Not Zero/Free Sensitive Buffers

**Rust status: RESOLVED**

All sensitive buffers are `Zeroizing<T>`. When a KDF derivation fails and returns `Err`, Rust drops all local variables, and `ZeroizeOnDrop` clears buffer contents before deallocation. The fallback loop in `keys.rs:372-403` handles partial iterations correctly because derived keys from failed attempts are `Zeroizing` and dropped at scope exit.

---

### C-8 (Medium): `trim()` Return Value Discarded for `sk_comment_line`

**Rust status: RESOLVED**

Same mechanism as C-5 — the secret key file parser (`keys.rs:853-864`) uses `.lines()`, which strips terminators. No manual trim calls.

---

### C-9 (Medium): `fopen_create_useronly` Follows Symlinks — TOCTOU

**Rust status: PARTIALLY MITIGATED**

Fresh creation uses `OpenOptions::create_new(true)` (`file_utils.rs:72`), which maps to `O_CREAT | O_EXCL` — atomic, rejects symlinks. This fully resolves the non-force case.

**Residual risk:** Force-overwrite uses `.create(true).truncate(true)` without `O_NOFOLLOW`. See RS-9 below.

---

### C-10 (Medium): `opt_seen` Bitmap Boundary Condition

**Rust status: NOT APPLICABLE**

The Rust implementation uses `clap` with derive macros and `group = "action"` for mutual exclusivity. No hand-rolled bitmask arithmetic exists.

---

### C-11 (Medium): Password Truncation Leaves Residual Bytes in `stdin`

**Rust status: RESOLVED**

Password reading uses `rpassword::read_password()` (`main.rs:849`), which reads until newline and returns the complete string. There is no fixed buffer, no truncation, and no stdin residue.

---

### C-12 (Medium): `pwd2` Held in Memory for Full KDF Duration

**Rust status: SUBSTANTIALLY MITIGATED**

The confirmation password is `Zeroizing<String>`. After the `ct_eq` comparison (`main.rs:873`), it goes out of scope when `prompt_password_with_confirmation` returns (`main.rs:884`), zeroing the buffer. The window where both passwords coexist is nanoseconds (the function return), not the multi-second KDF duration as in C.

---

### C-13 (Medium): No File Size Cap; `abort()` on `SIZE_MAX`

**Rust status: RESOLVED**

A 1 GB cap is enforced via `MAX_MESSAGE_SIZE_BYTES` (`constants.rs:78`), checked before `fs::read` in both sign and verify paths (`file_utils.rs:154-159`). Files above the limit get a clean error message guiding users to prehashed mode. No `abort()` or allocator panic.

---

### C-14 (Low): `crypto_sign_detached` Return Value Not Checked

**Rust status: RESOLVED**

Both signing calls use `?` for error propagation:
- First signature: `ops/sign.rs:532`
- Global signature: `ops/sign.rs:539`

---

### C-15 (Low): Key Existence Check TOCTOU

**Rust status: PRESENT, BENIGN**

`main.rs:77-82` uses `exists()` before scrypt, then `create_new()` atomically. The TOCTOU can only cause a spurious `FileExists` error (not a security bypass) because `create_new()` is atomic. The C code's TOCTOU between `access()` and `fopen_create_useronly()` had a genuine race; the Rust race has no security consequence.

---

### C-16 (Low): `file_basename` Returns Aliased Interior Pointer

**Rust status: NOT APPLICABLE**

Path handling uses `PathBuf` (owned) and `&Path` (borrowed with explicit lifetimes). The borrow checker enforces that references cannot outlive the data they point to. Dangling pointer issues are structurally impossible in safe Rust.

---

### C-17 (Low): `sodium_bin2hex` Does Not Null-Terminate on Error

**Rust status: NOT APPLICABLE**

Hex formatting uses `format!("{b:02X}")` in `KeyNum::to_hex()` (`crypto.rs:178`), returning an owned `String`. No null-termination concerns exist.

---

### C-18 (Low): No Compiler Hardening Flags

**Rust status: PARTIALLY PRESENT**

See RS-5 below. Rust's memory safety eliminates the buffer-overflow/stack-smash classes, but integer overflow checks and LTO are still relevant.

---

### C-19 (Info): Distribution Script Signs With Ambient Binary

**Rust status: NOT APPLICABLE** — no distribution script in `rs/`.

---

### C-20 (Info): Typo `LICEMSE` in `build.zig.zon`

**Rust status: NOT APPLICABLE** — `Cargo.toml` spells `license = "ISC"` correctly.

---

## Part 2 — New Rust-Specific Findings

### RS-1 — Medium: `ScryptParams::new` Receives Incorrect Output Length

**Severity:** Medium
**File:** `src/crypto.rs`, lines 531-539

```rust
let params_len = output_len.min(64);
let params = ScryptParams::new(log_n, r, p, params_len)
    .map_err(|e| Error::KdfError(format!("invalid scrypt parameters: {e}")))?;

scrypt(password, salt, &params, &mut output)
    .map_err(|e| Error::KdfError(format!("scrypt failed: {e}")))?;
```

**Vulnerability:** The scrypt crate's `Params::new` validates output length against a maximum of 64 bytes. The code caps the `Params` length at 64 but passes a 104-byte output buffer to the low-level `scrypt()` function. This works because `scrypt()` ignores `Params.len` and uses the buffer length directly.

If a future scrypt crate version changes `scrypt()` to respect `Params.len`, or adds a buffer-length check, the result is either a silently truncated KDF output (corrupting all keys) or a hard error. The code documents this coupling in comments, but it remains a fragile dependency on crate internals.

**Remediation:** Add an integration test that verifies a 104-byte scrypt derivation against a known-good test vector, catching any silent regression on crate upgrade.

---

### RS-2 — Low: Untrusted Comment Prefix Not Required on Parse

**Severity:** Low
**File:** `src/signature.rs`, lines 307-310

```rust
let untrusted_comment = lines[0]
    .strip_prefix("untrusted comment: ")
    .unwrap_or(lines[0])
    .to_string();
```

**Vulnerability:** If the first line of a `.minisig` file lacks the `"untrusted comment: "` prefix, the raw line is silently accepted as the comment body. The trusted comment on line 3 correctly requires its prefix via `.ok_or_else()`. This asymmetry means a crafted signature file with no untrusted comment prefix parses without error.

Practical impact is low — the untrusted comment is not authenticated and does not affect verification. But the inconsistency with trusted comment handling is a code quality defect.

**Remediation:** Apply the same `.ok_or_else()` pattern, or document why silent fallback is intentional.

---

### RS-3 — Low: Timestamp Silently Defaults to Zero on Clock Failure

**Severity:** Low
**File:** `src/ops/sign.rs`, lines 573-578

```rust
let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0);
```

**Vulnerability:** On systems with incorrect clocks (embedded, Wasm, broken NTP), `duration_since` fails and the timestamp silently becomes `"timestamp:0"`. This could mislead users relying on timestamp freshness. The C code has the same issue (`time(NULL)` returns `-1` on failure, which is silently embedded).

**Remediation:** Emit a warning to stderr on fallback.

---

### RS-4 — Low: `.expect()` Calls in Production Code

**Severity:** Low
**Files:** `src/keys.rs` lines 735, 740; `src/crypto.rs` line 197

```rust
write_u64_le(&mut bytes[...], self.kdf_opslimit)
    .expect("opslimit range is exactly 8 bytes");
```

```rust
let value = read_u64_le(&self.0).expect("KeyNum is always 8 bytes");
```

**Vulnerability:** These `.expect()` calls are structurally unreachable — the slice ranges are compile-time constants that provably produce 8-byte slices, and `KeyNum` is `[u8; 8]` by construction. However, `.expect()` in production paths introduces a theoretical panic vector. If the surrounding offset constants were ever refactored incorrectly, the process would panic with a stack trace rather than returning a clean error.

**Remediation:** Replace with direct byte operations:

```rust
bytes[OFFSET..OFFSET+8].copy_from_slice(&self.kdf_opslimit.to_le_bytes());
let value = u64::from_le_bytes(self.0);
```

---

### RS-5 — Low: Release Profile Missing Hardening Flags

**Severity:** Low
**File:** `Cargo.toml`, lines 63-65

```toml
[profile.release]
strip = true
```

**Vulnerability:** The release profile omits:
- `overflow-checks = true` — Rust release builds do not check integer overflow by default
- `lto = true` — reduces binary attack surface, improves dead-code elimination
- `panic = "abort"` — prevents stack unwinding from executing destructors in unexpected order
- `codegen-units = 1` — improves LTO effectiveness

While Rust's memory safety eliminates the buffer overflow class, integer overflow in release builds wraps silently, which could produce incorrect sizes or offsets in arithmetic-heavy code paths.

**Remediation:**

```toml
[profile.release]
strip = true
overflow-checks = true
lto = true
panic = "abort"
codegen-units = 1
```

---

### RS-6 — Low: `MINISIGN_CONFIG_DIR` Environment Variable Not Sanitised

**Severity:** Low
**File:** `src/cli.rs`, lines 207-210

```rust
if let Ok(config_dir) = std::env::var("MINISIGN_CONFIG_DIR") {
    PathBuf::from(config_dir).join("minisign.key")
}
```

**Vulnerability:** An attacker who can set environment variables (SUID wrapper, CI pipeline injection) can redirect the default secret key path to an arbitrary location, causing the tool to read an attacker-controlled key file. The write path uses `create_new(true)` (atomic), but the read path follows symlinks without restriction.

**Remediation:** Document that `MINISIGN_CONFIG_DIR` is trusted input. Optionally validate the path is absolute and contains no `..` components.

---

### RS-7 — Info: Parallel Signing Shares `SecretKey` Across Threads

**Severity:** Informational
**File:** `src/ops/sign.rs`, lines 400-408

```rust
files.into_par_iter().map(|file| {
    let result = sign_file_with_key(&file, &secret_key, keynum, options);
    // ...
})
```

The secret key is shared across Rayon threads via an immutable reference. This is safe per Rust's `Send + Sync` guarantees, and `ed25519-dalek` recreates the `SigningKey` for each call. However, the key bytes residing at a single address throughout all parallel operations means cache-line side-channel attacks are theoretically possible. This is inherent to all multi-threaded signing; the implementation does not make it worse.

---

### RS-8 — Info: OS Keyring Copy of Password Not Zeroized

**Severity:** Informational
**File:** `src/credential_store.rs`, lines 49-58

The `keyring` crate's `set_password` takes `&str` and internally copies it into OS-provided buffers (Keychain, libsecret). This copy is not under the application's control and is not `Zeroizing`. The Rust-side copy is properly `Zeroizing<String>`, but the intermediate representation inside the `keyring` crate's call stack is not cleared. This is an inherent limitation of the OS keyring API surface.

---

### RS-9 — Medium: Force-Overwrite (`-f`) Follows Symlinks on POSIX

**Severity:** Medium
**File:** `src/ops/file_utils.rs`, lines 69-71, 81-87

```rust
if force {
    options.create(true).truncate(true);
}
```

**Vulnerability:** When `force = true`, `OpenOptions` uses `.create(true).truncate(true)` without `O_NOFOLLOW`. On Linux/macOS, this follows symlinks. An attacker who can create a symlink at the key path before `minisign_rs -G -f` runs will cause key material to be written to the symlink target.

Exploitation requires write access to `~/.minisign/` (0700 by default), limiting feasibility.

**Remediation:** Use `O_NOFOLLOW` via `std::os::unix::fs::OpenOptionsExt`:

```rust
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}
```

---

## Summary Tables

### Comparison: C/Zig Findings in Rust

| # | C/Zig Severity | Finding | Rust Status |
|---|---|---|---|
| 1 | **Critical** | No secret zeroization | **RESOLVED** — `ZeroizeOnDrop` throughout |
| 2 | **High** | Opaque hash buffer, no size assertion | **RESOLVED** — type-safe generic Blake2b |
| 3 | **High** | `memcmp` checksum (non-constant-time) | **RESOLVED** — `subtle::ct_eq` everywhere |
| 4 | **High** | `unsigned long` type width mismatch | **RESOLVED** — `u64` with checked arithmetic |
| 5 | **High** | `trim()` return discarded for global sig | **RESOLVED** — `.lines()` strips terminators |
| 6 | **Medium** | Buffer size conflict 4096 vs 8192 | **RESOLVED** — heap `String`, named constants |
| 7 | **Medium** | KDF error path leaks sensitive buffers | **RESOLVED** — `Zeroizing` RAII |
| 8 | **Medium** | `trim()` return discarded for sk comment | **RESOLVED** — `.lines()` strips terminators |
| 9 | **Medium** | `fopen_create_useronly` follows symlinks | **PARTIAL** — create_new is safe; force-overwrite is not |
| 10 | **Medium** | `opt_seen` bitmask boundary | **N/A** — `clap` handles this |
| 11 | **Medium** | Password truncation stdin residue | **RESOLVED** — `rpassword`, no truncation |
| 12 | **Medium** | `pwd2` held for KDF duration | **MITIGATED** — `Zeroizing`, nanosecond window |
| 13 | **Medium** | No file size cap, `abort()` | **RESOLVED** — 1 GB cap, clean error |
| 14 | **Low** | `crypto_sign_detached` unchecked | **RESOLVED** — `?` on both calls |
| 15 | **Low** | Key existence check TOCTOU | **BENIGN** — `create_new` is atomic |
| 16 | **Low** | `file_basename` dangling pointer | **N/A** — Rust ownership/lifetimes |
| 17 | **Low** | `sodium_bin2hex` null-termination | **N/A** — Rust `String`/`fmt` |
| 18 | **Low** | No compiler hardening flags | **PARTIAL** — see RS-5 |
| 19 | **Info** | Distribution script ambient signing | **N/A** |
| 20 | **Info** | Typo `LICEMSE` | **N/A** |

### New Rust-Specific Findings

| # | Severity | Location | Category | Title |
|---|---|---|---|---|
| RS-1 | **Medium** | `crypto.rs:531-539` | Crypto / Compatibility | ScryptParams output length coupling to crate internals |
| RS-2 | **Low** | `signature.rs:307-310` | Input Validation | Untrusted comment prefix not required on parse |
| RS-3 | **Low** | `ops/sign.rs:573-578` | Error Handling | Timestamp silently defaults to zero on clock failure |
| RS-4 | **Low** | `keys.rs:735,740`, `crypto.rs:197` | Error Handling | `.expect()` in production code (structurally unreachable) |
| RS-5 | **Low** | `Cargo.toml:63-65` | Build | Release profile missing hardening flags |
| RS-6 | **Low** | `cli.rs:207-210` | Input Validation | `MINISIGN_CONFIG_DIR` env var unsanitised |
| RS-7 | **Info** | `ops/sign.rs:400-408` | Side-channel | Parallel signing shares SecretKey across threads |
| RS-8 | **Info** | `credential_store.rs:49-58` | Crypto | OS keyring copy of password not zeroized |
| RS-9 | **Medium** | `ops/file_utils.rs:69-71` | Path Traversal | Force-overwrite follows symlinks on POSIX |

### Risk Assessment

| Severity | C/Zig | Rust | Delta |
|----------|-------|------|-------|
| Critical | 1 | 0 | -1 |
| High | 4 | 0 | -4 |
| Medium | 8 | 2 | -6 |
| Low | 5 | 4 | -1 |
| Informational | 2 | 2 | 0 |
| **Total** | **20** | **8** | **-12** |

---

## Architectural Comparison

### What Rust Eliminates Structurally

These C/Zig vulnerability classes **cannot exist** in the Rust implementation:

| Class | C/Zig Findings | Rust Mechanism |
|-------|---------------|----------------|
| Buffer overflow | C-2, C-6 | Bounds checking on all array/slice access |
| Use-after-free / dangling pointers | C-16 | Ownership + borrow checker |
| Missing cleanup on error paths | C-1, C-7, C-12 | `Drop` / `ZeroizeOnDrop` RAII |
| Null-termination errors | C-17 | `String` type, no null terminators |
| Type width mismatches | C-4 | Fixed-width integers (`u64`), no platform variation |
| Manual string parsing errors | C-5, C-8 | `str::lines()`, `strip_prefix()`, iterators |
| Integer boundary in bitmasks | C-10 | `clap` derive macros |

### What Rust Does Not Eliminate

| Class | C/Zig Finding | Rust Finding | Why |
|-------|--------------|--------------|-----|
| Symlink following | C-9 | RS-9 | OS-level file operation, not memory safety |
| Logic errors | — | RS-1, RS-2 | Type system cannot catch semantic bugs |
| Missing hardening flags | C-18 | RS-5 | Build configuration, not language feature |
| Environment variable trust | — | RS-6 | Input validation policy, not memory safety |

### Dependency Security

| Crate | Version | Pinning | Known CVEs | Notes |
|-------|---------|---------|------------|-------|
| `ed25519-dalek` | 2.2.0 | `=2.2.0` | None (2.x fixed RUSTSEC-2022-0093) | Current stable |
| `blake2` | 0.10.6 | `=0.10.6` | None | RustCrypto maintained |
| `scrypt` | 0.11.0 | `=0.11.0` | None | See RS-1 re: output length |
| `zeroize` | 1.8.1 | `=1.8.1` | None | Core security primitive |
| `subtle` | 2.6.1 | `=2.6.1` | None | Constant-time operations |
| `rand_core` | 0.6.4 | `=0.6.4` | None | CSPRNG trait |
| `clap` | 4.5.x | Range | None | CLI parsing |
| `rayon` | 1.10.x | Range | None | Parallel iteration |
| `rpassword` | 5.0.x | Range | None | Password prompting |
| `keyring` | 3.6.x | Range | None | OS credential store |

Cryptographic crates are exact-pinned; non-crypto crates use range versions (standard Cargo convention). Running `cargo audit` periodically is recommended to catch future advisories.

---

## Recommendations

### Priority 1 (Address Soon)

1. **RS-9**: Add `O_NOFOLLOW` to the force-overwrite path in `file_utils.rs`
2. **RS-1**: Add a scrypt output-length regression test with a known-good 104-byte test vector

### Priority 2 (Address When Convenient)

3. **RS-5**: Add `overflow-checks = true`, `lto = true`, `panic = "abort"` to release profile
4. **RS-4**: Replace `.expect()` with infallible byte operations
5. **RS-2**: Enforce untrusted comment prefix consistently with trusted comment

### Priority 3 (Low Risk, Improve Incrementally)

6. **RS-3**: Warn on timestamp fallback
7. **RS-6**: Document `MINISIGN_CONFIG_DIR` trust model

---

*This audit was conducted by static analysis of the source code. No dynamic testing, fuzzing, or runtime instrumentation was performed. Line numbers reference the `lb_rust` branch at commit `5f75f2c`.*
