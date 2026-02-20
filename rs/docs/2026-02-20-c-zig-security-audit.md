# Security Audit: minisign C/Zig Implementation

**Date:** 2026-02-20
**Scope:** All C and Zig source files in the minisign project (excluding `rs/` Rust implementation)
**Auditor:** Claude Code (claude-opus-4-6)

## Audit Scope

Files examined:

- `src/minisign.c` (1066 lines) — all cryptographic operations, key loading, signing, verification, CLI entry point
- `src/minisign.h` — struct layouts, algorithm identifiers, size constants
- `src/helpers.c` — `xfprintf`, `xsodium_malloc`, `xor_buf`, `trim`, `fopen_create_useronly`
- `src/helpers.h`
- `src/base64.c` — base64 decoder for all key and signature parsing
- `src/base64.h`
- `src/get_line.c` — password input handling
- `src/get_line.h`
- `src/libzodium/libzodium.zig` — Zig shim replacing libsodium
- `src/libzodium/sodium.h` — C-facing API contract for the shim
- `build.zig` — Zig build system
- `build.zig.zon` — Zig package manifest
- `CMakeLists.txt` — CMake build system
- `build-dist-package.sh` — distribution packaging script

---

## Summary Table

| # | Severity | Location | Category | Title |
|---|---|---|---|---|
| 1 | **Critical** | `libzodium.zig:27-33` | Memory Safety / Crypto | `sodium_malloc`/`sodium_free` provide no secret-material protection |
| 2 | **High** | `libzodium.zig:54-56`, `sodium.h:32` | Buffer Overflow | `crypto_generichash_state` opaque buffer — no compile-time size assertion |
| 3 | **High** | `minisign.c:389` | Side-channel | `memcmp` used for checksum comparison derived from secret key |
| 4 | **High** | `minisign.c:401-402` | Integer Width | `unsigned long` for KDF parameters — type mismatch with libsodium API |
| 5 | **High** | `minisign.c:264` | Input Validation | `trim()` return value discarded for global signature line |
| 6 | **Medium** | `helpers.c:108` | Buffer / Error Handling | `xfprintf` 4096-byte limit conflicts with 8192-byte `TRUSTEDCOMMENTMAXBYTES` |
| 7 | **Medium** | `minisign.c:381` | Memory Safety | KDF error path does not zero/free sensitive buffers |
| 8 | **Medium** | `minisign.c:826` | Input Validation | `trim()` return value discarded for `sk_comment_line` |
| 9 | **Medium** | `helpers.c:191-204` | Path Traversal | `fopen_create_useronly` follows symlinks; TOCTOU between existence check and create |
| 10 | **Medium** | `minisign.c:1005` | Logic | `opt_seen` bitmap boundary — operator precedence / non-ASCII opt_flag |
| 11 | **Medium** | `get_line.c:98-106` | Input Validation | Password truncation leaves residual bytes in stdin |
| 12 | **Medium** | `minisign.c:398-430` | Memory Safety | `pwd2` held in memory for full KDF duration unnecessarily |
| 13 | **Medium** | `minisign.c:164-179` | DoS / Error Handling | No file size cap for non-hashed signing; `abort()` on SIZE_MAX |
| 14 | **Low** | `minisign.c:621` | Error Handling | `crypto_sign_detached` return value not checked on first call |
| 15 | **Low** | `minisign.c:686-713` | Path Traversal | Key existence check not atomic — TOCTOU symlink window |
| 16 | **Low** | `helpers.c:180` | Memory Safety | `file_basename` returns aliased interior pointer |
| 17 | **Low** | `libzodium.zig:132` | Error Handling | `sodium_bin2hex` does not null-terminate on error |
| 18 | **Low** | `build.zig`, `CMakeLists.txt` | Build | No compiler hardening flags |
| 19 | **Info** | `build-dist-package.sh` | Process | Distribution tarball signed by ambient binary; no post-sign verification |
| 20 | **Info** | `build.zig.zon:6` | Build | Typo: `"LICEMSE"` in paths array |

---

## Detailed Findings

### FINDING 1 — Critical: `sodium_malloc`/`sodium_free` replaced with plain `malloc`/`free` in libzodium

**Severity:** Critical
**File:** `src/libzodium/libzodium.zig`, lines 27-33

```zig
export fn sodium_malloc(len: usize) callconv(.c) ?*anyopaque {
    return std.c.malloc(len);
}

export fn sodium_free(pnt: ?*anyopaque) callconv(.c) void {
    return std.c.free(pnt);
}
```

**Vulnerability:** The libzodium shim replaces libsodium's `sodium_malloc`/`sodium_free` with plain `malloc`/`free`. In real libsodium, `sodium_malloc` allocates memory in guard-paged regions with canaries, marks pages non-swappable (`mlock`), and `sodium_free` zeroes the memory before releasing it. The C code relies on this behaviour for all secret material: passwords (`pwd`, `pwd2`), the KDF stream, `seckey_struct`, `seckey_s`, and `sk_comment_line` are all allocated with `xsodium_malloc` and freed with `sodium_free`.

**Consequence:** With libzodium, none of these protections apply:

1. Secret key material and passwords can be swapped to disk.
2. `sodium_free` does **not** zero memory before releasing it, so secret key bytes linger in the heap and may be recovered by a subsequent `malloc` in the same process, by a heap dump, or by a child process that inherits the address space.
3. The memory-canary protection is absent, removing an important use-after-free detection layer.

**Exploit scenario:** A signing operation leaves a copy of the 64-byte Ed25519 secret key in freed heap memory. Any code that runs later (including a maliciously crafted `.so` injected via `LD_PRELOAD`, or an exploited parser bug in the same process) can scan heap for the characteristic `"Ed"` prefix and extract the key.

**Remediation:** Either:
- (a) Implement `sodium_malloc`/`sodium_free` in libzodium.zig using `mlock`, guard pages, and explicit zeroing on free.
- (b) Document prominently that the libzodium build does not provide secret-material isolation and must not be used for production signing.
- At minimum, add explicit `crypto.secureZero` calls before every `std.c.free` of sensitive buffers.

The fundamental fix requires a size-tracking allocator wrapper, as libsodium does internally, since `free()` does not know the allocation size.

---

### FINDING 2 — High: `crypto_generichash_state` buffer may be too small for Blake2b state

**Severity:** High
**Files:** `src/libzodium/sodium.h` line 32; `src/libzodium/libzodium.zig` lines 54-56

```c
// sodium.h
typedef struct crypto_generichash_state {
    unsigned char opaque[512];
} crypto_generichash_state;
```

```zig
// libzodium.zig
const Blake2bState = crypto.hash.blake2.Blake2b512;
fn blake2bState(state_ptr: *anyopaque) *Blake2bState {
    return @ptrFromInt(mem.alignForward(usize, @intFromPtr(state_ptr), @alignOf(Blake2bState)));
}
```

**Vulnerability:** The 512-byte opaque buffer is cast to a `Blake2b512` state via a raw pointer after alignment-forwarding. Two compounding problems:

1. **Size not verified at compile time.** If `@sizeOf(Blake2b512)` plus the alignment padding exceeds 512 bytes, the write in `crypto_generichash_init` overflows into adjacent stack or heap memory. As of Zig 0.13–0.15, `Blake2b512` state is approximately 216 bytes, so this is currently safe, but there is no compile-time assertion protecting it. A Zig standard library update that adds fields to `Blake2b512` (e.g., for SIMD state) would silently produce a memory-safety bug.

2. **Alignment forwarding without size reduction.** `alignForward` shifts the usable pointer forward by up to `@alignOf(Blake2bState) - 1` bytes, reducing the available space without compensating.

**Exploit scenario:** After a Zig stdlib update that enlarges `Blake2b512`, `crypto_generichash_init` writes a struct that overflows the 512-byte opaque buffer allocated on the caller's stack (e.g., `hs` in `message_load_hashed` at `minisign.c:130`, or `seckey_compute_chk` at `minisign.c:355`), enabling stack smashing.

**Remediation:** Add a `comptime` assertion in libzodium.zig:

```zig
comptime {
    const max_padding = @alignOf(Blake2bState) - 1;
    std.debug.assert(@sizeOf(Blake2bState) + max_padding <= 512);
}
```

Or define the opaque buffer size as a Zig constant exported to the C header.

---

### FINDING 3 — High: Non-constant-time checksum comparison for password verification

**Severity:** High
**File:** `src/minisign.c`, lines 389-391

```c
seckey_compute_chk(chk, seckey_struct);
if (memcmp(chk, seckey_struct->keynum_sk.chk, crypto_generichash_BYTES) != 0) {
    exit_msg("Wrong password for that key");
}
sodium_memzero(chk, crypto_generichash_BYTES);
```

**Vulnerability:** `memcmp` is used to compare the derived checksum against the stored checksum. `memcmp` is allowed by the C standard to short-circuit on the first differing byte, leaking timing information about how many leading bytes of the checksum match. The checksum is `BLAKE2b(sig_alg || keynum || sk)` — derived from the secret key.

While the scrypt KDF completes before this comparison (limiting brute-force via timing), the pattern deviates from secure-coding best practice for any comparison involving values derived from secrets.

**Remediation:** Replace with `sodium_memcmp` or equivalent constant-time comparison:

```c
if (sodium_memcmp(chk, seckey_struct->keynum_sk.chk, crypto_generichash_BYTES) != 0) {
    exit_msg("Wrong password for that key");
}
```

Note: libzodium's `sodium.h` does not currently declare `sodium_memcmp` — it should be added to the shim.

---

### FINDING 4 — High: `unsigned long` type for KDF parameters — width mismatch on 32-bit platforms

**Severity:** High
**File:** `src/minisign.c`, lines 401-402, 436-437

```c
unsigned long  kdf_memlimit;
unsigned long  kdf_opslimit;
// ...
kdf_opslimit = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;
kdf_memlimit = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;
```

**Vulnerability:** `unsigned long` is 32 bits on 32-bit platforms and on Windows 64-bit (MSVC). The libsodium API takes `unsigned long long` for opslimit and `size_t` for memlimit. Current values fit in 32 bits, but a future increase of the sensitive limits beyond `UINT32_MAX` would silently truncate.

**Remediation:** Match the function signature types:

```c
unsigned long long kdf_opslimit;
size_t             kdf_memlimit;
```

---

### FINDING 5 — High: `trim()` return value discarded for global signature line

**Severity:** High
**File:** `src/minisign.c`, line 264

```c
trim(global_sig_s);   // return value discarded
```

All other security-critical `trim()` calls check the return value:

```c
if (trim(comment) == 0) { exit_msg("Untrusted signature comment too long"); }
if (trim(sig_s) == 0)   { exit_msg("Signature too long"); }
if (trim(trusted_comment) == 0) { exit_msg("Trusted comment too long"); }
```

**Vulnerability:** `trim()` returns 0 when the string did not end with `\n` (line truncated by `fgets`) or when the string contains an embedded `\r`. The return value is discarded for `global_sig_s`, meaning a truncated or malformed global signature line is silently passed to `b64_to_bin` for decoding without diagnostic.

**Remediation:**

```c
if (trim(global_sig_s) == 0) {
    exit_msg("Global signature too long or malformed");
}
```

---

### FINDING 6 — Medium: `xfprintf` fixed 4096-byte buffer conflicts with 8192-byte `TRUSTEDCOMMENTMAXBYTES`

**Severity:** Medium
**File:** `src/helpers.c`, lines 107-127

```c
size_t out_maxlen = 4096U;
// ...
len = vsnprintf(out, out_maxlen, format, va);
if (len < 0 || len >= (int) out_maxlen) {
    va_end(va);
    exit_msg("xfprintf() overflow");
}
```

**Vulnerability:** `TRUSTEDCOMMENTMAXBYTES` is 8192 bytes, but `xfprintf` has a hard 4096-byte buffer. A trusted comment of 4077+ characters causes a hard abort with the cryptic message "xfprintf() overflow" — before the explicit length check at line 640-641 fires.

**Remediation:** Increase `out_maxlen` to at least `TRUSTEDCOMMENTMAXBYTES + sizeof(TRUSTED_COMMENT_PREFIX) + 2`, or use dynamic allocation via `vsnprintf(NULL, 0, ...)` to determine required size first.

---

### FINDING 7 — Medium: KDF error path does not zero/free sensitive buffers

**Severity:** Medium
**File:** `src/minisign.c`, lines 381-392

```c
if (crypto_pwhash_scryptsalsa208sha256(...) != 0) {
    exit_err("Unable to complete key derivation");
    // chk, stream, pwd are NOT zeroed/freed before exit
}
```

**Vulnerability:** On the KDF failure path, `exit_err` is called without zeroing `chk` (stack), `stream` (heap, allocated via `xsodium_malloc`), or `pwd` (heap). With the libzodium backend, `sodium_free` is plain `free` (no zeroing), so sensitive material remains in the heap after exit.

**Remediation:** Zero and free sensitive buffers on all exit paths:

```c
if (crypto_pwhash_scryptsalsa208sha256(...) != 0) {
    sodium_free(stream);
    sodium_free(pwd);
    sodium_memzero(chk, sizeof chk);
    exit_err("...");
}
```

---

### FINDING 8 — Medium: `trim()` return value discarded for `sk_comment_line`

**Severity:** Medium
**File:** `src/minisign.c`, line 826

**Vulnerability:** Same pattern as Finding 5 — `trim(sk_comment_line)` return value is discarded in `update_password()`. An embedded `\r` in the comment would be retained and written to the key file, corrupting the format.

**Remediation:** Check the return value consistently with all other `trim()` calls.

---

### FINDING 9 — Medium: `fopen_create_useronly` follows symlinks; TOCTOU between existence check and create

**Severity:** Medium
**File:** `src/helpers.c`, lines 191-204

**Vulnerability:** `abort_on_existing_key_files` checks existence with `fopen(file, "r")`, then `fopen_create_useronly` creates with `O_CREAT | O_TRUNC`. Between check and creation, an attacker with filesystem access can create a symlink at the secret key path pointing to a privileged file. The `O_CREAT | O_TRUNC` open will follow the symlink and truncate the target.

**Remediation:** Use `O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW` in `fopen_create_useronly`:

```c
fd = open(file, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, (mode_t) 0600);
```

For the force-overwrite case, use `O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW`.

---

### FINDING 10 — Medium: `opt_seen` bitmap boundary condition

**Severity:** Medium
**File:** `src/minisign.c`, lines 900, 1005-1010

```c
unsigned char opt_seen[16] = { 0 };
// ...
if (opt_flag > 0 && opt_flag < (int) sizeof opt_seen * 8) {
```

**Vulnerability:** `sizeof opt_seen * 8` = 128. Non-ASCII `getopt` return values (128-255) are silently excluded from duplicate detection. Current option strings only use ASCII, but the check provides a false sense of safety. C operator precedence makes this parse correctly as `(int)(16) * 8 = 128`, but the intent is clearer as:

```c
if (opt_flag > 0 && opt_flag < 128) {
```

---

### FINDING 11 — Medium: Password truncation leaves residual bytes in stdin

**Severity:** Medium
**File:** `src/get_line.c`, lines 98-106

**Vulnerability:** When a password exceeds `PASSWORDMAXBYTES` (1024), the first 1023 characters are silently used. The remaining characters are **not drained from stdin**, so the next `fgets` call (for the confirmation prompt) reads the overflow characters, causing a password mismatch that confuses users.

**Remediation:** Drain stdin to the next newline on truncation:

```c
if (truncated) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
    fprintf(stderr, "Password too long; maximum length is %u characters.\n",
            (unsigned int) max_len - 1);
}
```

---

### FINDING 12 — Medium: `pwd2` held in memory for full KDF duration unnecessarily

**Severity:** Medium
**File:** `src/minisign.c`, lines 398-430

**Vulnerability:** Both password copies (`pwd`, `pwd2`) remain in memory during the multi-second scrypt KDF operation. The second copy serves no purpose after the `strcmp` check. With libzodium, these are plain `malloc` buffers that can be paged to disk.

**Remediation:** Free `pwd2` immediately after comparison:

```c
if (strcmp(pwd, pwd2) != 0) {
    exit_msg("Passwords don't match");
}
sodium_memzero(pwd2, PASSWORDMAXBYTES);
sodium_free(pwd2);
// then run KDF with only pwd in memory
```

---

### FINDING 13 — Medium: No file size cap for non-hashed signing; `abort()` on SIZE_MAX

**Severity:** Medium
**File:** `src/minisign.c`, lines 164-179

```c
if ((uintmax_t) message_len_ > (uintmax_t) SIZE_MAX || message_len_ < (off_t) 0) {
    abort();
}
message = xmalloc((*message_len = (size_t) message_len_));
```

**Vulnerability:** The non-hashed path reads the entire file into memory with no size cap. A malicious file can trigger a multi-GB allocation. The `abort()` on the `SIZE_MAX` check is an unconditional crash with no cleanup or user message, inconsistent with the rest of the codebase.

**Remediation:** Replace `abort()` with `exit_msg("File too large to sign without -H (prehashing)")` and consider adding a practical size limit for the non-hashed path. The hashed path (`message_load_hashed`) handles arbitrarily large files correctly via streaming.

---

### FINDING 14 — Low: `crypto_sign_detached` return value not checked on first invocation

**Severity:** Low
**File:** `src/minisign.c`, line 621

```c
crypto_sign_detached(sig_struct.sig, NULL, message, message_len, seckey_struct->keynum_sk.sk);
```

The second call correctly checks the return value. An invalid secret key would silently produce a garbage signature written to disk.

**Remediation:**

```c
if (crypto_sign_detached(sig_struct.sig, NULL, message, message_len,
                         seckey_struct->keynum_sk.sk) != 0) {
    exit_msg("Unable to compute a signature");
}
```

---

### FINDING 15 — Low: Key existence check TOCTOU — not atomic with key creation

**Severity:** Low
**File:** `src/minisign.c`, lines 686-713, 738-752

**Vulnerability:** `abort_on_existing_key_files` is called twice in `generate()` — once before `encrypt_key` and once after. The check uses `fopen(file, "r")` which follows symlinks. A symlink attack between the second check and `fopen_create_useronly` would not be caught. Overlaps with Finding 9.

---

### FINDING 16 — Low: `file_basename` returns aliased interior pointer

**Severity:** Low
**File:** `src/helpers.c`, lines 180-189

**Vulnerability:** Returns a pointer into the original string. If the underlying buffer is freed, the result is a dangling pointer. Current usages are safe, but the contract is fragile.

**Remediation:** Consider returning `size_t` (offset) instead of a pointer.

---

### FINDING 17 — Low: `sodium_bin2hex` in libzodium does not null-terminate on error

**Severity:** Low
**File:** `src/libzodium/libzodium.zig`, lines 132-140

**Vulnerability:** Real `sodium_bin2hex` always null-terminates and never returns NULL. The libzodium version returns NULL without null-terminating. This function is currently dead code (not called in the C source) but creates a divergent API surface.

---

### FINDING 18 — Low: No compiler hardening flags in build systems

**Severity:** Low
**Files:** `build.zig`, `CMakeLists.txt`

**Vulnerability:** Neither build system specifies:
- `-D_FORTIFY_SOURCE=2` (glibc buffer overflow detection)
- `-fstack-protector-strong` (stack canaries)
- `-Wformat=2 -Wformat-security` (format string warnings)
- Position-independent executable (`-fPIE`/`-pie`) flags

**Remediation (CMakeLists.txt):**

```cmake
target_compile_options(minisign PRIVATE
    -D_FORTIFY_SOURCE=2
    -fstack-protector-strong
    -Wformat=2 -Wformat-security
)
target_link_options(minisign PRIVATE -Wl,-z,relro -Wl,-z,now)
```

**Remediation (build.zig):**

```zig
.flags = &.{ "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong" },
```

---

### FINDING 19 — Informational: Distribution script signs with ambient binary

**Severity:** Informational
**File:** `build-dist-package.sh`

```sh
minisign -Sm minisign-0.12.tar.gz
```

The tarball is signed by whatever `minisign` is on `PATH`, relying on the default key. No explicit key path, no post-sign verification.

**Remediation:** Add explicit key path and verification:

```sh
minisign -Sm minisign-0.12.tar.gz -s ~/.minisign/minisign.key
minisign -Vm minisign-0.12.tar.gz -p ./minisign.pub
```

---

### FINDING 20 — Informational: Typo in `build.zig.zon` paths

**Severity:** Informational
**File:** `build.zig.zon`, line 6

```zig
"LICEMSE",  // should be "LICENSE"
```

The misspelled path may cause the license file to be excluded from Zig package integrity checks.

---

## Risk Assessment

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 4 |
| Medium | 8 |
| Low | 5 |
| Informational | 2 |
| **Total** | **20** |

### Key Themes

1. **libzodium shim is the highest-risk component.** The replacement of `sodium_malloc`/`sodium_free` with plain `malloc`/`free` eliminates all secret-material memory protections. This is the single most impactful finding and affects every operation that handles secret keys or passwords.

2. **Inconsistent error-path hygiene.** Several functions fail to zero sensitive buffers on error paths, and the libzodium shim makes this worse by removing the zeroing-on-free safety net.

3. **Input validation gaps.** Discarded `trim()` return values and the `xfprintf` buffer size mismatch with `TRUSTEDCOMMENTMAXBYTES` create edge cases where malformed or oversized input is not caught cleanly.

4. **TOCTOU in file operations.** Key file creation follows symlinks and has race windows between existence checks and creation.

5. **Missing compile-time safety assertions.** The Blake2b state buffer size is not verified at compile time, creating a latent overflow if the Zig standard library changes.

---

*Note: This audit was conducted by static analysis of the source code. No dynamic testing, fuzzing, or runtime instrumentation was performed. Line numbers reference the source as of the `lb_rust` branch at commit `5f75f2c`.*
