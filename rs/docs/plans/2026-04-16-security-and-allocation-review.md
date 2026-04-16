# Security and Allocation Review — Remediation Plan

**Date:** 2026-04-16
**Scope:** `rs/src/**/*.rs` (production code)
**Focus:** security issues + allocation/performance hot paths
**Size baseline:** 4335 LOC (tokei, code-only)

## Executive summary

The code is in a strong place — prior reviews have already closed the
big-ticket items (unbounded reads, KDF cost cap, constant-time keynum,
atomic secret-key overwrite). This pass finds **one high-severity TOCTOU
in the `-o` output flag**, two medium-severity file-race issues, and a
handful of low-impact zeroization / allocation cleanups.

| ID | Severity | Area | Summary |
|---|---|---|---|
| S1 | **High** | `-V -o` | Verified file is re-read from disk after verification — attacker can swap content. |
| S2 | **Medium** | sign/verify | TOCTOU between `check_file_size_limit` and `fs::read` — memory DoS via swap to giant file. |
| S3 | **Medium** | secret-key write | `SeckeyStruct::to_file_contents` returns plain `String` holding (possibly plaintext) key material. |
| S4 | **Low** | password file | Double `metadata()` + unbounded `read_to_string` window after size check. |
| S5 | **Low** | Windows | No atomic-overwrite path for secret keys on Windows. |
| P1 | Low | verify/sign hot path | `sig_box` comments are cloned into `VerifyResult`/`SignResult` instead of moved. |
| P2 | Low | crypto | Heap-allocated scratch buffers (`Zeroizing<Vec>`) for fixed 104-byte blobs. |
| P3 | Low | password file | `read_to_string` ignores `MAX_PASSWORD_FILE_BYTES` after the pre-check. |

---

## Security findings

### S1 — TOCTOU on `-V -o` output flag (High)

**Location:** `src/main.rs:434-439`

```rust
let result = verify(&options)?;

if cli.output {
    // -o: Output file content to stdout after verification
    let content =
        std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?;
    io::stdout().write_all(&content)...
}
```

`verify()` reads the message, confirms the signature, returns. Then `-o`
opens the file a **second time** and writes whatever is now on disk to
stdout. Between the two opens an attacker with write access to the file
(or to a parent directory, via symlink swap) can substitute arbitrary
content. The user sees "Signature verified" and unrelated bytes. This
defeats the core guarantee the tool provides.

The C implementation likely has the same shape; that is not an excuse.

**Remediation — design decision required.** Two reasonable approaches,
different trade-offs:

- **(A) Buffer during verify.** In non-prehashed mode, the file is
  already fully in memory during `crypto_verify`. Plumb that buffer out
  to the caller and emit it. In prehashed mode, buffer the stream
  alongside Blake2b hashing (costs RAM proportional to file size).
- **(B) Verify-then-stream-from-open-fd.** Hold the `File` from the
  verify call, `seek(0)` after verification, and stream it out.
  O(1) memory, but you still need to be sure the fd refers to the same
  inode (Unix: the open fd does; Windows: open handles share state).

I'd recommend **B on Unix** (open once, hash or read, then rewind and
emit) and **A on Windows**, since it sidesteps the `seek` semantics. But
**this is a user-facing behaviour change** (memory profile of `-o`
with prehashed mode) — worth confirming before implementing.

**User contribution slot:** Implement the chosen verification buffer
strategy in `src/ops/verify.rs`. Target: extend `VerifyResult` with an
optional `message_output: Option<MessageSource>` enum, where
`MessageSource` is either `Buffer(Vec<u8>)` or `FileHandle(File)`. I'll
stub the enum and the feature-gated code path; the caller logic in
`main.rs:handle_verify` is the ~10 lines where your judgement matters
most.

---

### S2 — TOCTOU between size check and full read (Medium)

**Locations:**
- `src/ops/sign.rs:551-555` (non-prehashed sign)
- `src/ops/verify.rs:316-318` (non-prehashed verify)

```rust
check_file_size_limit(message_file)?;        // metadata().len() < 1 GB ?
file_buf = std::fs::read(message_file)...    // unbounded read
```

Between the two calls the file can be swapped (symlink or rename)
for a much larger one. `std::fs::read` then allocates without bound —
memory DoS.

**Remediation:** open the file once, then use `File::metadata()` on the
open handle + `Read::take(MAX_MESSAGE_SIZE_BYTES + 1).read_to_end()`. The
`+ 1` lets you distinguish "exactly at limit" from "over limit".

```rust
let mut file = File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
let size = file.metadata().map_err(|e| Error::file_read(message_file, e))?.len();
if size > MAX_MESSAGE_SIZE_BYTES {
    return Err(...);
}
let mut file_buf = Vec::with_capacity(size as usize);
file.take(MAX_MESSAGE_SIZE_BYTES + 1).read_to_end(&mut file_buf)...;
if file_buf.len() as u64 > MAX_MESSAGE_SIZE_BYTES { return Err(...); }
```

The second bound check catches a file that grew during the read. The
`take(max + 1)` is the actual safety net.

Same change applies to both sites — extract a helper in `file_utils.rs`.

---

### S3 — Non-zeroized `String` for secret-key file contents (Medium)

**Location:** `src/keys.rs:862-869`

```rust
pub fn to_file_contents(&self, comment: &str) -> String {
    let bytes = Zeroizing::new(self.to_bytes());
    let base64 = Zeroizing::new(encode_base64(*bytes));
    let base64_str: &str = &base64;
    format!("untrusted comment: {comment}\n{base64_str}\n")  // <-- plain String
}
```

The intermediate buffers are zeroized; the return value is a plain
`String` the caller writes to disk and drops. For **unencrypted** keys
this string contains base64-encoded plaintext secret key material —
trivially recoverable from a core dump or heap scan. For encrypted keys
it is the encrypted blob, still worth protecting.

Callers: `ops/generate.rs:274`, `ops/change.rs:187`, both then pass the
string to `write_secret_key_file(&str, ...)`.

**Remediation:**

1. Change signature to `-> Zeroizing<String>`.
2. Update `write_secret_key_file` to accept `impl AsRef<[u8]>` or
   `&[u8]` instead of `&str`, so the caller can pass `Zeroizing<String>`
   without borrowing out of the zeroizing container and copying.

Keep `PubkeyStruct::to_file_contents` as plain `String` — public key
material is not sensitive.

---

### S4 / P3 — Password file metadata race + unbounded read (Low / medium)

**Location:** `src/main.rs:877-897`

Three problems in sequence:

```rust
let metadata = std::fs::metadata(path)...;      // call 1
if !metadata.is_file() { return Err(...); }
let password = Zeroizing::new({
    let size = std::fs::metadata(path)...len(); // call 2 (redundant)
    if size > MAX_PASSWORD_FILE_BYTES { return Err(...); }
    std::fs::read_to_string(path)               // call 3 — no size bound
});
```

1. Double `metadata()` call is a micro-inefficiency.
2. Between check and read, the file can be swapped. `read_to_string`
   has no upper bound; attacker wins the race → unbounded read.
3. `read_to_string` after a regular-file check does not guard against
   the file being replaced by a growing file between calls.

**Remediation:**

```rust
let mut file = File::open(path)?;
let metadata = file.metadata()?;
if !metadata.is_file() { return Err(...); }
if metadata.len() > MAX_PASSWORD_FILE_BYTES { return Err(...); }
let mut buf = Zeroizing::new(String::with_capacity(metadata.len() as usize));
file.take(MAX_PASSWORD_FILE_BYTES + 1).read_to_string(&mut buf)?;
if buf.len() as u64 > MAX_PASSWORD_FILE_BYTES { return Err(...); }
```

Single `open`, single `metadata` on the fd, hard-bounded read.

---

### S5 — Windows has no atomic secret-key overwrite (Low)

**Location:** `src/ops/file_utils.rs:175-228`

`atomic_overwrite_secret_key` is `#[cfg(unix)]`. On Windows the
`--force` path falls through to `create(true).truncate(true)`. A crash
between truncate and write corrupts the key file with no recovery path.

**Remediation — user contribution slot:** Windows semantics differ
(`MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` vs `rename`;
`FlushFileBuffers` vs `fsync`; no `O_NOFOLLOW` equivalent). The
algorithm is the same — write to `.{name}.{nonce}.tmp`, flush,
atomically replace. I can stub the skeleton but the Windows-specific
API choices (`MoveFileExW` via `std::fs::rename` is close enough in
modern Rust; should we also call `SetFileAttributesW` to hide the temp
file?) are worth your call.

Low priority — if Windows users are rare this can be deferred with a
`#[cfg(windows)] compile_error!` gate on the `--force` path to fail
loudly instead of silently corrupting.

---

## Performance / allocation findings

### P1 — Redundant comment clones in sign/verify results (Low)

**Locations:**
- `src/ops/verify.rs:220-221, 354-355`
- `src/ops/sign.rs:216`

`sig_box.trusted_comment().to_string()` clones. In batch verify of
1000 files this is 2000 small-String allocations we don't need.

**Remediation:** add `SignatureBox::into_parts(self) -> (String, SigStruct, String, Signature)`
and move instead of clone. Straightforward refactor but touches 4
call sites.

### P2 — Heap allocations for fixed-size crypto scratch buffers (Low)

**Locations:**
- `src/keys.rs:417` (encryption blob build)
- `src/keys.rs:486` (decryption blob build)
- `src/keys.rs:612` (checksum input build)

Each is a `Zeroizing::new(Vec::with_capacity(N))` for **compile-time
fixed N** (104 or 74 bytes). The heap alloc + indirection is avoidable.

**Remediation:** replace with stack arrays zeroized on drop. Either:

- Plain `[u8; N]` with explicit `.zeroize()` before return (the struct
  already has `ZeroizeOnDrop`, so temps just need a `Zeroizing` wrapper
  around the array — `Zeroizing<[u8; N]>` works).
- Or `Zeroizing::new([0u8; N])` — this is already the pattern used for
  `decrypted_blob` at `keys.rs:492`. Apply the same shape to the three
  `Vec` cases.

Not a perf crisis, but it aligns the module with itself (compare line
486 vs line 492 — inconsistent style in the same function).

### P3 — See S4 above.

---

## Non-issues (checked, nothing to do)

- **Constant-time comparisons:** keynum and checksum both use
  `subtle::ConstantTimeEq`. Verified at `src/ops/verify.rs:291` and
  `src/keys.rs:514`.
- **`#![forbid(unsafe_code)]`:** enforced in both `lib.rs` and `main.rs`.
- **KDF cost caps:** `MAX_SCRYPT_LOG_N = 25` rejects crafted expensive
  keys at `src/crypto.rs:468`.
- **Symlink handling on Unix secret-key write:** `O_NOFOLLOW` present
  at `src/ops/file_utils.rs:132, 204`.
- **`unwrap`/`expect` in production paths:** no occurrences in `src/`
  outside `unwrap_or_*` combinators.

---

## Proposed ordering

1. **S1** (High) — break the verify-then-reread pattern before anything else.
2. **S2** — small helper in `file_utils.rs`; both call sites convert over.
3. **S3** — signature change ripples through 2 callers; mechanical.
4. **S4 / P3** — single-file change in `main.rs`.
5. **P2** — style cleanup in `keys.rs`.
6. **P1** — nice-to-have, batch verify only.
7. **S5** — defer unless Windows is a supported surface.

Each of S1–S4 should land with a targeted test: oversized-file read
(S2/S4), swapped-file race with a canned harness (S1), and a memory
scanner test confirming the key-bytes string is no longer on the heap
after drop (S3, using something like `region` or a custom harness; if
too fiddly, rely on the type signature as the proof).

---

## Open questions for the user

1. **S1 strategy:** buffer (A) or rewind-fd (B)? See §S1.
2. **S5 priority:** is Windows a first-class platform here, or is a
   loud-failure gate acceptable?
3. **S3 zeroization scope:** propagate `Zeroizing<String>` into
   `write_secret_key_file`, or zeroize the string in place at the call
   site in `generate.rs` / `change.rs`? The former is cleaner, the
   latter is localised.
