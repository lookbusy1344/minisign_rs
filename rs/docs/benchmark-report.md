# Minisign Performance Benchmark Report

## Executive Summary

Performance comparison between the original C implementation and the Rust port of minisign. Benchmarks conducted using hyperfine on macOS (Apple Silicon) with `--shell=none` to eliminate shell overhead.

**Key Finding:** Verification performance is essentially identical. Write operations (signing, key generation) show a consistent ~4–5 ms overhead in the Rust implementation, traced to `sync_all()` (fsync) called after every file write — a durability guarantee the C implementation does not make. When writing to a RAM disk (eliminating fsync cost), both implementations are indistinguishable.

## Test Environment

- **Platform:** macOS (arm64, Apple Silicon)
- **C minisign:** v0.12 (70 KB binary, Homebrew)
- **Rust minisign:** v1.3.3 (1.1 MB binary, `cargo build --release --no-default-features`)
- **Benchmark Tool:** hyperfine (with `--shell=none`, warmup runs, and `--export-json`)
- **Date:** 2026-02-20

## Binary Size Comparison

| Implementation | Size  | Ratio |
|----------------|-------|-------|
| C (Original)   | 70 KB | 1.0x  |
| Rust           | 1.1 MB | 15.7x |

The Rust binary is larger due to inclusion of the Rust standard library and statically linked dependencies. 1.1 MB is negligible on modern systems.

## Benchmark Results

All benchmarks use unencrypted keys (`-W`) to isolate signing/verification cost from scrypt KDF time.

### 1. Version Display (Startup Overhead)

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 1.2 ms  | 0.1 ms  | 1.1 – 1.6 ms     | 200  |
| Rust           | 1.2 ms  | 0.1 ms  | 1.1 – 1.5 ms     | 200  |

**Winner:** Rust (1.02x faster, within noise)
**Analysis:** Process launch and argument parsing are indistinguishable.

---

### 2. Key Generation (Unencrypted, `-W`)

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 1.5 ms  | 0.1 ms  | 1.3 – 2.0 ms     | 50   |
| Rust           | 11.0 ms | 0.7 ms  | 9.7 – 12.1 ms    | 50   |

**Winner:** C (7.3x faster)
**Analysis:** Key generation writes two files (secret key + public key). Each `sync_all()` call costs ~4–5 ms on the test NVMe SSD. The two syncs account for ~9.5 ms of the ~9.5 ms gap. Ed25519 keygen itself is negligible.

---

### 3. Signing — 100 KB File

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 1.5 ms  | 0.1 ms  | 1.3 – 1.9 ms     | 100  |
| Rust           | 6.2 ms  | 0.3 ms  | 5.2 – 6.6 ms     | 100  |

**Winner:** C (4.1x faster)
**Analysis:** One `sync_all()` adds ~4.7 ms. Cryptographic work is identical; on RAM disk both measure 1.6 ms ± 0.1 ms.

---

### 4. Signing — 10 MB File

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 9.1 ms  | 0.2 ms  | 8.7 – 9.9 ms     | 50   |
| Rust           | 13.0 ms | 0.5 ms  | 12.3 – 13.6 ms   | 50   |

**Winner:** C (1.4x faster)
**Analysis:** File I/O dominates at 10 MB so the fixed sync cost (~4 ms) is a smaller fraction of total time. The crypto + I/O portion is identical (both ~8.5 ms user time).

---

### 5. Verification — 100 KB File

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 1.5 ms  | 0.2 ms  | 1.3 – 1.9 ms     | 100  |
| Rust           | 1.4 ms  | 0.1 ms  | 1.3 – 1.7 ms     | 100  |

**Winner:** Rust (1.06x faster)
**Analysis:** Verification writes nothing; no `sync_all()`. Performance is identical within measurement variance.

---

### 6. Verification — 10 MB File

| Implementation | Mean    | Std Dev | Range             | Runs |
|----------------|---------|---------|-------------------|------|
| C              | 8.9 ms  | 0.2 ms  | 8.6 – 9.7 ms     | 50   |
| Rust           | 8.4 ms  | 0.1 ms  | 8.2 – 8.7 ms     | 50   |

**Winner:** Rust (1.06x faster, lower variance)
**Analysis:** Rust's Blake2b streaming implementation is marginally faster at scale. The Rust result is also more consistent (0.1 ms σ vs 0.2 ms σ).

---

## Performance Summary

| Operation          | C       | Rust    | Winner | Ratio |
|--------------------|---------|---------|--------|-------|
| Version display    | 1.2 ms  | 1.2 ms  | Tie    | ~1.0x |
| Key gen (no pwd)   | 1.5 ms  | 11.0 ms | C      | 7.3x  |
| Sign 100 KB        | 1.5 ms  | 6.2 ms  | C      | 4.1x  |
| Sign 10 MB         | 9.1 ms  | 13.0 ms | C      | 1.4x  |
| Verify 100 KB      | 1.5 ms  | 1.4 ms  | Rust   | 1.06x |
| Verify 10 MB       | 8.9 ms  | 8.4 ms  | Rust   | 1.06x |

## Root Cause: `sync_all()` After Every Write

The Rust implementation calls `file.sync_all()` (`fsync(2)`) after writing every output file — signature files, secret key files, and public key files. The C implementation does not.

**Isolation test:** When signing to a HFS+ RAM disk (where `fsync` is instantaneous), both implementations complete in **1.6 ms ± 0.1 ms** — indistinguishable.

**Implication:** The overhead is not algorithmic. It is a deliberate durability trade-off: Rust guarantees that written files survive an OS crash immediately after the call, C does not. For a security tool writing private keys, this is arguably correct behaviour. For signing workloads processing many small files in a loop, it is a meaningful cost.

**Constant overhead model:** Each `sync_all()` costs ~4–5 ms on the test SSD. Operations are predictable:
- 1 write (sign) → +4.7 ms
- 2 writes (keygen) → +9.5 ms
- 0 writes (verify) → 0 ms

## Conclusions

1. **Verification is identical.** The Rust implementation matches or marginally beats C for all read-only operations.

2. **Write operations are slower by a fixed constant.** Not due to algorithm or language, but due to `sync_all()`. The absolute cost (~4–5 ms per write) will vary by storage hardware.

3. **Practical impact is low.** Both implementations complete all operations in under 20 ms. For interactive use the difference is imperceptible. For batch signing of thousands of files, `sync_all()` becomes relevant.

4. **Binary size:** Rust is 15.7x larger. Negligible on modern systems.

5. **Consistency:** Rust shows lower timing variance on large-file verification (0.1 ms σ vs 0.2 ms σ), indicating predictable performance.

## Methodology

- `hyperfine --shell=none` eliminates shell fork/exec overhead
- Warmup runs precede every benchmark to prime OS page cache
- Unencrypted keys (`-W`) used throughout to isolate crypto/IO from scrypt KDF
- Verification benchmarks use pre-generated signatures
- RAM disk isolation test: `hdiutil attach -nomount ram://204800` (100 MB HFS+ volume)
- Rust binary built with `cargo build --release --no-default-features` (strip = true in release profile)
