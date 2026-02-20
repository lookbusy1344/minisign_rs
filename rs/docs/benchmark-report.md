# Minisign Performance Benchmark Report

## Executive Summary

Performance comparison between the original C implementation and the Rust port of minisign. Benchmarks conducted using hyperfine on macOS (Apple Silicon) with `--shell=none` to eliminate shell overhead.

**Key Finding:** Both implementations deliver essentially identical performance across all operations. Differences are within measurement variance (≤8%), with Rust holding a slight edge on large-file operations.

## Test Environment

- **Platform:** macOS (arm64, Apple Silicon)
- **C minisign:** v0.12 (70 KB binary, Homebrew)
- **Rust minisign:** v1.3.3 (1.1 MB binary, `cargo build --release --no-default-features`)
- **Benchmark Tool:** hyperfine (`--shell=none`, warmup runs per benchmark)
- **Date:** 2026-02-20

## Binary Size Comparison

| Implementation | Size   | Ratio |
|----------------|--------|-------|
| C (Original)   | 70 KB  | 1.0x  |
| Rust           | 1.1 MB | 15.7x |

The Rust binary is larger due to statically linked Rust standard library and dependencies. Negligible on modern systems.

## Benchmark Results

All benchmarks use unencrypted keys (`-W`) to isolate signing/verification cost from scrypt KDF time.

### 1. Version Display (Startup Overhead)

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.2 ms | 0.1 ms  | 1.1 – 1.8 ms  | 200  |
| Rust           | 1.2 ms | 0.1 ms  | 1.1 – 1.6 ms  | 200  |

**Winner:** Rust (1.03x faster, within noise)
**Analysis:** Process launch and argument parsing are indistinguishable.

---

### 2. Key Generation (Unencrypted, `-W`)

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.4 ms | 0.1 ms  | 1.3 – 1.6 ms  | 50   |
| Rust           | 1.4 ms | 0.1 ms  | 1.3 – 1.8 ms  | 50   |

**Winner:** Tie (1.00x)
**Analysis:** Ed25519 keygen and file I/O are identical between implementations.

---

### 3. Signing — 100 KB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.5 ms | 0.2 ms  | 1.3 – 2.2 ms  | 100  |
| Rust           | 1.5 ms | 0.1 ms  | 1.4 – 1.8 ms  | 100  |

**Winner:** Rust (1.04x faster, within noise)
**Analysis:** Performance parity. Rust shows tighter variance.

---

### 4. Signing — 10 MB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 9.0 ms | 0.2 ms  | 8.8 – 9.8 ms  | 50   |
| Rust           | 8.5 ms | 0.2 ms  | 8.3 – 9.1 ms  | 50   |

**Winner:** Rust (1.05x faster)
**Analysis:** Rust's I/O buffering is marginally more efficient at scale.

---

### 5. Verification — 100 KB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.3 ms | 0.1 ms  | 1.2 – 1.7 ms  | 100  |
| Rust           | 1.4 ms | 0.1 ms  | 1.3 – 1.8 ms  | 100  |

**Winner:** C (1.08x faster, within noise)
**Analysis:** Statistically equivalent. Difference is within measurement variance.

---

### 6. Verification — 10 MB File

| Implementation | Mean    | Std Dev | Range           | Runs |
|----------------|---------|---------|-----------------|------|
| C              | 10.4 ms | 0.4 ms  | 9.4 – 11.1 ms  | 50   |
| Rust           | 9.1 ms  | 0.5 ms  | 8.4 – 10.5 ms  | 50   |

**Winner:** Rust (1.15x faster)
**Analysis:** Rust's Blake2b streaming implementation is measurably faster on larger files.

---

## Performance Summary

| Operation        | C      | Rust   | Winner | Margin |
|------------------|--------|--------|--------|--------|
| Version display  | 1.2 ms | 1.2 ms | Tie    | ~1.0x  |
| Key gen (no pwd) | 1.4 ms | 1.4 ms | Tie    | 1.00x  |
| Sign 100 KB      | 1.5 ms | 1.5 ms | Tie    | 1.04x  |
| Sign 10 MB       | 9.0 ms | 8.5 ms | Rust   | 1.05x  |
| Verify 100 KB    | 1.3 ms | 1.4 ms | C      | 1.08x  |
| Verify 10 MB     | 10.4 ms| 9.1 ms | Rust   | 1.15x  |

## Conclusions

1. **Runtime performance:** The Rust implementation matches the C implementation across all operations. All differences are within 15%, with Rust holding a consistent edge on large-file work.

2. **Scaling behaviour:** Rust pulls ahead as file size increases, particularly for 10 MB verification (1.15x faster) and signing (1.05x faster). This is consistent with more efficient I/O buffering in the Rust standard library.

3. **Consistency:** Rust shows equal or lower timing variance in most benchmarks, indicating more predictable performance.

4. **Binary size trade-off:** The Rust binary is 15.7x larger (1.1 MB vs 70 KB). Negligible for general use; relevant only for minimal containers or embedded targets.

5. **Practical impact:** All tested operations complete under 15 ms. The difference is imperceptible for interactive use.

## Methodology

- `hyperfine --shell=none` eliminates shell fork/exec overhead
- Warmup runs precede every benchmark to prime OS page cache
- Unencrypted keys (`-W`) used throughout to isolate signing/verification from scrypt KDF
- Verification benchmarks use pre-generated signatures
- Rust binary built with `cargo build --release --no-default-features` (`strip = true` in release profile)
- C binary: Homebrew minisign 0.12, `/opt/homebrew/bin/minisign`
