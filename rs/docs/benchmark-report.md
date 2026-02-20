# Minisign Performance Benchmark Report

## Executive Summary

Performance comparison between the original C implementation and the Rust port of minisign. Benchmarks conducted using hyperfine on macOS (Apple Silicon) with `--shell=none` to eliminate shell overhead.

**Key Finding:** Both implementations deliver essentially identical performance for single-file operations. Differences are within measurement variance (≤10%). Rust's parallel multi-file mode provides meaningful throughput gains at scale.

## Test Environment

- **Platform:** macOS (arm64, Apple Silicon)
- **C minisign:** v0.12 (70 KB binary, Homebrew)
- **Rust minisign:** v1.3.4 (782 KB binary, `cargo build --release --no-default-features`)
- **Benchmark Tool:** hyperfine (`--shell=none`, warmup runs per benchmark)
- **Date:** 2026-02-20

## Binary Size Comparison

| Implementation | Size   | Ratio |
|----------------|--------|-------|
| C (Original)   | 70 KB  | 1.0x  |
| Rust           | 782 KB | 11.2x |

The Rust binary is larger due to statically linked Rust standard library and dependencies. Negligible on modern systems.

## Benchmark Results

All benchmarks use unencrypted keys (`-W`) to isolate signing/verification cost from scrypt KDF time.

### 1. Version Display (Startup Overhead)

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.2 ms | 0.1 ms  | 1.1 – 1.5 ms  | 200  |
| Rust           | 1.2 ms | 0.1 ms  | 1.1 – 1.5 ms  | 200  |

**Winner:** Rust (1.03x faster, within noise)
**Analysis:** Process launch and argument parsing are indistinguishable.

---

### 2. Key Generation (Unencrypted, `-W`)

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.5 ms | 0.2 ms  | 1.3 – 1.9 ms  | 50   |
| Rust           | 1.4 ms | 0.1 ms  | 1.2 – 1.7 ms  | 50   |

**Winner:** Rust (1.10x faster, within noise)
**Analysis:** Ed25519 keygen and file I/O are essentially identical between implementations.

---

### 3. Signing — 100 KB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.5 ms | 0.1 ms  | 1.3 – 1.8 ms  | 100  |
| Rust           | 1.4 ms | 0.1 ms  | 1.3 – 1.7 ms  | 100  |

**Winner:** Rust (1.05x faster, within noise)
**Analysis:** Performance parity. Rust shows tighter variance.

---

### 4. Signing — 10 MB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 9.0 ms | 0.2 ms  | 8.7 – 10.1 ms | 50   |
| Rust           | 8.6 ms | 0.1 ms  | 8.4 – 9.2 ms  | 50   |

**Winner:** Rust (1.05x faster)
**Analysis:** Rust's I/O buffering is marginally more efficient at scale.

---

### 5. Verification — 100 KB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 1.5 ms | 0.1 ms  | 1.3 – 2.0 ms  | 100  |
| Rust           | 1.4 ms | 0.1 ms  | 1.3 – 1.7 ms  | 100  |

**Winner:** Rust (1.08x faster, within noise)
**Analysis:** Statistically equivalent. Difference is within measurement variance.

---

### 6. Verification — 10 MB File

| Implementation | Mean   | Std Dev | Range          | Runs |
|----------------|--------|---------|----------------|------|
| C              | 8.8 ms | 0.2 ms  | 8.5 – 9.5 ms  | 50   |
| Rust           | 8.4 ms | 0.2 ms  | 8.1 – 9.3 ms  | 50   |

**Winner:** Rust (1.05x faster)
**Analysis:** Performance parity across implementations.

---

## Performance Summary

| Operation        | C      | Rust   | Winner | Margin |
|------------------|--------|--------|--------|--------|
| Version display  | 1.2 ms | 1.2 ms | Tie    | ~1.0x  |
| Key gen (no pwd) | 1.5 ms | 1.4 ms | Rust   | 1.10x  |
| Sign 100 KB      | 1.5 ms | 1.4 ms | Rust   | 1.05x  |
| Sign 10 MB       | 9.0 ms | 8.6 ms | Rust   | 1.05x  |
| Verify 100 KB    | 1.5 ms | 1.4 ms | Rust   | 1.08x  |
| Verify 10 MB     | 8.8 ms | 8.4 ms | Rust   | 1.05x  |

## Conclusions

1. **Runtime performance:** The Rust implementation matches or slightly outperforms C across all single-file operations. All differences are within 10%, with Rust holding a consistent edge.

2. **Scaling behaviour:** Both implementations show the same throughput scaling with file size; the absolute gap widens proportionally but the ratio stays around 1.05x.

3. **Consistency:** Rust shows equal or lower timing variance in most benchmarks, indicating more predictable performance.

4. **Binary size trade-off:** The Rust binary is 11.2x larger (782 KB vs 70 KB), down from the earlier 1.1 MB figure. Negligible for general use; relevant only for minimal containers or embedded targets.

5. **Practical impact:** All tested operations complete under 10 ms. The difference is imperceptible for interactive use.

## Multi-File Benchmarks

Both implementations accept multiple files in a single invocation for **signing**. The execution model differs:

- **C:** signs files **sequentially** within one process (`sign_all` with positional args after `-m file1`)
- **Rust:** signs files **in parallel** via Rayon by default; `--sequential` flag opts out

**C does not support multi-file verification.** Its `-V` mode accepts only a single `-m` file and silently ignores any positional arguments. Verifying N files with C requires N separate process invocations.

### Multi-File Signing (single invocation, both tools)

| Operation         | C (sequential) | Rust (sequential) | Rust (parallel) | C→Rust speedup |
|-------------------|----------------|-------------------|-----------------|----------------|
| Sign 100 × 100 KB | 19.1 ms        | 18.5 ms           | 6.1 ms          | 3.1x           |
| Sign 10 × 10 MB   | 80.0 ms        | 74.4 ms           | 11.7 ms         | 6.8x           |

Rust sequential and C sequential are within 3-8% of each other — confirming equivalent CPU work. The wall-time gap to Rust parallel is entirely Rayon distributing files across all available cores.

### Multi-File Verification (Rust only; C requires N invocations)

| Operation            | Rust (sequential) | Rust (parallel) | Speedup |
|----------------------|-------------------|-----------------|---------|
| Verify 100 × 100 KB  | 16.0 ms           | 4.3 ms          | 3.7x    |
| Verify 10 × 10 MB    | 74.3 ms           | 11.6 ms         | 6.4x    |

For C, verifying N files via shell loop adds N × ~1.5 ms process-startup overhead (≈150 ms for 100 files, ≈90 ms for 10 × 10 MB). Rust parallel is the only path that avoids this.

---

## Methodology

- `hyperfine --shell=none` eliminates shell fork/exec overhead
- Warmup runs precede every benchmark to prime OS page cache
- Unencrypted keys (`-W`) used throughout to isolate signing/verification from scrypt KDF
- Verification benchmarks use pre-generated signatures
- Rust binary built with `cargo build --release --no-default-features` (`strip = true` in release profile)
- C binary: Homebrew minisign 0.12, `/opt/homebrew/bin/minisign`
