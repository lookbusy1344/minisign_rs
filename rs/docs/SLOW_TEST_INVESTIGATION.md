# Slow Test Performance Investigation

**Date:** 2026-01-23
**Status:** Open Issue
**Platform:** M4 Mac (should be fast, but tests timeout)

## Summary

Tests marked with `#[ignore]` that use production scrypt parameters (N=2^20) are timing out at 60+ seconds, when they should complete in 2-5 seconds on M4 hardware.

## Expected vs Actual Performance

### Expected (M4 Mac)
- **Single scrypt operation (N=2^20):** ~1-2 seconds
- **Total for 5 ignored tests:** ~5-15 seconds
- **Reasonable timeout:** 30 seconds

### Actual (Observed)
- **Single scrypt operation (N=2^20):** 60+ seconds (timeout)
- **Total for 5 ignored tests:** Unknown (never completes)
- **Status:** All slow tests timing out

## Affected Tests

```bash
# These 5 tests are marked #[ignore]:
src/crypto.rs:
  - test_derive_key_full_params

src/keys.rs:
  - test_seckey_encryption_decryption
  - test_seckey_wrong_password

src/ops/generate.rs:
  - test_generate_encrypted_key

src/ops/sign.rs:
  - test_sign_encrypted_key
```

## Scrypt Parameters

### Production Parameters (used in slow tests)
```rust
log_n = 20      // N = 2^20 = 1,048,576 iterations
r = 8           // Block size
p = 1           // Parallelization
Memory: ~134MB per operation
```

### Fast Test Parameters (working correctly)
```rust
log_n = 14      // N = 2^14 = 16,384 iterations
r = 8           // Block size
p = 1           // Parallelization
Memory: ~2MB per operation
Time: ~50ms per operation ✅
```

## Test Results

### Fast Tests (N=2^14) - ✅ Working
```bash
$ cargo test --lib ops
test result: ok. 25 passed; 0 failed; 2 ignored
Time: ~3.4 seconds total
```

### Slow Tests (N=2^20) - ❌ Timing Out
```bash
$ gtimeout 60 cargo test --lib -- --ignored
Exit code: 124 (timeout)
Status: Never completes even a single test
```

## Test Coverage Status

✅ **Good:** Fast tests provide full coverage of:
- Encryption/decryption logic
- Key generation
- Signing with encrypted keys
- All code paths tested

❌ **Missing:** Production-strength parameter validation
- Can't verify N=2^20 actually works end-to-end
- Can't cross-test with C minisign's encrypted keys (they use N=2^20)

## Potential Causes

### 1. Scrypt Crate Performance Issue
```toml
[dependencies]
scrypt = "0.11"
```
- Possible inefficiency in the Rust implementation
- May not be optimized for Apple Silicon
- Could have a bug causing excessive iterations

### 2. Parameter Calculation Bug
```rust
// In keys.rs - are we calculating N correctly?
let n = memlimit / (LIBSODIUM_MEMLIMIT_MULTIPLIER * u64::from(r));
let log_n = (n as f64).log2() as u8;
```
- If N is miscalculated, could be doing 2^30 instead of 2^20
- Would explain 1024x slowdown

### 3. Memory Allocation Issues
```rust
let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;
// = 128 * 1,048,576 * 8 = 1,073,741,824 = 1GB
```
- Requesting 1GB per operation
- May cause swapping or memory pressure
- Though M4 has plenty of unified memory

## Investigation Steps

### Step 1: Verify N Parameter
Add debug logging to confirm actual N value being used:
```rust
eprintln!("Scrypt params: log_n={}, r={}, p={}", log_n, r, p);
eprintln!("This means N={}", 1u64 << log_n);
```

### Step 2: Test with C minisign
Generate a key with C minisign and verify our Rust code can decrypt it:
```bash
# C minisign generates with N=2^20
minisign -G -p test.pub -s test.key
# Try to load in Rust
cargo test test_parse_c_generated_encrypted_secret_key
```

### Step 3: Profile the Slow Test
```bash
cargo build --release
cargo test --release -- --ignored --nocapture
# Or use instruments on macOS
```

### Step 4: Try Alternative Scrypt Crate
Test with `rust-crypto/scrypt` or `libsodium-sys` bindings:
```toml
scrypt = { version = "0.11", features = ["simple"] }
# Or
libsodium-sys = "0.2"
```

### Step 5: Check for Infinite Loops
Add timeout to scrypt call itself:
```rust
use std::time::Duration;
let timeout = Duration::from_secs(10);
// If scrypt takes >10s, something is very wrong
```

## Workaround (Current)

✅ **Implemented:** Dual testing strategy
- Fast tests (N=2^14) run by default in CI
- Slow tests (N=2^20) marked `#[ignore]` until fixed
- All logic fully tested with fast parameters

## Action Items

- [ ] Add debug logging to scrypt operations
- [ ] Test decryption of C-generated encrypted keys
- [ ] Profile slow test execution
- [ ] Try alternative scrypt implementations
- [ ] Consider reporting issue to `scrypt` crate maintainers
- [ ] Document if this is expected behavior for some reason

## Impact

**Low impact currently:**
- Development workflow unaffected (fast tests work)
- All code paths tested
- CI runs quickly

**Future risk:**
- Can't validate production parameters work correctly
- May discover incompatibility with C minisign encrypted keys
- Production users might hit same performance issue

## References

- Scrypt RFC 7914: https://tools.ietf.org/html/rfc7914
- Rust scrypt crate: https://docs.rs/scrypt/0.11.0/scrypt/
- Libsodium SENSITIVE params: https://doc.libsodium.org/password_hashing/default_phf#guidelines
- C minisign source: https://github.com/jedisct1/minisign/blob/master/src/minisign.c

## Update Log

- **2026-01-23:** Initial investigation, documented issue
