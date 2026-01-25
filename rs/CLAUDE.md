# Claude Code - Minisign Rust Project

## What This Is
Pure Rust rewrite of minisign (cryptographic signing tool). Security-critical. Must be 100% compatible with C version.

## Non-Negotiable Rules
- **ZERO unsafe code**
- **ZERO clippy warnings** (pedantic mode)
- **Write tests BEFORE code** (TDD required)
- **Run ALL checks before committing** (see below)
- All secrets use `Zeroize` + `ZeroizeOnDrop`
- No `.unwrap()`/`.expect()` in production paths
- Use `?` operator for errors

## Pre-Commit Checklist
```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
cargo test                    # Fast tests (~9s)
cargo test -- --ignored       # Slow security tests (~16s)
```

## Key Locations
```
src/
├── crypto.rs      # Ed25519, Blake2b, Scrypt
├── keys.rs        # Key types, generation, encryption
├── signature.rs   # Signature creation/verification
├── ops/           # High-level operations (sign, verify, etc)
└── main.rs        # CLI

tests/
├── cli_test.rs           # CLI integration tests
├── compatibility.rs      # C minisign cross-tests
└── cross_binary_test.rs  # C/Rust interop tests
```

## Testing
- **Fast tests** (148 tests): Default, use N=2^14 for scrypt
- **Slow tests** (11 tests): `--ignored`, use production N=2^20
- Must test compatibility with C minisign after crypto changes
- C minisign must be installed for compatibility tests

## Crypto Dependencies (ONLY These)
- `ed25519-dalek` - Ed25519 signatures
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time comparisons

Do not add other crypto libs.

## Documentation
- `README.md` - User docs
- `COMPATIBILITY.md` - C/Rust compatibility proof
- `docs/benchmark-report.md` - Performance comparison
- `docs/c-rust-parity-gaps.md` - C/Rust implementation differences
