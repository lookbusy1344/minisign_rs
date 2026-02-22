# Running Tests

All `cargo test` commands must be wrapped with `gtimeout`. Run from `rs/` (the Rust crate root).

## Commands

**All tests** (~30s):
```bash
gtimeout 120 cargo test --no-default-features
```

Tests requiring the C minisign binary (`cross_binary_test`, `compatibility`) will skip with a
warning when the binary is not installed. OS credential store tests are gated behind the
`credential_store_tests` feature flag to avoid system prompts.

## Pre-Commit Order

Always run in this exact order before committing:

```bash
gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
gtimeout 120 cargo test --no-default-features
```

`cargo fmt` must be the last formatting step before commit.
