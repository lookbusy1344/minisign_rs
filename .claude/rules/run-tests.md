# Running Tests

All `cargo test` commands must be wrapped with `gtimeout`. Run from `rs/` (the Rust crate root).

## Commands

**Fast tests** (~9s, run frequently):
```bash
gtimeout 60 cargo test --no-default-features
```

**Slow/security tests** (~16s, run before committing):
```bash
gtimeout 60 cargo test --no-default-features -- --ignored
```

## Pre-Commit Order

Always run in this exact order before committing:

```bash
gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
gtimeout 60 cargo test --no-default-features
gtimeout 60 cargo test --no-default-features -- --ignored
```

`cargo fmt` must be the last formatting step before commit.
