---
name: require-pre-commit-checks
enabled: true
event: bash
pattern: git\s+commit
action: warn
---

**Pre-commit check required.**

Before proceeding, run `git diff --cached --name-only` to inspect staged files.

**If all staged files are documentation only** (`.md` files, `docs/`, `README`):
- No build or test checks required. Proceed with the commit.

**If any Rust source files are staged** (`.rs`, `Cargo.toml`, `Cargo.lock`):
- You must run ALL of the following in this exact order before committing:

```bash
gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
gtimeout 30 cargo clippy --lib --bins --all-features -- -F unsafe_code
cargo fmt
gtimeout 120 cargo nextest run --no-default-features
```

`cargo fmt` must be the last formatting step — run it after clippy, before the test run.

All steps must pass with zero warnings or errors.

If you have already completed all checks in this session and they passed, you may proceed.
