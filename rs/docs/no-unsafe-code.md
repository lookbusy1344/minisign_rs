# Preventing Unsafe Code in Rust

This document describes the layers used to keep unsafe code out of the production
codebase, and explains what each layer catches and why no single layer is sufficient
on its own.

## Why Layers Matter

Any single guard can be accidentally or deliberately removed. Belt-and-braces means
that removing one layer still leaves the others standing.

---

## Layer 1 — Crate-Level Attribute (`#![forbid(unsafe_code)]`)

```rust
// src/lib.rs and src/main.rs
#![forbid(unsafe_code)]
```

**What it does:** The compiler refuses to compile any `unsafe` block, `unsafe fn`,
or `unsafe impl` anywhere in the crate. Unlike `deny`, `forbid` cannot be downgraded
by a downstream `#[allow(unsafe_code)]` attribute — the restriction is absolute.

**What it catches:** Any `unsafe` introduced in a module that `lib.rs` or `main.rs`
re-exports or includes.

**Weakness:** Lives in source code. A developer can remove the attribute line.
A lax code review might miss the removal.

---

## Layer 2 — CI Clippy Step (`-F unsafe_code`)

```bash
cargo clippy --lib --bins --all-features -- -F unsafe_code
```

The `-F` flag is the command-line equivalent of `#![forbid(...)]`. It is passed to
rustc by Clippy for every compilation unit matched by `--lib --bins`.

**What it does:** Independently enforces the same restriction at the build-system
level, without relying on the source attribute being present.

**Why `--lib --bins` not `--all-targets`:** Integration tests (`tests/`) are separate
crates and may legitimately contain `unsafe` — for example, `env::set_var` and
`env::remove_var` became `unsafe` in Rust 1.82 because they are inherently
thread-unsafe. When guarded by `#[serial]` those calls are safe in practice but the
compiler still requires the `unsafe` block. Limiting the check to production targets
avoids false positives there.

**Weakness:** Only runs in CI. A developer can push a branch that breaks CI and merge
with admin bypass.

---

## Layer 3 — `[lints.rust]` in `Cargo.toml` (not used here, documented for reference)

```toml
[lints.rust]
unsafe_code = "forbid"
```

**What it does:** Cargo forwards this to rustc as a lint flag for every target in the
package — library, binaries, examples, integration tests, and benchmarks.

**Why this project does not use it:** It applies to integration test crates as well,
which breaks compilation of the legitimate `unsafe { env::set_var(...) }` test
helpers. There is no per-target scoping in `[lints]`. If the test-only unsafe were
removed (e.g. by adopting a crate like `temp-env`), this would be the strongest
single-line option.

---

## Layer 4 — `cargo geiger` (optional, audit tool)

`cargo geiger` counts unsafe usage across the entire dependency tree, including
third-party crates. It does not prevent compilation but produces a report useful for
periodic audits.

```bash
cargo geiger --all-features
```

Not part of the regular pre-commit or CI flow here, but worth running when adding or
upgrading cryptographic dependencies.

---

## Summary

| Layer | Enforced by | Scope | Can be bypassed by |
|-------|-------------|-------|-------------------|
| `#![forbid(unsafe_code)]` | Compiler | Crate that declares it | Removing the attribute |
| `-F unsafe_code` in CI | CI pipeline | `--lib --bins` only | Admin CI bypass |
| `[lints.rust]` in Cargo.toml | Cargo/compiler | All package targets | Removing the table entry |
| `cargo geiger` | Manual audit | Whole dependency tree | Not running it |

The combination of layers 1 and 2 in use here means that removing the source
attribute does not help an attacker (CI catches it), and subverting CI does not help
(the source attribute still prevents a local build from succeeding).

---

## Test-Only Exception

Integration tests may use `unsafe { env::set_var(...) }` and
`unsafe { env::remove_var(...) }`. These became `unsafe` in Rust 1.82 due to
inherent thread-unsafety. When tests are annotated with `#[serial]` the safety
invariant is met at runtime. All such blocks must carry a `// SAFETY:` comment
explaining the justification.
