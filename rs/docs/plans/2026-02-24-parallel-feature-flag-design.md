# Design: `parallel` Feature Flag for Rayon

**Date:** 2026-02-24
**Branch:** lb_rust
**Status:** Approved

## Goal

Add a compile-time `parallel` Cargo feature to make rayon optional, allowing smaller binaries when parallel multi-file processing is not needed.

## Behaviour

- `parallel` is included in `default` — no change to current behaviour when building normally
- Build with `--no-default-features --features credential_store` (or just omit `parallel`) to exclude rayon
- The runtime `--sequential` CLI flag is only compiled in when `parallel` is active; when the feature is off the binary always processes sequentially

## Changes

### `rs/Cargo.toml`

- Change `rayon = "1"` to `rayon = { version = "1", optional = true }`
- Add `parallel = ["dep:rayon"]` to `[features]`
- Add `"parallel"` to the `default` feature list

### `rs/src/ops/sign.rs`

- Gate `use rayon::prelude::*` with `#[cfg(feature = "parallel")]`
- Gate the `else { .into_par_iter() }` branch with `#[cfg(feature = "parallel")]`
- Add `#[cfg(not(feature = "parallel"))]` fallback that uses `.into_iter()`

### `rs/src/ops/verify.rs`

- Same changes as `sign.rs`

### `rs/src/cli.rs`

- Gate the `--sequential` field with `#[cfg(feature = "parallel")]`

### `rs/src/main.rs`

- Gate `cli.sequential` usages with `#[cfg(feature = "parallel")]`
- Pass `true` (always sequential) to `sign_multiple_files` / `verify_multiple_files` when the feature is off

## Testing

- Existing test suite passes unchanged (both with and without `parallel` feature)
- CI / pre-commit checks should pass with `--no-default-features`
