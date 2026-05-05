# Minisign Rust Project

Pure Rust rewrite of minisign (cryptographic signing tool). Security-critical. Must be 100% compatible with C version.

## Git Workflow
- **Main branch**: `lb_rust` (not master)
- Create feature branches from `lb_rust`

## Privacy & Security
- No PII in commits — use placeholders (`your@email.com`, `YOUR_TEAM_ID`, etc.)
- Test files use synthetic/mock data only

## Non-Negotiable Rules
- **ZERO unsafe code** — `#![forbid(unsafe_code)]` in lib and main. Prefer std safe equivalents over syscalls. Test-only exception: `unsafe { env::set_var(...) }` with `#[serial]` and `// SAFETY:` comment.
- **Minimize dependencies** — check std and existing deps before adding a crate
- **ZERO clippy warnings** (pedantic mode)
- Run clippy with `--all-targets` so platform-specific test and bin code is checked too:
  - `gtimeout 300 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic`
- **TDD** — write tests before code
- All secrets use `Zeroize` + `ZeroizeOnDrop`
- No `.unwrap()`/`.expect()` in production paths; use `?`
- Inline format strings: `format!("{name}")` not `format!("{}", name)`

## Performance & Memory
- Prefer references (`&Path`, `&str`, `&[T]`) over owned types
- Use `as_ref()`/`as_deref()` on `Option<T>`; `Cow<T>` for conditional ownership
- Avoid cloning unless required (threading, owned returns, API constraints)

## API Design
- Private fields for security-sensitive types and types with invariants
- Getters return references, use `#[must_use]`, no `get_` prefix
- Builder pattern for structs with 3+ params or multiple booleans
