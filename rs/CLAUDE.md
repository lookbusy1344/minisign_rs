# Minisign Rust Project

## What This Is
Pure Rust rewrite of minisign (cryptographic signing tool). Security-critical. Must be 100% compatible with C version.

## Git Workflow
- **Main branch**: `lb_rust` (not master)
- Create feature branches from `lb_rust`
- Merge completed work back to `lb_rust`

## Privacy & Security
- **NO personally identifiable information (PII) in commits**
  - No real email addresses (use `your@email.com` as placeholder)
  - No team IDs, device IDs, or account identifiers
  - No real names, usernames, or handles
  - Use placeholders: `YOUR_TEAM_ID`, `EXAMPLE_ID`, etc.
- **Check for PII before committing:**
  ```bash
  # Search for potential PII patterns
  rg -i "your-real-email|YOUR_TEAM_ID_HERE"
  git diff --cached  # Review staged changes
  ```
- **In documentation/examples:** Always use generic placeholders
- **Test files:** Use synthetic/mock data only

## Non-Negotiable Rules
- **ZERO unsafe code** — no `unsafe` blocks in production code, ever. Enforced by
  `#![forbid(unsafe_code)]` in `src/lib.rs` and `src/main.rs`, and by a dedicated CI clippy
  step (`--lib --bins --all-features -- -F unsafe_code`). Before reaching for `unsafe` to call a syscall,
  check whether std provides a safe equivalent. Example: `File::set_permissions` calls `fchmod`
  on the fd internally — no `unsafe` needed (see commit 53aa335).
  Test-only exception: `unsafe { env::set_var(...) }` is required by Rust 1.82+ for env
  mutation; guard it with `#[serial]` for thread-safety and document the `// SAFETY:` reason.
- **Minimize dependencies** — every new crate must be justified. Before adding one, check
  whether std or an already-present dependency covers the need. Prefer a few lines of code
  over a new transitive dependency tree.
- **ZERO clippy warnings** (pedantic mode)
- **Write tests BEFORE code** (TDD required)
- **Run ALL checks before committing**
- All secrets use `Zeroize` + `ZeroizeOnDrop`
- No `.unwrap()`/`.expect()` in production paths
- Use `?` operator for errors
- Use inline format strings: `format!("Hello {name}")` not `format!("Hello {}", name)`

## Performance & Memory Efficiency
- **Avoid cloning** - NOT idiomatic, expensive
- **Prefer references** (`&Path`, `&str`, `&[T]`) over owned types
- Use `as_ref()`/`as_deref()` to extract references from `Option<T>`
- Use `Cow<T>` for conditional ownership
- Only clone when required (threading, owned returns, API constraints)

## API Design & Encapsulation
- **Favor private fields** for:
  - Security-sensitive types (keys, signatures, secrets)
  - Types with invariants to maintain
  - Public API surfaces that may need future flexibility
- Provide constructors (`new()`) and getters instead of public fields
- Getters should:
  - Return references (`&Path`, `&str`, `&[T]`) not owned types (`&PathBuf`, `&String`)
  - Use `#[must_use]` attribute
  - Avoid `get_` prefix (Rust convention)
- **Prefer builder pattern** for structs with 3+ params or multiple booleans (saved 452 lines in commit 17c648d)
- Never use `#[allow(clippy::fn_params_excessive_bools)]` - use builder instead

## Security Auditing
**Run periodically (weekly or before releases):**
```bash
cargo audit                   # Check for known vulnerabilities in dependencies
```
Install with: `cargo install cargo-audit`

After dependency updates, always run full test suite and audit.

## Refactoring Tools
**Available tools for code refactoring:**
- `rust-analyzer` - Installed via `rustup component add rust-analyzer`
- `ast-grep` - Installed via `cargo install ast-grep`

## Documentation

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development workflow and dependency management.
