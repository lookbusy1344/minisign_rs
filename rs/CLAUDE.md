# Claude Code - Minisign Rust Project

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
- **ZERO unsafe code**
- **ZERO clippy warnings** (pedantic mode)
- **Write tests BEFORE code** (TDD required)
- **Run ALL checks before committing** (see below)
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

## Pre-Commit Checklist
**ALWAYS run in this exact order before committing:**
```bash
cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt                     # REQUIRED: Always run AFTER clippy, BEFORE commit
cargo test                    # Fast tests (~9s)
cargo test -- --ignored       # Slow security tests (~16s)
```
**Note:** `cargo fmt` MUST be the last formatting step before commit to ensure consistent style.

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

## Testing

**Run before committing:**
```bash
cargo test --no-default-features           # Fast tests (~9s)
cargo test --no-default-features -- --ignored  # Slow tests (~16s)
```

See [docs/TESTING.md](docs/TESTING.md) for complete testing guide.

## Documentation

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development workflow and dependency management.
