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

These tools support structural search and replace, rename operations, and other automated refactoring tasks.

## Key Locations
```
src/
├── crypto.rs            # Ed25519, Blake2b, Scrypt
├── keys.rs              # Key types, generation, encryption
├── signature.rs         # Signature creation/verification
├── credential_store.rs  # OS credential store for password caching
├── ops/                 # High-level operations (sign, verify, etc)
└── main.rs              # CLI

tests/
├── cli_test.rs           # CLI integration tests
├── compatibility.rs      # C minisign cross-tests
└── cross_binary_test.rs  # C/Rust interop tests
```

## Testing

### Credential Store Feature

The `credential_store` feature controls OS keyring integration (macOS Keychain, Windows Credential Manager, etc.):

- **Enabled by default** for production builds
- **Disable during development** to avoid keychain popup dialogs:
  ```bash
  cargo test --no-default-features     # Run tests without keychain access
  cargo build --no-default-features    # Build without keyring dependency
  ```
- When disabled, credential store functions become no-ops (return Ok/None/false)

### Test Categories

- **Fast tests** (~420 tests, ~9s): Default test suite using N=2^14 for scrypt
  - Run with: `cargo test --no-default-features` (no keychain popups)
  - Or: `cargo test` (with keychain access, may show popups)

- **Slow tests** (~10 tests, ~16s): Security tests using production N=2^20 for scrypt
  - Run with: `cargo test --no-default-features -- --ignored`

- **Credential store tests** (~15 tests): Tests that interact with OS keyring
  - **Require user interaction** (authorization prompts)
  - **Must run sequentially** (`--test-threads=1`) to avoid parallel prompts
  - Enabled with: `cargo test --features credential_store_tests -- --test-threads=1`
  - Run with: `./run_all_tests.sh --credential-store`
  - Marked with `#[cfg_attr(not(feature = "credential_store_tests"), ignore)]`
  - Use RAII cleanup guards to ensure credentials removed even on panic

### Test Runner Script

```bash
./run_all_tests.sh                     # Fast + slow tests (default, no keychain popups)
./run_all_tests.sh --credential-store  # Credential store tests only
./run_all_tests.sh --all               # All tests including credential store
```

### Test Requirements

- Must test compatibility with C minisign after crypto changes
- C minisign must be installed for compatibility tests
- **IMPORTANT**: All tests MUST be in the `tests/` directory (not `src/`) to enable proper CodeQL security analysis exclusions
- Credential store tests are **completely separate** from fast/slow tests to avoid accidental user prompts during development

## Crypto Dependencies (ONLY These)
- `ed25519-dalek` - Ed25519 signatures
- `blake2` - Blake2b hashing
- `scrypt` - Key derivation
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time comparisons

Do not add other crypto libs.

## Other Key Dependencies
- `keyring` - OS credential store integration (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- `clap` - CLI argument parsing
- `rayon` - Parallel verification for multiple files

## Dependency Management

When updating dependencies:
1. Review changelogs for breaking changes
2. Update version in Cargo.toml
3. Run full test suite including slow tests
4. Run `cargo audit` to check for vulnerabilities

## Documentation
- `README.md` - User docs
- `COMPATIBILITY.md` - C/Rust compatibility proof
- `docs/benchmark-report.md` - Performance comparison
- `docs/c-rust-parity-gaps.md` - C/Rust implementation differences
