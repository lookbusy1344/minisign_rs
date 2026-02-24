# Replace clap with pico-args Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the `clap` and `git-version` dependencies with `pico-args` to reduce binary size by ~77 KB.

**Architecture:** `cli.rs` keeps the `Cli` struct as a plain data struct (no derives) and gains a `parse_args()` associated function that manually extracts every flag and option using `pico_args::Arguments`. Help text and version output become static strings printed directly to stdout. The `Action` enum and all path-helper methods remain unchanged.

**Tech Stack:** `pico-args 0.5`, `std::process::exit`, `env!("CARGO_PKG_VERSION")`

---

## Background

`cargo bloat --crates` shows `clap_builder` at 77 KB — 18.6% of the `.text` section, nearly equal to all crypto code combined. `clap` pulls in `anstream`, `anstyle`, `strsim`, and `clap_lex` as transitive deps. `git-version` is consumed solely to populate the clap version string; once clap is gone, it can be dropped too.

The binary's CLI is small and stable (6 actions, ~25 flags), making manual parsing straightforward.

---

## Task 1: Update Cargo.toml

**Files:**
- Modify: `rs/Cargo.toml`

**Step 1: Remove clap and git-version, add pico-args**

Replace:
```toml
clap = { version = "4.5", features = ["derive"] }
git-version = "0.3"
```
With:
```toml
pico-args = { version = "0.5", features = ["eq-separator"] }
```

The `eq-separator` feature allows `--flag=value` syntax (GNU-style), matching what clap supported.

**Step 2: Verify the change compiles (expected: errors in cli.rs and main.rs)**

```bash
cd rs && cargo check --no-default-features 2>&1 | head -40
```

Expected: errors about `clap::Parser`, `clap::ArgAction`, `git_version::git_version!` — confirms old deps are gone.

**Step 3: Commit**

```bash
git add rs/Cargo.toml rs/Cargo.lock
git commit -m "build: replace clap + git-version with pico-args"
```

---

## Task 2: Rewrite cli.rs

**Files:**
- Modify: `rs/src/cli.rs`

The rewrite preserves the `Cli` struct fields and `Action` enum exactly. Only the parsing machinery changes.

**Step 1: Replace the entire file contents**

```rust
//! Command-line interface definition using pico-args
//!
//! This module defines the CLI structure matching the C minisign interface exactly.

use crate::errors::{Error, Result};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
minisign_rs - A dead simple Rust tool to sign files and verify signatures

USAGE:
    minisign_rs -G [-f] [-p pubkey] [-s seckey] [-W] [-c comment]
    minisign_rs -S [-H | -l] [-x sigfile] [-s seckey] [-c comment] [-t comment] -m file [files...]
    minisign_rs -V [-x sigfile] [-p pubkey | -P key] [-o] [-q|-Q] -m file [files...]
    minisign_rs -R [-s seckey] [-p pubkey]
    minisign_rs -K [-s seckey] [-W]
    minisign_rs -I [-s seckey | -p pubkey | -P key | -x sigfile]

ACTIONS:
    -G, --generate          Generate a new keypair
    -S, --sign              Sign files
    -V, --verify            Verify a signature
    -R, --recreate          Recreate a public key from a secret key
    -K, --change-password   Change or remove password from a secret key
    -I, --inspect           Inspect a key file

OPTIONS:
    -c, --untrusted-comment <COMMENT>   Untrusted comment
    -f, --force                         Force overwrite existing files
    -h, --help                          Show this help
    -H, --prehashed                     Sign or verify a prehashed file
    -l, --legacy                        Legacy mode (sign only)
    -m, --input <FILE>                  Message file
    -o, --output                        Output verification result to stdout
    -p, --publickey-path <FILE>         Public key file
    -P, --publickey <KEY>               Public key as base64 string
    -q, --quiet                         Quiet mode (minimal output)
    -Q, --pretty-quiet                  Pretty quiet mode (trusted comment only)
    -s, --secretkey-path <FILE>         Secret key file
    -t, --trusted-comment <COMMENT>     Trusted comment
    -v, --version                       Show version
    -W, --no-password                   Do not use password (generate and change only)
    -x, --signature <FILE>              Signature file
        --allow-kdf-fallback            Allow KDF parameter fallback if 128MB allocation fails
        --forget-password, --fp         Remove saved password from credential store
        --no-decrypt                    Skip decryption of encrypted keys
        --password-file <FILE>          Read password from file (testing only - insecure)
        --save-password, --sp           Save password to OS credential store
";

// clippy: clap derive requires boolean fields for CLI flags - builder pattern is not applicable here
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct Cli {
    pub generate: bool,
    pub sign: bool,
    pub verify: bool,
    pub recreate: bool,
    pub change: bool,
    pub inspect: bool,

    pub force: bool,
    pub no_decrypt: bool,
    pub prehashed: bool,
    pub legacy: bool,
    pub output: bool,
    pub quiet: bool,
    pub pretty_quiet: bool,
    pub no_password: bool,
    pub allow_kdf_fallback: bool,
    pub save_password: bool,
    pub forget_password: bool,

    pub message_file: Option<PathBuf>,
    pub extra_files: Vec<PathBuf>,
    pub public_key_file: Option<PathBuf>,
    pub public_key_base64: Option<String>,
    pub secret_key_file: Option<PathBuf>,
    pub trusted_comment: Option<String>,
    pub untrusted_comment: Option<String>,
    pub signature_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,

    #[cfg(feature = "parallel")]
    pub sequential: bool,

    pub force_weak_kdf: bool,
}

impl Cli {
    /// Parse arguments from the process environment.
    ///
    /// Exits the process (code 0) for `--help` and `--version`.
    ///
    /// # Errors
    ///
    /// Returns an error if an unknown flag is encountered or a required value
    /// is missing from a flag that takes an argument.
    pub fn parse() -> Result<Self> {
        let mut args = pico_args::Arguments::from_env();

        // Handle --help / --version before anything else
        if args.contains(["-h", "--help"]) {
            print!("{HELP}");
            std::process::exit(0);
        }
        if args.contains(["-v", "--version"]) {
            println!("minisign_rs {VERSION}");
            std::process::exit(0);
        }

        let mut cli = Self {
            generate:          args.contains(["-G", "--generate"]),
            sign:              args.contains(["-S", "--sign"]),
            verify:            args.contains(["-V", "--verify"]),
            recreate:          args.contains(["-R", "--recreate"]),
            change:            args.contains(["-K", "--change-password"]),
            inspect:           args.contains(["-I", "--inspect"]),

            force:             args.contains(["-f", "--force"]),
            no_decrypt:        args.contains(["--no-decrypt"]),
            prehashed:         args.contains(["-H", "--prehashed"]),
            legacy:            args.contains(["-l", "--legacy"]),
            output:            args.contains(["-o", "--output"]),
            quiet:             args.contains(["-q", "--quiet"]),
            pretty_quiet:      args.contains(["-Q", "--pretty-quiet"]),
            no_password:       args.contains(["-W", "--no-password"]),
            allow_kdf_fallback: args.contains(["--allow-kdf-fallback"]),
            save_password:     args.contains(["--save-password", "--sp"]),
            forget_password:   args.contains(["--forget-password", "--fp"]),

            message_file:      args.opt_value_from_str(["-m", "--input"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            public_key_file:   args.opt_value_from_str(["-p", "--publickey-path"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            public_key_base64: args.opt_value_from_str(["-P", "--publickey"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            secret_key_file:   args.opt_value_from_str(["-s", "--secretkey-path"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            trusted_comment:   args.opt_value_from_str(["-t", "--trusted-comment"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            untrusted_comment: args.opt_value_from_str(["-c", "--untrusted-comment"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            signature_file:    args.opt_value_from_str(["-x", "--signature"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,
            password_file:     args.opt_value_from_str(["--password-file"])
                                   .map_err(|e| Error::Usage(e.to_string().into()))?,

            #[cfg(feature = "parallel")]
            sequential: args.contains(["--sequential"]),

            // Debug-only flag: present in debug builds, always false in release
            #[cfg(debug_assertions)]
            force_weak_kdf: args.contains(["--force-weak-kdf"]),
            #[cfg(not(debug_assertions))]
            force_weak_kdf: false,

            extra_files: Vec::new(),
        };

        // Collect remaining positional arguments as extra files
        let remaining = args.finish();
        if !remaining.is_empty() {
            cli.extra_files = remaining
                .into_iter()
                .map(PathBuf::from)
                .collect();
        }

        Ok(cli)
    }

    /// Get the selected action, or None if no action was specified
    #[must_use]
    pub const fn action(&self) -> Option<Action> {
        if self.generate {
            Some(Action::Generate)
        } else if self.sign {
            Some(Action::Sign)
        } else if self.verify {
            Some(Action::Verify)
        } else if self.recreate {
            Some(Action::Recreate)
        } else if self.change {
            Some(Action::Change)
        } else if self.inspect {
            Some(Action::Inspect)
        } else {
            None
        }
    }

    /// Merge `-m` file and positional extra files into a single list.
    ///
    /// Matches C minisign semantics: `-m` specifies the first file, any
    /// remaining positional arguments are additional files to sign.
    ///
    /// Returns a `Cow` to avoid cloning when only `extra_files` are present.
    #[must_use]
    pub fn all_message_files(&self) -> Cow<'_, [PathBuf]> {
        match &self.message_file {
            Some(first) => {
                let mut files = Vec::with_capacity(1 + self.extra_files.len());
                files.push(first.clone());
                files.extend_from_slice(&self.extra_files);
                Cow::Owned(files)
            }
            None => Cow::Borrowed(&self.extra_files),
        }
    }

    /// Get the default secret key path based on platform.
    ///
    /// Checks `MINISIGN_CONFIG_DIR` first, then falls back to `~/.minisign/`.
    #[must_use]
    pub fn default_secret_key_path() -> PathBuf {
        if let Ok(config_dir) = std::env::var("MINISIGN_CONFIG_DIR") {
            PathBuf::from(config_dir).join("minisign.key")
        } else if let Some(home) = dirs::home_dir() {
            home.join(".minisign").join("minisign.key")
        } else {
            PathBuf::from(".minisign.key")
        }
    }

    /// Get the default public key path (current directory)
    #[must_use]
    pub fn default_public_key_path() -> PathBuf {
        PathBuf::from("./minisign.pub")
    }

    /// Get the default signature path for a message file.
    ///
    /// # Errors
    ///
    /// Returns an error if the path has no valid filename component.
    pub fn default_signature_path(message_file: &Path) -> Result<PathBuf> {
        let mut sig_path = message_file.to_path_buf();
        let file_name = message_file
            .file_name()
            .ok_or_else(|| Error::InvalidPath(message_file.to_path_buf()))?;

        let mut file_name_string = file_name.to_string_lossy().into_owned();
        file_name_string.push_str(".minisig");
        sig_path.set_file_name(file_name_string);
        Ok(sig_path)
    }
}

/// Determine which action was selected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Generate,
    Sign,
    Verify,
    Recreate,
    Change,
    Inspect,
}
```

**Step 2: Verify cli.rs compiles in isolation**

```bash
cd rs && cargo check --no-default-features 2>&1 | grep "^error" | head -20
```

Expected: errors only in `main.rs` (still uses `clap::Parser`), none in `cli.rs`.

**Step 3: Commit**

```bash
git add rs/src/cli.rs
git commit -m "feat(cli): replace clap derive with pico-args manual parsing"
```

---

## Task 3: Update main.rs

**Files:**
- Modify: `rs/src/main.rs:1-6` (imports and `run()` call site)

**Step 1: Remove clap import, update `run()`**

Remove line 1:
```rust
use clap::Parser;
```

In `run()` (line 46), change:
```rust
let cli = Cli::parse();
```
to:
```rust
let cli = Cli::parse()?;
```

That's the complete change — `Cli::parse()` now returns `Result<Self>` instead of panicking.

**Step 2: Compile check**

```bash
cd rs && cargo check --no-default-features 2>&1 | grep "^error"
```

Expected: no errors.

**Step 3: Full clippy**

```bash
cd rs && gtimeout 60 cargo clippy --all-targets --no-default-features -- -D clippy::all -D clippy::pedantic 2>&1 | grep "^error"
```

Fix any warnings surfaced by clippy before proceeding.

**Step 4: Commit**

```bash
git add rs/src/main.rs
git commit -m "feat(main): update run() to use pico-args Cli::parse()"
```

---

## Task 4: Run the test suite

**Step 1: Run all tests**

```bash
cd rs && gtimeout 120 cargo test --no-default-features 2>&1 | tail -40
```

Expected: all tests pass. Pay particular attention to:
- `test_no_arguments` — must exit code 2 with "No action specified"
- `test_help_flag` — must exit 0, stdout contains "A dead simple Rust tool to sign files"
- `test_version_flag` — must exit 0, stdout contains "minisign_rs"

**Step 2: Fix any failures**

Common failure modes with pico-args vs clap:
- `--flag=value` syntax: requires `eq-separator` feature (already added in Task 1)
- Unknown flags: `args.finish()` returns leftover OsStrings — if tests pass unknown flags expecting an error message, add explicit unknown-flag detection before `args.finish()`

If tests expect a specific error message for unknown flags, add after `args.finish()`:
```rust
// Detect unknown flags (leftover args starting with '-')
let unknown: Vec<_> = remaining.iter()
    .filter(|a| a.to_string_lossy().starts_with('-'))
    .collect();
if !unknown.is_empty() {
    return Err(Error::Usage(
        format!("Unknown argument: {}", unknown[0].to_string_lossy()).into(),
    ));
}
```

**Step 3: Commit fixes if any**

```bash
git add rs/src/cli.rs rs/src/main.rs
git commit -m "fix(cli): handle edge cases surfaced by test suite"
```

---

## Task 5: Measure and verify size reduction

**Step 1: Build release binary**

```bash
cd rs && cargo build --release --no-default-features
ls -lh target/release/minisign_rs
```

**Step 2: Run cargo bloat to confirm clap is gone**

```bash
cargo bloat --release --no-default-features --crates
```

Expected: `clap_builder`, `anstream`, `strsim`, `clap_lex` no longer appear. Total binary size should be materially smaller.

**Step 3: Pre-commit checks**

```bash
cd rs
gtimeout 60 cargo clippy --all-targets --all-features -- -D clippy::all -D clippy::pedantic
cargo fmt
gtimeout 120 cargo test --no-default-features
```

**Step 4: Final commit**

```bash
git add -p  # stage only if there are fmt changes
git commit -m "perf: remove clap — reduces binary .text by ~77KB"
```

---

## Notes

### pico-args behaviours to be aware of

- `args.contains()` **consumes** the flag from the args list. Call it before `opt_value_from_str`.
- `args.finish()` returns any unparsed `OsString`s — this is how we collect `extra_files`.
- The `eq-separator` feature is required for `--flag=value` to work; without it `--flag value` (space-separated) is the only supported form.
- There is no built-in mutual-exclusion between flags — action group validation remains in `Cli::action()` returning `None` (handled in `run()` as before).

### What we intentionally dropped

- Git commit hash in version string (`VERSION` is now the crate version only). This is acceptable — the version is already in `Cargo.toml` and git log provides history.
- clap's coloured error output and usage suggestions on unknown flags. The binary now emits a plain error message consistent with the C minisign behaviour.
