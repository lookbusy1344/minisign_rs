# Version and Commit Hash Reporting Design

**Date:** 2026-01-24
**Status:** Approved

## Overview

Add build-time git commit hash to version reporting, displayed in `--version` output and at the top of `--help` text.

## Requirements

1. Version output format: `minisign_rs 0.12.0 (6a4f667)`
2. Display in `--version` flag output
3. Display at top of `--help` output
4. Build-time commit hash extraction (no runtime git dependency)
5. Graceful fallback when git unavailable

## Design

### 1. Build-Time Git Integration

**File:** `build.rs` (new file at repository root)

**Responsibilities:**
- Execute `git rev-parse HEAD` during compilation
- Truncate to 7-character short hash (standard Git convention)
- Set `GIT_COMMIT_HASH` environment variable for use in source
- Handle missing `.git` directory gracefully
- Register `.git/HEAD` as rebuild dependency

**Error Handling:**
- Git command fails → hash = "unknown"
- Not in git repository → hash = "unknown"
- Missing git binary → hash = "unknown"

**Implementation approach:**
```rust
use std::process::Command;

fn main() {
    // Get commit hash
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output();

    let commit_hash = match output {
        Ok(output) if output.status.success() => {
            let hash = String::from_utf8_lossy(&output.stdout);
            hash.trim().chars().take(7).collect()
        }
        _ => "unknown".to_string(),
    };

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);

    // Rerun if HEAD changes
    println!("cargo:rerun-if-changed=.git/HEAD");
}
```

### 2. Version String Construction

**File:** `src/cli.rs`

**Current (line 12):**
```rust
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (Rust)"))]
```

**Updated:**
```rust
#[command(version = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("GIT_COMMIT_HASH"),
    ")"
))]
```

**Output examples:**
- With git: `minisign_rs 0.12.0 (6a4f667)`
- Without git: `minisign_rs 0.12.0 (unknown)`

### 3. Automatic Help Integration

Clap automatically displays the version string at the top of `--help` output when `#[command(version = ...)]` is set. No additional changes needed.

## Testing Strategy

### Unit Tests
Not applicable - this is build-time metadata, no runtime logic to test.

### Integration Tests
Add test to `tests/cli_test.rs`:

```rust
#[test]
fn test_version_includes_commit() {
    Command::cargo_bin("minisign_rs")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")))
        .stdout(predicates::str::contains("("));
}

#[test]
fn test_help_shows_version() {
    Command::cargo_bin("minisign_rs")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}
```

### Manual Verification
```bash
# Local dev build
cargo build --release
./target/release/minisign_rs --version
# Expected: minisign_rs 0.12.0 (6a4f667)

./target/release/minisign_rs --help
# Expected: Version shown at top

# Tarball simulation (no .git)
mkdir /tmp/test && cp -r rs /tmp/test/
rm -rf /tmp/test/rs/.git
cd /tmp/test/rs && cargo build --release
./target/release/minisign_rs --version
# Expected: minisign_rs 0.12.0 (unknown)
```

## Implementation Checklist

- [ ] Create `build.rs` at repository root
- [ ] Update `src/cli.rs` version attribute
- [ ] Add integration tests to `tests/cli_test.rs`
- [ ] Test with git available
- [ ] Test without .git directory
- [ ] Run full test suite
- [ ] Update README if needed

## Compatibility Impact

**C minisign compatibility:** None - this only affects version reporting, not file formats or crypto operations.

**Breaking changes:** None - purely additive feature.

## Future Enhancements

Potential future additions (out of scope for this design):
- Build timestamp in version output
- Rust version used for build
- Feature flags enabled at compile time

## References

- Cargo environment variables: https://doc.rust-lang.org/cargo/reference/environment-variables.html
- Build scripts: https://doc.rust-lang.org/cargo/reference/build-scripts.html
- Clap versioning: https://docs.rs/clap/latest/clap/_derive/index.html#command-attributes
