# Force Prehashed Verification Design

**Date:** 2026-02-05
**Status:** Approved
**Goal:** Add `-H` flag support for verification to reject legacy signatures (match C minisign behavior)

## Overview

The C version of minisign has a `-H` flag that serves dual purposes:
- **Signing mode:** Create prehashed signatures
- **Verification mode:** Reject legacy (non-prehashed) signatures

The Rust implementation currently supports `-H` for signing but not for verification enforcement. This design adds the verification behavior to achieve 100% C compatibility.

## Background

From C minisign (`src/minisign.c:513-517`):
```c
if (hashed == 0 && allow_legacy == 0) {
    if (quiet == 0) {
        fprintf(stderr, "Legacy (non-prehashed) signature found\n");
    }
    exit(1);
}
```

When `-H` is passed during verification, C minisign checks if the signature is legacy (non-prehashed, "Ed" marker) and rejects it. This provides a way to enforce that only modern prehashed signatures ("ED" marker) are accepted.

## Design

### 1. Flag Behavior

**Context-dependent `-H/--prehashed` flag:**
- **Signing (`-S -H`):** Create prehashed signature (existing behavior)
- **Verification (`-V -H`):** Reject legacy signatures (new behavior)

### 2. Code Changes

#### 2.1 VerifyOptions Structure (`src/ops/verify.rs`)

Add `force_prehashed` field:
```rust
pub struct VerifyOptions<'a> {
    public_key: PublicKeySource<'a>,
    signature_file: &'a Path,
    message_file: &'a Path,
    output: bool,
    quiet: bool,
    force_prehashed: bool,  // NEW
}
```

Update constructor and add getter:
```rust
pub fn new(
    public_key: PublicKeySource<'a>,
    signature_file: &'a Path,
    message_file: &'a Path,
    output: bool,
    quiet: bool,
    force_prehashed: bool,  // NEW
) -> Self { ... }

pub fn force_prehashed(&self) -> bool {
    self.force_prehashed
}
```

#### 2.2 Verification Logic (`src/ops/verify.rs`)

Update `verify_message_signature()`:
```rust
pub fn verify_message_signature(
    pubkey: &PubkeyStruct,
    sig_box: &SignatureBox,
    message_file: &Path,
    force_prehashed: bool,  // NEW
) -> Result<()> {
    // Existing keynum check...

    // NEW: Check for legacy signature when force_prehashed is enabled
    if force_prehashed && !sig_box.sig_struct().is_prehashed() {
        return Err(Error::LegacySignatureRejected);
    }

    // Existing verification logic...
}
```

Update call sites:
- `verify()` function: pass `options.force_prehashed()`
- `verify_file_with_key()`: use `options` parameter instead of ignoring it

#### 2.3 Error Type (`src/errors.rs`)

Add new error variant:
```rust
#[error("Legacy (non-prehashed) signature found")]
LegacySignatureRejected,
```

#### 2.4 CLI Integration (`src/main.rs`)

Update verify action handling:
```rust
Action::Verify => {
    // ... existing code ...
    let options = VerifyOptions::new(
        public_key,
        &sig_file,
        &msg_file,
        cli.output,
        quiet,
        cli.prehashed,  // NEW: pass the flag
    );
    // ... rest of verification ...
}
```

### 3. Testing Strategy

#### 3.1 Unit Tests (`tests/unit/ops/verify.rs`)

1. `test_verify_rejects_legacy_with_force_prehashed()`
   - Create legacy signature
   - Verify with `force_prehashed=true`
   - Assert `LegacySignatureRejected` error

2. `test_verify_accepts_legacy_without_force_prehashed()`
   - Create legacy signature
   - Verify with `force_prehashed=false`
   - Assert success

3. `test_verify_accepts_prehashed_with_force_prehashed()`
   - Create prehashed signature
   - Verify with `force_prehashed=true`
   - Assert success

#### 3.2 CLI Integration Tests (`tests/cli_test.rs`)

4. `test_cli_verify_h_flag_rejects_legacy()`
   - Sign file with `-S -l` (legacy mode)
   - Run `minisign_rs -V -H -m file.txt`
   - Assert exit code 1
   - Assert stderr contains "Legacy (non-prehashed) signature found"

5. `test_cli_verify_h_flag_accepts_prehashed()`
   - Sign file with `-S` (prehashed mode)
   - Run `minisign_rs -V -H -m file.txt`
   - Assert exit code 0

#### 3.3 Cross-Binary Compatibility (`tests/cross_binary_test.rs`)

6. `test_h_flag_compatibility_with_c_minisign()`
   - C minisign creates legacy signature
   - Rust rejects with `-H` (matches C behavior)
   - C minisign creates prehashed signature
   - Rust accepts with `-H` (matches C behavior)

### 4. Documentation Updates

#### 4.1 README.md

**Mode Options table** (~line 140):
```markdown
| `-H` | `--prehashed` | Sign in prehashed mode, or require prehashed verification (reject legacy signatures) |
```

**Verify a signature section** (~line 219):
Add example:
```bash
# Require prehashed signature (reject legacy)
minisign_rs -V -H -m file.txt -p key.pub
```

**Signing Modes section** (~line 320):
Add note under "When to Use Each Mode":
```markdown
**Note on verification:** The `-H` flag can be used during verification to enforce
that only prehashed signatures are accepted. This rejects legacy (non-prehashed)
signatures, useful when organizational policy requires modern signature formats.
```

## Implementation Order

Following TDD approach (per CLAUDE.md):

1. **Write error type** - Add `LegacySignatureRejected` to `errors.rs`
2. **Write unit tests** - All three unit tests (should fail)
3. **Update VerifyOptions** - Add field, constructor, getter
4. **Implement verification logic** - Add rejection check
5. **Update call sites** - Pass flag through
6. **Verify unit tests pass**
7. **Write CLI tests** - Integration tests (should fail initially)
8. **Update main.rs** - Wire up CLI flag
9. **Verify CLI tests pass**
10. **Write cross-binary test** - C compatibility test
11. **Verify all tests pass**
12. **Update README.md** - Document the feature
13. **Run full test suite** - Fast + slow tests
14. **Run clippy and fmt** - Code quality checks

## Success Criteria

- [ ] All new tests pass
- [ ] All existing tests still pass
- [ ] Zero clippy warnings
- [ ] Cross-binary test confirms C compatibility
- [ ] README.md accurately documents behavior
- [ ] Error message matches C: "Legacy (non-prehashed) signature found"

## Compatibility

This change maintains 100% compatibility with C minisign:
- Same flag name and behavior
- Same error message
- Same exit code (1 for rejection)
- No breaking changes to existing functionality
