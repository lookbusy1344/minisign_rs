# Signature File Inspection Design

**Date:** 2026-01-31
**Status:** Approved

## Overview

Extend `-I` (inspect) to support signature files via the existing `-x` flag. When inspecting a signature, display the key ID that created it in both hex and PGP word list formats.

## CLI Changes

- **Current behavior preserved**: `-I` without `-x` works exactly as before (inspects keys)
- **New behavior**: `-I -x signature.minisig` inspects the signature file
- **No auto-detection**: Each flag (`-s`, `-p`, `-x`) expects its specific file type
- **No defaults**: Signatures require explicit `-x` flag (no fallback path)

## Example Usage

```bash
# Inspect signature file
minisign -I -x file.txt.minisig
```

**Output:**
```
Inspecting: file.txt.minisig

Signature Information:
├─ Key ID: 1234567890ABCDEF
├─ Key ID (words): snapline atmosphere sugar sardonic crackdown provincial offload quantity
└─ Algorithm: Normal (Ed25519)
```

**For prehashed signatures:**
```
Inspecting: file.txt.minisig

Signature Information:
├─ Key ID: 1234567890ABCDEF
├─ Key ID (words): snapline atmosphere sugar sardonic crackdown provincial offload quantity
└─ Algorithm: Prehashed (Blake2b-512)
```

## Implementation Details

### Code Changes

**1. `ops/inspect.rs` - Add new function:**

```rust
pub fn inspect_signature(signature_file: &str) -> Result<SignatureInspectResult>
```

Responsibilities:
- Parse `SignatureBox` from file
- Extract `keynum` from `sig_struct`
- Convert to hex via `keynum.to_key_id()`
- Convert to words via `wordlist::keynum_to_words()`
- Return algorithm type (normal vs prehashed)

**2. `main.rs::handle_inspect()` - Add `-x` to priority chain:**

- Check for `cli.signature_file` before falling back to keys
- Call `inspect_signature()` if `-x` provided
- Format and display signature-specific output

### New Types

```rust
pub struct SignatureInspectResult {
    pub key_id: String,           // hex format
    pub key_id_words: String,     // PGP word list
    pub algorithm: SignatureAlgorithm,
}

pub enum SignatureAlgorithm {
    Normal,      // "Ed"
    Prehashed,   // "ED"
}
```

### Code Reuse

- `SignatureBox::from_file_contents()` - already parses .minisig files
- `KeyNum::to_key_id()` - already converts to hex
- `wordlist::keynum_to_words()` - already converts to words

## Output Format

**Header label:**
- Keys use: `Key Information:`
- Signatures use: `Signature Information:`

**Tree structure:**
- `├─` for all middle items (Key ID, Key ID words)
- `└─` for last item (Algorithm)
- Matches existing key inspection layout exactly

**Algorithm display:**
- Normal signatures: `Algorithm: Normal (Ed25519)`
- Prehashed signatures: `Algorithm: Prehashed (Blake2b-512)`

## Error Handling

**Invalid signature file:**
```rust
Error::InvalidSignatureFormat("expected 4 lines, got 2")
```

**Wrong file type with -x:**

If user does `-I -x mykey.pub`:
- `SignatureBox::from_file_contents()` will fail
- Return: `Error::InvalidSignatureFormat("File is not a valid signature")`

**Missing -x flag:**

If user tries `-I signature.minisig` (no flag):
- Falls back to default secret key path (current behavior)
- Error: can't read `~/.minisign/minisign.key` or file doesn't exist
- **No special handling** - user must use `-x` explicitly

## Testing Strategy (TDD)

### Test Files

1. `tests/unit/ops/inspect.rs` - Unit tests for `inspect_signature()`
2. `tests/cli_test.rs` - Integration tests for `-I -x` CLI

### Test Cases

**Unit tests** (`inspect_signature()` function):
- ✓ Normal signature file - extracts key ID correctly
- ✓ Prehashed signature file - detects prehashed algorithm
- ✓ Invalid signature file (wrong format) - returns error
- ✓ Key ID matches expected hex format
- ✓ Word list conversion works correctly

**Integration tests** (CLI behavior):
- ✓ `minisign -I -x file.minisig` - shows signature info
- ✓ `minisign -I -x nonexistent.minisig` - file not found error
- ✓ `minisign -I -x keyfile.pub` - invalid signature format error
- ✓ Output format matches key inspection tree structure
- ✓ Works with both normal and prehashed signatures

### Test Data

- Create test `.minisig` files in `tests/` directory
- Reuse existing test keys/signatures where possible
- Generate both normal and prehashed signatures for testing

### TDD Workflow

1. Write failing tests first
2. Implement `inspect_signature()` function
3. Update `handle_inspect()` to support `-x`
4. Verify all tests pass
5. Run clippy (pedantic mode)

## Success Criteria

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Zero clippy warnings (pedantic mode)
- [ ] Output format matches existing key inspection
- [ ] Error messages are clear and helpful
- [ ] Documentation updated (if needed)
