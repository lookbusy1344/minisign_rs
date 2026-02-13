# Credential Store Cleanup Script Design

**Date:** 2026-02-13
**Language:** Python
**Goal:** Create a utility script to discover and clean up minisign credential entries from the macOS Keychain

## Motivation

During development and testing of the credential store feature, multiple minisign entries can accumulate in the macOS Keychain. These include:
- Test credentials from development
- Orphaned credentials from deleted keys
- Credentials from old/renamed credential IDs

A cleanup utility is needed to:
- Discover all minisign entries in the keychain
- Allow selective or bulk deletion
- Provide dry-run capability to preview deletions

## Design

### Architecture

The script operates in three phases:

1. **Discovery Phase**: Execute `security dump-keychain` and parse output to find all entries with service name "minisign"
2. **Selection Phase**: Display entries to user and collect selection (interactive mode or `--all` flag)
3. **Deletion Phase**: Use `security delete-generic-password -s minisign -a <credential_id>` for each selected entry

**File location**: `rs/scripts/cleanup_credentials.py`

**Module Structure**:
```python
- find_minisign_entries() -> List[CredentialEntry]
  Parse security dump-keychain output

- display_entries(entries) -> None
  Show numbered list with credential IDs

- select_entries(entries, all_flag) -> List[CredentialEntry]
  Interactive selection or return all if --all

- delete_entry(entry, dry_run) -> bool
  Execute deletion via security command

- main()
  Orchestrate phases, handle flags
```

**CLI Flags**:
- `--all` - Delete all minisign entries without prompting
- `--dry-run` - Show what would be deleted without actually deleting
- `--help` - Show usage

### Data Parsing & Structure

**Keychain Output Format**:
The `security dump-keychain` command outputs entries in a multi-line format:
```
keychain: "/Users/user/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    0x00000007 <blob>="minisign"
    "acct"<blob>="0102030405060708"
    ...
```

**Data Structure**:
```python
@dataclass
class CredentialEntry:
    credential_id: str    # The account name (hex string)
    keychain_path: str    # Which keychain it's in

    def __str__(self) -> str:
        return f"{self.credential_id} (in {os.path.basename(self.keychain_path)})"
```

**Parsing Strategy**:
- Look for entries where service (`svce` or attribute `0x00000007`) equals "minisign"
- Extract the account (`acct`) field containing the credential_id
- Track which keychain file each entry belongs to
- Handle edge cases:
  - Multiple keychains (login, System, etc.)
  - Malformed entries (skip with warning)
  - Special characters in hex IDs (preserve exactly)

**Why `dump-keychain` instead of `find-generic-password`**:
The `find-generic-password` command requires knowing the account name (credential_id) upfront, which defeats the purpose of discovery. The `dump-keychain` approach allows us to find all minisign entries without prior knowledge.

### Interactive Selection UI

**Display Format**:
```
Found 5 minisign credential entries:

  1. [ ] a1b2c3d4e5f6g7h8 (in login.keychain-db)
  2. [ ] 0807060504030201 (in login.keychain-db)
  3. [ ] deadbeefcafebabe (in login.keychain-db)
  4. [ ] 1234567890abcdef (in System.keychain)
  5. [ ] fedcba0987654321 (in login.keychain-db)

Enter selection (numbers separated by spaces, or 'all' for all, 'q' to quit):
```

**Selection Input Modes**:
- **Individual numbers**: `1 3 5` - Select specific entries
- **Ranges**: `1-3` - Select range of entries
- **All**: `all` - Select all entries
- **Quit**: `q` or empty input - Exit without deleting

**Input Validation**:
- Reject invalid numbers (out of range, non-numeric)
- Show clear error message and re-prompt
- Allow ctrl-C to abort at any time

**Flag Behavior**:
- **`--all` flag**: Skip interactive selection, select all entries automatically
- **`--dry-run` flag**: After selection, show "Would delete:" list instead of executing deletions

### Error Handling

**Keychain Access Failures**:
- If `security dump-keychain` fails (permissions, locked keychain): Show error and exit with code 1
- If no minisign entries found: Print "No minisign entries found in keychain" and exit with code 0

**Deletion Failures**:
- If `security delete-generic-password` fails for an entry:
  - Print warning with credential_id and error message
  - Continue with remaining entries
  - Track successes/failures
- Show summary at end:
  ```
  Deleted 3 entries successfully
  Failed to delete 1 entry:
    - a1b2c3d4e5f6g7h8: The specified item could not be found in the keychain
  ```

**User Interruption**:
- Catch `KeyboardInterrupt` (ctrl-C) during any phase
- Exit gracefully with "Aborted" message
- If interrupted during deletion: Show which entries were successfully deleted

**Invalid Input**:
- Re-prompt on invalid selection input
- Maximum 3 retries before exiting with error

**Platform Check**:
- Verify running on macOS (check `platform.system() == "Darwin"`)
- Exit with clear error if run on non-macOS system

### Testing Strategy

**Manual Testing** (appropriate for utility script):

**Test Setup**:
```bash
cd rs
cargo build --release
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password
```

**Test Cases**:
1. **Discovery**: Verify script finds test entries
2. **Selective deletion**: Select one entry, verify only that one deleted
3. **`--all` flag**: Run with `--all`, verify all entries deleted
4. **`--dry-run` flag**: Run with `--dry-run`, verify nothing actually deleted
5. **Empty keychain**: After cleanup, verify reports "No entries found"
6. **Invalid input**: Test bad selection (letters, out of range), verify re-prompt
7. **Ctrl-C abort**: Press ctrl-C during selection, verify clean exit

**Cleanup After Testing**:
Use the script itself with `--all` flag to clean up test credentials.

## Implementation Notes

**Dependencies**:
- Standard library only (subprocess, re, dataclasses, argparse, sys, os, platform)
- No external packages required

**Security Considerations**:
- Never display actual passwords (script only works with credential IDs)
- Use subprocess with shell=False to prevent injection
- Validate all user input before passing to system commands

**Compatibility**:
- Requires macOS (uses `security` command)
- Python 3.7+ (for dataclasses)
- Works with any keychain accessible to the user

## Usage Examples

**Interactive mode**:
```bash
python3 scripts/cleanup_credentials.py
```

**Delete all without prompting**:
```bash
python3 scripts/cleanup_credentials.py --all
```

**Preview deletions (dry run)**:
```bash
python3 scripts/cleanup_credentials.py --dry-run
python3 scripts/cleanup_credentials.py --all --dry-run
```

**Get help**:
```bash
python3 scripts/cleanup_credentials.py --help
```

## Future Enhancements (Not in Scope)

- Cross-platform support (Windows Credential Manager, Linux Secret Service)
- Match credential IDs against current keys and suggest orphans
- Export/import credential lists
- Backup credentials before deletion

These enhancements are not needed for the current use case (manual cleanup during development).
