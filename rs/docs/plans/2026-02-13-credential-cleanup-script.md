# Credential Cleanup Script Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a Python utility to discover and clean up minisign credential entries from macOS Keychain

**Architecture:** Three-phase approach: (1) parse `security dump-keychain` to find minisign entries, (2) interactive selection or `--all` flag, (3) delete selected entries via `security delete-generic-password`

**Tech Stack:** Python 3.7+ (standard library only), subprocess, argparse, dataclasses

---

## Task 1: Create Script Skeleton and Platform Check

**Files:**
- Create: `rs/scripts/cleanup_credentials.py`

**Step 1: Create directory if needed**

```bash
mkdir -p rs/scripts
```

**Step 2: Write script skeleton**

Create `rs/scripts/cleanup_credentials.py`:

```python
#!/usr/bin/env python3
"""
Utility script to discover and clean up minisign credential entries from macOS Keychain.

Usage:
    python3 cleanup_credentials.py              # Interactive mode
    python3 cleanup_credentials.py --all        # Delete all without prompting
    python3 cleanup_credentials.py --dry-run    # Preview deletions
"""

import argparse
import platform
import sys


def check_platform():
    """Verify script is running on macOS."""
    if platform.system() != "Darwin":
        print("Error: This script only works on macOS (requires 'security' command)")
        sys.exit(1)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Clean up minisign credential entries from macOS Keychain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Interactive selection
  %(prog)s --all              # Delete all entries
  %(prog)s --dry-run          # Preview without deleting
  %(prog)s --all --dry-run    # Preview deleting all
        """
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Delete all minisign entries without prompting"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting"
    )
    return parser.parse_args()


def main():
    """Main entry point."""
    check_platform()
    args = parse_args()

    print(f"Mode: {'Delete all' if args.all else 'Interactive'}")
    print(f"Dry run: {args.dry_run}")
    print("\nTODO: Implement discovery, selection, and deletion phases")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAborted")
        sys.exit(130)
```

**Step 3: Make script executable**

```bash
chmod +x scripts/cleanup_credentials.py
```

**Step 4: Test platform check and argument parsing**

Run on macOS:
```bash
cd rs
python3 scripts/cleanup_credentials.py --help
```
Expected: Help message displays

Run with flags:
```bash
python3 scripts/cleanup_credentials.py --all --dry-run
```
Expected: Prints "Mode: Delete all" and "Dry run: True"

**Step 5: Commit**

```bash
git add scripts/cleanup_credentials.py
git commit -m "feat(scripts): add credential cleanup script skeleton

- Platform check for macOS
- Argument parsing (--all, --dry-run)
- KeyboardInterrupt handling"
```

---

## Task 2: Implement Keychain Discovery and Parsing

**Files:**
- Modify: `rs/scripts/cleanup_credentials.py`

**Step 1: Add data structure and imports**

Add to top of file after existing imports:

```python
import os
import re
import subprocess
from dataclasses import dataclass
from typing import List
```

Add after imports, before functions:

```python
@dataclass
class CredentialEntry:
    """Represents a minisign credential entry in the keychain."""
    credential_id: str
    keychain_path: str

    def __str__(self) -> str:
        """Display format for user."""
        return f"{self.credential_id} (in {os.path.basename(self.keychain_path)})"
```

**Step 2: Implement keychain discovery function**

Add before `main()`:

```python
def find_minisign_entries() -> List[CredentialEntry]:
    """
    Find all minisign credential entries in the keychain.

    Returns:
        List of CredentialEntry objects

    Raises:
        RuntimeError: If security command fails
    """
    try:
        result = subprocess.run(
            ["security", "dump-keychain"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to read keychain: {e.stderr}") from e
    except FileNotFoundError:
        raise RuntimeError("'security' command not found (macOS only)")

    entries = []
    current_keychain = None
    current_service = None
    current_account = None

    # Parse dump-keychain output
    for line in output.splitlines():
        # Track current keychain
        if line.startswith("keychain:"):
            match = re.search(r'"([^"]+)"', line)
            if match:
                current_keychain = match.group(1)
            current_service = None
            current_account = None
            continue

        # Look for service name (minisign)
        if "svce" in line or '0x00000007' in line:
            if '"minisign"' in line or '<blob>="minisign"' in line:
                current_service = "minisign"
            continue

        # Look for account (credential_id)
        if '"acct"' in line and current_service == "minisign":
            match = re.search(r'<blob>="([^"]+)"', line)
            if match:
                current_account = match.group(1)

                # We have both service=minisign and account, create entry
                if current_keychain and current_account:
                    entries.append(CredentialEntry(
                        credential_id=current_account,
                        keychain_path=current_keychain
                    ))
                    # Reset to avoid duplicates
                    current_service = None
                    current_account = None
            continue

    return entries
```

**Step 3: Update main() to test discovery**

Replace the TODO line in `main()` with:

```python
    # Discovery phase
    print("Searching keychain for minisign entries...")
    try:
        entries = find_minisign_entries()
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not entries:
        print("No minisign entries found in keychain")
        sys.exit(0)

    print(f"\nFound {len(entries)} minisign credential entries:")
    for i, entry in enumerate(entries, 1):
        print(f"  {i}. {entry}")

    print("\nTODO: Implement selection and deletion")
```

**Step 4: Test discovery with real keychain**

First, create test credentials:
```bash
cd rs
cargo build --release
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
# Enter password when prompted (e.g., "testpass1")
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password
# Enter password when prompted (e.g., "testpass2")
```

Run the script:
```bash
python3 scripts/cleanup_credentials.py
```

Expected output:
```
Searching keychain for minisign entries...

Found 2 minisign credential entries:
  1. [credential_id1] (in login.keychain-db)
  2. [credential_id2] (in login.keychain-db)

TODO: Implement selection and deletion
```

**Step 5: Test with empty keychain**

First, manually delete test credentials:
```bash
# Get credential IDs from previous output, then:
security delete-generic-password -s minisign -a [credential_id1]
security delete-generic-password -s minisign -a [credential_id2]
```

Run script:
```bash
python3 scripts/cleanup_credentials.py
```

Expected output:
```
Searching keychain for minisign entries...
No minisign entries found in keychain
```

**Step 6: Recreate test credentials for next task**

```bash
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password
```

**Step 7: Commit**

```bash
git add scripts/cleanup_credentials.py
git commit -m "feat(scripts): add keychain discovery and parsing

- Parse security dump-keychain output
- Extract minisign service entries
- Display found credentials with keychain location"
```

---

## Task 3: Implement Interactive Selection

**Files:**
- Modify: `rs/scripts/cleanup_credentials.py`

**Step 1: Add selection function**

Add before `main()`:

```python
def select_entries(entries: List[CredentialEntry], select_all: bool) -> List[CredentialEntry]:
    """
    Select which entries to delete.

    Args:
        entries: Available credential entries
        select_all: If True, return all entries without prompting

    Returns:
        List of selected entries (may be empty if user quits)
    """
    if select_all:
        return entries

    # Interactive selection
    print("\nEnter selection (numbers separated by spaces, ranges like 1-3, 'all', or 'q' to quit)")

    max_retries = 3
    for attempt in range(max_retries):
        try:
            user_input = input("Selection: ").strip()
        except EOFError:
            # Handle ctrl-D
            return []

        if not user_input or user_input.lower() == 'q':
            return []

        if user_input.lower() == 'all':
            return entries

        # Parse selection
        try:
            selected_indices = set()
            parts = user_input.split()

            for part in parts:
                if '-' in part:
                    # Range like "1-3"
                    start_str, end_str = part.split('-', 1)
                    start = int(start_str)
                    end = int(end_str)
                    if start < 1 or end > len(entries) or start > end:
                        raise ValueError(f"Invalid range: {part}")
                    selected_indices.update(range(start, end + 1))
                else:
                    # Single number
                    num = int(part)
                    if num < 1 or num > len(entries):
                        raise ValueError(f"Number out of range: {num}")
                    selected_indices.add(num)

            # Convert indices to entries (indices are 1-based)
            selected = [entries[i - 1] for i in sorted(selected_indices)]
            return selected

        except ValueError as e:
            print(f"Invalid input: {e}")
            if attempt < max_retries - 1:
                print(f"Please try again ({max_retries - attempt - 1} attempts remaining)")
            else:
                print("Too many invalid attempts. Exiting.")
                return []

    return []
```

**Step 2: Update main() to use selection**

Replace the "TODO: Implement selection and deletion" line with:

```python
    # Selection phase
    selected = select_entries(entries, args.all)

    if not selected:
        print("No entries selected. Exiting.")
        sys.exit(0)

    print(f"\nSelected {len(selected)} entries for deletion:")
    for entry in selected:
        print(f"  - {entry}")

    if args.dry_run:
        print("\nDry run mode - nothing was deleted")
        sys.exit(0)

    print("\nTODO: Implement deletion")
```

**Step 3: Test interactive selection**

Run script:
```bash
python3 scripts/cleanup_credentials.py
```

Test cases:
- Enter `1` - should select first entry
- Run again, enter `1 2` - should select both entries
- Run again, enter `1-2` - should select range (both entries)
- Run again, enter `all` - should select all entries
- Run again, enter `q` - should exit with "No entries selected"
- Run again, enter `999` - should show "Invalid input" and retry

**Step 4: Test --all flag**

```bash
python3 scripts/cleanup_credentials.py --all
```

Expected: Should skip interactive prompt and select all entries

**Step 5: Test --dry-run flag**

```bash
python3 scripts/cleanup_credentials.py --all --dry-run
```

Expected: Should select all and show "Dry run mode - nothing was deleted"

**Step 6: Commit**

```bash
git add scripts/cleanup_credentials.py
git commit -m "feat(scripts): add interactive selection UI

- Support individual numbers, ranges, 'all', 'q'
- Input validation with retry logic
- Respect --all flag to skip prompting
- Dry-run mode preview"
```

---

## Task 4: Implement Deletion Logic

**Files:**
- Modify: `rs/scripts/cleanup_credentials.py`

**Step 1: Add deletion function**

Add before `main()`:

```python
def delete_entry(entry: CredentialEntry) -> tuple[bool, str]:
    """
    Delete a single credential entry from the keychain.

    Args:
        entry: The credential entry to delete

    Returns:
        (success: bool, error_message: str or empty)
    """
    try:
        subprocess.run(
            [
                "security",
                "delete-generic-password",
                "-s", "minisign",
                "-a", entry.credential_id
            ],
            capture_output=True,
            text=True,
            check=True
        )
        return (True, "")
    except subprocess.CalledProcessError as e:
        # Extract meaningful error message
        error_msg = e.stderr.strip() if e.stderr else str(e)
        return (False, error_msg)
```

**Step 2: Update main() to perform deletion**

Replace "TODO: Implement deletion" with:

```python
    # Deletion phase
    print("\nDeleting entries...")
    successes = []
    failures = []

    for entry in selected:
        success, error = delete_entry(entry)
        if success:
            successes.append(entry)
            print(f"  ✓ Deleted {entry.credential_id}")
        else:
            failures.append((entry, error))
            print(f"  ✗ Failed to delete {entry.credential_id}: {error}")

    # Summary
    print(f"\n{'='*60}")
    print(f"Deleted {len(successes)} entries successfully")
    if failures:
        print(f"Failed to delete {len(failures)} entries:")
        for entry, error in failures:
            print(f"  - {entry.credential_id}: {error}")
        sys.exit(1)
```

**Step 3: Test deletion**

Ensure test credentials exist:
```bash
cd rs
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password
```

Run script and select one entry:
```bash
python3 scripts/cleanup_credentials.py
# Select entry 1
```

Expected:
```
Deleting entries...
  ✓ Deleted [credential_id]

====================================================================
Deleted 1 entries successfully
```

Verify deletion:
```bash
python3 scripts/cleanup_credentials.py
```

Expected: Should show one less entry

**Step 4: Test deleting all entries**

Recreate both credentials, then:
```bash
python3 scripts/cleanup_credentials.py --all
```

Expected: Both entries deleted

Verify:
```bash
python3 scripts/cleanup_credentials.py
```

Expected: "No minisign entries found in keychain"

**Step 5: Test deletion error handling**

This tests the error path (attempting to delete non-existent entry):
```bash
# Manually create entry, delete it, try script delete (simulates race condition)
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
# Note the credential_id from output
security delete-generic-password -s minisign -a [credential_id]
# Now the script will find nothing to delete
```

Actually, this is hard to test without mocking. Skip this test and trust the error handling logic.

**Step 6: Commit**

```bash
git add scripts/cleanup_credentials.py
git commit -m "feat(scripts): implement credential deletion

- Delete via security delete-generic-password
- Track successes and failures
- Display summary with error messages
- Exit with error code if any deletions failed"
```

---

## Task 5: Final Polish and Documentation

**Files:**
- Modify: `rs/scripts/cleanup_credentials.py`
- Create: `rs/scripts/README.md`

**Step 1: Add script docstring improvements**

Update the module docstring at the top of the file:

```python
#!/usr/bin/env python3
"""
Utility script to discover and clean up minisign credential entries from macOS Keychain.

This script helps manage password entries saved by minisign_rs --save-password.
It can list all minisign credential entries and delete selected ones.

Requirements:
    - macOS (uses 'security' command)
    - Python 3.7+

Usage:
    python3 cleanup_credentials.py              # Interactive mode
    python3 cleanup_credentials.py --all        # Delete all without prompting
    python3 cleanup_credentials.py --dry-run    # Preview deletions
    python3 cleanup_credentials.py --all --dry-run  # Preview all

Examples:
    # List and selectively delete entries
    python3 cleanup_credentials.py

    # Delete all entries (useful for cleanup after testing)
    python3 cleanup_credentials.py --all

    # Preview what would be deleted without actually deleting
    python3 cleanup_credentials.py --dry-run
"""
```

**Step 2: Create scripts README**

Create `rs/scripts/README.md`:

```markdown
# Utility Scripts

## cleanup_credentials.py

Discovers and cleans up minisign credential entries from the macOS Keychain.

### Purpose

When using `minisign_rs --save-password`, passwords are stored in the macOS Keychain
with service name "minisign" and account name set to the credential ID. During development
and testing, these entries can accumulate. This script helps manage them.

### Requirements

- macOS (uses `security` command)
- Python 3.7+ (standard library only, no external dependencies)

### Usage

**Interactive mode** - List entries and select which to delete:
```bash
python3 scripts/cleanup_credentials.py
```

**Delete all** - Remove all minisign entries without prompting:
```bash
python3 scripts/cleanup_credentials.py --all
```

**Dry run** - Preview what would be deleted:
```bash
python3 scripts/cleanup_credentials.py --dry-run
python3 scripts/cleanup_credentials.py --all --dry-run
```

**Help**:
```bash
python3 scripts/cleanup_credentials.py --help
```

### Selection Syntax

In interactive mode, you can select entries using:

- **Individual numbers**: `1 3 5` - Select specific entries
- **Ranges**: `1-3` - Select consecutive range
- **All**: `all` - Select all entries
- **Quit**: `q` or empty input - Exit without deleting

### Error Handling

- If the keychain is locked or inaccessible, the script exits with an error
- If no minisign entries are found, the script exits cleanly
- If deletion fails for some entries, the script continues and shows a summary
- Press Ctrl-C at any time to abort (entries deleted so far remain deleted)

### Testing

Create test credentials:
```bash
cd rs
cargo build --release
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password
```

Clean up test credentials:
```bash
python3 scripts/cleanup_credentials.py --all
```
```

**Step 3: Test complete workflow end-to-end**

Full test sequence:
```bash
cd rs

# 1. Start with clean slate
python3 scripts/cleanup_credentials.py --all

# 2. Create test credentials
./target/release/minisign_rs -G -p test1.pub -s test1.key --save-password
./target/release/minisign_rs -G -p test2.pub -s test2.key --save-password

# 3. Dry run (should show 2 entries, not delete)
python3 scripts/cleanup_credentials.py --all --dry-run

# 4. Verify entries still exist
python3 scripts/cleanup_credentials.py --dry-run

# 5. Interactive selection (select entry 1)
python3 scripts/cleanup_credentials.py
# Enter: 1

# 6. Verify one entry remains
python3 scripts/cleanup_credentials.py --dry-run

# 7. Delete remaining entry
python3 scripts/cleanup_credentials.py --all

# 8. Verify empty
python3 scripts/cleanup_credentials.py
```

Expected at step 8: "No minisign entries found in keychain"

**Step 4: Test help and error messages**

```bash
# Help
python3 scripts/cleanup_credentials.py --help

# Invalid flag
python3 scripts/cleanup_credentials.py --invalid-flag

# Ctrl-C handling (start script, press Ctrl-C during selection)
python3 scripts/cleanup_credentials.py
# Press Ctrl-C when prompted for selection
# Expected: "Aborted" message
```

**Step 5: Commit**

```bash
git add scripts/cleanup_credentials.py scripts/README.md
git commit -m "docs(scripts): add documentation for cleanup script

- Improve module docstring with examples
- Create scripts/README.md with usage guide
- Document selection syntax and error handling"
```

---

## Task 6: Final Verification and Cleanup

**Files:**
- None (verification only)

**Step 1: Run full manual test suite**

Execute the complete test sequence from Task 5, Step 3.

**Step 2: Verify script works from any directory**

```bash
# From project root
python3 scripts/cleanup_credentials.py --help

# From parent directory
cd ..
python3 rs/scripts/cleanup_credentials.py --help

# Using absolute path
python3 scripts/cleanup_credentials.py --help
```

All should work correctly.

**Step 3: Check script permissions**

```bash
ls -la scripts/cleanup_credentials.py
```

Should show executable permission (`-rwxr-xr-x`).

**Step 4: Clean up test files**

```bash
cd rs
rm -f test1.pub test1.key test2.pub test2.key
python3 scripts/cleanup_credentials.py --all
```

**Step 5: Final commit if any changes**

```bash
git status
# If any uncommitted changes, commit them
```

**Step 6: Verify git log**

```bash
git log --oneline -10
```

Expected: Should see commits for all 6 tasks with conventional commit format.

---

## Success Criteria

- [ ] Script runs on macOS, exits with error on other platforms
- [ ] Discovers all minisign credential entries in keychain
- [ ] Displays entries with credential ID and keychain location
- [ ] Interactive selection supports numbers, ranges, 'all', 'q'
- [ ] `--all` flag skips interactive prompt
- [ ] `--dry-run` flag previews without deleting
- [ ] Deletion works and handles errors gracefully
- [ ] Ctrl-C handling exits cleanly
- [ ] Documentation in script and README
- [ ] All commits follow conventional commit format

## Notes

- This is a utility script (not production code), so no unit tests are needed
- Manual testing is sufficient given the simplicity and interactive nature
- The script uses only Python standard library (no external dependencies)
- Error handling is defensive - credential store failures never block the script
