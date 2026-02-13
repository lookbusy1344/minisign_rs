#!/usr/bin/env python3
"""
Utility script to discover and clean up minisign credential entries from macOS Keychain.

Usage:
    python3 cleanup_credentials.py              # Interactive mode
    python3 cleanup_credentials.py --all        # Delete all without prompting
    python3 cleanup_credentials.py --dry-run    # Preview deletions
"""

import argparse
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List


@dataclass
class CredentialEntry:
    """Represents a minisign credential entry in the keychain."""
    credential_id: str
    keychain_path: str

    def __str__(self) -> str:
        """Display format for user."""
        return f"{self.credential_id} (in {os.path.basename(self.keychain_path)})"


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
    print("\nEnter selection (numbers separated by spaces, ranges like 1-3, 'all', 'q' or empty to quit)")

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


def main():
    """Main entry point."""
    check_platform()
    args = parse_args()

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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAborted")
        sys.exit(130)
