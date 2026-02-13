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
