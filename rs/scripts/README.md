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
