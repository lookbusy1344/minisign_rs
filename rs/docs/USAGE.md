# Minisign-rs Usage Guide

Complete reference for all minisign-rs operations and command-line options.

**See also:**
- [README.md](../README.md) - Quick start and installation
- [ARCHITECTURE.md](ARCHITECTURE.md) - Internal design
- [TESTING.md](TESTING.md) - Testing guide
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development workflow

---

## Command-Line Options

minisign-rs provides a simple, intuitive command-line interface with both short and long option names for better usability.

These reflect zig-minisign where it differs from classic C implementation. https://github.com/jedisct1/zig-minisign

### Actions

| Short | Long | Description |
|-------|------|-------------|
| `-G` | `--generate` | Generate a new keypair |
| `-S` | `--sign` | Sign files |
| `-V` | `--verify` | Verify a signature |
| `-R` | `--recreate` | Recreate a public key from a secret key |
| `-K` | `--change-password` | Change or remove password from a secret key |
| `-I` | `--inspect` | Inspect a key file and display security parameters (prompts for password if encrypted) |

### Key and File Options

| Short | Long | Description |
|-------|------|-------------|
| `-s <FILE>` | `--secretkey-path <FILE>` | Secret key file path |
| `-p <FILE>` | `--publickey-path <FILE>` | Public key file path |
| `-P <STRING>` | `--publickey <STRING>` | Public key as base64 string |
| `-m <FILE>` | `--input <FILE>` | Input file (message to sign/verify). Additional files to sign can follow as positional args: `-m file1 file2 file3` |
| `-x <FILE>` | `--signature <FILE>` | Signature file (default: `<file>.minisig`) |

### Comment Options

| Short | Long | Description |
|-------|------|-------------|
| `-t <STRING>` | `--trusted-comment <STRING>` | Add a trusted comment to the signature |
| `-c <STRING>` | `--untrusted-comment <STRING>` | Add an untrusted comment to the signature |

### Mode Options

| Short | Long | Description |
|-------|------|-------------|
| `-l` | `--legacy` | Legacy mode (sign only) |
| `-H` | `--prehashed` | Sign in prehashed mode, or require prehashed verification (reject legacy signatures) |
| `-q` | `--quiet` | Quiet mode (minimal output) |
| `-Q` | `--pretty-quiet` | Pretty quiet mode (show only trusted comment) |
| `-f` | `--force` | Force overwrite of existing files |
| `-o` | `--output` | Output verification result to stdout |
| `-W` | `--no-password` | Do not use password (generate and change only) |
| | `--sequential` | Process files sequentially instead of in parallel |
| | `--save-password` / `--sp` | Save password to OS credential store after successful use |
| | `--forget-password` / `--fp` | Remove saved password from OS credential store |

### Additional Options

| Short | Long | Description |
|-------|------|-------------|
| `-h` | `--help` | Display help message and exit |
| `-v` | `--version` | Show version information and exit |
| | `--password-file <FILE>` | Read password from file (testing only - insecure) |
| | `--allow-kdf-fallback` | Allow KDF parameter fallback if 128MB allocation fails (permission only, does not force fallback) |
| | `--no-decrypt` | Skip decryption of encrypted keys (show [encrypted] instead of prompting) |

## Common Usage Examples

### Generate a new keypair

```bash
# Interactive (prompts for password)
minisign_rs -G

# With custom paths
minisign_rs --generate --secretkey-path mykey.key --publickey-path mykey.pub

# Without password protection
minisign_rs -G -W

# Force overwrite existing keys
minisign_rs -G -f
```

**Password Strength:** Use 20+ character passwords or passphrases. Despite strong KDF parameters (scrypt N=2^20), weak passwords enable offline brute-force attacks. Avoid dictionary words, personal information, and short passwords (<16 characters).

### Sign a file

```bash
# Sign with default keys
minisign_rs --sign --input file.txt

# Sign with custom key
minisign_rs -S -m file.txt -s custom.key

# Sign with custom comment
minisign_rs -S -m file.txt --trusted-comment "v1.0.0 release"

# Sign in legacy mode (non-prehashed)
minisign_rs -S -m file.txt --legacy

# Sign without password (for unencrypted keys)
minisign_rs -S -m file.txt -W
```

### Sign multiple files

Multiple files are signed in a single command using the same syntax as C minisign: `-m` specifies the first file, and any remaining positional arguments are additional files. Each file gets its own `.minisig` signature file. By default files are signed in parallel across all available CPU cores.

```bash
# Sign three files in parallel (default)
minisign_rs -S -m file1.txt file2.bin release.tar.gz

# Sign sequentially (single-threaded)
minisign_rs -S --sequential -m file1.txt file2.bin release.tar.gz

# With a custom key and trusted comment
minisign_rs -S -s release.key -t "v2.1.0 release" -m file1.txt file2.txt file3.txt
```

**Note:** All flags must appear before `-m` and the file list. Positional arguments (the extra files) must be the final tokens on the command line — this matches the C version's getopt behaviour.

**Error handling:** If any file fails (e.g. missing), signing continues for the remaining files. A summary is printed at the end and the exit code is 1. Successfully signed files retain their `.minisig` files.

**Limitation:** `-x` (custom signature path) is not supported when signing multiple files — each file automatically gets `<filename>.minisig`.

### Verify a signature

```bash
# Verify with default public key
minisign_rs --verify --input file.txt

# Verify with specific public key
minisign_rs -V -m file.txt -p key.pub

# Verify using base64 public key
minisign_rs -V -m file.txt --publickey RWQwpZXcv6r8MS48...

# Verify in quiet mode
minisign_rs -V -m file.txt --quiet

# Require prehashed signature (reject legacy)
minisign_rs -V -H -m file.txt -p key.pub
```

### Verify multiple files

Multiple files are verified in a single command using the same syntax as signing: `-m` specifies the first file, and any remaining positional arguments are additional files. Each file's corresponding `.minisig` signature is automatically located. By default files are verified in parallel across all available CPU cores.

```bash
# Verify three files in parallel (default)
minisign_rs -V -m file1.txt file2.bin release.tar.gz -p key.pub

# Verify sequentially (single-threaded)
minisign_rs -V --sequential -m file1.txt file2.bin release.tar.gz -p key.pub

# Verify in quiet mode (no output if successful)
minisign_rs -V -q -m file1.txt file2.txt file3.txt -p key.pub
```

**Output format:** Shows the public key ID once at the top, then displays verification status and trusted comment for each file:
```
Verifying with key: E0A55C53BAE7BDB0 (robust rebellion trauma pyramid...)
Verified: file1.txt
  Trusted comment: timestamp:1769972985
Verified: file2.txt
  Trusted comment: Signed by Alice
Verified: file3.txt
  Trusted comment: v1.0.0 release
```

**Error handling:** If any file fails verification (e.g. corrupted, wrong key), verification continues for the remaining files. A summary is printed at the end and the exit code is 1.

**Limitation:** `-x` (custom signature path) is not supported when verifying multiple files — each file automatically uses `<filename>.minisig`.

### Recreate public key from secret key

```bash
# Recreate using default paths
minisign_rs --recreate

# Recreate with custom paths
minisign_rs -R --secretkey-path mykey.key --publickey-path recovered.pub
```

### Change password

```bash
# Change password on default key
minisign_rs --change-password

# Change password on specific key
minisign_rs -K -s mykey.key

# Remove password
minisign_rs -K -W
```

### Inspect key security

```bash
# Inspect default secret key (prompts for password if encrypted)
minisign_rs -I

# Inspect specific secret key (smart: prompts only if encrypted)
minisign_rs -Is mykey.key

# Inspect without decrypting (non-interactive, shows [encrypted] for key ID)
minisign_rs -Is mykey.key --no-decrypt

# Inspect public key file (never prompts)
minisign_rs -Ip key.pub

# Inspect public key from command line (base64)
minisign_rs -IP RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa

# Inspect signature file (shows key ID used to sign)
minisign_rs -Ix file.txt.minisig
```

## Password Management with Credential Store

Minisign-rs integrates with your operating system's credential store to securely cache passwords for encrypted keys. This provides a convenient workflow similar to `gh auth`, `cargo publish`, and other CLI tools.

### Platform Support

| Platform | Credential Store | Backend |
|----------|-----------------|---------|
| macOS    | Keychain        | Native macOS Keychain APIs |
| Windows  | Credential Manager | Windows Credential Manager |
| Linux    | Secret Service  | libsecret/gnome-keyring |

### Save password during key generation

```bash
# Generate key and save password to credential store
minisign_rs -G --save-password

# Short flag alias
minisign_rs -G --sp

# With custom paths
minisign_rs -G --sp -s mykey.key -p mykey.pub
```

**Security**: Passwords are stored securely using your OS's native credential store, encrypted with your user account credentials. On macOS, this integrates with FileVault and system keychain encryption.

### Auto-retrieve saved passwords

Once saved, passwords are automatically retrieved from the credential store when needed:

```bash
# Sign - automatically uses saved password if available
minisign_rs -S -m file.txt

# No password prompt if password is saved for this key
minisign_rs -S -m file1.txt file2.txt file3.txt

# Change password - retrieves old password automatically
minisign_rs -K -s mykey.key
```

**Behavior**:
- If password is saved: Silent retrieval, no prompt
- If password not saved: Normal password prompt
- If credential store unavailable: Falls back to password prompt (graceful degradation)

### Save password after first use

You can also save a password after successfully using it:

```bash
# Sign and save password on successful decrypt
minisign_rs -S -m file.txt --save-password

# Inspect and save password on successful decrypt
minisign_rs -I -s mykey.key --save-password

# Change password and save the new password
minisign_rs -K --save-password
```

### Remove saved passwords

```bash
# Remove saved password for default key
minisign_rs -K --forget-password

# Short flag alias
minisign_rs -K --fp

# Remove saved password for specific key
minisign_rs -K --forget-password -s mykey.key
```

**Idempotent**: `--forget-password` succeeds even if no password is saved.

### Check password status

```bash
# Inspect shows whether password is saved
minisign_rs -I -s mykey.key

# Example output shows "Password saved: Yes" or "Password saved: No"
```

### Cleanup utility

For managing credential store entries during development, use the cleanup utility script:

```bash
# Interactive cleanup - list and select entries to delete
python3 scripts/cleanup_credentials.py

# Delete all credential store entries
python3 scripts/cleanup_credentials.py --all

# Preview what would be deleted (dry run)
python3 scripts/cleanup_credentials.py --dry-run
```

See [scripts/README.md](scripts/README.md) for complete documentation.

### Security model

**What's protected**:
- Passwords stored in OS credential store (encrypted by OS)
- Key IDs used as credential identifiers (portable across file moves)
- Automatic cleanup on credential removal

**Security properties**:
- **Opt-in only**: Passwords never saved automatically
- **Per-key storage**: Each key ID has independent credential entry
- **OS-level encryption**: Credentials protected by OS keychain encryption
- **No silent failures**: Credential store errors never block operations

**When to use**:
- Personal development machines with full-disk encryption
- Laptops/desktops where you sign frequently
- Workstations with trusted OS credential management
- Streamlining workflows without compromising key file security

**When NOT to use**:
- Shared/multi-user systems (credentials are per-user account)
- Headless servers without credential store backend
- CI/CD pipelines (use `--password-file` or unencrypted keys)
- Untrusted environments or systems without disk encryption

## Signature File Format

Minisign creates `.minisig` files with 4 lines:
1. **Untrusted comment** - Human-readable, not verified (`-c` flag)
2. **Signature data** - Base64-encoded Ed25519 signature of the file
3. **Trusted comment** - Cryptographically verified (`-t` flag)
4. **Global signature** - Signs lines 2+3 together

**Security:** Only the trusted comment (line 3) is cryptographically protected. The untrusted comment (line 1) can be modified without breaking verification.

## Signing Modes

Minisign supports two signing modes that differ in how they process file content before signing:

### Prehashed Mode (Default)

**How it works:** The file is first hashed with Blake2b-512 (producing a 64-byte hash), then that hash is signed with Ed25519.

**Signature marker:** `"ED"` (uppercase) in the signature file

**Advantages:**
- **Memory efficient** - Streams files of any size without loading into memory
- **Fast for large files** - No file size limits
- **Default behavior** - Compatible with standard minisign workflows

**Trade-off:**
- Slightly reduced security - the signature authenticates the hash, not the raw file content
- An attacker with a Blake2b-512 collision could substitute different content (computationally infeasible with current technology)

**Usage:**
```bash
# Default mode (prehashed)
minisign_rs -S -m large-file.bin

# Explicit prehashed mode
minisign_rs -S -m large-file.bin -H
```

### Legacy Mode (Direct Signing)

**How it works:** The raw file content is signed directly with Ed25519, without hashing first.

**Signature marker:** `"Ed"` (mixed case) in the signature file

**Advantages:**
- **Stronger formal security proof** - The full message participates in Ed25519's nonce derivation, resilient even against hypothetical hash collisions
- **Direct message authentication** - Signature authenticates the file content directly, not a pre-computed hash

**Note on hash dependencies:** Both modes depend on hash functions. Legacy mode uses SHA-512 (internally by Ed25519 for nonce derivation), while prehashed mode uses both Blake2b-512 (for the pre-hash) and SHA-512 (within Ed25519). The security advantage of legacy mode is theoretical — Blake2b-512 has no known weaknesses and finding collisions is computationally infeasible.

**Limitations:**
- **1 GB file size limit** - Files must fit in memory for signing/verification
- **Higher memory usage** - Entire file loaded into RAM
- **Slower for large files** - No streaming support

**Usage:**
```bash
# Legacy mode (non-prehashed)
minisign_rs -S -m small-file.txt --legacy
```

### When to Use Each Mode

**Use prehashed mode (default) for all use cases.** It provides strong cryptographic security with efficient memory usage and no file size limits.

**Legacy mode** is maintained for compatibility with older signatures only. Both modes use Ed25519 signatures and provide equivalent practical security - Blake2b-512 is cryptographically secure and no practical attacks exist.

### Enforcing Prehashed Signatures

The `-H` flag serves dual purposes depending on context:
- **During signing (`-S -H`)**: Creates a prehashed signature (default behavior, explicit flag)
- **During verification (`-V -H`)**: Rejects legacy (non-prehashed) signatures

**Use case for verification enforcement:**
When organizational policy requires modern signature formats only, use `-H` during verification to ensure legacy signatures are rejected. This matches the C minisign behavior.

```bash
# This will fail if the signature is legacy (non-prehashed)
minisign_rs -V -H -m file.txt -p key.pub

# Error output: "Legacy (non-prehashed) signature found"
```

## Configuration

**`MINISIGN_CONFIG_DIR`** - Override default key directory (default: `~/.minisign/` on Unix, `%USERPROFILE%\.minisign\` on Windows). Useful for custom security policies, multi-user systems, or containers. Compatible with C minisign.
