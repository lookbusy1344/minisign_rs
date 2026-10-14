# Security Model

This document describes the current security design of minisign-rs. Dated audits record what was found and fixed at a point in time; see [Audit history](#audit-history). Update this file when a change alters any behaviour it describes.

minisign-rs must stay byte-compatible with C minisign. Where C is permissive and the permissiveness carries real risk, this document says so under [Known limitations](#known-limitations).

## Threat model

### What the tool protects

- **Integrity and origin of signed files.** A verified signature proves that the holder of the secret key signed this exact file and this exact trusted comment.
- **Confidentiality of the secret key at rest**, when it is encrypted with a password.

### Untrusted inputs

These inputs may come from an attacker. They must never cause memory corruption, unbounded resource use, or a false "verified" result:

- signature files (`.minisig`)
- public keys, as a file or as a `-P` string
- secret key files from a third party, including their KDF parameters
- the message files themselves
- the names of message files, which appear in the default trusted comment and in output
- the current working directory, for example an unpacked download

### Trusted inputs

- The public key the user supplies with `-p` or `-P`. Verification proves possession of the matching secret key and nothing more. Trust in the key comes from how the user obtained it.
- The `MINISIGN_CONFIG_DIR` environment variable and the home directory, which locate the default secret key.
- The local user account. A process running as the same user can read the secret key file and process memory. Encryption at rest is the defence against theft of the file, not against a compromised account.

### Out of scope

- Side channels beyond the constant-time comparisons listed below.
- Physical access and memory forensics after the process exits.
- Recovery from a stolen password together with the key file.

## Cryptography

| Purpose | Primitive | Crate |
|---|---|---|
| Signatures | Ed25519 | `ed25519-dalek` 2.2.0 |
| Prehash (default) | BLAKE2b-512 | `blake2` 0.10.6 |
| Key checksum | BLAKE2b-256 | `blake2` 0.10.6 |
| Key encryption | scrypt, XOR with the derived stream | `scrypt` 0.11.0 |
| Randomness | OS RNG (`OsRng`) | `rand_core` 0.6.4 |

The cryptographic crates are pinned to exact versions in `Cargo.toml`. An upgrade needs a release review, `cargo audit` and the full test suite, including the C cross-binary tests.

### Verification

1. The keynum in the signature must equal the public key's keynum. The comparison is constant-time and runs before any message I/O.
2. The message signature is checked with `verify_strict`, which rejects:
   - non-canonical `S`
   - small-order `R`
   - small-order public keys (also rejected by an explicit `is_weak` check)

   This matches libsodium as used by C minisign.
3. The global signature over `signature ‖ trusted comment` is checked the same way.
4. Only after both checks pass does the tool print the trusted comment or emit the message with `-o`.
   - With `-o`, the message is read once into memory, then verified and emitted from that buffer, so a file changed on disk cannot be emitted unverified.
   - Combining `-o` with a message over 1 GiB is refused.

Prehashed signatures (`ED`) are the default when signing. Verification accepts legacy signatures (`Ed`) unless `-H` is given, as C does.

### Signing

- `SigningKey::from_keypair_bytes` rejects a secret key whose stored public half does not match its scalar.
- After signing, both signatures are verified against a public key derived from the scalar. The `.minisig` is written only if both verify.
- The default trusted comment has a timestamp and the file's base name. When building it, signing fails if the clock reads earlier than 2020-01-01.

### Key encryption

An encrypted key stores a 104-byte blob: keynum, secret key and BLAKE2b-256 checksum, XORed with 104 bytes of scrypt output. This matches C minisign.

- **New keys** use N = 2²⁰, r = 8, p = 1. That needs 1 GiB of memory and matches libsodium's `SENSITIVE` level.
- **Stored parameters** are accepted only in the exact minisign encoding: r = 8, p = 1, N a power of two.
- **KDF memory budget.** `memlimit` is capped at 1 GiB. The check runs before any password prompt or credential-store access, so a crafted key file cannot make the process allocate more. `scrypt` aborts the process on allocation failure, so the cap is enforced before calling it.
- **Weak keys.** Keys with parameters below production strength still decrypt, with a warning on stderr. `-I` reports their security level. C minisign produces such keys on memory-constrained hosts.
- **Checksum.** After decryption, the checksum is compared in constant time. A mismatch means a wrong password or a corrupted file.
- **`scrypt` output length.** A runtime guard checks that derived bytes past index 64 are not all zero. This catches a `scrypt` crate upgrade that starts honouring `Params.len`, which would otherwise leave part of the key unencrypted on disk.

## Secret handling in memory

- `SecretKey`, `SeckeyStruct`, derived keys, decrypted blobs and serialised key file contents are `Zeroize` and `ZeroizeOnDrop`, or wrapped in `Zeroizing`.
- A compile-time assertion fails the build if `ed25519-dalek` loses its `zeroize` feature.
- Passwords are held in `Zeroizing<String>`.
  - Password files are read into a buffer sized up front, so no unwiped reallocation is left behind.
  - Credential-store secrets are read as raw bytes and converted in place.
- Copies made by the OS keyring backend and the terminal library cannot be reached and are not wiped. See `src/credential_store.rs`.
- `SecretKey` and `SeckeyStruct` redact their `Debug` output.
- There is no `unsafe` code in the library or the binary (`#![forbid(unsafe_code)]`). See [docs/no-unsafe-code.md](docs/no-unsafe-code.md).
- Release builds enable `overflow-checks` and `panic = "abort"`.

## Files on disk

### Writing

- **Secret keys** are created with mode `0600` and `O_NOFOLLOW`.
  - Without `--force`, the key is written to a temporary file, synced, then hard-linked into place. The link fails if the target exists, so an existing file is never overwritten.
  - With `--force`, the file is replaced by atomic rename.
- **Secret key directories** that `-G` creates are mode `0700`. Existing directories keep their mode.
- **Key pairs.** `-G --force` takes a lock file, backs up existing files and rolls back on failure.
- **Public keys and signatures** are created with `O_NOFOLLOW` and never overwrite a file unless `--force` is given. `--force` refuses a symlink at the target.
- **Overwriting inputs.** Signing refuses a signature path that resolves to a message being signed or to the secret key. Key generation refuses a public key path that resolves to the secret key path.
- **Loading a secret key** prints a warning if the file is readable by group or others.

### Reading

| Input | Size limit |
|---|---|
| Public or secret key file | 4 KiB |
| Signature file | 16 KiB |
| Password file | 1 KiB |
| Message, non-prehashed or with `-o` | 1 GiB |
| Message, prehashed | none (streamed) |

- Password files must be regular files. They are opened with `O_NONBLOCK`, so a FIFO cannot block the process.
- Key and signature files must be valid UTF-8.

## Untrusted text and the terminal

- Trusted and untrusted comments must be valid UTF-8. They may contain tab but no other C0 or C1 control character and no DEL. This applies both when parsing signatures and when creating them.
- Paths are shown with control characters escaped (`sanitised_path_display`), or in `Debug` form inside errors.
- Bytes from untrusted files that appear in error messages are escaped.

## Passwords

- **Interactive input.** Passwords are read from the terminal without echo. New passwords are asked for twice, compared in constant time, and trigger a warning if shorter than 8 characters.
- **`--password-file`** is meant for automation. It prints a warning on every use. With `-K` it holds the current password only; `--new-password-file` holds the new one. See [docs/USAGE.md](docs/USAGE.md#using---password-file-securely).
- **Credential store.** `--save-password` stores the password in the OS credential store: macOS Keychain, Windows Credential Manager or Linux Secret Service.
  - Entries use the service name `minisign`, keyed by the hex of the encrypted keynum. The ID changes when the password or salt changes.
  - A saved password is read back and compared before the tool reports success.
  - `--forget-password` deletes the entry.
- **Shared credential IDs.** A crafted key file that reuses another key's credential ID gets that password run through its own salt and KDF parameters. The command reports only a checksum failure, which reveals nothing about the password.

## Known limitations

These are kept for compatibility with C minisign, or are platform gaps.

- **Unencrypted secret keys have no integrity check.** Their checksum field is all zeros and is not verified (C does the same). Prefer encrypted keys.
- **Legacy signatures are accepted by default.** Pass `-H` to `-V` to require prehashed signatures.
- **The default public key comes from the current directory.** Without `-p` or `-P`, `-V` reads `./minisign.pub` and prints a warning to stderr unless `-q` is given. Always pass the key explicitly when verifying downloaded files.
- **Memory use of parallel batch verification.** Each legacy signature buffers its whole message, up to 1 GiB per worker. Use `-H` or `--sequential` to bound memory.
- **Windows:**
  - Secret keys get the directory's default ACLs, not owner-only permissions.
  - `-G --force` refuses to overwrite an existing secret key.
  - Path checks reject reserved device names (`CON`, `NUL`, `COM1`, ...).

## Verifying these properties

| Property | Tests |
|---|---|
| Crafted inputs and attack scenarios | `tests/security_attacks.rs`, `tests/edge_cases.rs`, `tests/fuzzing.rs` |
| KDF budget | `tests/kdf_budget.rs` |
| Secret key loading and zeroization | `tests/secret_loading.rs`, `tests/unit/security_hardening.rs`, `tests/unit/constant_time_and_kdf.rs` |
| Overwriting inputs | `tests/output_aliasing.rs` |
| Password files and password changes | `tests/password_file.rs`, `tests/change_password.rs` |
| File modes and default key paths | `tests/key_directory.rs`, `tests/default_public_key.rs` |
| Compatibility with C minisign | `tests/cross_binary_test.rs`, `tests/compatibility.rs` (skipped when the C binary is absent) |

## Audit history

| Date | Report |
|---|---|
| 2026-01-28 | [Security review](docs/2026-01-28-security-review.md) |
| 2026-01-30 | [Full code review](docs/2026-01-30-full-code-review.md) |
| 2026-02-17 | [Security audit, v1.3.1](docs/2026-02-17-security-audit.md) |
| 2026-02-20 | [Rust security audit](docs/2026-02-20-rust-security-audit.md) and [C/Zig security audit](docs/2026-02-20-c-zig-security-audit.md) |
| 2026-10-01 | [Security audit remediation plan](docs/plans/2026-10-01-security-audit-remediation.md) |
| 2026-10-14 | [Security review](docs/2026-10-14-security-review.md) |

[KDF fallback security analysis](docs/kdf-fallback-security-analysis.md) covers weak-parameter keys. The Rust tool no longer creates them, but it still decrypts keys that C created on memory-constrained hosts.
