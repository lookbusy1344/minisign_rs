//! Common file operation utilities for key and signature file handling

use crate::{
    Error, Result, constants::MAX_MESSAGE_SIZE_BYTES, keys::SeckeyStruct,
    validation::validate_windows_path,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Maximum file size accepted for key files (secret key and public key).
///
/// Key files are small, fixed-layout base64 blobs. The largest legitimate key
/// file (`SeckeyStruct`) encodes to roughly 250 bytes of base64 plus a comment
/// line. 4 KiB gives generous headroom while capping memory allocation.
pub const MAX_KEY_FILE_BYTES: u64 = 4096;

/// Maximum file size accepted for signature files.
///
/// A signature file has four lines: untrusted comment (≤ `COMMENTMAXBYTES` = 1024 B),
/// base64 sig struct (~100 B), trusted comment (≤ `TRUSTEDCOMMENTMAXBYTES` = 8192 B),
/// and base64 global sig (~88 B). 16 KiB covers all legitimate signatures.
pub const MAX_SIGNATURE_FILE_BYTES: u64 = 16384;

/// Maximum file size accepted for password files (`--password-file`).
///
/// Passwords are short strings. 1 KiB is more than enough and prevents
/// callers from accidentally feeding an unbounded file to the KDF path.
pub const MAX_PASSWORD_FILE_BYTES: u64 = 1024;

/// Unix file permissions for secret key files (read/write for owner only)
#[cfg(unix)]
const SECRET_KEY_FILE_PERMISSIONS: u32 = 0o600;

/// Returns true if the file at `path` has permissions accessible by group or others.
///
/// Used to warn users about secret key files that may be readable by other OS users.
/// Returns `false` if the file metadata cannot be read.
#[cfg(unix)]
#[must_use]
pub fn has_lax_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0)
}

/// Emit a warning to stderr if `path` has group- or world-accessible permissions.
#[cfg(unix)]
fn check_secret_key_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                let display = path.display();
                eprintln!("Warning: {display} is accessible to other users (mode {mode:o})");
                eprintln!("Consider running: chmod 600 {display}");
            }
        }
        Err(e) => {
            eprintln!(
                "Warning: could not check permissions for '{}': {e}",
                path.display()
            );
        }
    }
}

/// Fsync the parent directory of `path` to flush the directory entry to disk.
///
/// Required after `rename(2)` or `link(2)` to guarantee that the new directory
/// entry survives a crash. Without this the directory block may not be flushed
/// even though the file data is durable.
#[cfg(unix)]
pub(super) fn sync_parent_directory(path: &Path) -> Result<()> {
    use std::fs::File;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let dir = File::open(parent).map_err(|e| Error::file_write(parent, e))?;
        dir.sync_all().map_err(|e| Error::file_write(parent, e))?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(super) fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

cfg_select! {
    unix => {
        /// Apply `unix_mode` and `O_NOFOLLOW` to a `create_new` open.
        fn configure_write_options(options: &mut OpenOptions, unix_mode: Option<u32>) {
            use std::os::unix::fs::OpenOptionsExt;

            if let Some(mode) = unix_mode {
                options.mode(mode);
            }
            options.custom_flags(libc::O_NOFOLLOW);
        }

        fn write_secret_key_file_impl(path: &Path, contents: &[u8], force: bool) -> Result<()> {
            if force {
                atomic_replace_file(path, contents, Some(SECRET_KEY_FILE_PERMISSIONS))
            } else {
                atomic_create_secret_key(path, contents, SECRET_KEY_FILE_PERMISSIONS)
            }
        }
    }
    _ => {
        fn configure_write_options(_options: &mut OpenOptions, _unix_mode: Option<u32>) {}

        fn write_secret_key_file_impl(path: &Path, contents: &[u8], force: bool) -> Result<()> {
            if force {
                overwrite_secret_key_via_backup(path, contents)
            } else {
                write_file(path, contents, false)
            }
        }
    }
}

fn sibling_temp_path(path: &Path, suffix: &str) -> PathBuf {
    use rand_core::{OsRng, RngCore};

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut nonce_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = u64::from_le_bytes(nonce_bytes);
    let file_name = path
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("key"), ToOwned::to_owned);
    let name = file_name.to_string_lossy();

    dir.join(format!(".{name}.{nonce:016x}.{suffix}"))
}

#[cfg(not(unix))]
fn overwrite_secret_key_via_backup(path: &Path, contents: &[u8]) -> Result<()> {
    validate_windows_path(path)?;

    let tmp_path = sibling_temp_path(path, "tmp");
    let backup_path = sibling_temp_path(path, "bak");
    let mut backup_created = false;

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| Error::file_write(&tmp_path, e))?;
        file.write_all(contents)
            .map_err(|e| Error::file_write(&tmp_path, e))?;
        file.sync_all()
            .map_err(|e| Error::file_write(&tmp_path, e))?;
        drop(file);

        match std::fs::rename(path, &backup_path) {
            Ok(()) => backup_created = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::file_write(path, e)),
        }

        if let Err(e) = std::fs::rename(&tmp_path, path) {
            if backup_created && let Err(restore_error) = std::fs::rename(&backup_path, path) {
                eprintln!(
                    "CRITICAL: rollback failed - could not restore '{}' from backup '{}': {restore_error}; recover manually",
                    path.display(),
                    backup_path.display()
                );
            }
            return Err(Error::file_write(path, e));
        }

        Ok(())
    })();

    if let Err(e) = std::fs::remove_file(&tmp_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "Warning: could not remove '{}': {e}; delete manually",
            tmp_path.display()
        );
    }
    if result.is_ok() && backup_created {
        std::fs::remove_file(&backup_path).map_err(|e| Error::file_write(&backup_path, e))?;
    }

    result
}

/// Read a file into a `String`, rejecting files that exceed `max_bytes`.
///
/// Checks `metadata().len()` before allocating. This guards against memory
/// memory-DoS from maliciously large files. The check is a pre-allocation guard, not
/// a strict enforcement boundary — content is always validated by the parser.
///
/// # Errors
///
/// Returns `Error::Other` if the file exceeds `max_bytes`, or `Error::FileRead`
/// on any I/O failure.
pub fn read_file_bounded(path: &Path, max_bytes: u64) -> Result<String> {
    let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
    let size = file
        .metadata()
        .map_err(|e| Error::file_read(path, e))?
        .len();
    if size > max_bytes {
        return Err(Error::Other(format!(
            "File too large: {size} bytes exceeds maximum {max_bytes} bytes"
        )));
    }
    read_bounded_string_from_reader(file, path, max_bytes)
}

/// Read UTF-8 text from a reader, rejecting input larger than `max_bytes`.
///
/// The reader is capped with `take(max_bytes + 1)`, so the returned buffer cannot
/// grow beyond the configured bound even if the source continues producing bytes.
///
/// # Errors
///
/// Returns `Error::Other` if the collected byte length exceeds `max_bytes`,
/// `Error::InvalidUtf8` if the buffered bytes are not UTF-8, or `Error::FileRead`
/// on any I/O failure while consuming the reader.
pub fn read_bounded_string_from_reader<R: Read>(
    reader: R,
    path: impl AsRef<Path>,
    max_bytes: u64,
) -> Result<String> {
    let path = path.as_ref();
    let mut buf = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| Error::file_read(path, e))?;
    let max_bytes_usize = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    if buf.len() > max_bytes_usize {
        return Err(Error::Other(format!(
            "File too large: {} bytes exceeds maximum {max_bytes} bytes",
            buf.len()
        )));
    }
    String::from_utf8(buf).map_err(|e| Error::InvalidUtf8 {
        context: path.display().to_string(),
        source: e.utf8_error(),
    })
}

/// Read a secret-key file into a guarded buffer, rejecting files over `max_bytes`.
///
/// The buffer is allocated once at `max_bytes + 1` and filled in place, so it never
/// reallocates and leaves no unwiped copy behind. The extra byte detects files that
/// grow past the limit after the metadata check.
///
/// # Errors
///
/// Returns `Error::Other` if the file exceeds `max_bytes`, or `Error::FileRead`
/// on any I/O failure.
pub fn read_secret_file_bounded(path: &Path, max_bytes: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = File::open(path).map_err(|e| Error::file_read(path, e))?;
    let size = file
        .metadata()
        .map_err(|e| Error::file_read(path, e))?
        .len();
    let too_large = |size| {
        Error::Other(format!(
            "File too large: {size} bytes exceeds maximum {max_bytes} bytes"
        ))
    };
    if size > max_bytes {
        return Err(too_large(size));
    }

    let max = usize::try_from(max_bytes).map_err(|_| too_large(size))?;
    let mut buf = Zeroizing::new(vec![0u8; max + 1]);
    let mut len = 0;
    while len < buf.len() {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::file_read(path, e)),
        }
    }
    if len > max {
        return Err(too_large(len as u64));
    }
    buf.truncate(len);
    Ok(buf)
}

/// Borrow `bytes` as UTF-8 text without copying them.
///
/// # Errors
///
/// Returns `Error::InvalidUtf8` naming `path`. The error holds no file content.
pub fn utf8_text<'a>(bytes: &'a [u8], path: &Path) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 {
        context: path.display().to_string(),
        source,
    })
}

/// Load a secret key from a file
///
/// On Unix systems, emits a warning to stderr if the file is readable by
/// group or others (permissions wider than `0600`).
///
/// # Errors
///
/// Returns an error if:
/// - The file exceeds `MAX_KEY_FILE_BYTES`
/// - The file cannot be read
/// - The file contents cannot be parsed as a secret key
pub fn load_secret_key(path: impl AsRef<Path>) -> Result<SeckeyStruct> {
    let path = path.as_ref();
    #[cfg(unix)]
    check_secret_key_permissions(path);
    let bytes = read_secret_file_bounded(path, MAX_KEY_FILE_BYTES)?;
    SeckeyStruct::from_file_contents(utf8_text(&bytes, path)?)
}

/// Write a public key or signature file.
///
/// Without `force`, the file is created with `create_new` and an existing path fails
/// with [`Error::FileExists`]. With `force`, an existing symlink is rejected and the
/// file is replaced through [`atomic_replace_file`], so the old inode — and every
/// hard-link name for it — keeps its bytes.
fn write_file(path: &Path, contents: &[u8], force: bool) -> Result<()> {
    validate_windows_path(path)?;

    if force {
        reject_symlink(path)?;
        return atomic_replace_file(path, contents, None);
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_write_options(&mut options, None);

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::FileExists(path.into())
        } else {
            Error::file_write(path, e)
        }
    })?;

    file.write_all(contents)
        .map_err(|e| Error::file_write(path, e))?;

    Ok(())
}

/// Fail with [`Error::OutputIsSymlink`] if `path` is a symlink.
fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(Error::OutputIsSymlink(path.into()))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::file_write(path, e)),
    }
}

/// Replace `path` with `contents` by staging a sibling file and renaming it over `path`.
///
/// 1. Open `.{name}.{nonce}.tmp` exclusively (`create_new`, plus `O_NOFOLLOW` on Unix)
/// 2. On Unix with `unix_mode`, set permissions on the open handle (`fchmod`), which a
///    path swap cannot redirect
/// 3. Write all content and `fsync`
/// 4. `rename` over `path` and sync the parent directory
///
/// `rename` replaces the directory entry: the previous inode is never truncated or
/// written, and a crash leaves either the old or the new file. On Windows,
/// `std::fs::rename` replaces an existing file in the same directory.
///
/// The temp name uses a CSPRNG 8-byte nonce. The temp file is removed on any failure.
///
/// # Errors
///
/// Returns [`Error::FileWrite`] on any I/O failure.
fn atomic_replace_file(path: &Path, contents: &[u8], unix_mode: Option<u32>) -> Result<()> {
    validate_windows_path(path)?;
    let tmp_path = sibling_temp_path(path, "tmp");

    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_write_options(&mut options, unix_mode);
        let mut file = options
            .open(&tmp_path)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        #[cfg(unix)]
        if let Some(mode) = unix_mode {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::file_write(&tmp_path, e))?;
        }

        file.write_all(contents)
            .map_err(|e| Error::file_write(&tmp_path, e))?;
        file.sync_all()
            .map_err(|e| Error::file_write(&tmp_path, e))?;
        drop(file);

        std::fs::rename(&tmp_path, path).map_err(|e| Error::file_write(path, e))
    })();

    if result.is_err()
        && let Err(e) = std::fs::remove_file(&tmp_path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "Warning: could not remove '{}': {e}; delete manually",
            tmp_path.display()
        );
    }

    result?;
    sync_parent_directory(path)
}

/// Resolve `path` to the location its directory entry occupies, without following
/// the final component.
///
/// The nearest existing ancestor is canonicalised (resolving symlinks, `.` and `..`)
/// and the remaining components are applied to it, so the result is defined whether
/// or not `path` exists. Case aliases on case-insensitive filesystems are not
/// unified.
///
/// # Errors
///
/// Returns [`Error::FileWrite`] if an existing ancestor cannot be canonicalised.
pub fn resolve_destination(path: &Path) -> Result<PathBuf> {
    fn resolve(path: &Path) -> std::io::Result<PathBuf> {
        use std::path::Component;

        let Some(parent) = path.parent() else {
            return Ok(path.to_path_buf());
        };
        let parent = match parent.canonicalize() {
            Ok(canonical) => canonical,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => resolve(parent)?,
            Err(e) => return Err(e),
        };
        Ok(match path.components().next_back() {
            Some(Component::ParentDir) => parent
                .parent()
                .map_or_else(|| parent.clone(), Path::to_path_buf),
            Some(Component::CurDir) | None => parent,
            Some(last) => parent.join(last),
        })
    }

    std::path::absolute(path)
        .and_then(|absolute| resolve(&absolute))
        .map_err(|e| Error::file_write(path, e))
}

/// Fail with [`Error::OutputAlias`] if `output` names the same file as any of `others`.
///
/// `output` is resolved with [`resolve_destination`]. Each existing entry in `others`
/// is fully canonicalised, following a final symlink to the file it reads; a missing
/// entry is resolved like `output`. Relative forms, `.`/`..` components and
/// symlinked directories are therefore detected. A distinct hard-link name is a
/// different destination and is allowed: replacing it through
/// [`atomic_replace_file`] leaves the other name's inode untouched.
///
/// # Errors
///
/// Returns [`Error::OutputAlias`] on a match, or [`Error::FileWrite`] if a path
/// cannot be resolved.
pub fn reject_output_alias(output: &Path, others: &[&Path]) -> Result<()> {
    let destination = resolve_destination(output)?;
    for &other in others {
        let resolved = match other.canonicalize() {
            Ok(canonical) => canonical,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => resolve_destination(other)?,
            Err(e) => return Err(Error::file_write(other, e)),
        };
        if resolved == destination {
            return Err(Error::OutputAlias {
                output: output.into(),
                other: other.into(),
            });
        }
    }
    Ok(())
}

/// Atomically create a new secret key file using write-temp-then-link.
///
/// Identical to [`atomic_replace_file`] except it uses `hard_link(2)` instead of
/// `rename(2)`. `link(2)` fails atomically with `EEXIST` if the destination already
/// exists, giving `create_new` semantics while still guaranteeing that a partial write
/// never reaches the final path.
///
/// # Errors
///
/// Returns [`Error::FileExists`] if `path` already exists.
/// Returns [`Error::FileWrite`] on any other I/O failure.
#[cfg(unix)]
fn atomic_create_secret_key(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    validate_windows_path(path)?;
    let tmp_path = sibling_temp_path(path, "tmp");

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::file_write(path, e))?;

        file.write_all(contents)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        file.sync_all()
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        // hard_link fails atomically with EEXIST if the destination exists —
        // create_new semantics without the partial-write hazard of O_CREAT|O_EXCL.
        std::fs::hard_link(&tmp_path, path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::FileExists(path.into())
            } else {
                Error::file_write(path, e)
            }
        })?;

        sync_parent_directory(path)
    })();

    if let Err(e) = std::fs::remove_file(&tmp_path) {
        eprintln!(
            "Warning: could not remove '{}': {e}; delete manually",
            tmp_path.display()
        );
    }
    result
}

/// Write a secret key file with mode 0600 on Unix (read/write for owner only).
///
/// When `force` is true and the platform is Unix, uses an atomic write-temp-then-rename
/// sequence to prevent data loss on crash and to apply permissions via `fchmod` (not the
/// path-based `set_permissions`, which is subject to TOCTOU races).
///
/// # Errors
///
/// Returns [`Error::FileExists`] if the file exists and `force` is false.
/// Returns [`Error::FileWrite`] on I/O failure.
pub fn write_secret_key_file(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    force: bool,
) -> Result<()> {
    let path = path.as_ref();
    let contents = contents.as_ref();
    write_secret_key_file_impl(path, contents, force)
}

/// Write a public key file.
///
/// # Errors
///
/// Returns [`Error::FileExists`] if the file exists and `force` is false.
/// Returns [`Error::FileWrite`] on I/O failure.
pub fn write_public_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    write_file(path.as_ref(), contents.as_bytes(), force)
}

/// Write a signature file.
///
/// This function is public for unit testing purposes but is not part of the stable API.
///
/// # Errors
///
/// Returns [`Error::FileExists`] if the file exists and `force` is false.
/// Returns [`Error::FileWrite`] on I/O failure.
pub fn write_signature_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    write_file(path, contents.as_bytes(), force)
}

/// Check that a file doesn't exceed the maximum size for non-prehashed mode
///
/// Files larger than `MAX_MESSAGE_SIZE_BYTES` (1 GB) should use prehashed mode,
/// which streams the file through Blake2b-512 without loading it into memory.
///
/// # Errors
///
/// Returns an error if:
/// - File metadata cannot be read
/// - File size exceeds the maximum allowed
pub fn check_file_size_limit(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|e| Error::file_read(path, e))?;

    let file_size = metadata.len();
    if file_size > MAX_MESSAGE_SIZE_BYTES {
        return Err(Error::Other(format!(
            "File too large for non-prehashed mode: {file_size} bytes (max: {MAX_MESSAGE_SIZE_BYTES} bytes). Use --prehashed (-H) for files larger than 1 GB."
        )));
    }

    Ok(())
}

/// Open a message file, check its size, and read it into memory — all on a single fd.
///
/// The size check and read share the same open file descriptor, closing the TOCTOU window
/// that exists when `check_file_size_limit` (metadata on the path) is called before
/// `std::fs::read` (a separate open). A `take(MAX_MESSAGE_SIZE_BYTES + 1)` cap is the
/// actual safety net: even if the file grows during the read it cannot allocate beyond
/// the limit. The second bound check distinguishes "exactly at limit" from "over limit".
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be opened
/// - File metadata cannot be read
/// - The file size (at open time or post-read) exceeds `MAX_MESSAGE_SIZE_BYTES`
/// - The read fails
pub fn read_message_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| Error::file_read(path, e))?;
    let size = file
        .metadata()
        .map_err(|e| Error::file_read(path, e))?
        .len();
    if size > MAX_MESSAGE_SIZE_BYTES {
        return Err(Error::Other(format!(
            "File too large for non-prehashed mode: {size} bytes (max: {MAX_MESSAGE_SIZE_BYTES} bytes). Use --prehashed (-H) for files larger than 1 GB."
        )));
    }
    let mut buf = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    file.take(MAX_MESSAGE_SIZE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| Error::file_read(path, e))?;
    if buf.len() as u64 > MAX_MESSAGE_SIZE_BYTES {
        return Err(Error::Other(format!(
            "File too large for non-prehashed mode: {} bytes (max: {MAX_MESSAGE_SIZE_BYTES} bytes). Use --prehashed (-H) for files larger than 1 GB.",
            buf.len()
        )));
    }
    Ok(buf)
}

/// Return a sanitised string representation of `path` safe to print in a terminal.
///
/// Escapes ASCII control characters (U+0000–U+001F), DEL (U+007F), and C1
/// control codes (U+0080–U+009F) as `\xNN` to prevent ANSI-injection attacks
/// via crafted filenames.
#[must_use]
pub fn sanitised_path_display(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        let code = c as u32;
        if code < 0x20 || code == 0x7F || (0x80..=0x9F).contains(&code) {
            use std::fmt::Write as _;
            let _ = write!(out, "\\x{code:02X}");
        } else {
            out.push(c);
        }
    }
    out
}
