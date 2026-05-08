//! Common file operation utilities for key and signature file handling

use crate::{
    Error, Result, constants::MAX_MESSAGE_SIZE_BYTES, keys::SeckeyStruct,
    validation::validate_windows_path,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

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
    if let Ok(metadata) = std::fs::metadata(path) {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            let display = path.display();
            eprintln!("Warning: {display} is accessible to other users (mode {mode:o})");
            eprintln!("Consider running: chmod 600 {display}");
        }
    }
}

cfg_select! {
    unix => {
        fn configure_write_options(options: &mut OpenOptions, force: bool, unix_mode: Option<u32>) {
            use std::os::unix::fs::OpenOptionsExt;

            if let Some(mode) = unix_mode {
                options.mode(mode);
            }
            if force {
                // O_NOFOLLOW prevents following symlinks in the final path component.
                // Without this, create(true).truncate(true) would silently clobber a
                // symlink's target. The non-force path uses create_new(true) which
                // implies O_EXCL, so symlinks are already rejected there.
                options.custom_flags(libc::O_NOFOLLOW);
            }
        }

        fn write_secret_key_file_impl(path: &Path, contents: &[u8], force: bool) -> Result<()> {
            if force {
                return atomic_overwrite_secret_key(path, contents, SECRET_KEY_FILE_PERMISSIONS);
            }

            write_file(path, contents, force, Some(SECRET_KEY_FILE_PERMISSIONS))
        }
    }
    _ => {
        fn configure_write_options(_options: &mut OpenOptions, _force: bool, _unix_mode: Option<u32>) {}

        fn write_secret_key_file_impl(path: &Path, contents: &[u8], force: bool) -> Result<()> {
            write_file(path, contents, force, None)
        }
    }
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
        source: e,
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
    let contents = read_file_bounded(path, MAX_KEY_FILE_BYTES)?;
    SeckeyStruct::from_file_contents(&contents)
}

/// Write a file, optionally setting Unix permissions on creation.
///
/// Used for non-secret files (public keys, signatures) and for new secret key creation.
/// The `unix_mode` parameter is `Some(mode)` only for secret key files (0600).
///
/// For force-overwriting secret key files, use [`atomic_overwrite_secret_key`] instead.
fn write_file(path: &Path, contents: &[u8], force: bool, unix_mode: Option<u32>) -> Result<()> {
    validate_windows_path(path)?;

    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    configure_write_options(&mut options, force, unix_mode);

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

/// Atomically overwrite a secret key file by writing to a temp sibling, then renaming.
///
/// Protects against two hazards:
/// - **Data loss (O1):** A crash mid-write on the original file would corrupt it. Here,
///   the original is only replaced after the new content is fully fsynced.
/// - **TOCTOU on permissions (S4):** `std::fs::set_permissions(path, perms)` (free
///   function) operates on the path; between open and chmod an attacker could swap the
///   file. `File::set_permissions` operates on the open fd and is immune.
///
/// Algorithm:
/// 1. Open `.{name}.{nonce}.tmp` exclusively (`O_CREAT|O_EXCL`) with mode 0600 and `O_NOFOLLOW`
/// 2. `File::set_permissions` — sets permissions on the fd, not the path
/// 3. Write all content
/// 4. `fsync` — flush to disk before rename
/// 5. `rename` — POSIX guarantees this is atomic; the destination is never half-written
///
/// The temp file name uses a CSPRNG 8-byte nonce (16 hex chars) so it is
/// unpredictable and collision-resistant. `create_new(true)` (`O_EXCL`) ensures
/// a pre-existing path with the same name is a hard error, not a silent truncation.
///
/// The temp file is removed on any failure.
///
/// # Errors
///
/// Returns [`Error::FileWrite`] on any I/O failure.
#[cfg(unix)]
fn atomic_overwrite_secret_key(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use rand_core::{OsRng, RngCore};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    validate_windows_path(path)?;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));

    // Use a CSPRNG nonce for an unpredictable, collision-resistant temp name.
    let mut nonce_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = u64::from_le_bytes(nonce_bytes);
    let tmp_name = format!(
        ".{}.{nonce:016x}.tmp",
        path.file_name()
            .map_or_else(|| std::ffi::OsString::from("key"), ToOwned::to_owned)
            .to_string_lossy()
    );
    let tmp_path = dir.join(&tmp_name);

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: fails if path exists — no silent truncation
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        // File::set_permissions operates on the open fd — immune to path-based TOCTOU races.
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::file_write(path, e))?;

        file.write_all(contents)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        // Flush data to disk before the rename so a crash after rename doesn't
        // leave the destination file with the old (or empty) content.
        file.sync_all()
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        std::fs::rename(&tmp_path, path).map_err(|e| Error::file_write(path, e))
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
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
    write_file(path.as_ref(), contents.as_bytes(), force, None)
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
    write_file(path, contents.as_bytes(), force, None)
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
