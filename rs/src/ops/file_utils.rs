//! Common file operation utilities for key and signature file handling

use crate::{
    Error, Result, constants::MAX_MESSAGE_SIZE_BYTES, keys::SeckeyStruct,
    validation::validate_windows_path,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o077 != 0)
        .unwrap_or(false)
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

/// Load a secret key from a file
///
/// On Unix systems, emits a warning to stderr if the file is readable by
/// group or others (permissions wider than `0600`).
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file contents cannot be parsed as a secret key
pub fn load_secret_key(path: impl AsRef<Path>) -> Result<SeckeyStruct> {
    let path = path.as_ref();
    #[cfg(unix)]
    check_secret_key_permissions(path);
    let contents = std::fs::read_to_string(path).map_err(|e| Error::file_read(path, e))?;
    SeckeyStruct::from_file_contents(&contents)
}

/// Write a file, optionally setting Unix permissions on creation.
///
/// Used for non-secret files (public keys, signatures) and for new secret key creation.
/// The `unix_mode` parameter is `Some(mode)` only for secret key files (0600).
///
/// For force-overwriting secret key files, use [`atomic_overwrite_secret_key`] instead.
fn write_file(path: &Path, contents: &str, force: bool, unix_mode: Option<u32>) -> Result<()> {
    validate_windows_path(path)?;

    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    #[cfg(unix)]
    {
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

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::FileExists(path.into())
        } else {
            Error::file_write(path, e)
        }
    })?;

    file.write_all(contents.as_bytes())
        .map_err(|e| Error::file_write(path, e))?;

    Ok(())
}

/// Atomically overwrite a secret key file by writing to a temp sibling, then renaming.
///
/// Protects against two hazards:
/// - **Data loss (O1):** A crash mid-write on the original file would corrupt it. Here,
///   the original is only replaced after the new content is fully fsynced.
/// - **TOCTOU on permissions (S4):** `std::fs::set_permissions` operates on the path;
///   between open and chmod an attacker could swap the file. `fchmod` on the fd is immune.
///
/// Algorithm:
/// 1. Open `.{name}.tmp` in the same directory with mode 0600 and `O_NOFOLLOW`
/// 2. `fchmod(fd, mode)` — sets permissions on the fd, not the path
/// 3. Write all content
/// 4. `fsync` — flush to disk before rename
/// 5. `rename` — POSIX guarantees this is atomic; the destination is never half-written
///
/// The temp file is removed on any failure.
///
/// # Errors
///
/// Returns [`Error::FileWrite`] on any I/O failure.
#[cfg(unix)]
fn atomic_overwrite_secret_key(path: &Path, contents: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    validate_windows_path(path)?;

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));

    // Include a monotonic counter to give each concurrent invocation a unique
    // temp file, preventing races where two threads share the same .tmp path.
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(
        ".{}.{seq}.tmp",
        path.file_name()
            .map_or_else(|| std::ffi::OsString::from("key"), ToOwned::to_owned)
            .to_string_lossy()
    );
    let tmp_path = dir.join(&tmp_name);

    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp_path)
            .map_err(|e| Error::file_write(&tmp_path, e))?;

        // fchmod operates on the open fd — immune to path-based TOCTOU races.
        // SAFETY: `file.as_raw_fd()` is valid for the lifetime of `file`.
        // mode_t is u16 on some platforms; 0o600 (= 384) fits without truncation.
        #[allow(clippy::cast_possible_truncation)]
        let ret = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
        if ret != 0 {
            return Err(Error::file_write(path, std::io::Error::last_os_error()));
        }

        file.write_all(contents.as_bytes())
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
pub fn write_secret_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    let path = path.as_ref();

    #[cfg(unix)]
    if force {
        return atomic_overwrite_secret_key(path, contents, SECRET_KEY_FILE_PERMISSIONS);
    }

    #[cfg(unix)]
    let unix_mode = Some(SECRET_KEY_FILE_PERMISSIONS);
    #[cfg(not(unix))]
    let unix_mode = None;
    write_file(path, contents, force, unix_mode)
}

/// Write a public key file.
///
/// # Errors
///
/// Returns [`Error::FileExists`] if the file exists and `force` is false.
/// Returns [`Error::FileWrite`] on I/O failure.
pub fn write_public_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    write_file(path.as_ref(), contents, force, None)
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
    write_file(path, contents, force, None)
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
