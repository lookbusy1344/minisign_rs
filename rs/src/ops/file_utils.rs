//! Common file operation utilities for key and signature file handling

use crate::{
    Error, Result, constants::MAX_MESSAGE_SIZE_BYTES, keys::SeckeyStruct,
    validation::validate_windows_path,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

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

/// Write a file, optionally setting Unix permissions on creation and on force-overwrite.
///
/// All three public file-write functions delegate here. The `unix_mode` parameter is
/// `Some(mode)` only for secret key files (0600); public key and signature files pass `None`.
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
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }

    let mut file = options.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::FileExists(path.into())
        } else {
            Error::file_write(path, e)
        }
    })?;

    // When forcing overwrite of a secret key, re-apply permissions so that an
    // existing file with lax permissions (mode() only affects newly created files)
    // is also secured.
    #[cfg(unix)]
    if force && let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms).map_err(|e| Error::file_write(path, e))?;
    }

    file.write_all(contents.as_bytes())
        .map_err(|e| Error::file_write(path, e))?;

    Ok(())
}

/// Write a secret key file with mode 0600 on Unix (read/write for owner only).
///
/// # Errors
///
/// Returns [`Error::FileExists`] if the file exists and `force` is false.
/// Returns [`Error::FileWrite`] on I/O failure.
pub fn write_secret_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    #[cfg(unix)]
    let unix_mode = Some(SECRET_KEY_FILE_PERMISSIONS);
    #[cfg(not(unix))]
    let unix_mode = None;
    write_file(path.as_ref(), contents, force, unix_mode)
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
