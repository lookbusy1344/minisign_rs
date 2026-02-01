//! Common file operation utilities for key and signature file handling

use crate::{Error, Result, constants::MAX_MESSAGE_SIZE_BYTES, keys::SeckeyStruct};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// Unix file permissions for secret key files (read/write for owner only)
#[cfg(unix)]
const SECRET_KEY_FILE_PERMISSIONS: u32 = 0o600;

/// Load a secret key from a file
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file contents cannot be parsed as a secret key
pub fn load_secret_key(path: impl AsRef<Path>) -> Result<SeckeyStruct> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| Error::file_read(path, e))?;
    SeckeyStruct::from_file_contents(&contents)
}

/// Write a secret key file with appropriate permissions
///
/// On Unix systems, sets mode 0600 (read/write for owner only).
///
/// # Arguments
///
/// * `path` - Path to write the file
/// * `contents` - File contents to write
/// * `force` - If true, overwrite existing files. If false, fail if file exists.
///
/// # Errors
///
/// Returns an error if:
/// - File already exists (when `force` is false)
/// - File cannot be created or written
///
/// # Security
///
/// Uses atomic creation (`create_new(true)`) when `force` is false to prevent
/// TOCTOU (Time-of-Check-Time-of-Use) race conditions.
pub fn write_secret_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.write(true);

    if force {
        // Force mode: create or truncate existing file
        options.create(true).truncate(true);
    } else {
        // Normal mode: fail if file already exists (atomic check)
        options.create_new(true);
    }

    // Set restrictive permissions on Unix systems (before writing)
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(SECRET_KEY_FILE_PERMISSIONS);
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

    // Ensure data is durably written to disk before returning success
    // This prevents data loss if the system crashes immediately after key generation
    file.sync_all().map_err(|e| Error::file_write(path, e))?;

    Ok(())
}

/// Write a public key file with atomic creation
///
/// This prevents TOCTOU (Time-of-Check-Time-of-Use) race conditions by using
/// `create_new(true)`, which atomically creates the file only if it doesn't exist.
///
/// # Arguments
///
/// * `path` - Path to write the file
/// * `contents` - File contents to write
/// * `force` - If true, overwrite existing files. If false, fail if file exists.
///
/// # Errors
///
/// Returns an error if:
/// - File already exists (when `force` is false)
/// - File cannot be created or written
pub fn write_public_key_file(path: impl AsRef<Path>, contents: &str, force: bool) -> Result<()> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.write(true);

    if force {
        // Force mode: create or truncate existing file
        options.create(true).truncate(true);
    } else {
        // Normal mode: fail if file already exists (atomic check)
        options.create_new(true);
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

    // Ensure data is durably written to disk before returning success
    file.sync_all().map_err(|e| Error::file_write(path, e))?;

    Ok(())
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
pub fn check_file_size_limit(path: &str) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|e| Error::file_read(path, e))?;

    let file_size = metadata.len();
    if file_size > MAX_MESSAGE_SIZE_BYTES {
        return Err(Error::Other(format!(
            "File too large for non-prehashed mode: {file_size} bytes (max: {MAX_MESSAGE_SIZE_BYTES} bytes). Use --prehashed (-p) for files larger than 1 GB."
        )));
    }

    Ok(())
}
