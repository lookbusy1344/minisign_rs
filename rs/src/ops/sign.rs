//! Signature creation operations
//!
//! This module implements the core signing logic for minisign.

use super::file_utils::load_secret_key;
use crate::{
    Result,
    constants::MAX_MESSAGE_SIZE_BYTES,
    crypto::{SecretKey, blake2b_512_stream, sign as crypto_sign},
    errors::Error,
    signature::{
        COMMENT_PREFIX_SIZE, COMMENTMAXBYTES, SigStruct, SignatureBox, TRUSTED_COMMENT_PREFIX_SIZE,
        TRUSTEDCOMMENTMAXBYTES,
    },
    validation::validate_comment,
};
use std::{fs::OpenOptions, io::Write, path::Path};

/// Options for signing files
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Path to the secret key file
    pub secret_key_file: String,
    /// Path to the message file
    pub message_file: String,
    /// Path to output signature file (optional, defaults to `message_file.minisig`)
    pub signature_file: Option<String>,
    /// Use prehashed mode (hash the message with Blake2b-512 before signing)
    pub prehashed: bool,
    /// Trusted comment to include in the signature
    pub trusted_comment: Option<String>,
    /// Untrusted comment to include in the signature
    pub untrusted_comment: Option<String>,
    /// Force overwrite existing signature file
    pub force: bool,
}

/// Result of signing operation
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Path where the signature was written
    pub signature_file: String,
    /// The trusted comment used
    pub trusted_comment: String,
    /// Key ID in base64 format
    pub key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    pub key_id_words: String,
}

/// Sign a file with a secret key
///
/// # Arguments
///
/// * `options` - Signing options including key, message, and comment settings
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be loaded or decrypted
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign(options: &SignOptions, password: Option<&[u8]>) -> Result<SignResult> {
    // Load and decrypt the secret key
    let seckey = load_secret_key(&options.secret_key_file)?;

    // Decrypt if necessary (weak KDF warning is shown by decrypt() if applicable)
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Determine the signature file path
    let sig_file_path = options
        .signature_file
        .clone()
        .unwrap_or_else(|| format!("{}.minisig", options.message_file));

    // Create the signature
    let sig_box = create_signature(
        &secret_key,
        keynum,
        &options.message_file,
        options.prehashed,
        options.trusted_comment.as_deref(),
        options.untrusted_comment.as_deref(),
    )?;

    // Write the signature file atomically
    let sig_contents = sig_box.to_file_contents();
    write_signature_file(Path::new(&sig_file_path), &sig_contents, options.force)?;

    // Generate key ID display formats
    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(&keynum);

    Ok(SignResult {
        signature_file: sig_file_path,
        trusted_comment: sig_box.trusted_comment().to_string(),
        key_id,
        key_id_words,
    })
}

/// Create a signature for a message
///
/// # Errors
///
/// Returns an error if:
/// - File cannot be read
/// - File size exceeds limit (non-prehashed mode)
/// - Signing operation fails
/// - Comment validation fails
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn create_signature(
    secret_key: &SecretKey,
    keynum: crate::crypto::KeyNum,
    message_file: &str,
    prehashed: bool,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<SignatureBox> {
    // Determine what data to sign
    let data_to_sign = if prehashed {
        // Open file and stream hash
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        blake2b_512_stream(file)?.to_vec()
    } else {
        // For non-prehashed mode, check file size limit first
        check_file_size_limit(message_file)?;

        // For non-prehashed mode, we need the full message in memory
        // (Ed25519 requires the full message for signing)
        std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
    };

    // Sign the message
    let signature = crypto_sign(secret_key, &data_to_sign)?;

    // Create the SigStruct
    let sig_struct = SigStruct::new(keynum, signature, prehashed);

    // Generate trusted comment if not provided
    let trusted_comment =
        trusted_comment.map_or_else(generate_default_trusted_comment, String::from);

    // Generate untrusted comment if not provided
    let untrusted_comment = untrusted_comment.map_or_else(
        || "signature from minisign secret key".to_string(),
        String::from,
    );

    // Validate comment lengths (matches C implementation behavior)
    if untrusted_comment.len() >= COMMENTMAXBYTES - COMMENT_PREFIX_SIZE {
        eprintln!("Warning: comment too long. This breaks compatibility with signify.");
    }

    if trusted_comment.len() >= TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE {
        return Err(Error::Other("Trusted comment too long".to_string()));
    }

    // Validate comments for printability and carriage returns (matches C implementation)
    validate_comment(&untrusted_comment)?;
    validate_comment(&trusted_comment)?;

    // Create global signature (signs: signature_bytes || trusted_comment)
    let global_sig_data = create_global_signature_data(&sig_struct, &trusted_comment);
    let global_signature = crypto_sign(secret_key, &global_sig_data)?;

    Ok(SignatureBox::new(
        untrusted_comment,
        sig_struct,
        trusted_comment,
        global_signature,
    ))
}

/// Create the data that the global signature signs
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
#[must_use]
pub fn create_global_signature_data(sig_struct: &SigStruct, trusted_comment: &str) -> Vec<u8> {
    let capacity = sig_struct.signature().as_bytes().len() + trusted_comment.len();
    let mut data = Vec::with_capacity(capacity);
    data.extend_from_slice(sig_struct.signature().as_bytes());
    data.extend_from_slice(trusted_comment.as_bytes());
    data
}

/// Generate a default trusted comment with timestamp
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
#[must_use]
pub fn generate_default_trusted_comment() -> String {
    // Get current timestamp in UTC
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!("timestamp:{timestamp}")
}

/// Write signature file with atomic creation
///
/// This prevents TOCTOU (Time-of-Check-Time-of-Use) race conditions by using
/// `create_new(true)`, which atomically creates the file only if it doesn't exist.
///
/// # Errors
///
/// Returns an error if:
/// - File already exists (when force is false)
/// - File cannot be created or written
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn write_signature_file(path: &Path, contents: &str, force: bool) -> Result<()> {
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
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
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
