//! Signature creation operations
//!
//! This module implements the core signing logic for minisign.

use super::file_utils::{check_file_size_limit, load_secret_key};
use crate::{
    Result,
    crypto::{SecretKey, blake2b_512_stream, sign as crypto_sign},
    errors::Error,
    signature::{
        COMMENT_PREFIX_SIZE, COMMENTMAXBYTES, SigStruct, SignatureBox, TRUSTED_COMMENT_PREFIX_SIZE,
        TRUSTEDCOMMENTMAXBYTES,
    },
    validation::validate_comment,
};
use rayon::prelude::*;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

/// Options for signing files
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SignOptions<'a> {
    /// Path to the secret key file
    secret_key_file: &'a Path,
    /// Path to the message file
    message_file: &'a Path,
    /// Path to output signature file (optional, defaults to `message_file.minisig`)
    signature_file: Option<&'a Path>,
    /// Use prehashed mode (hash the message with Blake2b-512 before signing)
    prehashed: bool,
    /// Trusted comment to include in the signature
    trusted_comment: Option<String>,
    /// Untrusted comment to include in the signature
    untrusted_comment: Option<String>,
    /// Force overwrite existing signature file
    force: bool,
    /// Suppress informational output
    quiet: bool,
}

impl<'a> SignOptions<'a> {
    /// Create new sign options
    ///
    /// # Arguments
    ///
    /// * `secret_key_file` - Path to the secret key file
    /// * `message_file` - Path to the message file
    /// * `signature_file` - Optional path to output signature file (defaults to `message_file.minisig`)
    /// * `prehashed` - Use prehashed mode (hash the message with Blake2b-512 before signing)
    /// * `trusted_comment` - Optional trusted comment to include in the signature
    /// * `untrusted_comment` - Optional untrusted comment to include in the signature
    /// * `force` - Force overwrite existing signature file
    /// * `quiet` - Suppress informational output
    #[allow(clippy::fn_params_excessive_bools)]
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        secret_key_file: &'a Path,
        message_file: &'a Path,
        signature_file: Option<&'a Path>,
        prehashed: bool,
        trusted_comment: Option<String>,
        untrusted_comment: Option<String>,
        force: bool,
        quiet: bool,
    ) -> Self {
        Self {
            secret_key_file,
            message_file,
            signature_file,
            prehashed,
            trusted_comment,
            untrusted_comment,
            force,
            quiet,
        }
    }

    /// Get the secret key file path
    #[must_use]
    pub fn secret_key_file(&self) -> &Path {
        self.secret_key_file
    }

    /// Get the message file path
    #[must_use]
    pub fn message_file(&self) -> &Path {
        self.message_file
    }

    /// Get the signature file path
    #[must_use]
    pub fn signature_file(&self) -> Option<&Path> {
        self.signature_file
    }

    /// Get the prehashed flag
    #[must_use]
    pub fn prehashed(&self) -> bool {
        self.prehashed
    }

    /// Get the trusted comment
    #[must_use]
    pub fn trusted_comment(&self) -> Option<&str> {
        self.trusted_comment.as_deref()
    }

    /// Get the untrusted comment
    #[must_use]
    pub fn untrusted_comment(&self) -> Option<&str> {
        self.untrusted_comment.as_deref()
    }

    /// Get the force flag
    #[must_use]
    pub fn force(&self) -> bool {
        self.force
    }

    /// Get the quiet flag
    #[must_use]
    pub fn quiet(&self) -> bool {
        self.quiet
    }
}

/// Result of signing operation
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Path where the signature was written
    pub signature_file: PathBuf,
    /// The trusted comment used
    pub trusted_comment: String,
    /// Key ID in base64 format
    pub key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    pub key_id_words: String,
}

/// Result of a single file signing operation (for batch processing)
#[derive(Debug)]
pub struct FileSignResult {
    /// Path to the file that was signed
    pub file: PathBuf,
    /// Result of the signing operation
    pub result: Result<SignResult>,
}

/// Load and decrypt a secret key from a file
///
/// Handles both encrypted and unencrypted keys. For encrypted keys, the weak
/// KDF warning is emitted by `decrypt()` if applicable.
fn load_and_decrypt_key(
    secret_key_file: &Path,
    password: Option<&[u8]>,
) -> Result<(SecretKey, crate::crypto::KeyNum)> {
    let seckey = load_secret_key(secret_key_file)?;

    if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)
    } else {
        Ok((seckey.get_unencrypted_secret_key()?, *seckey.keynum()))
    }
}

/// Sign a single file with an already-loaded secret key
fn sign_file_with_key(
    message_file: &Path,
    secret_key: &SecretKey,
    keynum: crate::crypto::KeyNum,
    options: &SignOptions<'_>,
) -> Result<SignResult> {
    let sig_file_path = options.signature_file().map_or_else(
        || PathBuf::from(format!("{}.minisig", message_file.display())),
        Path::to_path_buf,
    );

    let sig_box = create_signature(
        secret_key,
        keynum,
        message_file,
        options.prehashed(),
        options.trusted_comment(),
        options.untrusted_comment(),
    )?;

    let sig_contents = sig_box.to_file_contents();
    write_signature_file(&sig_file_path, &sig_contents, options.force())?;

    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(&keynum);

    Ok(SignResult {
        signature_file: sig_file_path,
        trusted_comment: sig_box.trusted_comment().to_string(),
        key_id,
        key_id_words,
    })
}

/// Sign a single file with a secret key
///
/// # Arguments
///
/// * `message_file` - Path to the message file
/// * `options` - Signing options (all fields except `message_file` are used)
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
pub fn sign_single_file(
    message_file: &Path,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
) -> Result<SignResult> {
    let (secret_key, keynum) = load_and_decrypt_key(options.secret_key_file(), password)?;
    sign_file_with_key(message_file, &secret_key, keynum, options)
}

/// Sign a file with a secret key (backwards compatibility wrapper)
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
/// # Examples
///
/// ```no_run
/// use minisign::ops::{sign, SignOptions};
/// use std::path::Path;
///
/// let secret_key_path = Path::new("~/.minisign/minisign.key");
/// let message_file = Path::new("file.txt");
/// let password = Some(b"my_password".as_ref());
///
/// let options = SignOptions::new(
///     secret_key_path,
///     message_file,
///     None,        // signature_path (defaults to message_file.minisig)
///     true,        // prehashed (default mode)
///     None,        // trusted_comment
///     None,        // untrusted_comment
///     false,       // force
///     false,       // quiet
/// );
///
/// let result = sign(&options, password)?;
/// println!("File signed: {}", result.signature_file.display());
/// # Ok::<(), minisign::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be loaded or decrypted
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign(options: &SignOptions<'_>, password: Option<&[u8]>) -> Result<SignResult> {
    sign_single_file(options.message_file(), options, password)
}

/// Sign multiple files (parallel or sequential)
///
/// # Arguments
///
/// * `files` - Vector of file paths to sign
/// * `options` - Signing options (`message_file` field is ignored)
/// * `password` - Password to decrypt the secret key (if encrypted)
/// * `sequential` - If true, process files sequentially; if false, use parallel execution
///
/// # Returns
///
/// `Ok(())` if all files signed successfully, `Err(PartialFailure)` if any failed
///
/// # Errors
///
/// Returns `PartialFailure` error if any files could not be signed.
/// Individual file errors are reported to stderr during execution.
pub fn sign_multiple_files(
    files: Vec<PathBuf>,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
    sequential: bool,
) -> Result<()> {
    // Fast path for single file
    if files.len() == 1 {
        sign_single_file(&files[0], options, password)?;
        println!(
            "Signed: {} → {}.minisig",
            files[0].display(),
            files[0].display()
        );
        return Ok(());
    }

    // Load and decrypt key once — avoids N-1 redundant scrypt derivations
    let (secret_key, keynum) = load_and_decrypt_key(options.secret_key_file(), password)?;

    // Show key ID once at the top (like verification does)
    if !options.quiet() {
        let key_id = keynum.to_key_id();
        let key_id_words = crate::wordlist::keynum_to_words(&keynum);
        println!("Signing with key: {key_id} ({key_id_words})");
    }

    // Multi-file path: sign all files with the already-loaded key
    let results: Vec<FileSignResult> = if sequential {
        files
            .into_iter()
            .map(|file| {
                let result = sign_file_with_key(&file, &secret_key, keynum, options);
                report_file_result(&file, &result);
                FileSignResult { file, result }
            })
            .collect()
    } else {
        files
            .par_iter()
            .map(|file| {
                let result = sign_file_with_key(file, &secret_key, keynum, options);
                report_file_result(file, &result);
                FileSignResult {
                    file: file.clone(),
                    result,
                }
            })
            .collect()
    };

    print_summary(&results)
}

/// Report the result of signing a single file (called for each file)
fn report_file_result(file: &Path, result: &Result<SignResult>) {
    match result {
        Ok(_) => println!("Signed: {} → {}.minisig", file.display(), file.display()),
        Err(e) => eprintln!("Failed: {} ({})", file.display(), e),
    }
}

/// Print summary of batch signing operation
fn print_summary(results: &[FileSignResult]) -> Result<()> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|r| r.result.as_ref().err().map(|_| &r.file))
        .collect();

    let success_count = results.len() - failures.len();

    if !failures.is_empty() {
        eprintln!(
            "\nSummary: {} signed, {} failed",
            success_count,
            failures.len()
        );
        eprintln!("Failed files:");
        for file in &failures {
            eprintln!("  - {}", file.display());
        }
        return Err(Error::PartialFailure);
    }

    Ok(())
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
    message_file: &Path,
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
