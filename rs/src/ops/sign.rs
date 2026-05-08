//! Signature creation operations
//!
//! This module implements the core signing logic for minisign.

use super::file_utils::{load_secret_key, read_message_file};
use crate::{
    Result,
    crypto::{SecretKey, blake2b_512_stream, sign as crypto_sign},
    errors::Error,
    keys::SeckeyStruct,
    signature::{
        COMMENT_PREFIX_SIZE, COMMENTMAXBYTES, SigStruct, SignatureBox, TRUSTED_COMMENT_PREFIX_SIZE,
        TRUSTEDCOMMENTMAXBYTES,
    },
    validation::validate_comment_with_length,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::path::{Path, PathBuf};

/// Default untrusted comment for signatures
const DEFAULT_UNTRUSTED_COMMENT: &str = "signature from minisign secret key";

/// Options for signing files
#[derive(Debug, Clone)]
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
    trusted_comment: Option<&'a str>,
    /// Untrusted comment to include in the signature
    untrusted_comment: Option<&'a str>,
    /// Force overwrite existing signature file
    force: bool,
    /// Suppress informational output
    quiet: bool,
}

impl<'a> SignOptions<'a> {
    /// # Example
    ///
    /// ```
    /// # use minisign::ops::sign::SignOptions;
    /// # use std::path::Path;
    /// let options = SignOptions::builder(
    ///     Path::new("secret.key"),
    ///     Path::new("message.txt")
    /// )
    /// .prehashed(true)
    /// .trusted_comment("timestamp:12345")
    /// .force(true);
    /// ```
    #[must_use]
    pub const fn builder(secret_key_file: &'a Path, message_file: &'a Path) -> Self {
        Self {
            secret_key_file,
            message_file,
            signature_file: None,
            prehashed: true, // Default matches C minisign: prehashed mode
            trusted_comment: None,
            untrusted_comment: None,
            force: false,
            quiet: false,
        }
    }

    #[must_use]
    pub const fn build(self) -> Self {
        self
    }

    #[must_use]
    pub const fn signature_file(mut self, path: &'a Path) -> Self {
        self.signature_file = Some(path);
        self
    }

    /// Default: `true` (matches C minisign behavior)
    #[must_use]
    pub const fn prehashed(mut self, prehashed: bool) -> Self {
        self.prehashed = prehashed;
        self
    }

    #[must_use]
    pub const fn trusted_comment(mut self, comment: &'a str) -> Self {
        self.trusted_comment = Some(comment);
        self
    }

    #[must_use]
    pub const fn untrusted_comment(mut self, comment: &'a str) -> Self {
        self.untrusted_comment = Some(comment);
        self
    }

    #[must_use]
    pub const fn force(mut self, force: bool) -> Self {
        self.force = force;
        self
    }

    #[must_use]
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    #[must_use]
    pub const fn secret_key_file(&self) -> &Path {
        self.secret_key_file
    }

    #[must_use]
    pub const fn message_file(&self) -> &Path {
        self.message_file
    }
}

/// Result of signing operation
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Path where the signature was written
    signature_file: PathBuf,
    /// The trusted comment used
    trusted_comment: String,
    /// Key ID in base64 format
    key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    key_id_words: String,
}

impl SignResult {
    #[must_use]
    pub fn signature_file(&self) -> &Path {
        &self.signature_file
    }

    #[must_use]
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn key_id_words(&self) -> &str {
        &self.key_id_words
    }
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
    seckey.extract_key(password)
}

/// Sign a single file with an already-loaded secret key
fn sign_file_with_key(
    message_file: &Path,
    secret_key: &SecretKey,
    keynum: crate::crypto::KeyNum,
    options: &SignOptions<'_>,
) -> Result<SignResult> {
    let sig_file_path = options.signature_file.map_or_else(
        || {
            // Append .minisig extension using OsString to handle non-UTF8 paths correctly
            let mut path = message_file.as_os_str().to_os_string();
            path.push(".minisig");
            PathBuf::from(path)
        },
        Path::to_path_buf,
    );

    let sig_box = create_signature(
        secret_key,
        keynum,
        message_file,
        options.prehashed,
        options.trusted_comment,
        options.untrusted_comment,
    )?;

    let sig_contents = sig_box.to_file_contents();
    write_signature_file(&sig_file_path, &sig_contents, options.force)?;

    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(&keynum);
    let (_, _, trusted_comment, _) = sig_box.into_parts();

    Ok(SignResult {
        signature_file: sig_file_path,
        trusted_comment,
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

/// Sign a file with a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded (e.g., for credential store lookups).
///
/// # Arguments
///
/// * `message_file` - Path to the message file to sign
/// * `seckey` - Pre-loaded secret key structure
/// * `options` - Signing options (signature file, comments, prehashed mode, etc.)
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign_with_key(
    message_file: &Path,
    seckey: &SeckeyStruct,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
) -> Result<SignResult> {
    // Decrypt the key if needed
    let (secret_key, keynum) = seckey.extract_key(password)?;

    // Sign the file using the existing helper
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
/// let options = SignOptions::builder(secret_key_path, message_file)
///     .prehashed(true)
///     .build();
///
/// let result = sign(&options, password)?;
/// println!("File signed: {}", result.signature_file().display());
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

cfg_select! {
    feature = "parallel" => {
        fn collect_sign_results(
            files: Vec<PathBuf>,
            secret_key: &SecretKey,
            keynum: crate::crypto::KeyNum,
            options: &SignOptions<'_>,
            sequential: bool,
        ) -> Vec<FileSignResult> {
            if sequential {
                files
                    .into_iter()
                    .map(|file| {
                        let result = sign_file_with_key(&file, secret_key, keynum, options);
                        report_file_result(&file, &result, options);
                        FileSignResult { file, result }
                    })
                    .collect()
            } else {
                files
                    .into_par_iter()
                    .map(|file| {
                        let result = sign_file_with_key(&file, secret_key, keynum, options);
                        report_file_result(&file, &result, options);
                        FileSignResult { file, result }
                    })
                    .collect()
            }
        }
    }
    _ => {
        fn collect_sign_results(
            files: Vec<PathBuf>,
            secret_key: &SecretKey,
            keynum: crate::crypto::KeyNum,
            options: &SignOptions<'_>,
            _sequential: bool,
        ) -> Vec<FileSignResult> {
            files
                .into_iter()
                .map(|file| {
                    let result = sign_file_with_key(&file, secret_key, keynum, options);
                    report_file_result(&file, &result, options);
                    FileSignResult { file, result }
                })
                .collect()
        }
    }
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
/// * `Ok(())` if all files signed successfully
/// * `Err(PartialFailure)` if some (but not all) files failed
/// * `Err(TotalFailure)` if all files failed
///
/// # Errors
///
/// Returns `PartialFailure` if some files failed, or `TotalFailure` if all files failed.
/// Individual file errors are reported to stderr during execution.
pub fn sign_multiple_files(
    files: Vec<PathBuf>,
    options: &SignOptions<'_>,
    password: Option<&[u8]>,
    sequential: bool,
) -> Result<()> {
    // Deduplicate files to prevent race conditions when signing the same file multiple times
    // Use a HashSet to track unique paths
    let mut seen = std::collections::HashSet::new();
    let mut deduped_files = Vec::new();

    for file in files {
        // Try to canonicalize for better deduplication (e.g., ./file vs file)
        // Fall back to original path if canonicalization fails (file doesn't exist yet)
        let canonical = file.canonicalize().unwrap_or_else(|_| file.clone());

        if seen.insert(canonical) {
            deduped_files.push(file);
        }
    }

    let files = deduped_files;

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
    if !options.quiet {
        let key_id = keynum.to_key_id();
        let key_id_words = crate::wordlist::keynum_to_words(&keynum);
        println!("Signing with key: {key_id} ({key_id_words})");
    }

    // Multi-file path: sign all files with the already-loaded key.
    let results = collect_sign_results(files, &secret_key, keynum, options, sequential);

    print_summary(&results, options)
}

/// Report the result of signing a single file (called for each file)
fn report_file_result(file: &Path, result: &Result<SignResult>, options: &SignOptions<'_>) {
    match result {
        Ok(_) => {
            if !options.quiet {
                println!("Signed: {} → {}.minisig", file.display(), file.display());
            }
        }
        Err(e) => {
            // Always show errors, even in quiet mode
            eprintln!("Failed: {} ({})", file.display(), e);
        }
    }
}

/// Format the batch-signing summary as a string.
///
/// Returns `None` when all files succeeded. When failures exist, returns a string
/// with counts and the filenames of failed files — but not per-file error details,
/// which are reported in real-time by `report_file_result`.
#[must_use]
pub fn format_batch_summary(results: &[FileSignResult]) -> Option<String> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|r| r.result.as_ref().err().map(|_| &r.file))
        .collect();

    if failures.is_empty() {
        return None;
    }

    let success_count = results.len() - failures.len();
    let mut out = format!(
        "\nSummary: {} signed, {} failed\nFailed files:\n",
        success_count,
        failures.len()
    );
    for file in failures {
        use std::fmt::Write as _;
        let _ = writeln!(out, "  - {}", file.display());
    }
    Some(out)
}

/// Print summary of batch signing operation
fn print_summary(results: &[FileSignResult], _options: &SignOptions<'_>) -> Result<()> {
    let Some(summary) = format_batch_summary(results) else {
        return Ok(());
    };
    // Always show the failure summary even in quiet mode.
    // Individual per-file errors are reported by report_file_result (also always shown).
    // Suppressing the summary in quiet mode would leave users without a machine-readable
    // failure list when running unattended batch operations.
    eprint!("{summary}");
    if results.iter().all(|r| r.result.is_err()) {
        Err(Error::TotalFailure)
    } else {
        Err(Error::PartialFailure)
    }
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
    // M6: Validate comments BEFORE any file I/O or crypto operations
    // This ensures we fail fast on invalid input without wasting resources

    // Generate trusted comment if not provided
    let trusted_comment =
        trusted_comment.map_or_else(generate_default_trusted_comment, String::from);

    // Generate untrusted comment if not provided
    let untrusted_comment =
        untrusted_comment.map_or_else(|| DEFAULT_UNTRUSTED_COMMENT.to_string(), String::from);

    // Validate comments for printability, carriage returns, and length (matches C implementation behavior)
    // Both untrusted and trusted comments now use fatal errors for consistency
    validate_comment_with_length(
        &untrusted_comment,
        Some(COMMENTMAXBYTES - COMMENT_PREFIX_SIZE),
        "untrusted",
    )?;

    validate_comment_with_length(
        &trusted_comment,
        Some(TRUSTEDCOMMENTMAXBYTES - TRUSTED_COMMENT_PREFIX_SIZE),
        "trusted",
    )?;

    // Now that validation is complete, proceed with file I/O and crypto operations

    // Determine what data to sign.
    // Avoid heap allocation on the prehash path: blake2b_512_stream returns [u8; 64]
    // (stack-allocated), so we hold both possible backing stores as separate bindings and
    // coerce whichever one is initialised into a &[u8] slice.
    let hash_buf;
    let file_buf;
    let data_to_sign: &[u8] = if prehashed {
        // Open file and stream hash
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        hash_buf = blake2b_512_stream(file)?;
        &hash_buf
    } else {
        file_buf = read_message_file(message_file)?;
        &file_buf
    };

    // Sign the message
    let signature = crypto_sign(secret_key, data_to_sign)?;

    // Create the SigStruct
    let sig_struct = SigStruct::new(keynum, signature, prehashed);

    // Create global signature (signs: signature_bytes || trusted_comment)
    let global_sig_data = create_global_signature_data(&sig_struct, &trusted_comment);
    let global_signature = crypto_sign(secret_key, &global_sig_data)?;

    SignatureBox::new(
        untrusted_comment,
        sig_struct,
        trusted_comment,
        global_signature,
    )
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
        .unwrap_or_else(|_| {
            eprintln!("Warning: system clock is before UNIX epoch, using timestamp 0");
            std::time::Duration::ZERO
        })
        .as_secs();

    format!("timestamp:{timestamp}")
}

pub use super::file_utils::write_signature_file;
