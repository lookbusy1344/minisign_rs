//! Signature verification operations
//!
//! This module implements the core verification logic for minisign signatures.

use super::file_utils::check_file_size_limit;
use crate::{
    Result,
    crypto::{blake2b_512_stream, verify as crypto_verify},
    errors::Error,
    keys::PubkeyStruct,
    signature::SignatureBox,
};
use rayon::prelude::*;
use std::path::{Path, PathBuf};

/// Options for signature verification
#[derive(Debug, Clone)]
pub struct VerifyOptions<'a> {
    /// Public key (either from file or provided directly)
    public_key: PublicKeySource<'a>,
    /// Path to the signature file
    signature_file: &'a Path,
    /// Path to the message file
    message_file: &'a Path,
    /// Output verification result to stdout
    output: bool,
    /// Quiet mode (no output)
    quiet: bool,
}

impl<'a> VerifyOptions<'a> {
    /// Create new verify options
    ///
    /// # Arguments
    ///
    /// * `public_key` - Public key (either from file or provided directly)
    /// * `signature_file` - Path to the signature file
    /// * `message_file` - Path to the message file
    /// * `output` - Output verification result to stdout
    /// * `quiet` - Quiet mode (no output)
    #[must_use]
    pub fn new(
        public_key: PublicKeySource<'a>,
        signature_file: &'a Path,
        message_file: &'a Path,
        output: bool,
        quiet: bool,
    ) -> Self {
        Self {
            public_key,
            signature_file,
            message_file,
            output,
            quiet,
        }
    }

    /// Get the public key source
    #[must_use]
    pub fn public_key(&self) -> &PublicKeySource<'a> {
        &self.public_key
    }

    /// Get the signature file path
    #[must_use]
    pub fn signature_file(&self) -> &Path {
        self.signature_file
    }

    /// Get the message file path
    #[must_use]
    pub fn message_file(&self) -> &Path {
        self.message_file
    }

    /// Get the output flag
    #[must_use]
    pub fn output(&self) -> bool {
        self.output
    }

    /// Get the quiet flag
    #[must_use]
    pub fn quiet(&self) -> bool {
        self.quiet
    }
}

/// Source of the public key
#[derive(Debug, Clone)]
pub enum PublicKeySource<'a> {
    /// Read from a file
    File(&'a Path),
    /// Provided as base64-encoded string
    Base64(String),
}

/// Result of signature verification
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// The trusted comment from the signature
    pub trusted_comment: String,
    /// The untrusted comment from the signature
    pub untrusted_comment: String,
    /// Key ID in base64 format
    pub key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    pub key_id_words: String,
}

/// Result of a single file verification operation (for batch processing)
#[derive(Debug)]
pub struct FileVerifyResult {
    /// Path to the file that was verified
    pub file: PathBuf,
    /// Result of the verification operation
    pub result: Result<VerifyResult>,
}

/// Verify a file's signature
///
/// # Arguments
///
/// * `options` - Verification options including key, signature, and message paths
///
/// # Returns
///
/// A `VerifyResult` containing verification status and comments
///
/// # Errors
///
/// Returns an error if:
/// - The public key cannot be loaded or parsed
/// - The signature file cannot be loaded or parsed
/// - The message file cannot be read
/// - The signature is invalid
/// - The global signature is invalid
pub fn verify(options: &VerifyOptions<'_>) -> Result<VerifyResult> {
    // Load the public key
    let pubkey = load_public_key(options.public_key())?;

    // Load the signature
    let sig_box = load_signature(options.signature_file())?;

    // Verify the signature on the message
    verify_message_signature(&pubkey, &sig_box, options.message_file())?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    Ok(VerifyResult {
        valid: true,
        trusted_comment: sig_box.trusted_comment().to_string(),
        untrusted_comment: sig_box.untrusted_comment().to_string(),
        key_id,
        key_id_words,
    })
}

/// Load a public key from the specified source
///
/// # Errors
///
/// Returns an error if:
/// - File cannot be read (for file source)
/// - Public key parsing fails
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn load_public_key(source: &PublicKeySource<'_>) -> Result<PubkeyStruct> {
    match source {
        PublicKeySource::File(path) => {
            let contents = std::fs::read_to_string(path).map_err(|e| Error::file_read(path, e))?;
            PubkeyStruct::from_file_contents(&contents)
        }
        PublicKeySource::Base64(base64_str) => {
            // For base64 input, we expect just the encoded PubkeyStruct without comment
            PubkeyStruct::from_base64(base64_str)
        }
    }
}

/// Load a signature from a file
///
/// # Errors
///
/// Returns an error if:
/// - File cannot be read
/// - Signature parsing fails
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn load_signature(path: impl AsRef<Path>) -> Result<SignatureBox> {
    let contents =
        std::fs::read_to_string(path.as_ref()).map_err(|e| Error::file_read(path.as_ref(), e))?;
    SignatureBox::from_file_contents(&contents)
}

/// Verify the message signature, handling prehashed mode
///
/// # Errors
///
/// Returns an error if:
/// - Key number doesn't match
/// - File cannot be read
/// - File size exceeds limit (non-prehashed mode)
/// - Signature verification fails
///
/// # Note
///
/// This function is public for unit testing purposes but is not part of the stable API.
pub fn verify_message_signature(
    pubkey: &PubkeyStruct,
    sig_box: &SignatureBox,
    message_file: &Path,
) -> Result<()> {
    // First, verify that the keynum matches
    if pubkey.keynum() != sig_box.sig_struct().keynum() {
        return Err(Error::KeyMismatch {
            sig_keynum: sig_box.sig_struct().keynum().to_key_id(),
            pub_keynum: pubkey.keynum().to_key_id(),
        });
    }

    // For prehashed signatures, we stream hash the message
    // For non-prehashed, we need the full message in memory
    let data_to_verify = if sig_box.sig_struct().is_prehashed() {
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        blake2b_512_stream(file)?.to_vec()
    } else {
        // For non-prehashed mode, check file size limit first
        check_file_size_limit(message_file)?;

        std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
    };

    // Verify the Ed25519 signature
    crypto_verify(
        pubkey.public_key(),
        &data_to_verify,
        sig_box.sig_struct().signature(),
    )
}

/// Verify a single file with an already-loaded public key
fn verify_file_with_key(
    message_file: &Path,
    pubkey: &PubkeyStruct,
    _options: &VerifyOptions<'_>,
) -> Result<VerifyResult> {
    let sig_file_path = PathBuf::from(format!("{}.minisig", message_file.display()));

    let sig_box = load_signature(&sig_file_path)?;

    // Verify the signature on the message
    verify_message_signature(pubkey, &sig_box, message_file)?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    Ok(VerifyResult {
        valid: true,
        trusted_comment: sig_box.trusted_comment().to_string(),
        untrusted_comment: sig_box.untrusted_comment().to_string(),
        key_id,
        key_id_words,
    })
}

/// Verify multiple files (parallel or sequential)
///
/// # Arguments
///
/// * `files` - Vector of file paths to verify
/// * `options` - Verification options (`message_file` and `signature_file` fields are ignored)
/// * `sequential` - If true, process files sequentially; if false, use parallel execution
///
/// # Returns
///
/// `Ok(())` if all files verified successfully, `Err(PartialFailure)` if any failed
///
/// # Errors
///
/// Returns `PartialFailure` error if any files could not be verified.
/// Individual file errors are reported to stderr during execution.
pub fn verify_multiple_files(
    files: Vec<PathBuf>,
    options: &VerifyOptions<'_>,
    sequential: bool,
) -> Result<()> {
    // Fast path for single file
    if files.len() == 1 {
        let result =
            verify_file_with_key(&files[0], &load_public_key(options.public_key())?, options)?;
        if !options.quiet() {
            println!(
                "Verified: {}\n  Trusted comment: {}\n  Key ID: {} ({})",
                files[0].display(),
                result.trusted_comment,
                result.key_id,
                result.key_id_words
            );
        }
        return Ok(());
    }

    // Load public key once — avoids N-1 redundant I/O operations
    let pubkey = load_public_key(options.public_key())?;

    // Show key ID once at the top (like signing does)
    if !options.quiet() {
        let key_id = pubkey.keynum().to_key_id();
        let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());
        println!("Verifying with key: {key_id} ({key_id_words})");
    }

    // Multi-file path: verify all files with the already-loaded key
    let results: Vec<FileVerifyResult> = if sequential {
        files
            .into_iter()
            .map(|file| {
                let result = verify_file_with_key(&file, &pubkey, options);
                report_file_result(&file, &result, options);
                FileVerifyResult { file, result }
            })
            .collect()
    } else {
        files
            .par_iter()
            .map(|file| {
                let result = verify_file_with_key(file, &pubkey, options);
                report_file_result(file, &result, options);
                FileVerifyResult {
                    file: file.clone(),
                    result,
                }
            })
            .collect()
    };

    print_summary(&results, options)
}

/// Report the result of verifying a single file (called for each file)
fn report_file_result(file: &Path, result: &Result<VerifyResult>, options: &VerifyOptions<'_>) {
    match result {
        Ok(verify_result) => {
            if !options.quiet() {
                println!(
                    "Verified: {}\n  Trusted comment: {}",
                    file.display(),
                    verify_result.trusted_comment
                );
            }
        }
        Err(e) => {
            if !options.quiet() {
                eprintln!("Failed: {} ({})", file.display(), e);
            }
        }
    }
}

/// Print summary of batch verification operation
fn print_summary(results: &[FileVerifyResult], options: &VerifyOptions<'_>) -> Result<()> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|r| r.result.as_ref().err().map(|_| &r.file))
        .collect();

    let success_count = results.len() - failures.len();

    if !failures.is_empty() {
        if !options.quiet() {
            eprintln!(
                "\nSummary: {} verified, {} failed",
                success_count,
                failures.len()
            );
            eprintln!("Failed files:");
            for file in &failures {
                eprintln!("  - {}", file.display());
            }
            if success_count == 0 {
                eprintln!("Total failure: all files failed");
            } else {
                eprintln!("Partial failure: some files could not be verified");
            }
        }
        return Err(Error::PartialFailure);
    }

    Ok(())
}
