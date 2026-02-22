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
    /// Require prehashed signatures (reject legacy signatures)
    force_prehashed: bool,
}

impl<'a> VerifyOptions<'a> {
    /// # Example
    ///
    /// ```
    /// # use minisign::ops::verify::{VerifyOptions, PublicKeySource};
    /// # use std::path::Path;
    /// let options = VerifyOptions::builder(
    ///     PublicKeySource::File(Path::new("key.pub")),
    ///     Path::new("message.txt.sig"),
    ///     Path::new("message.txt")
    /// )
    /// .output(true)
    /// .force_prehashed(true);
    /// ```
    #[must_use]
    pub const fn builder(
        public_key: PublicKeySource<'a>,
        signature_file: &'a Path,
        message_file: &'a Path,
    ) -> Self {
        Self {
            public_key,
            signature_file,
            message_file,
            output: false,
            quiet: false,
            force_prehashed: false,
        }
    }

    #[must_use]
    pub const fn build(self) -> Self {
        self
    }

    #[must_use]
    pub const fn output(mut self, output: bool) -> Self {
        self.output = output;
        self
    }

    #[must_use]
    pub const fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Reject legacy (non-prehashed) signatures.
    #[must_use]
    pub const fn force_prehashed(mut self, force_prehashed: bool) -> Self {
        self.force_prehashed = force_prehashed;
        self
    }

    #[must_use]
    pub const fn public_key(&self) -> &PublicKeySource<'a> {
        &self.public_key
    }

    #[must_use]
    pub const fn signature_file(&self) -> &Path {
        self.signature_file
    }

    #[must_use]
    pub const fn message_file(&self) -> &Path {
        self.message_file
    }
}

/// Source of the public key
#[derive(Debug, Clone)]
pub enum PublicKeySource<'a> {
    /// Read from a file
    File(&'a Path),
    /// Provided as base64-encoded string
    Base64(&'a str),
}

/// Result of signature verification
///
/// Note: If you receive this struct, the verification succeeded.
/// Failures return `Err` instead.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// The trusted comment from the signature
    trusted_comment: String,
    /// The untrusted comment from the signature
    untrusted_comment: String,
    /// Key ID in base64 format
    key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    key_id_words: String,
}

impl VerifyResult {
    #[must_use]
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    #[must_use]
    pub fn untrusted_comment(&self) -> &str {
        &self.untrusted_comment
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
///
/// # Examples
///
/// ```no_run
/// use minisign::ops::{verify, VerifyOptions, PublicKeySource};
/// use std::path::Path;
///
/// let signature_path = Path::new("file.txt.minisig");
/// let data_path = Path::new("file.txt");
/// let pubkey_source = PublicKeySource::File(Path::new("minisign.pub"));
///
/// let options = VerifyOptions::builder(pubkey_source, signature_path, data_path).build();
///
/// let result = verify(&options)?;
/// println!("Signature verified: {}", result.trusted_comment());
/// # Ok::<(), minisign::Error>(())
/// ```
pub fn verify(options: &VerifyOptions<'_>) -> Result<VerifyResult> {
    // Load the public key
    let pubkey = load_public_key(options.public_key())?;

    // Load the signature
    let sig_box = load_signature(options.signature_file())?;

    // Verify the signature on the message
    verify_message_signature(
        &pubkey,
        &sig_box,
        options.message_file(),
        options.force_prehashed,
    )?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    Ok(VerifyResult {
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
/// - Legacy signature found when `force_prehashed` is true
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
    force_prehashed: bool,
) -> Result<()> {
    // H5: Use constant-time comparison for keynum to prevent timing side-channels
    // during signature verification (matches constant-time comparison used for
    // checksum validation in keys.rs)
    use subtle::ConstantTimeEq;
    if !bool::from(pubkey.keynum().ct_eq(sig_box.sig_struct().keynum())) {
        return Err(Error::KeyMismatch {
            sig_keynum: sig_box.sig_struct().keynum().to_key_id(),
            pub_keynum: pubkey.keynum().to_key_id(),
        });
    }

    // Check if legacy signature is rejected (matches C minisign behavior with -H flag)
    if force_prehashed && !sig_box.sig_struct().is_prehashed() {
        return Err(Error::LegacySignatureRejected);
    }

    // For prehashed signatures, we stream hash the message.
    // For non-prehashed, we need the full message in memory.
    // Avoid heap allocation on the prehash path: blake2b_512_stream returns [u8; 64]
    // (stack-allocated), so we hold both possible backing stores as separate bindings and
    // coerce whichever one is initialised into a &[u8] slice.
    let hash_buf;
    let file_buf;
    let data_to_verify: &[u8] = if sig_box.sig_struct().is_prehashed() {
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        hash_buf = blake2b_512_stream(file)?;
        &hash_buf
    } else {
        // For non-prehashed mode, check file size limit first
        check_file_size_limit(message_file)?;

        file_buf = std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?;
        &file_buf
    };

    // Verify the Ed25519 signature
    crypto_verify(
        pubkey.public_key(),
        data_to_verify,
        sig_box.sig_struct().signature(),
    )
}

/// Verify a single file with an already-loaded public key
fn verify_file_with_key(
    message_file: &Path,
    pubkey: &PubkeyStruct,
    options: &VerifyOptions<'_>,
) -> Result<VerifyResult> {
    // Append .minisig extension using OsString to handle non-UTF8 paths correctly
    let mut sig_path = message_file.as_os_str().to_os_string();
    sig_path.push(".minisig");
    let sig_file_path = PathBuf::from(sig_path);

    let sig_box = load_signature(&sig_file_path)?;

    // Verify the signature on the message
    verify_message_signature(pubkey, &sig_box, message_file, options.force_prehashed)?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    Ok(VerifyResult {
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
/// * `Ok(())` if all files verified successfully
/// * `Err(PartialFailure)` if some (but not all) files failed
/// * `Err(TotalFailure)` if all files failed
///
/// # Errors
///
/// Returns `PartialFailure` if some files failed, or `TotalFailure` if all files failed.
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
        if !options.quiet {
            println!(
                "Verified: {}\n  Trusted comment: {}\n  Key ID: {} ({})",
                files[0].display(),
                result.trusted_comment(),
                result.key_id(),
                result.key_id_words()
            );
        }
        return Ok(());
    }

    // Load public key once — avoids N-1 redundant I/O operations
    let pubkey = load_public_key(options.public_key())?;

    // Show key ID once at the top (like signing does)
    if !options.quiet {
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
            .into_par_iter()
            .map(|file| {
                let result = verify_file_with_key(&file, &pubkey, options);
                report_file_result(&file, &result, options);
                FileVerifyResult { file, result }
            })
            .collect()
    };

    print_summary(&results, options)
}

/// Report the result of verifying a single file (called for each file)
fn report_file_result(file: &Path, result: &Result<VerifyResult>, options: &VerifyOptions<'_>) {
    match result {
        Ok(verify_result) => {
            if !options.quiet {
                println!(
                    "Verified: {}\n  Trusted comment: {}",
                    file.display(),
                    verify_result.trusted_comment
                );
            }
        }
        Err(e) => {
            // Always show errors, even in quiet mode (matches sign behavior and Unix conventions)
            eprintln!("Failed: {} ({})", file.display(), e);
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
        if !options.quiet {
            eprintln!(
                "\nSummary: {} verified, {} failed",
                success_count,
                failures.len()
            );
            eprintln!("Failed files:");
            for file in &failures {
                eprintln!("  - {}", file.display());
            }
        }
        return if success_count == 0 {
            Err(Error::TotalFailure)
        } else {
            Err(Error::PartialFailure)
        };
    }

    Ok(())
}
