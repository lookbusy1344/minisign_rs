//! Signature verification operations
//!
//! This module implements the core verification logic for minisign signatures.

use super::file_utils::{
    MAX_KEY_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES, read_file_bounded, read_message_file,
};
use crate::{
    Result,
    constants::MAX_MESSAGE_SIZE_BYTES,
    crypto::{blake2b_512, blake2b_512_stream, verify as crypto_verify},
    errors::Error,
    keys::PubkeyStruct,
    signature::SignatureBox,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::fs::File;
use std::io;
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

/// Verified message content captured at verification time.
///
/// All paths (prehashed and non-prehashed) buffer the file content before verification,
/// so the bytes returned here are exactly what was hashed — no TOCTOU window.
#[derive(Debug)]
pub enum MessageSource {
    Buffer(Vec<u8>),
}

impl MessageSource {
    /// Write the verified content to `w`, consuming self.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn write_to(self, w: &mut impl io::Write) -> io::Result<()> {
        match self {
            Self::Buffer(buf) => w.write_all(&buf),
        }
    }
}

/// Result of signature verification
///
/// Note: If you receive this struct, the verification succeeded.
/// Failures return `Err` instead.
#[derive(Debug)]
pub struct VerifyResult {
    /// The trusted comment from the signature
    trusted_comment: String,
    /// The untrusted comment from the signature
    untrusted_comment: String,
    /// Key ID in base64 format
    key_id: String,
    /// Key ID in PGP Word List format (human-readable)
    key_id_words: String,
    /// Captured message content from verification time (populated when `output` is set).
    message_output: Option<MessageSource>,
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

    /// Extract the captured message output, if any.
    pub fn take_message_output(&mut self) -> Option<MessageSource> {
        self.message_output.take()
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

    // Verify the signature on the message, capturing content if -o is set
    let message_output = verify_message_signature(
        &pubkey,
        &sig_box,
        options.message_file(),
        options.force_prehashed,
        options.output,
    )?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());
    let (untrusted_comment, _, trusted_comment, _) = sig_box.into_parts();

    Ok(VerifyResult {
        trusted_comment,
        untrusted_comment,
        key_id,
        key_id_words,
        message_output,
    })
}

cfg_select! {
    feature = "parallel" => {
        fn collect_verify_results(
            files: Vec<PathBuf>,
            pubkey: &PubkeyStruct,
            options: &VerifyOptions<'_>,
            sequential: bool,
        ) -> Vec<FileVerifyResult> {
            if sequential {
                files
                    .into_iter()
                    .map(|file| {
                        let result = verify_file_with_key(&file, pubkey, options);
                        report_file_result(&file, &result, options);
                        FileVerifyResult { file, result }
                    })
                    .collect()
            } else {
                files
                    .into_par_iter()
                    .map(|file| {
                        let result = verify_file_with_key(&file, pubkey, options);
                        report_file_result(&file, &result, options);
                        FileVerifyResult { file, result }
                    })
                    .collect()
            }
        }
    }
    _ => {
        fn collect_verify_results(
            files: Vec<PathBuf>,
            pubkey: &PubkeyStruct,
            options: &VerifyOptions<'_>,
            _sequential: bool,
        ) -> Vec<FileVerifyResult> {
            files
                .into_iter()
                .map(|file| {
                    let result = verify_file_with_key(&file, pubkey, options);
                    report_file_result(&file, &result, options);
                    FileVerifyResult { file, result }
                })
                .collect()
        }
    }
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
            let contents = read_file_bounded(path, MAX_KEY_FILE_BYTES)?;
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
    let contents = read_file_bounded(path.as_ref(), MAX_SIGNATURE_FILE_BYTES)?;
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
    capture_output: bool,
) -> Result<Option<MessageSource>> {
    use subtle::ConstantTimeEq;
    if !bool::from(pubkey.keynum().ct_eq(sig_box.sig_struct().keynum())) {
        return Err(Error::KeyMismatch {
            sig_keynum: sig_box.sig_struct().keynum().to_key_id(),
        });
    }

    if force_prehashed && !sig_box.sig_struct().is_prehashed() {
        return Err(Error::LegacySignatureRejected);
    }

    if sig_box.sig_struct().is_prehashed() {
        if capture_output {
            // H6: close the TOCTOU window between hashing and emitting.
            // The old path (stream-hash → seek → io::copy) lets an attacker modify the file
            // between verification and output. Buffering first means the hash and the returned
            // bytes are the same allocation: no window exists.
            // Files > MAX_MESSAGE_SIZE_BYTES cannot be safely buffered; refuse that combination.
            let file_size = std::fs::metadata(message_file)
                .map_err(|e| Error::file_read(message_file, e))?
                .len();
            if file_size > MAX_MESSAGE_SIZE_BYTES {
                return Err(Error::other(format!(
                    "cannot combine prehashed mode (-H) with output (-o) for files larger \
                     than {MAX_MESSAGE_SIZE_BYTES} bytes: the file must be buffered to \
                     eliminate the TOCTOU window between hash verification and output"
                )));
            }
            let file_buf = read_message_file(message_file)?;
            let hash = blake2b_512(&file_buf);
            crypto_verify(pubkey.public_key(), &hash, sig_box.sig_struct().signature())?;
            return Ok(Some(MessageSource::Buffer(file_buf)));
        }
        // No output needed: stream-hash without buffering (handles files > 1 GB).
        let file = File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        let hash = blake2b_512_stream(file)?;
        crypto_verify(pubkey.public_key(), &hash, sig_box.sig_struct().signature())?;
        Ok(None)
    } else {
        let file_buf = read_message_file(message_file)?;
        crypto_verify(
            pubkey.public_key(),
            &file_buf,
            sig_box.sig_struct().signature(),
        )?;
        if capture_output {
            return Ok(Some(MessageSource::Buffer(file_buf)));
        }
        Ok(None)
    }
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

    // Batch path never uses -o output
    verify_message_signature(
        pubkey,
        &sig_box,
        message_file,
        options.force_prehashed,
        false,
    )?;

    // Verify the global signature (trusted comment binding)
    sig_box.verify_global_signature(pubkey.public_key())?;

    // Generate key ID display formats
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());
    let (untrusted_comment, _, trusted_comment, _) = sig_box.into_parts();

    Ok(VerifyResult {
        trusted_comment,
        untrusted_comment,
        key_id,
        key_id_words,
        message_output: None,
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

    // Multi-file path: verify all files with the already-loaded key.
    let results = collect_verify_results(files, &pubkey, options, sequential);

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

/// Format the batch-verification summary as a string.
///
/// Returns `None` when all files succeeded. When failures exist, returns a string
/// with counts and the filenames of failed files — but not per-file error details,
/// which are reported in real-time by `report_file_result`.
#[must_use]
pub fn format_batch_summary(results: &[FileVerifyResult]) -> Option<String> {
    let failures: Vec<_> = results
        .iter()
        .filter_map(|r| r.result.as_ref().err().map(|_| &r.file))
        .collect();

    if failures.is_empty() {
        return None;
    }

    let success_count = results.len() - failures.len();
    let mut out = format!(
        "\nSummary: {} verified, {} failed\nFailed files:\n",
        success_count,
        failures.len()
    );
    for file in failures {
        use std::fmt::Write as _;
        let _ = writeln!(out, "  - {}", file.display());
    }
    Some(out)
}

/// Print summary of batch verification operation
fn print_summary(results: &[FileVerifyResult], _options: &VerifyOptions<'_>) -> Result<()> {
    let Some(summary) = format_batch_summary(results) else {
        return Ok(());
    };
    // Always show the failure summary even in quiet mode; per-file errors are also
    // always shown. Suppressing the summary would lose the failure list in unattended
    // batch runs.
    eprint!("{summary}");
    if results.iter().all(|r| r.result.is_err()) {
        Err(Error::TotalFailure)
    } else {
        Err(Error::PartialFailure)
    }
}
