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
use std::path::{Path, PathBuf};

/// Options for signature verification
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Public key (either from file or provided directly)
    pub public_key: PublicKeySource,
    /// Path to the signature file
    pub signature_file: PathBuf,
    /// Path to the message file
    pub message_file: PathBuf,
    /// Output verification result to stdout
    pub output: bool,
    /// Quiet mode (no output)
    pub quiet: bool,
}

/// Source of the public key
#[derive(Debug, Clone)]
pub enum PublicKeySource {
    /// Read from a file
    File(PathBuf),
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
pub fn verify(options: &VerifyOptions) -> Result<VerifyResult> {
    // Load the public key
    let pubkey = load_public_key(&options.public_key)?;

    // Load the signature
    let sig_box = load_signature(&options.signature_file)?;

    // Verify the signature on the message
    verify_message_signature(&pubkey, &sig_box, &options.message_file)?;

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
pub fn load_public_key(source: &PublicKeySource) -> Result<PubkeyStruct> {
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
