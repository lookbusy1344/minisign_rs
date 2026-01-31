//! Signature structures for minisign
//!
//! This module implements the binary formats for signatures
//! as defined in the minisign specification.

use crate::Result;
use crate::crypto::{
    KEYNUM_BYTES, KeyNum, PublicKey, SIGNATURE_BYTES, SecretKey, Signature, sign, verify,
};
use crate::errors::Error;
use crate::formats::{decode_base64, encode_base64};
use crate::validation::validate_comment;

/// Size of the signature structure in bytes
pub const SIG_STRUCT_SIZE: usize = 2 + KEYNUM_BYTES + SIGNATURE_BYTES; // 74 bytes

/// Maximum length for untrusted comments (matches C implementation)
pub const COMMENTMAXBYTES: usize = 1024;

/// Maximum length for trusted comments (matches C implementation)
pub const TRUSTEDCOMMENTMAXBYTES: usize = 8192;

/// Size of "untrusted comment: " prefix in C (includes null terminator)
pub const COMMENT_PREFIX_SIZE: usize = 20;

/// Size of "trusted comment: " prefix in C (includes null terminator)
pub const TRUSTED_COMMENT_PREFIX_SIZE: usize = 18;

/// Signature algorithm identifier for normal mode
const SIG_ALG_NORMAL: &[u8; 2] = b"Ed";

/// Signature algorithm identifier for prehashed mode
const SIG_ALG_PREHASHED: &[u8; 2] = b"ED";

// Signature structure byte offsets
const SIG_ALG_OFFSET: usize = 0;
const SIG_ALG_SIZE: usize = 2;
const SIG_KEYNUM_OFFSET: usize = 2;
const SIG_KEYNUM_SIZE: usize = KEYNUM_BYTES;
const SIG_SIGNATURE_OFFSET: usize = 10;
const SIG_SIGNATURE_SIZE: usize = SIGNATURE_BYTES;

/// Signature file structure (74 bytes)
///
/// Binary layout:
/// - 0-1: `sig_alg` ("Ed" for normal, "ED" for prehashed)
/// - 2-9: keynum (8 bytes)
/// - 10-73: `signature` (64 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SigStruct {
    prehashed: bool,
    keynum: KeyNum,
    signature: Signature,
}

impl SigStruct {
    /// Create a new signature structure
    ///
    /// # Arguments
    ///
    /// * `keynum` - The 8-byte key number identifier (must match the signing key)
    /// * `signature` - The 64-byte Ed25519 signature
    /// * `prehashed` - Whether this signature is for a prehashed message (Blake2b-512)
    ///
    /// # Returns
    ///
    /// A `SigStruct` containing the signature metadata and signature bytes
    ///
    /// # Prehashed Mode
    ///
    /// When `prehashed=true`, the signature is computed over the Blake2b-512 hash of the
    /// file content rather than the raw content. This is useful for large files to avoid
    /// loading them entirely into memory, though it reduces security slightly as the
    /// signature doesn't directly authenticate the file content.
    ///
    /// # Examples
    ///
    /// ```
    /// use minisign::signature::SigStruct;
    /// use minisign::crypto::{sign, generate_keypair};
    ///
    /// let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    /// let message = b"Hello, world!";
    /// let signature = sign(&secret_key, message).unwrap();
    /// let sig_struct = SigStruct::new(keynum, signature, false);
    /// ```
    #[must_use]
    pub fn new(keynum: KeyNum, signature: Signature, prehashed: bool) -> Self {
        Self {
            prehashed,
            keynum,
            signature,
        }
    }

    /// Get whether this is a prehashed signature
    #[must_use]
    pub fn is_prehashed(&self) -> bool {
        self.prehashed
    }

    /// Get the key number
    #[must_use]
    pub fn keynum(&self) -> &KeyNum {
        &self.keynum
    }

    /// Get the signature
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIG_STRUCT_SIZE] {
        let mut bytes = [0u8; SIG_STRUCT_SIZE];
        let sig_alg_end = SIG_ALG_OFFSET + SIG_ALG_SIZE;
        let keynum_end = SIG_KEYNUM_OFFSET + SIG_KEYNUM_SIZE;
        let signature_end = SIG_SIGNATURE_OFFSET + SIG_SIGNATURE_SIZE;

        let sig_alg = if self.prehashed {
            SIG_ALG_PREHASHED
        } else {
            SIG_ALG_NORMAL
        };

        bytes[SIG_ALG_OFFSET..sig_alg_end].copy_from_slice(sig_alg);
        bytes[SIG_KEYNUM_OFFSET..keynum_end].copy_from_slice(self.keynum.as_bytes());
        bytes[SIG_SIGNATURE_OFFSET..signature_end].copy_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Parse from bytes
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidSignatureFormat` if:
    /// - Input is not exactly 74 bytes
    /// - Signature algorithm is not "Ed" or "ED"
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIG_STRUCT_SIZE {
            return Err(Error::InvalidSignatureFormat(format!(
                "expected {} bytes, got {}",
                SIG_STRUCT_SIZE,
                bytes.len()
            )));
        }

        let sig_alg_end = SIG_ALG_OFFSET + SIG_ALG_SIZE;
        let keynum_end = SIG_KEYNUM_OFFSET + SIG_KEYNUM_SIZE;
        let signature_end = SIG_SIGNATURE_OFFSET + SIG_SIGNATURE_SIZE;

        // Verify signature algorithm
        let sig_alg = &bytes[SIG_ALG_OFFSET..sig_alg_end];
        let prehashed = if sig_alg == SIG_ALG_NORMAL {
            false
        } else if sig_alg == SIG_ALG_PREHASHED {
            true
        } else {
            return Err(Error::InvalidSignatureFormat(format!(
                "invalid signature algorithm: expected 'Ed' or 'ED', got '{}'",
                String::from_utf8_lossy(sig_alg)
            )));
        };

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[SIG_KEYNUM_OFFSET..keynum_end]);
        let keynum = KeyNum::from_bytes(keynum_bytes);

        let mut signature_bytes = [0u8; SIGNATURE_BYTES];
        signature_bytes.copy_from_slice(&bytes[SIG_SIGNATURE_OFFSET..signature_end]);
        let signature = Signature::from_bytes(signature_bytes);

        Ok(Self {
            prehashed,
            keynum,
            signature,
        })
    }
}

impl std::fmt::Debug for SigStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigStruct")
            .field("prehashed", &self.prehashed)
            .field("keynum", &self.keynum)
            .field("signature", &"[...]")
            .finish()
    }
}

/// Complete signature file structure
///
/// File format:
/// ```text
/// untrusted comment: <freely modifiable>
/// <base64-encoded SigStruct>
/// trusted comment: <cryptographically bound comment>
/// <base64-encoded global signature>
/// ```
///
/// The global signature signs: `SigStruct.signature || trusted_comment_text`
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureBox {
    pub untrusted_comment: String,   // pub for unit tests
    pub sig_struct: SigStruct,       // pub for unit tests
    pub trusted_comment: String,     // pub for unit tests
    pub global_signature: Signature, // pub for unit tests
}

impl SignatureBox {
    /// Create a new signature box
    #[must_use]
    pub fn new(
        untrusted_comment: String,
        sig_struct: SigStruct,
        trusted_comment: String,
        global_signature: Signature,
    ) -> Self {
        Self {
            untrusted_comment,
            sig_struct,
            trusted_comment,
            global_signature,
        }
    }

    /// Get the untrusted comment
    #[must_use]
    pub fn untrusted_comment(&self) -> &str {
        &self.untrusted_comment
    }

    /// Get the signature structure
    #[must_use]
    pub fn sig_struct(&self) -> &SigStruct {
        &self.sig_struct
    }

    /// Get the trusted comment
    #[must_use]
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }

    /// Get the global signature
    #[must_use]
    pub fn global_signature(&self) -> &Signature {
        &self.global_signature
    }

    /// Parse from signature file contents
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File doesn't have exactly 4 lines
    /// - Base64 decoding fails
    /// - `SigStruct` parsing fails
    pub fn from_file_contents(contents: &str) -> Result<Self> {
        let lines: Vec<&str> = contents.lines().collect();
        if lines.len() != 4 {
            return Err(Error::InvalidSignatureFormat(format!(
                "expected 4 lines, got {}",
                lines.len()
            )));
        }

        // Line 1: untrusted comment
        let untrusted_comment = lines[0]
            .strip_prefix("untrusted comment: ")
            .unwrap_or(lines[0])
            .to_string();

        // Validate untrusted comment for printability and embedded carriage returns
        // This prevents display-based attacks via control characters
        validate_comment(&untrusted_comment)?;

        // Line 2: base64-encoded SigStruct
        let sig_struct_bytes = decode_base64(lines[1])?;
        let sig_struct = SigStruct::from_bytes(&sig_struct_bytes)?;

        // Line 3: trusted comment (must have prefix for C compatibility)
        let trusted_comment = lines[2]
            .strip_prefix("trusted comment: ")
            .ok_or_else(|| {
                Error::InvalidSignatureFormat(
                    "trusted comment must start with \"trusted comment: \"".to_string(),
                )
            })?
            .to_string();

        // Validate trusted comment for printability and embedded carriage returns
        // This matches C implementation's is_printable() check
        validate_comment(&trusted_comment)?;

        // Line 4: base64-encoded global signature
        let global_sig_bytes = decode_base64(lines[3])?;
        if global_sig_bytes.len() != SIGNATURE_BYTES {
            return Err(Error::InvalidSignatureFormat(format!(
                "global signature must be {} bytes, got {}",
                SIGNATURE_BYTES,
                global_sig_bytes.len()
            )));
        }

        let mut sig_bytes = [0u8; SIGNATURE_BYTES];
        sig_bytes.copy_from_slice(&global_sig_bytes);
        let global_signature = Signature::from_bytes(sig_bytes);

        Ok(Self {
            untrusted_comment,
            sig_struct,
            trusted_comment,
            global_signature,
        })
    }

    /// Serialize to signature file format
    #[must_use]
    pub fn to_file_contents(&self) -> String {
        let sig_struct_base64 = encode_base64(self.sig_struct.to_bytes());
        let global_sig_base64 = encode_base64(*self.global_signature.as_bytes());

        format!(
            "untrusted comment: {}\n{}\ntrusted comment: {}\n{}\n",
            self.untrusted_comment, sig_struct_base64, self.trusted_comment, global_sig_base64
        )
    }

    /// Verify the global signature
    ///
    /// The global signature signs: `SigStruct.signature || trusted_comment_text`
    ///
    /// # Errors
    ///
    /// Returns `Error::VerificationFailed` if the global signature is invalid
    pub fn verify_global_signature(&self, public_key: &PublicKey) -> Result<()> {
        // Build the data that was signed: signature bytes + trusted comment
        let capacity = self.sig_struct.signature().as_bytes().len() + self.trusted_comment.len();
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(self.sig_struct.signature().as_bytes());
        data.extend_from_slice(self.trusted_comment.as_bytes());

        verify(public_key, &data, &self.global_signature)
    }

    /// Create a signature box with a new global signature
    ///
    /// Signs: `SigStruct.signature || trusted_comment_text`
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails
    pub fn with_global_signature(
        untrusted_comment: String,
        sig_struct: SigStruct,
        trusted_comment: String,
        secret_key: &SecretKey,
    ) -> Result<Self> {
        // Build the data to sign: signature bytes + trusted comment
        let capacity = sig_struct.signature().as_bytes().len() + trusted_comment.len();
        let mut data = Vec::with_capacity(capacity);
        data.extend_from_slice(sig_struct.signature().as_bytes());
        data.extend_from_slice(trusted_comment.as_bytes());

        let global_signature = sign(secret_key, &data)?;

        Ok(Self {
            untrusted_comment,
            sig_struct,
            trusted_comment,
            global_signature,
        })
    }
}

impl std::fmt::Debug for SignatureBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureBox")
            .field("untrusted_comment", &self.untrusted_comment)
            .field("sig_struct", &self.sig_struct)
            .field("trusted_comment", &self.trusted_comment)
            .field("global_signature", &"[...]")
            .finish()
    }
}
