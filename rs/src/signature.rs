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
    untrusted_comment: String,
    sig_struct: SigStruct,
    trusted_comment: String,
    global_signature: Signature,
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

        // Line 3: trusted comment
        let trusted_comment = lines[2]
            .strip_prefix("trusted comment: ")
            .unwrap_or(lines[2])
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
        let mut data = Vec::new();
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
        let mut data = Vec::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_struct_size() {
        assert_eq!(SIG_STRUCT_SIZE, 74);
    }

    #[test]
    fn test_sig_struct_serialization_roundtrip_normal() {
        let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let signature = Signature::from_bytes([42; SIGNATURE_BYTES]);
        let sig = SigStruct::new(keynum, signature, false);

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), SIG_STRUCT_SIZE);

        let parsed = SigStruct::from_bytes(&bytes).expect("should parse");
        assert_eq!(parsed, sig);
        assert!(!parsed.is_prehashed());
    }

    #[test]
    fn test_sig_struct_serialization_roundtrip_prehashed() {
        let keynum = KeyNum::from_bytes([9, 8, 7, 6, 5, 4, 3, 2]);
        let signature = Signature::from_bytes([99; SIGNATURE_BYTES]);
        let sig = SigStruct::new(keynum, signature, true);

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), SIG_STRUCT_SIZE);

        let parsed = SigStruct::from_bytes(&bytes).expect("should parse");
        assert_eq!(parsed, sig);
        assert!(parsed.is_prehashed());
    }

    #[test]
    fn test_sig_struct_normal_algorithm_marker() {
        let keynum = KeyNum::from_bytes([0; KEYNUM_BYTES]);
        let signature = Signature::from_bytes([0; SIGNATURE_BYTES]);
        let sig = SigStruct::new(keynum, signature, false);

        let bytes = sig.to_bytes();
        assert_eq!(&bytes[0..2], b"Ed");
    }

    #[test]
    fn test_sig_struct_prehashed_algorithm_marker() {
        let keynum = KeyNum::from_bytes([0; KEYNUM_BYTES]);
        let signature = Signature::from_bytes([0; SIGNATURE_BYTES]);
        let sig = SigStruct::new(keynum, signature, true);

        let bytes = sig.to_bytes();
        assert_eq!(&bytes[0..2], b"ED");
    }

    #[test]
    fn test_invalid_sig_struct_too_short() {
        let bytes = [0u8; 73];
        let result = SigStruct::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_sig_struct_wrong_algorithm() {
        let mut bytes = [0u8; SIG_STRUCT_SIZE];
        bytes[0..2].copy_from_slice(b"XX");
        let result = SigStruct::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_box_file_format_roundtrip() {
        use crate::crypto::{generate_keypair, sign};

        let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
        let message = b"test message";
        let signature = sign(&secret_key, message).expect("signing should succeed");

        let sig_struct = SigStruct::new(keynum, signature, false);
        let untrusted = "This is untrusted".to_string();
        let trusted = "timestamp:1234567890".to_string();

        let sig_box = SignatureBox::with_global_signature(
            untrusted.clone(),
            sig_struct,
            trusted.clone(),
            &secret_key,
        )
        .expect("should create signature box");

        // Serialize and parse
        let contents = sig_box.to_file_contents();
        let parsed = SignatureBox::from_file_contents(&contents).expect("should parse");

        assert_eq!(parsed.untrusted_comment(), &untrusted);
        assert_eq!(parsed.sig_struct(), &sig_struct);
        assert_eq!(parsed.trusted_comment(), &trusted);

        // Verify global signature
        parsed
            .verify_global_signature(&public_key)
            .expect("global signature should verify");
    }

    #[test]
    fn test_signature_box_global_signature_verification() {
        use crate::crypto::generate_keypair;

        let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
        let signature = Signature::from_bytes([42; SIGNATURE_BYTES]);
        let sig_struct = SigStruct::new(keynum, signature, false);

        let sig_box = SignatureBox::with_global_signature(
            "untrusted".to_string(),
            sig_struct,
            "trusted".to_string(),
            &secret_key,
        )
        .expect("should create signature box");

        // Should verify with correct key
        sig_box
            .verify_global_signature(&public_key)
            .expect("should verify");

        // Should fail with wrong key
        let (_, wrong_key, _) = generate_keypair().expect("RNG should work");
        assert!(sig_box.verify_global_signature(&wrong_key).is_err());
    }

    #[test]
    fn test_signature_box_invalid_wrong_line_count() {
        let contents = "line1\nline2\nline3";
        let result = SignatureBox::from_file_contents(contents);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_box_prehashed_mode() {
        use crate::crypto::generate_keypair;

        let (secret_key, _, keynum) = generate_keypair().expect("RNG should work");
        let signature = Signature::from_bytes([99; SIGNATURE_BYTES]);
        let sig_struct = SigStruct::new(keynum, signature, true);

        let sig_box = SignatureBox::with_global_signature(
            "untrusted".to_string(),
            sig_struct,
            "trusted".to_string(),
            &secret_key,
        )
        .expect("should create signature box");

        let contents = sig_box.to_file_contents();
        let parsed = SignatureBox::from_file_contents(&contents).expect("should parse");

        assert!(parsed.sig_struct().is_prehashed());
    }

    // Property-based tests
    use proptest::prelude::*;

    proptest! {
        /// Property test: SigStruct serialization roundtrip for normal mode
        #[test]
        fn prop_sig_struct_roundtrip_normal(
            keynum_data in prop::array::uniform8(any::<u8>()),
            sig_data in prop::collection::vec(any::<u8>(), 64..=64)
        ) {
            let keynum = crate::crypto::KeyNum(keynum_data);
            let mut sig_array = [0u8; SIGNATURE_BYTES];
            sig_array.copy_from_slice(&sig_data);
            let signature = Signature::from_bytes(sig_array);
            let sig_struct = SigStruct::new(keynum, signature, false);

            let serialized = sig_struct.to_bytes();
            let deserialized = SigStruct::from_bytes(&serialized).unwrap();

            prop_assert_eq!(sig_struct.keynum().0, deserialized.keynum().0);
            prop_assert_eq!(sig_struct.signature().as_bytes(), deserialized.signature().as_bytes());
            prop_assert_eq!(sig_struct.is_prehashed(), deserialized.is_prehashed());
        }

        /// Property test: SigStruct serialization roundtrip for prehashed mode
        #[test]
        fn prop_sig_struct_roundtrip_prehashed(
            keynum_data in prop::array::uniform8(any::<u8>()),
            sig_data in prop::collection::vec(any::<u8>(), 64..=64)
        ) {
            let keynum = crate::crypto::KeyNum(keynum_data);
            let mut sig_array = [0u8; SIGNATURE_BYTES];
            sig_array.copy_from_slice(&sig_data);
            let signature = Signature::from_bytes(sig_array);
            let sig_struct = SigStruct::new(keynum, signature, true);

            let serialized = sig_struct.to_bytes();
            let deserialized = SigStruct::from_bytes(&serialized).unwrap();

            prop_assert_eq!(sig_struct.keynum().0, deserialized.keynum().0);
            prop_assert_eq!(sig_struct.signature().as_bytes(), deserialized.signature().as_bytes());
            prop_assert_eq!(sig_struct.is_prehashed(), deserialized.is_prehashed());
        }
    }

    #[test]
    fn test_untrusted_comment_with_control_characters() {
        // Create a signature box with control characters in untrusted comment
        let sig_box = SignatureBox {
            untrusted_comment: "test\x00null".to_string(), // Embedded null byte
            sig_struct: SigStruct::new(
                KeyNum([0; 8]),
                Signature::from_bytes([0; SIGNATURE_BYTES]),
                false,
            ),
            trusted_comment: "valid comment".to_string(),
            global_signature: Signature::from_bytes([0; SIGNATURE_BYTES]),
        };

        let serialized = sig_box.to_file_contents();
        let result = SignatureBox::from_file_contents(&serialized);

        // Should fail validation due to control character
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid comment"));
    }

    #[test]
    fn test_untrusted_comment_with_carriage_return() {
        // Create a signature box with carriage return in untrusted comment
        let sig_box = SignatureBox {
            untrusted_comment: "test\rcarriage".to_string(),
            sig_struct: SigStruct::new(
                KeyNum([0; 8]),
                Signature::from_bytes([0; SIGNATURE_BYTES]),
                false,
            ),
            trusted_comment: "valid comment".to_string(),
            global_signature: Signature::from_bytes([0; SIGNATURE_BYTES]),
        };

        let serialized = sig_box.to_file_contents();
        let result = SignatureBox::from_file_contents(&serialized);

        // Should fail validation due to carriage return
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        // The error message should mention either "carriage return" or just "invalid comment"
        assert!(err_msg.contains("carriage return") || err_msg.contains("invalid comment"));
    }
}
