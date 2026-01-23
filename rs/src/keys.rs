//! Key structures for minisign
//!
//! This module implements the binary formats for public and secret keys
//! as defined in the minisign specification.

use crate::crypto::{
    KeyNum, PublicKey, SecretKey, CHECKSUM_BYTES, KDF_SALT_BYTES, KEYNUM_BYTES,
    PUBLIC_KEY_BYTES, SECRET_KEY_BYTES,
};
use crate::errors::Error;
use crate::formats::{decode_base64, encode_base64, read_u64_le, write_u64_le};
use crate::Result;

/// Size of the public key structure in bytes
pub const PUBKEY_STRUCT_SIZE: usize = 2 + KEYNUM_BYTES + PUBLIC_KEY_BYTES; // 42 bytes

/// Size of the secret key structure in bytes
pub const SECKEY_STRUCT_SIZE: usize = 2 + 2 + 2 + KDF_SALT_BYTES + 8 + 8 + KEYNUM_BYTES
    + SECRET_KEY_BYTES
    + CHECKSUM_BYTES; // 158 bytes

/// Signature algorithm identifier
const SIG_ALG: &[u8; 2] = b"Ed";

/// KDF algorithm identifier for encrypted keys
const KDF_ALG_SCRYPT: &[u8; 2] = b"Sc";

/// KDF algorithm identifier for unencrypted keys
const KDF_ALG_NONE: &[u8; 2] = b"\0\0";

/// Checksum algorithm identifier
const CHK_ALG: &[u8; 2] = b"B2";

/// Public key file structure (42 bytes)
///
/// Binary layout:
/// - 0-1: sig_alg ("Ed")
/// - 2-9: keynum (8 bytes)
/// - 10-41: public_key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PubkeyStruct {
    keynum: KeyNum,
    public_key: PublicKey,
}

impl PubkeyStruct {
    /// Create a new public key structure
    #[must_use]
    pub fn new(keynum: KeyNum, public_key: PublicKey) -> Self {
        Self { keynum, public_key }
    }

    /// Get the key number
    #[must_use]
    pub fn keynum(&self) -> &KeyNum {
        &self.keynum
    }

    /// Get the public key
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBKEY_STRUCT_SIZE] {
        let mut bytes = [0u8; PUBKEY_STRUCT_SIZE];
        bytes[0..2].copy_from_slice(SIG_ALG);
        bytes[2..10].copy_from_slice(self.keynum.as_bytes());
        bytes[10..42].copy_from_slice(self.public_key.as_bytes());
        bytes
    }

    /// Parse from bytes
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPublicKey` if:
    /// - Input is not exactly 42 bytes
    /// - Signature algorithm is not "Ed"
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBKEY_STRUCT_SIZE {
            return Err(Error::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                PUBKEY_STRUCT_SIZE,
                bytes.len()
            )));
        }

        // Verify signature algorithm
        if &bytes[0..2] != SIG_ALG {
            return Err(Error::InvalidPublicKey(
                "invalid signature algorithm".to_string(),
            ));
        }

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[2..10]);
        let keynum = KeyNum::from_bytes(keynum_bytes);

        let mut pk_bytes = [0u8; PUBLIC_KEY_BYTES];
        pk_bytes.copy_from_slice(&bytes[10..42]);
        let public_key = PublicKey::from_bytes(pk_bytes);

        Ok(Self { keynum, public_key })
    }

    /// Parse from a public key file (comment + base64)
    ///
    /// # Errors
    ///
    /// Returns an error if the file format is invalid or base64 decoding fails
    pub fn from_file_contents(contents: &str) -> Result<Self> {
        let lines: Vec<&str> = contents.lines().collect();
        if lines.len() < 2 {
            return Err(Error::InvalidPublicKey(
                "missing comment or data line".to_string(),
            ));
        }

        // First line is the untrusted comment (ignored for parsing)
        // Second line is base64-encoded PubkeyStruct
        let data = decode_base64(lines[1])?;
        Self::from_bytes(&data)
    }

    /// Serialize to file format (comment + base64)
    #[must_use]
    pub fn to_file_contents(&self, comment: &str) -> String {
        let bytes = self.to_bytes();
        let base64 = encode_base64(&bytes);
        format!("untrusted comment: {comment}\n{base64}\n")
    }
}

impl std::fmt::Debug for PubkeyStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PubkeyStruct")
            .field("keynum", &self.keynum)
            .field("public_key", &"[...]")
            .finish()
    }
}

/// Secret key file structure (158 bytes)
///
/// Binary layout:
/// - 0-1: sig_alg ("Ed")
/// - 2-3: kdf_alg ("Sc" or "\0\0")
/// - 4-5: chk_alg ("B2")
/// - 6-37: kdf_salt (32 bytes)
/// - 38-45: kdf_opslimit (u64 LE)
/// - 46-53: kdf_memlimit (u64 LE)
/// - 54-61: keynum (8 bytes)
/// - 62-125: secret_key (64 bytes, encrypted if kdf_alg != "\0\0")
/// - 126-157: checksum (32 bytes, Blake2b-256 of keynum + secret_key)
#[derive(Clone)]
pub struct SeckeyStruct {
    encrypted: bool,
    kdf_salt: [u8; KDF_SALT_BYTES],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum: KeyNum,
    secret_key_encrypted: [u8; SECRET_KEY_BYTES],
    checksum: [u8; CHECKSUM_BYTES],
}

impl SeckeyStruct {
    /// Create a new secret key structure (unencrypted)
    ///
    /// The checksum will be computed automatically.
    #[must_use]
    pub fn new_unencrypted(keynum: KeyNum, secret_key: &SecretKey) -> Self {
        let checksum = Self::compute_checksum(&keynum, secret_key.as_bytes());
        let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
        secret_key_encrypted.copy_from_slice(secret_key.as_bytes());

        Self {
            encrypted: false,
            kdf_salt: [0u8; KDF_SALT_BYTES],
            kdf_opslimit: 0,
            kdf_memlimit: 0,
            keynum,
            secret_key_encrypted,
            checksum,
        }
    }

    /// Compute the checksum (Blake2b-256 of keynum + secret_key)
    fn compute_checksum(keynum: &KeyNum, secret_key: &[u8; SECRET_KEY_BYTES]) -> [u8; CHECKSUM_BYTES] {
        use crate::crypto::blake2b_256;

        let mut data = Vec::with_capacity(KEYNUM_BYTES + SECRET_KEY_BYTES);
        data.extend_from_slice(keynum.as_bytes());
        data.extend_from_slice(secret_key);

        blake2b_256(&data)
    }

    /// Get the key number
    #[must_use]
    pub fn keynum(&self) -> &KeyNum {
        &self.keynum
    }

    /// Check if the key is encrypted
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Get the encrypted secret key bytes
    #[must_use]
    pub fn encrypted_secret_key(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.secret_key_encrypted
    }

    /// Get the KDF salt (only meaningful if encrypted)
    #[must_use]
    pub fn kdf_salt(&self) -> &[u8; KDF_SALT_BYTES] {
        &self.kdf_salt
    }

    /// Get the KDF operations limit (only meaningful if encrypted)
    #[must_use]
    pub fn kdf_opslimit(&self) -> u64 {
        self.kdf_opslimit
    }

    /// Get the KDF memory limit (only meaningful if encrypted)
    #[must_use]
    pub fn kdf_memlimit(&self) -> u64 {
        self.kdf_memlimit
    }

    /// Serialize to bytes
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SECKEY_STRUCT_SIZE] {
        let mut bytes = [0u8; SECKEY_STRUCT_SIZE];

        bytes[0..2].copy_from_slice(SIG_ALG);

        if self.encrypted {
            bytes[2..4].copy_from_slice(KDF_ALG_SCRYPT);
        } else {
            bytes[2..4].copy_from_slice(KDF_ALG_NONE);
        }

        bytes[4..6].copy_from_slice(CHK_ALG);
        bytes[6..38].copy_from_slice(&self.kdf_salt);
        write_u64_le(&mut bytes[38..46], self.kdf_opslimit);
        write_u64_le(&mut bytes[46..54], self.kdf_memlimit);
        bytes[54..62].copy_from_slice(self.keynum.as_bytes());
        bytes[62..126].copy_from_slice(&self.secret_key_encrypted);
        bytes[126..158].copy_from_slice(&self.checksum);

        bytes
    }

    /// Parse from bytes
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidSecretKey` if:
    /// - Input is not exactly 158 bytes
    /// - Signature algorithm is not "Ed"
    /// - KDF algorithm is not "Sc" or "\0\0"
    /// - Checksum algorithm is not "B2"
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECKEY_STRUCT_SIZE {
            return Err(Error::InvalidSecretKey(format!(
                "expected {} bytes, got {}",
                SECKEY_STRUCT_SIZE,
                bytes.len()
            )));
        }

        // Verify signature algorithm
        if &bytes[0..2] != SIG_ALG {
            return Err(Error::InvalidSecretKey(
                "invalid signature algorithm".to_string(),
            ));
        }

        // Check KDF algorithm
        let encrypted = if &bytes[2..4] == KDF_ALG_SCRYPT {
            true
        } else if &bytes[2..4] == KDF_ALG_NONE {
            false
        } else {
            return Err(Error::InvalidSecretKey(
                "invalid KDF algorithm".to_string(),
            ));
        };

        // Verify checksum algorithm
        if &bytes[4..6] != CHK_ALG {
            return Err(Error::InvalidSecretKey(
                "invalid checksum algorithm".to_string(),
            ));
        }

        let mut kdf_salt = [0u8; KDF_SALT_BYTES];
        kdf_salt.copy_from_slice(&bytes[6..38]);

        let kdf_opslimit = read_u64_le(&bytes[38..46]);
        let kdf_memlimit = read_u64_le(&bytes[46..54]);

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[54..62]);
        let keynum = KeyNum::from_bytes(keynum_bytes);

        let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
        secret_key_encrypted.copy_from_slice(&bytes[62..126]);

        let mut checksum = [0u8; CHECKSUM_BYTES];
        checksum.copy_from_slice(&bytes[126..158]);

        Ok(Self {
            encrypted,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            keynum,
            secret_key_encrypted,
            checksum,
        })
    }

    /// Parse from a secret key file (comment + base64)
    ///
    /// # Errors
    ///
    /// Returns an error if the file format is invalid or base64 decoding fails
    pub fn from_file_contents(contents: &str) -> Result<Self> {
        let lines: Vec<&str> = contents.lines().collect();
        if lines.len() < 2 {
            return Err(Error::InvalidSecretKey(
                "missing comment or data line".to_string(),
            ));
        }

        // First line is the untrusted comment (ignored for parsing)
        // Second line is base64-encoded SeckeyStruct
        let data = decode_base64(lines[1])?;
        Self::from_bytes(&data)
    }

    /// Serialize to file format (comment + base64)
    #[must_use]
    pub fn to_file_contents(&self, comment: &str) -> String {
        let bytes = self.to_bytes();
        let base64 = encode_base64(&bytes);
        format!("untrusted comment: {comment}\n{base64}\n")
    }
}

impl std::fmt::Debug for SeckeyStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeckeyStruct")
            .field("encrypted", &self.encrypted)
            .field("keynum", &self.keynum)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_pubkey_struct_size() {
        assert_eq!(PUBKEY_STRUCT_SIZE, 42);
    }

    #[test]
    fn test_seckey_struct_size() {
        assert_eq!(SECKEY_STRUCT_SIZE, 158);
    }

    #[test]
    fn test_parse_c_generated_public_key() {
        // Load the C-generated public key fixture
        let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
            .expect("Failed to read test.pub fixture");

        // Parse the public key
        let pubkey = PubkeyStruct::from_file_contents(&contents)
            .expect("Failed to parse public key");

        // Verify structure - the actual values depend on the generated key,
        // but we can check that parsing succeeds and produces valid data
        assert_eq!(pubkey.keynum().as_bytes().len(), KEYNUM_BYTES);
        assert_eq!(pubkey.public_key().as_bytes().len(), PUBLIC_KEY_BYTES);
    }

    #[test]
    fn test_parse_c_generated_encrypted_secret_key() {
        // Load the C-generated encrypted secret key fixture
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        // Parse the secret key structure
        let seckey = SeckeyStruct::from_file_contents(&contents)
            .expect("Failed to parse secret key");

        // Verify it's encrypted
        assert!(seckey.is_encrypted(), "Expected key to be encrypted");

        // Verify structure
        assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
        assert!(seckey.kdf_opslimit() > 0, "Expected non-zero opslimit");
        assert!(seckey.kdf_memlimit() > 0, "Expected non-zero memlimit");
    }

    #[test]
    fn test_parse_c_generated_unencrypted_secret_key() {
        // Load the C-generated unencrypted secret key fixture
        let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
            .expect("Failed to read unencrypted.key fixture");

        // Parse the secret key structure
        let seckey = SeckeyStruct::from_file_contents(&contents)
            .expect("Failed to parse unencrypted secret key");

        // Verify it's NOT encrypted
        assert!(!seckey.is_encrypted(), "Expected key to be unencrypted");

        // Verify structure
        assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
        assert_eq!(seckey.kdf_opslimit(), 0, "Expected zero opslimit for unencrypted key");
        assert_eq!(seckey.kdf_memlimit(), 0, "Expected zero memlimit for unencrypted key");
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        // Load and parse C-generated public key
        let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
            .expect("Failed to read test.pub fixture");

        let original = PubkeyStruct::from_file_contents(&contents)
            .expect("Failed to parse public key");

        // Serialize to bytes and parse back
        let bytes = original.to_bytes();
        let roundtrip = PubkeyStruct::from_bytes(&bytes)
            .expect("Failed to parse roundtripped bytes");

        // Verify they're identical
        assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
        assert_eq!(original.public_key().as_bytes(), roundtrip.public_key().as_bytes());
    }

    #[test]
    fn test_secret_key_serialization_roundtrip() {
        // Load and parse C-generated secret key
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        let original = SeckeyStruct::from_file_contents(&contents)
            .expect("Failed to parse secret key");

        // Serialize to bytes and parse back
        let bytes = original.to_bytes();
        let roundtrip = SeckeyStruct::from_bytes(&bytes)
            .expect("Failed to parse roundtripped bytes");

        // Verify they're identical
        assert_eq!(original.is_encrypted(), roundtrip.is_encrypted());
        assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
        assert_eq!(original.kdf_opslimit(), roundtrip.kdf_opslimit());
        assert_eq!(original.kdf_memlimit(), roundtrip.kdf_memlimit());
        assert_eq!(original.encrypted_secret_key(), roundtrip.encrypted_secret_key());
    }

    #[test]
    fn test_public_key_file_format_roundtrip() {
        // Create a test public key
        let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let pk_bytes = [42u8; PUBLIC_KEY_BYTES];
        let public_key = PublicKey::from_bytes(pk_bytes);
        let pubkey = PubkeyStruct::new(keynum, public_key);

        // Serialize to file format
        let file_contents = pubkey.to_file_contents("test comment");

        // Verify format
        assert!(file_contents.starts_with("untrusted comment: test comment\n"));
        assert!(file_contents.ends_with('\n'));

        // Parse back
        let parsed = PubkeyStruct::from_file_contents(&file_contents)
            .expect("Failed to parse file contents");

        assert_eq!(pubkey.keynum().as_bytes(), parsed.keynum().as_bytes());
        assert_eq!(pubkey.public_key().as_bytes(), parsed.public_key().as_bytes());
    }

    #[test]
    fn test_invalid_public_key_too_short() {
        let short_data = [0u8; 10];
        let result = PubkeyStruct::from_bytes(&short_data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn test_invalid_public_key_wrong_algorithm() {
        let mut data = [0u8; PUBKEY_STRUCT_SIZE];
        data[0..2].copy_from_slice(b"XX"); // Wrong algorithm
        let result = PubkeyStruct::from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn test_invalid_secret_key_too_short() {
        let short_data = [0u8; 10];
        let result = SeckeyStruct::from_bytes(&short_data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
    }

    #[test]
    fn test_invalid_secret_key_wrong_sig_algorithm() {
        let mut data = [0u8; SECKEY_STRUCT_SIZE];
        data[0..2].copy_from_slice(b"XX"); // Wrong sig algorithm
        data[2..4].copy_from_slice(b"\0\0"); // Valid KDF
        data[4..6].copy_from_slice(b"B2"); // Valid checksum
        let result = SeckeyStruct::from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
    }

    #[test]
    fn test_invalid_secret_key_wrong_kdf_algorithm() {
        let mut data = [0u8; SECKEY_STRUCT_SIZE];
        data[0..2].copy_from_slice(b"Ed"); // Valid sig algorithm
        data[2..4].copy_from_slice(b"XX"); // Wrong KDF
        data[4..6].copy_from_slice(b"B2"); // Valid checksum
        let result = SeckeyStruct::from_bytes(&data);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
    }
}
