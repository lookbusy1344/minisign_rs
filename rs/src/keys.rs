//! Key structures for minisign
//!
//! This module implements the binary formats for public and secret keys
//! as defined in the minisign specification.

use crate::Result;
use crate::crypto::{
    CHECKSUM_BYTES, KDF_SALT_BYTES, KEYNUM_BYTES, KeyNum, PUBLIC_KEY_BYTES, PublicKey,
    SECRET_KEY_BYTES, SecretKey, blake2b_256, derive_key_with_params,
};
use crate::errors::Error;
use crate::formats::{decode_base64, encode_base64, read_u64_le, write_u64_le};

/// Size of the public key structure in bytes
pub const PUBKEY_STRUCT_SIZE: usize = 2 + KEYNUM_BYTES + PUBLIC_KEY_BYTES; // 42 bytes

/// Size of the secret key structure in bytes
pub const SECKEY_STRUCT_SIZE: usize =
    2 + 2 + 2 + KDF_SALT_BYTES + 8 + 8 + KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES; // 158 bytes

/// Size of encrypted blob (keynum + secret key + checksum)
/// Matches C minisign: sizeof(seckey_struct->keynum_sk) = 8 + 64 + 32 = 104 bytes
const ENCRYPTED_BLOB_SIZE: usize = KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES; // 104 bytes

/// Signature algorithm identifier
const SIG_ALG: &[u8; 2] = b"Ed";

/// KDF algorithm identifier for encrypted keys
const KDF_ALG_SCRYPT: &[u8; 2] = b"Sc";

/// KDF algorithm identifier for unencrypted keys
const KDF_ALG_NONE: &[u8; 2] = b"\0\0";

/// Checksum algorithm identifier
const CHK_ALG: &[u8; 2] = b"B2";

// Public key structure byte offsets
const PUBKEY_SIG_ALG_OFFSET: usize = 0;
const PUBKEY_SIG_ALG_SIZE: usize = 2;
const PUBKEY_KEYNUM_OFFSET: usize = 2;
const PUBKEY_KEYNUM_SIZE: usize = KEYNUM_BYTES;
const PUBKEY_PK_OFFSET: usize = 10;
const PUBKEY_PK_SIZE: usize = PUBLIC_KEY_BYTES;

// Secret key structure byte offsets
const SECKEY_SIG_ALG_OFFSET: usize = 0;
const SECKEY_SIG_ALG_SIZE: usize = 2;
const SECKEY_KDF_ALG_OFFSET: usize = 2;
const SECKEY_KDF_ALG_SIZE: usize = 2;
const SECKEY_CHK_ALG_OFFSET: usize = 4;
const SECKEY_CHK_ALG_SIZE: usize = 2;
const SECKEY_KDF_SALT_OFFSET: usize = 6;
const SECKEY_KDF_SALT_SIZE: usize = KDF_SALT_BYTES;
const SECKEY_KDF_OPSLIMIT_OFFSET: usize = 38;
const SECKEY_KDF_OPSLIMIT_SIZE: usize = 8;
const SECKEY_KDF_MEMLIMIT_OFFSET: usize = 46;
const SECKEY_KDF_MEMLIMIT_SIZE: usize = 8;
const SECKEY_KEYNUM_OFFSET: usize = 54;
const SECKEY_KEYNUM_SIZE: usize = KEYNUM_BYTES;
const SECKEY_SK_OFFSET: usize = 62;
const SECKEY_SK_SIZE: usize = SECRET_KEY_BYTES;
const SECKEY_CHECKSUM_OFFSET: usize = 126;
const SECKEY_CHECKSUM_SIZE: usize = CHECKSUM_BYTES;

// Libsodium KDF formula constants
// opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * N * r
// memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * N * r
const LIBSODIUM_OPSLIMIT_MULTIPLIER: u64 = 4;
const LIBSODIUM_MEMLIMIT_MULTIPLIER: u64 = 128;

// Standard scrypt parameters used by minisign
const SCRYPT_R_STANDARD: u32 = 8;
const SCRYPT_P_STANDARD: u32 = 1;

/// Public key file structure (42 bytes)
///
/// Binary layout:
/// - 0-1: `sig_alg` ("Ed")
/// - 2-9: keynum (8 bytes)
/// - 10-41: `public_key` (32 bytes)
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
        let sig_end = PUBKEY_SIG_ALG_OFFSET + PUBKEY_SIG_ALG_SIZE;
        let keynum_end = PUBKEY_KEYNUM_OFFSET + PUBKEY_KEYNUM_SIZE;
        let pk_end = PUBKEY_PK_OFFSET + PUBKEY_PK_SIZE;

        bytes[PUBKEY_SIG_ALG_OFFSET..sig_end].copy_from_slice(SIG_ALG);
        bytes[PUBKEY_KEYNUM_OFFSET..keynum_end].copy_from_slice(self.keynum.as_bytes());
        bytes[PUBKEY_PK_OFFSET..pk_end].copy_from_slice(self.public_key.as_bytes());
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

        let sig_end = PUBKEY_SIG_ALG_OFFSET + PUBKEY_SIG_ALG_SIZE;
        let keynum_end = PUBKEY_KEYNUM_OFFSET + PUBKEY_KEYNUM_SIZE;
        let pk_end = PUBKEY_PK_OFFSET + PUBKEY_PK_SIZE;

        // Verify signature algorithm
        if &bytes[PUBKEY_SIG_ALG_OFFSET..sig_end] != SIG_ALG {
            return Err(Error::InvalidPublicKey(
                "invalid signature algorithm".to_string(),
            ));
        }

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[PUBKEY_KEYNUM_OFFSET..keynum_end]);
        let keynum = KeyNum::from_bytes(keynum_bytes);

        let mut pk_bytes = [0u8; PUBLIC_KEY_BYTES];
        pk_bytes.copy_from_slice(&bytes[PUBKEY_PK_OFFSET..pk_end]);
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

    /// Parse from base64-encoded string (without comment)
    ///
    /// # Errors
    ///
    /// Returns an error if base64 decoding fails or the data is invalid
    pub fn from_base64(base64_str: &str) -> Result<Self> {
        let data = decode_base64(base64_str)?;
        Self::from_bytes(&data)
    }

    /// Serialize to file format (comment + base64)
    #[must_use]
    pub fn to_file_contents(&self, comment: &str) -> String {
        let bytes = self.to_bytes();
        let base64 = encode_base64(bytes);
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
/// - 0-1: `sig_alg` ("Ed")
/// - 2-3: `kdf_alg` ("Sc" or "\0\0")
/// - 4-5: `chk_alg` ("B2")
/// - 6-37: `kdf_salt` (32 bytes)
/// - 38-45: `kdf_opslimit` (u64 LE)
/// - 46-53: `kdf_memlimit` (u64 LE)
/// - 54-61: keynum (8 bytes, encrypted if `kdf_alg` != "\0\0")
/// - 62-125: `secret_key` (64 bytes, encrypted if `kdf_alg` != "\0\0")
/// - 126-157: checksum (32 bytes, Blake2b-256 of `sig_alg` + `keynum` + `secret_key`, encrypted if `kdf_alg` != "\0\0")
///
/// For encrypted keys, `keynum`/`secret_key`/checksum fields store the encrypted versions.
/// The plaintext keynum is recovered during decryption.
#[derive(Clone)]
pub struct SeckeyStruct {
    encrypted: bool,
    kdf_salt: [u8; KDF_SALT_BYTES],
    kdf_opslimit: u64,
    kdf_memlimit: u64,
    keynum: KeyNum,
    encrypted_keynum: [u8; KEYNUM_BYTES],
    secret_key_encrypted: [u8; SECRET_KEY_BYTES],
    checksum: [u8; CHECKSUM_BYTES],
}

impl SeckeyStruct {
    /// Create a new secret key structure (unencrypted)
    ///
    /// For unencrypted keys, the checksum is set to all zeros (matching C behavior).
    #[must_use]
    pub fn new_unencrypted(keynum: KeyNum, secret_key: &SecretKey) -> Self {
        let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
        secret_key_encrypted.copy_from_slice(secret_key.as_bytes());

        Self {
            encrypted: false,
            kdf_salt: [0u8; KDF_SALT_BYTES],
            kdf_opslimit: 0,
            kdf_memlimit: 0,
            keynum,
            encrypted_keynum: [0u8; KEYNUM_BYTES], // Not used for unencrypted keys
            secret_key_encrypted,
            checksum: [0u8; CHECKSUM_BYTES], // All zeros for unencrypted keys
        }
    }

    /// Create a new encrypted secret key structure
    ///
    /// The `keynum`, secret key, and checksum are encrypted together using XOR with a key derived from the password.
    /// This matches the C minisign behavior which encrypts the combined 104-byte blob (`keynum` + `secret_key` + checksum).
    ///
    /// # Arguments
    ///
    /// * `keynum` - The key number identifier
    /// * `secret_key` - The secret key to encrypt
    /// * `password` - The password for encryption
    /// * `kdf_salt` - The salt for key derivation
    /// * `kdf_opslimit` - Operations limit (N * r * `OPSLIMIT_MULTIPLIER`)
    /// * `kdf_memlimit` - Memory limit (N * r * `MEMLIMIT_MULTIPLIER`)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails
    pub fn new_encrypted(
        keynum: KeyNum,
        secret_key: &SecretKey,
        password: &[u8],
        kdf_salt: [u8; KDF_SALT_BYTES],
        kdf_opslimit: u64,
        kdf_memlimit: u64,
    ) -> Result<Self> {
        // Convert opslimit/memlimit to scrypt parameters
        let (log_n, r, p) = Self::opslimit_memlimit_to_params(kdf_opslimit, kdf_memlimit);

        // Compute checksum of unencrypted keynum + secret_key (before encryption)
        let computed_checksum = Self::compute_checksum(keynum, secret_key.as_bytes());

        // Derive 104 bytes (keynum + secret_key + checksum) to match C implementation
        let derived_key =
            derive_key_with_params(password, &kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)?;

        // Create combined blob: keynum + secret_key + checksum
        let mut blob = Vec::with_capacity(ENCRYPTED_BLOB_SIZE);
        blob.extend_from_slice(keynum.as_bytes());
        blob.extend_from_slice(secret_key.as_bytes());
        blob.extend_from_slice(&computed_checksum);

        // Encrypt entire blob with XOR
        let mut encrypted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
        for i in 0..ENCRYPTED_BLOB_SIZE {
            encrypted_blob[i] = blob[i] ^ derived_key[i];
        }

        // Split back into encrypted components
        let mut encrypted_keynum = [0u8; KEYNUM_BYTES];
        encrypted_keynum.copy_from_slice(&encrypted_blob[0..KEYNUM_BYTES]);

        let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
        secret_key_encrypted
            .copy_from_slice(&encrypted_blob[KEYNUM_BYTES..(KEYNUM_BYTES + SECRET_KEY_BYTES)]);

        let mut checksum = [0u8; CHECKSUM_BYTES];
        checksum.copy_from_slice(&encrypted_blob[(KEYNUM_BYTES + SECRET_KEY_BYTES)..]);

        Ok(Self {
            encrypted: true,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            keynum,
            encrypted_keynum,
            secret_key_encrypted,
            checksum, // This is the encrypted checksum
        })
    }

    /// Decrypt the secret key using a password
    ///
    /// Decrypts the combined 104-byte blob (`keynum` + `secret_key` + checksum) to match C minisign behavior.
    ///
    /// Returns a tuple of (`secret_key`, `keynum`) where `keynum` is the decrypted key number.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key is not encrypted
    /// - Key derivation fails
    /// - Checksum validation fails (wrong password or corrupted data)
    pub fn decrypt(&self, password: &[u8]) -> Result<(SecretKey, KeyNum)> {
        if !self.encrypted {
            return Err(Error::Other("key is not encrypted".to_string()));
        }

        // Convert opslimit/memlimit to scrypt parameters
        let (log_n, r, p) = Self::opslimit_memlimit_to_params(self.kdf_opslimit, self.kdf_memlimit);

        // Derive 104 bytes (keynum + secret_key + checksum) to match C implementation
        let derived_key =
            derive_key_with_params(password, &self.kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)?;

        // Reconstruct encrypted blob: keynum + secret_key + checksum
        let mut encrypted_blob = Vec::with_capacity(ENCRYPTED_BLOB_SIZE);
        encrypted_blob.extend_from_slice(&self.encrypted_keynum);
        encrypted_blob.extend_from_slice(&self.secret_key_encrypted);
        encrypted_blob.extend_from_slice(&self.checksum); // checksum field contains encrypted checksum

        // Decrypt entire blob
        let mut decrypted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
        for i in 0..ENCRYPTED_BLOB_SIZE {
            decrypted_blob[i] = encrypted_blob[i] ^ derived_key[i];
        }

        // Extract decrypted components
        let mut decrypted_keynum_bytes = [0u8; KEYNUM_BYTES];
        decrypted_keynum_bytes.copy_from_slice(&decrypted_blob[0..KEYNUM_BYTES]);
        let decrypted_keynum = KeyNum::from_bytes(decrypted_keynum_bytes);

        let mut secret_key_bytes = [0u8; SECRET_KEY_BYTES];
        secret_key_bytes
            .copy_from_slice(&decrypted_blob[KEYNUM_BYTES..(KEYNUM_BYTES + SECRET_KEY_BYTES)]);

        let mut decrypted_checksum = [0u8; CHECKSUM_BYTES];
        decrypted_checksum.copy_from_slice(&decrypted_blob[(KEYNUM_BYTES + SECRET_KEY_BYTES)..]);

        // Recompute checksum from decrypted keynum + secret_key
        let computed_checksum = Self::compute_checksum(decrypted_keynum, &secret_key_bytes);

        // Verify decrypted checksum matches recomputed checksum
        if computed_checksum != decrypted_checksum {
            return Err(Error::ChecksumFailed);
        }

        Ok((SecretKey::from_bytes(secret_key_bytes), decrypted_keynum))
    }

    /// Get the unencrypted secret key (only works for unencrypted keys)
    ///
    /// # Errors
    ///
    /// Returns an error if key is encrypted (use decrypt instead)
    pub fn get_unencrypted_secret_key(&self) -> Result<SecretKey> {
        if self.encrypted {
            return Err(Error::PasswordRequired);
        }

        // Note: For unencrypted keys, the checksum field is typically all zeros
        // and is not validated. The checksum is only used for encrypted keys
        // to detect wrong passwords.

        Ok(SecretKey::from_bytes(self.secret_key_encrypted))
    }

    /// Compute the checksum (Blake2b-256 of keynum + `secret_key`)
    fn compute_checksum(
        keynum: KeyNum,
        secret_key: &[u8; SECRET_KEY_BYTES],
    ) -> [u8; CHECKSUM_BYTES] {
        // Matches C minisign: hash(sig_alg + keynum + sk)
        let mut data = Vec::with_capacity(2 + KEYNUM_BYTES + SECRET_KEY_BYTES);
        data.extend_from_slice(SIG_ALG); // "Ed"
        data.extend_from_slice(keynum.as_bytes());
        data.extend_from_slice(secret_key);

        blake2b_256(&data)
    }

    /// Convert opslimit/memlimit to scrypt parameters
    ///
    /// Returns (`log_n`, r, p) suitable for scrypt
    ///
    /// libsodium uses these formulas:
    /// - opslimit = `LIBSODIUM_OPSLIMIT_MULTIPLIER` * N * r
    /// - memlimit = `LIBSODIUM_MEMLIMIT_MULTIPLIER` * N * r
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> (u8, u32, u32) {
        // Standard minisign uses r=8, p=1
        // We can derive N from either formula, using memlimit is simpler
        let r = SCRYPT_R_STANDARD;
        let p = SCRYPT_P_STANDARD;

        // N = memlimit / (LIBSODIUM_MEMLIMIT_MULTIPLIER * r)
        let n = memlimit / (LIBSODIUM_MEMLIMIT_MULTIPLIER * u64::from(r));
        // Safe cast: log2 of u64 max is ~64, which fits in u8
        let log_n = (n as f64).log2() as u8;

        // Verify our calculation is consistent with opslimit
        // opslimit should equal LIBSODIUM_OPSLIMIT_MULTIPLIER * N * r
        let expected_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * u64::from(r);
        if expected_opslimit != opslimit {
            // If they don't match, the key might use non-standard parameters
            // Fall back to deriving r from opslimit
            // Safe cast: r values are typically small (8-16)
            let derived_r =
                u32::try_from(opslimit / (LIBSODIUM_OPSLIMIT_MULTIPLIER * n)).unwrap_or(r);
            return (log_n, derived_r, p);
        }

        (log_n, r, p)
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

        let sig_end = SECKEY_SIG_ALG_OFFSET + SECKEY_SIG_ALG_SIZE;
        let kdf_end = SECKEY_KDF_ALG_OFFSET + SECKEY_KDF_ALG_SIZE;
        let chk_end = SECKEY_CHK_ALG_OFFSET + SECKEY_CHK_ALG_SIZE;
        let salt_end = SECKEY_KDF_SALT_OFFSET + SECKEY_KDF_SALT_SIZE;
        let opslimit_end = SECKEY_KDF_OPSLIMIT_OFFSET + SECKEY_KDF_OPSLIMIT_SIZE;
        let memlimit_end = SECKEY_KDF_MEMLIMIT_OFFSET + SECKEY_KDF_MEMLIMIT_SIZE;
        let keynum_end = SECKEY_KEYNUM_OFFSET + SECKEY_KEYNUM_SIZE;
        let sk_end = SECKEY_SK_OFFSET + SECKEY_SK_SIZE;
        let checksum_end = SECKEY_CHECKSUM_OFFSET + SECKEY_CHECKSUM_SIZE;

        bytes[SECKEY_SIG_ALG_OFFSET..sig_end].copy_from_slice(SIG_ALG);

        if self.encrypted {
            bytes[SECKEY_KDF_ALG_OFFSET..kdf_end].copy_from_slice(KDF_ALG_SCRYPT);
        } else {
            bytes[SECKEY_KDF_ALG_OFFSET..kdf_end].copy_from_slice(KDF_ALG_NONE);
        }

        bytes[SECKEY_CHK_ALG_OFFSET..chk_end].copy_from_slice(CHK_ALG);
        bytes[SECKEY_KDF_SALT_OFFSET..salt_end].copy_from_slice(&self.kdf_salt);
        write_u64_le(
            &mut bytes[SECKEY_KDF_OPSLIMIT_OFFSET..opslimit_end],
            self.kdf_opslimit,
        );
        write_u64_le(
            &mut bytes[SECKEY_KDF_MEMLIMIT_OFFSET..memlimit_end],
            self.kdf_memlimit,
        );

        // For encrypted keys, write encrypted_keynum; for unencrypted, write plaintext keynum
        if self.encrypted {
            bytes[SECKEY_KEYNUM_OFFSET..keynum_end].copy_from_slice(&self.encrypted_keynum);
        } else {
            bytes[SECKEY_KEYNUM_OFFSET..keynum_end].copy_from_slice(self.keynum.as_bytes());
        }

        bytes[SECKEY_SK_OFFSET..sk_end].copy_from_slice(&self.secret_key_encrypted);
        bytes[SECKEY_CHECKSUM_OFFSET..checksum_end].copy_from_slice(&self.checksum);

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

        let sig_end = SECKEY_SIG_ALG_OFFSET + SECKEY_SIG_ALG_SIZE;
        let kdf_end = SECKEY_KDF_ALG_OFFSET + SECKEY_KDF_ALG_SIZE;
        let chk_end = SECKEY_CHK_ALG_OFFSET + SECKEY_CHK_ALG_SIZE;
        let salt_end = SECKEY_KDF_SALT_OFFSET + SECKEY_KDF_SALT_SIZE;
        let opslimit_end = SECKEY_KDF_OPSLIMIT_OFFSET + SECKEY_KDF_OPSLIMIT_SIZE;
        let memlimit_end = SECKEY_KDF_MEMLIMIT_OFFSET + SECKEY_KDF_MEMLIMIT_SIZE;
        let keynum_end = SECKEY_KEYNUM_OFFSET + SECKEY_KEYNUM_SIZE;
        let sk_end = SECKEY_SK_OFFSET + SECKEY_SK_SIZE;
        let checksum_end = SECKEY_CHECKSUM_OFFSET + SECKEY_CHECKSUM_SIZE;

        // Verify signature algorithm
        if &bytes[SECKEY_SIG_ALG_OFFSET..sig_end] != SIG_ALG {
            return Err(Error::InvalidSecretKey(
                "invalid signature algorithm".to_string(),
            ));
        }

        // Check KDF algorithm
        let encrypted = if &bytes[SECKEY_KDF_ALG_OFFSET..kdf_end] == KDF_ALG_SCRYPT {
            true
        } else if &bytes[SECKEY_KDF_ALG_OFFSET..kdf_end] == KDF_ALG_NONE {
            false
        } else {
            return Err(Error::InvalidSecretKey("invalid KDF algorithm".to_string()));
        };

        // Verify checksum algorithm
        if &bytes[SECKEY_CHK_ALG_OFFSET..chk_end] != CHK_ALG {
            return Err(Error::InvalidSecretKey(
                "invalid checksum algorithm".to_string(),
            ));
        }

        let mut kdf_salt = [0u8; KDF_SALT_BYTES];
        kdf_salt.copy_from_slice(&bytes[SECKEY_KDF_SALT_OFFSET..salt_end]);

        let kdf_opslimit = read_u64_le(&bytes[SECKEY_KDF_OPSLIMIT_OFFSET..opslimit_end]);
        let kdf_memlimit = read_u64_le(&bytes[SECKEY_KDF_MEMLIMIT_OFFSET..memlimit_end]);

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[SECKEY_KEYNUM_OFFSET..keynum_end]);
        let keynum = KeyNum::from_bytes(keynum_bytes);

        // For encrypted keys, store encrypted keynum separately for serialization
        let encrypted_keynum = if encrypted {
            keynum_bytes
        } else {
            [0u8; KEYNUM_BYTES]
        };

        let mut secret_key_encrypted = [0u8; SECRET_KEY_BYTES];
        secret_key_encrypted.copy_from_slice(&bytes[SECKEY_SK_OFFSET..sk_end]);

        let mut checksum = [0u8; CHECKSUM_BYTES];
        checksum.copy_from_slice(&bytes[SECKEY_CHECKSUM_OFFSET..checksum_end]);

        Ok(Self {
            encrypted,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
            keynum,           // Contains encrypted keynum if encrypted, plaintext if not
            encrypted_keynum, // Stores encrypted keynum for roundtrip serialization
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
        let base64 = encode_base64(bytes);
        format!("untrusted comment: {comment}\n{base64}\n")
    }
}

impl std::fmt::Debug for SeckeyStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeckeyStruct")
            .field("encrypted", &self.encrypted)
            .field("keynum", &self.keynum)
            .field("kdf_salt", &"[...]")
            .field("kdf_opslimit", &self.kdf_opslimit)
            .field("kdf_memlimit", &self.kdf_memlimit)
            .field("encrypted_keynum", &"[REDACTED]")
            .field("secret_key_encrypted", &"[REDACTED]")
            .field("checksum", &"[...]")
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
        let pubkey =
            PubkeyStruct::from_file_contents(&contents).expect("Failed to parse public key");

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
        let seckey =
            SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

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
        assert_eq!(
            seckey.kdf_opslimit(),
            0,
            "Expected zero opslimit for unencrypted key"
        );
        assert_eq!(
            seckey.kdf_memlimit(),
            0,
            "Expected zero memlimit for unencrypted key"
        );
    }

    #[test]
    fn test_public_key_serialization_roundtrip() {
        // Load and parse C-generated public key
        let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
            .expect("Failed to read test.pub fixture");

        let original =
            PubkeyStruct::from_file_contents(&contents).expect("Failed to parse public key");

        // Serialize to bytes and parse back
        let bytes = original.to_bytes();
        let roundtrip =
            PubkeyStruct::from_bytes(&bytes).expect("Failed to parse roundtripped bytes");

        // Verify they're identical
        assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
        assert_eq!(
            original.public_key().as_bytes(),
            roundtrip.public_key().as_bytes()
        );
    }

    #[test]
    fn test_secret_key_serialization_roundtrip() {
        // Load and parse C-generated secret key
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        let original =
            SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

        // Serialize to bytes and parse back
        let bytes = original.to_bytes();
        let roundtrip =
            SeckeyStruct::from_bytes(&bytes).expect("Failed to parse roundtripped bytes");

        // Verify they're identical
        assert_eq!(original.is_encrypted(), roundtrip.is_encrypted());
        assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
        assert_eq!(original.kdf_opslimit(), roundtrip.kdf_opslimit());
        assert_eq!(original.kdf_memlimit(), roundtrip.kdf_memlimit());
        assert_eq!(
            original.encrypted_secret_key(),
            roundtrip.encrypted_secret_key()
        );
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
        assert_eq!(
            pubkey.public_key().as_bytes(),
            parsed.public_key().as_bytes()
        );
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

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use crate::crypto::generate_keypair;

        // Generate a test keypair
        let (secret_key, _public_key, keynum) = generate_keypair();

        let password = b"test_password";
        let kdf_salt = [42u8; KDF_SALT_BYTES];
        // Use reduced parameters for testing (log_n=14 for reasonable speed)
        // Using libsodium formulas:
        // opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * N * r
        // memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * N * r
        let n = 1u64 << 14; // N = 16384
        let r = u64::from(SCRYPT_R_STANDARD);
        let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
        let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

        // Create encrypted secret key
        let encrypted_key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .expect("Failed to encrypt key");

        assert!(encrypted_key.is_encrypted());

        // Decrypt it
        let (decrypted_key, _) = encrypted_key
            .decrypt(password)
            .expect("Failed to decrypt key");

        // Verify it matches the original
        assert_eq!(secret_key.as_bytes(), decrypted_key.as_bytes());
    }

    #[test]
    fn test_decrypt_with_wrong_password() {
        use crate::crypto::generate_keypair;

        let (secret_key, _public_key, keynum) = generate_keypair();

        let password = b"correct_password";
        let wrong_password = b"wrong_password";
        let kdf_salt = [42u8; KDF_SALT_BYTES];
        // Use reduced parameters for testing
        let n = 1u64 << 14;
        let r = u64::from(SCRYPT_R_STANDARD);
        let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
        let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

        let encrypted_key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .expect("Failed to encrypt key");

        // Try to decrypt with wrong password
        let result = encrypted_key.decrypt(wrong_password);

        // Should fail with checksum error
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ChecksumFailed)));
    }

    #[test]
    fn test_get_unencrypted_secret_key() {
        use crate::crypto::generate_keypair;

        // Generate a test keypair
        let (secret_key, _public_key, keynum) = generate_keypair();

        // Create unencrypted secret key structure
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        assert!(!seckey.is_encrypted());

        // Get the unencrypted key
        let retrieved_key = seckey
            .get_unencrypted_secret_key()
            .expect("Failed to get unencrypted key");

        assert_eq!(secret_key.as_bytes(), retrieved_key.as_bytes());
    }

    #[test]
    #[ignore = "expensive test with log_n=20, run with --ignored"]
    fn test_decrypt_c_generated_encrypted_key() {
        // Load the C-generated encrypted secret key
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        let seckey =
            SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

        assert!(seckey.is_encrypted());

        // The password we used when generating the fixture is "test"
        let password = b"test";

        // Decrypt it
        let (secret_key, _) = seckey.decrypt(password).expect("Failed to decrypt key");

        // Verify we got a valid secret key
        assert_eq!(secret_key.as_bytes().len(), SECRET_KEY_BYTES);

        // The decrypted key should have a valid checksum
        // (checksum validation happens inside decrypt())
    }

    #[test]
    #[ignore = "expensive test with log_n=20, run with --ignored"]
    fn test_decrypt_c_generated_encrypted_key_wrong_password() {
        // Load the C-generated encrypted secret key
        let contents = fs::read_to_string("tests/fixtures/keys/test.key")
            .expect("Failed to read test.key fixture");

        let seckey =
            SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

        // Try with wrong password
        let result = seckey.decrypt(b"wrong_password");

        // Should fail
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::ChecksumFailed)));
    }

    #[test]
    fn test_get_c_generated_unencrypted_key() {
        // Load the C-generated unencrypted secret key
        let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
            .expect("Failed to read unencrypted.key fixture");

        let seckey =
            SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

        assert!(!seckey.is_encrypted());

        // Debug: check checksum
        let computed = SeckeyStruct::compute_checksum(seckey.keynum, &seckey.secret_key_encrypted);
        eprintln!("Stored checksum:   {:02x?}", &seckey.checksum[..8]);
        eprintln!("Computed checksum: {:02x?}", &computed[..8]);

        // Get the unencrypted key
        let secret_key = seckey
            .get_unencrypted_secret_key()
            .expect("Failed to get unencrypted key");

        // Verify we got a valid secret key
        assert_eq!(secret_key.as_bytes().len(), SECRET_KEY_BYTES);
    }
}
