//! Key structures for minisign
//!
//! This module implements the binary formats for public and secret keys
//! as defined in the minisign specification.
//!
//! ## Checksum Behavior
//!
//! **Important:** Unencrypted secret keys use an all-zeros checksum rather than
//! a computed Blake2b-256 hash. This matches the C minisign implementation but
//! means **unencrypted keys have no integrity check**.
//!
//! ### Implications
//!
//! - **Encrypted keys:** Checksum is computed over the unencrypted secret key and
//!   verified after decryption, protecting against corruption or tampering
//! - **Unencrypted keys:** Checksum is set to all zeros (`[0u8; 32]`) and not verified,
//!   meaning corrupted unencrypted key files will load without error
//!
//! ### Rationale
//!
//! This behavior preserves exact compatibility with the C implementation. Since
//! unencrypted keys are typically only used for testing or automation where security
//! is already compromised, the lack of integrity checking is acceptable. For
//! production use, always use encrypted keys (with `--password`).
//!
//! ### Migration Note
//!
//! Changing this behavior would break compatibility with C minisign. Any future
//! enhancement to add checksums for unencrypted keys would require a new key format
//! version or file format extension.

use crate::Result;
use crate::crypto::{
    CHECKSUM_BYTES, KDF_SALT_BYTES, KEYNUM_BYTES, KeyNum, PUBLIC_KEY_BYTES, PublicKey,
    SECRET_KEY_BYTES, SecretKey, blake2b_256, derive_key_with_params,
};
use crate::errors::Error;
use crate::formats::{decode_base64, encode_base64, read_u64_le, write_u64_le};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Size of the public key structure in bytes
pub const PUBKEY_STRUCT_SIZE: usize = 2 + KEYNUM_BYTES + PUBLIC_KEY_BYTES; // 42 bytes

/// Size of the secret key structure in bytes
pub const SECKEY_STRUCT_SIZE: usize =
    2 + 2 + 2 + KDF_SALT_BYTES + 8 + 8 + KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES; // 158 bytes

/// Size of encrypted blob (keynum + secret key + checksum)
/// Matches C minisign: sizeof(seckey_struct->keynum_sk) = 8 + 64 + 32 = 104 bytes
pub const ENCRYPTED_BLOB_SIZE: usize = KEYNUM_BYTES + SECRET_KEY_BYTES + CHECKSUM_BYTES; // 104 bytes

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
    pub const fn new(keynum: KeyNum, public_key: PublicKey) -> Self {
        Self { keynum, public_key }
    }

    /// Get the key number
    #[must_use]
    pub const fn keynum(&self) -> &KeyNum {
        &self.keynum
    }

    /// Get the public key
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
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
    /// This parses the base64 representation typically found in `.pub` files
    /// (excluding the untrusted comment line).
    ///
    /// # Arguments
    ///
    /// * `base64_str` - Base64-encoded public key structure (42 bytes when decoded)
    ///
    /// # Returns
    ///
    /// A `PubkeyStruct` containing the signature algorithm, key number, and public key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Base64 decoding fails
    /// - The decoded data is not exactly 42 bytes
    /// - The signature algorithm is not "Ed" (Ed25519)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use minisign::keys::PubkeyStruct;
    ///
    /// let base64 = "RWQwpZXcv6r8MS48xbhFK+8F8ZPL5VBlUK6+sKAUXTl5kp/EsIKbKAEa";
    /// let pubkey = PubkeyStruct::from_base64(base64)?;
    /// # Ok::<(), minisign::Error>(())
    /// ```
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
    /// Creates an unencrypted secret key structure with no password protection.
    /// The secret key is stored in plain form and the checksum is set to all zeros
    /// (matching C minisign behavior for unencrypted keys).
    ///
    /// # Arguments
    ///
    /// * `keynum` - The 8-byte key number identifier
    /// * `secret_key` - The 64-byte Ed25519 secret key
    ///
    /// # Returns
    ///
    /// A `SeckeyStruct` with `encrypted=false` and zero-filled KDF parameters
    ///
    /// # Security Note
    ///
    /// Unencrypted keys have two significant limitations:
    /// 1. **No encryption:** Keys are stored in plaintext with no password protection
    /// 2. **No integrity check:** The checksum is set to all zeros (not computed),
    ///    meaning corrupted key files will load without error
    ///
    /// This matches C minisign behavior for compatibility. For production use,
    /// always use `new_encrypted()` for password-protected keys with integrity verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use minisign::crypto::generate_keypair;
    /// use minisign::keys::SeckeyStruct;
    ///
    /// let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    /// let seckey_struct = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    /// assert!(!seckey_struct.is_encrypted());
    /// ```
    #[must_use]
    pub const fn new_unencrypted(keynum: KeyNum, secret_key: &SecretKey) -> Self {
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
    /// * `allow_fallback` - If true, allow reduced parameters on failure (LESS SECURE, opt-in only)
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails or if fallback would be needed but is not allowed
    pub fn new_encrypted(
        keynum: KeyNum,
        secret_key: &SecretKey,
        password: &[u8],
        kdf_salt: [u8; KDF_SALT_BYTES],
        kdf_opslimit: u64,
        kdf_memlimit: u64,
        allow_fallback: bool,
    ) -> Result<Self> {
        use crate::crypto::{SCRYPT_MEMLIMIT_MIN, SCRYPT_OPSLIMIT_MIN};

        // Compute checksum of unencrypted keynum + secret_key (before encryption)
        let computed_checksum = Self::compute_checksum(keynum, secret_key.as_bytes());

        // Implement scrypt parameter fallback (matches C minisign.c:419-427)
        // Try derivation with initial parameters, halving on failure until minimum reached
        // SECURITY: Fallback is opt-in only (allow_fallback must be true)
        let mut current_opslimit = kdf_opslimit;
        let mut current_memlimit = kdf_memlimit;
        let mut fallback_used = false;

        let derived_key = loop {
            // Convert opslimit/memlimit to scrypt parameters
            let (log_n, r, p) =
                Self::opslimit_memlimit_to_params(current_opslimit, current_memlimit)?;

            // Attempt key derivation
            if let Ok(key) =
                derive_key_with_params(password, &kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)
            {
                break key;
            }

            // Derivation failed - check if we can fallback
            if !allow_fallback {
                return Err(Error::KdfError(
                    "Key derivation failed - more memory needed (use --allow-kdf-fallback to reduce security parameters, not recommended)".to_string(),
                ));
            }

            // Fallback is allowed - try with reduced parameters
            current_opslimit /= 2;
            current_memlimit /= 2;

            // Check if we've fallen below minimum thresholds
            if current_opslimit < SCRYPT_OPSLIMIT_MIN || current_memlimit < SCRYPT_MEMLIMIT_MIN {
                return Err(Error::KdfError(
                    "Unable to complete key derivation - more memory needed even with minimum parameters".to_string(),
                ));
            }

            fallback_used = true;
        };

        // Display CLEAR WARNING if fallback was used
        if fallback_used {
            eprintln!("\n*** WARNING: REDUCED SECURITY PARAMETERS ***");
            eprintln!("Key derivation used weaker parameters due to memory constraints:");
            eprintln!("  Original: opslimit={kdf_opslimit}, memlimit={kdf_memlimit}");
            eprintln!("  Reduced:  opslimit={current_opslimit}, memlimit={current_memlimit}");
            eprintln!(
                "This makes your key easier to brute-force. Consider using a system with more memory.\n"
            );
        }

        // Create combined blob: keynum + secret_key + checksum (zeroized on drop)
        let mut blob = Zeroizing::new(Vec::with_capacity(ENCRYPTED_BLOB_SIZE));
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
            kdf_opslimit: current_opslimit, // Store actual parameters that worked
            kdf_memlimit: current_memlimit,
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

        // Warn if key was created with weak KDF parameters (fallback)
        if self.is_weak_kdf() {
            eprintln!("\n*** WARNING: WEAK KEY DETECTED ***");
            eprintln!("This key was created with reduced security parameters.");
            eprintln!("It is easier to brute-force than a production-strength key.");
            eprintln!("Consider regenerating this key on a system with more memory.");
            eprintln!("See rs/docs/kdf-fallback-security-analysis.md for details.\n");
        }

        // Convert opslimit/memlimit to scrypt parameters
        let (log_n, r, p) =
            Self::opslimit_memlimit_to_params(self.kdf_opslimit, self.kdf_memlimit)?;

        // Derive 104 bytes (keynum + secret_key + checksum) to match C implementation
        let derived_key =
            derive_key_with_params(password, &self.kdf_salt, log_n, r, p, ENCRYPTED_BLOB_SIZE)?;

        // Reconstruct encrypted blob: keynum + secret_key + checksum (zeroized on drop)
        let mut encrypted_blob = Zeroizing::new(Vec::with_capacity(ENCRYPTED_BLOB_SIZE));
        encrypted_blob.extend_from_slice(&self.encrypted_keynum);
        encrypted_blob.extend_from_slice(&self.secret_key_encrypted);
        encrypted_blob.extend_from_slice(&self.checksum); // checksum field contains encrypted checksum

        // Decrypt entire blob (zeroized on drop)
        let mut decrypted_blob = Zeroizing::new([0u8; ENCRYPTED_BLOB_SIZE]);
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
        // Use constant-time comparison to prevent timing side-channel attacks
        if computed_checksum.ct_eq(&decrypted_checksum).into() {
            Ok((SecretKey::from_bytes(secret_key_bytes), decrypted_keynum))
        } else {
            Err(Error::ChecksumFailed)
        }
    }

    /// Get the unencrypted secret key (only works for unencrypted keys)
    ///
    /// # Errors
    ///
    /// Returns an error if key is encrypted (use decrypt instead)
    pub const fn get_unencrypted_secret_key(&self) -> Result<SecretKey> {
        if self.encrypted {
            return Err(Error::PasswordRequired);
        }

        // IMPORTANT: For unencrypted keys, the checksum field is all zeros
        // and is NOT validated. This matches C minisign behavior but means
        // corrupted unencrypted key files will load without error.
        // The checksum is only computed and verified for encrypted keys.

        Ok(SecretKey::from_bytes(self.secret_key_encrypted))
    }

    /// Check if this key was created with weak KDF parameters (fallback parameters)
    ///
    /// Returns `true` if the key's KDF parameters are below production strength,
    /// indicating it was created with `--allow-kdf-fallback` or on a memory-constrained
    /// system using the C implementation's automatic fallback.
    ///
    /// Production strength parameters:
    /// - `opslimit` = 33,554,432 (N=2^20, r=8, p=1)
    /// - `memlimit` = 1,073,741,824 (1024 MB)
    ///
    /// # Returns
    ///
    /// - `true` if either `kdf_opslimit` or `kdf_memlimit` is below production strength
    /// - `false` if the key is unencrypted (no KDF used)
    /// - `false` if the key uses production-strength parameters
    ///
    /// # Security Implications
    ///
    /// Weak KDF parameters make the key easier to brute-force:
    /// - After 1 fallback (512 MB): 2x easier to attack
    /// - After 3 fallbacks (128 MB): 8x easier to attack
    /// - Minimum parameters (16 MB): 64x easier to attack
    ///
    /// See `rs/docs/kdf-fallback-security-analysis.md` for details.
    #[must_use]
    pub const fn is_weak_kdf(&self) -> bool {
        // Unencrypted keys have kdf_opslimit and kdf_memlimit set to 0
        // They should not be considered weak (they have no KDF at all)
        if !self.encrypted {
            return false;
        }

        // Key is weak if either parameter is below production strength
        self.kdf_opslimit < crate::constants::PRODUCTION_OPSLIMIT
            || self.kdf_memlimit < crate::constants::PRODUCTION_MEMLIMIT
    }

    /// Compute the checksum (Blake2b-256 of keynum + `secret_key`)
    #[must_use]
    pub fn compute_checksum(
        // pub for unit tests
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

    /// Convert opslimit/memlimit to scrypt parameters (`log_n`, r, p)
    ///
    /// Delegates to [`crate::crypto::opslimit_memlimit_to_params`].
    ///
    /// # Errors
    ///
    /// See [`crate::crypto::opslimit_memlimit_to_params`] for error conditions.
    pub fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
        crate::crypto::opslimit_memlimit_to_params(opslimit, memlimit)
    }

    /// Get the key number
    #[must_use]
    pub const fn keynum(&self) -> &KeyNum {
        &self.keynum
    }

    /// Raw encrypted keynum bytes (positions 54-61 in the key file).
    /// For unencrypted keys, returns all zeros.
    #[must_use]
    pub const fn encrypted_keynum(&self) -> &[u8; KEYNUM_BYTES] {
        &self.encrypted_keynum
    }

    /// Credential store lookup key — always available without decryption.
    ///
    /// For encrypted keys: hex of the encrypted keynum bytes at file offset 54-61.
    /// For unencrypted keys: hex of the plaintext keynum (same as `to_key_id()`).
    ///
    /// This value is deterministic for a given key file and changes when the
    /// password or KDF salt changes. It is unique per key+password+salt combination.
    #[must_use]
    pub fn credential_id(&self) -> String {
        if self.encrypted {
            // Use encrypted keynum bytes interpreted as little-endian u64
            // This matches the encoding used by to_key_id() for consistency
            let value = u64::from_le_bytes(self.encrypted_keynum);
            format!("{value:016X}")
        } else {
            self.keynum.to_key_id()
        }
    }

    /// Check if the key is encrypted
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Get the encrypted secret key bytes
    #[must_use]
    pub const fn encrypted_secret_key(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.secret_key_encrypted
    }

    /// Get the KDF salt (only meaningful if encrypted)
    #[must_use]
    pub const fn kdf_salt(&self) -> &[u8; KDF_SALT_BYTES] {
        &self.kdf_salt
    }

    /// Get the KDF operations limit (only meaningful if encrypted)
    #[must_use]
    pub const fn kdf_opslimit(&self) -> u64 {
        self.kdf_opslimit
    }

    /// Get the KDF memory limit (only meaningful if encrypted)
    #[must_use]
    pub const fn kdf_memlimit(&self) -> u64 {
        self.kdf_memlimit
    }

    /// Get the checksum bytes
    ///
    /// For encrypted keys, this returns the encrypted checksum.
    /// For unencrypted keys, this returns all zeros (matching C minisign behavior).
    #[must_use]
    pub const fn checksum(&self) -> &[u8; CHECKSUM_BYTES] {
        &self.checksum
    }

    /// Serialize to bytes
    ///
    /// # Panics
    ///
    /// Never panics - all slices are correctly sized by the struct layout constants.
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
        )
        .expect("opslimit range is exactly 8 bytes");
        write_u64_le(
            &mut bytes[SECKEY_KDF_MEMLIMIT_OFFSET..memlimit_end],
            self.kdf_memlimit,
        )
        .expect("memlimit range is exactly 8 bytes");

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

        let kdf_opslimit = read_u64_le(&bytes[SECKEY_KDF_OPSLIMIT_OFFSET..opslimit_end])
            .map_err(|e| Error::InvalidKeyFormat(format!("Invalid KDF opslimit: {e}")))?;
        let kdf_memlimit = read_u64_le(&bytes[SECKEY_KDF_MEMLIMIT_OFFSET..memlimit_end])
            .map_err(|e| Error::InvalidKeyFormat(format!("Invalid KDF memlimit: {e}")))?;

        let mut keynum_bytes = [0u8; KEYNUM_BYTES];
        keynum_bytes.copy_from_slice(&bytes[SECKEY_KEYNUM_OFFSET..keynum_end]);

        // For encrypted keys, the bytes on disk are encrypted - we cannot interpret them as a keynum
        // For unencrypted keys, the bytes are plaintext keynum
        let (keynum, encrypted_keynum) = if encrypted {
            // Encrypted: store encrypted bytes for serialization, zero keynum until decrypt
            ([0u8; KEYNUM_BYTES], keynum_bytes)
        } else {
            // Unencrypted: bytes are plaintext keynum
            (keynum_bytes, [0u8; KEYNUM_BYTES])
        };

        let keynum = KeyNum::from_bytes(keynum);

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
