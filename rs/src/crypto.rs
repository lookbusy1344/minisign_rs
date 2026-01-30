//! Cryptographic primitives for minisign
//!
//! This module provides wrappers around `RustCrypto` implementations that match
//! the behavior of libsodium (used by C minisign).

use crate::errors::{Error, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use scrypt::{Params as ScryptParams, scrypt};
use std::io::Read;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Constants from the minisign specification
pub const SIGNATURE_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 32;
pub const SECRET_KEY_BYTES: usize = 64;
pub const KEYNUM_BYTES: usize = 8;
pub const KDF_SALT_BYTES: usize = 32;
pub const CHECKSUM_BYTES: usize = 32;

// Scrypt parameters matching libsodium SENSITIVE level
// N = 2^20 = 1,048,576
pub const SCRYPT_LOG_N: u8 = 20;
pub const SCRYPT_R: u32 = 8;
pub const SCRYPT_P: u32 = 1;

// Libsodium formula constants for converting between (N, r, p) and (opslimit, memlimit)
// These multipliers match libsodium's crypto_pwhash_scryptsalsa208sha256 implementation
pub const LIBSODIUM_OPSLIMIT_MULTIPLIER: u64 = 4;
pub const LIBSODIUM_MEMLIMIT_MULTIPLIER: u64 = 128;

// Minimum scrypt parameters (matching libsodium minimums)
// These are used as lower bounds for fallback mechanism
pub const SCRYPT_OPSLIMIT_MIN: u64 = 32_768; // 2^15
pub const SCRYPT_MEMLIMIT_MIN: u64 = 16_777_216; // 16 MB

/// Buffer size for streaming hash operations (8 KB)
///
/// This buffer size provides good performance for streaming large files
/// through Blake2b without excessive memory usage.
const STREAM_BUFFER_SIZE: usize = 8192;

/// Ed25519 secret key (64 bytes) with automatic zeroization
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; SECRET_KEY_BYTES]);

impl SecretKey {
    /// Create a new secret key from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; SECRET_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the secret key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Ed25519 public key (32 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_BYTES]);

impl PublicKey {
    /// Create a new public key from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the public key bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:02x}..)", self.0[0])
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_BYTES]);

impl Signature {
    /// Create a new signature from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Get a reference to the signature bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({:02x}..)", self.0[0])
    }
}

/// Key number / identifier (8 bytes)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyNum(pub [u8; KEYNUM_BYTES]);

impl KeyNum {
    /// Create a new key number from bytes
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEYNUM_BYTES]) -> Self {
        Self(bytes)
    }

    /// Generate a random key number
    ///
    /// # Errors
    ///
    /// Returns an error if the system random number generator fails
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; KEYNUM_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| Error::RngError(e.to_string()))?;
        Ok(Self(bytes))
    }

    /// Get a reference to the key number bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEYNUM_BYTES] {
        &self.0
    }

    /// Convert to hexadecimal string for display
    #[must_use]
    pub fn to_hex(&self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{b:02X}");
            output
        })
    }
}

impl std::fmt::Debug for KeyNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyNum({})", self.to_hex())
    }
}

/// Generate an Ed25519 keypair with a random key number
///
/// # Returns
///
/// A tuple of (`secret_key`, `public_key`, `keynum`)
///
/// # Errors
///
/// Returns an error if the random number generator fails
pub fn generate_keypair() -> Result<(SecretKey, PublicKey, KeyNum)> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let secret_key = SecretKey::from_bytes(signing_key.to_keypair_bytes());
    let public_key = PublicKey::from_bytes(verifying_key.to_bytes());
    let keynum = KeyNum::generate()?;

    Ok((secret_key, public_key, keynum))
}

/// Sign a message with a secret key
///
/// # Arguments
///
/// * `secret_key` - The Ed25519 secret key (64 bytes)
/// * `message` - The message to sign
///
/// # Returns
///
/// A 64-byte Ed25519 signature
///
/// # Errors
///
/// Returns `Error::InvalidSecretKey` if the key is malformed
pub fn sign(secret_key: &SecretKey, message: &[u8]) -> Result<Signature> {
    let signing_key = SigningKey::from_keypair_bytes(secret_key.as_bytes())
        .map_err(|e| Error::InvalidSecretKey(e.to_string()))?;
    let signature = signing_key.sign(message);
    Ok(Signature::from_bytes(signature.to_bytes()))
}

/// Verify an Ed25519 signature
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key (32 bytes)
/// * `message` - The message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
///
/// `Ok(())` if the signature is valid
///
/// # Errors
///
/// Returns `Error::VerificationFailed` if the signature is invalid or malformed
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key.as_bytes()).map_err(|_| Error::InvalidSignature)?;

    let sig = DalekSignature::from_bytes(signature.as_bytes());

    verifying_key
        .verify(message, &sig)
        .map_err(|_| Error::VerificationFailed)
}

/// Compute Blake2b-256 hash (32 bytes)
///
/// Used for checksums in minisign
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-byte hash
#[must_use]
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Blake2b-512 hash (64 bytes)
///
/// Used for global signatures in minisign
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 64-byte hash
#[must_use]
pub fn blake2b_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Blake2b-512 hash from a reader (streaming)
///
/// Used for hashing large files without loading them entirely into memory
///
/// # Arguments
///
/// * `reader` - The data source to hash
///
/// # Returns
///
/// A 64-byte hash
///
/// # Errors
///
/// Returns an error if reading from the input fails
pub fn blake2b_512_stream(mut reader: impl Read) -> Result<[u8; 64]> {
    let mut hasher = Blake2b512::new();
    let mut buffer = [0u8; STREAM_BUFFER_SIZE];

    loop {
        let n = reader
            .read(&mut buffer)
            .map_err(|e| Error::Io(format!("failed to read data for hashing: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize().into())
}

/// Derive a key from a password using Scrypt with custom parameters
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - The salt (should be 32 bytes)
/// * `log_n` - The log2 of the work factor N (e.g., 20 for N=1,048,576)
/// * `r` - Block size parameter
/// * `p` - Parallelization parameter
/// * `output_len` - The desired output length in bytes
///
/// # Returns
///
/// The derived key wrapped in `Zeroizing` for automatic memory cleanup
///
/// # Errors
///
/// Returns `Error::KdfError` if key derivation fails
pub fn derive_key_with_params(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(vec![0u8; output_len]);

    // The scrypt Params::new() has a max len of 64 bytes, but the low-level scrypt()
    // function can produce any length output. We use a nominal len for Params (capped at 64),
    // but pass the full output_len buffer to scrypt(), which determines the actual output size.
    let params_len = output_len.min(64);
    let params = ScryptParams::new(log_n, r, p, params_len)
        .map_err(|e| Error::KdfError(format!("invalid scrypt parameters: {e}")))?;

    scrypt(password, salt, &params, &mut output)
        .map_err(|e| Error::KdfError(format!("scrypt failed: {e}")))?;

    Ok(output)
}

/// Derive a key from a password using Scrypt with libsodium SENSITIVE parameters
///
/// Matches libsodium's SENSITIVE level parameters:
/// - N = 2^20 (1,048,576)
/// - r = 8
/// - p = 1
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - The salt (should be 32 bytes)
/// * `output_len` - The desired output length in bytes
///
/// # Returns
///
/// The derived key wrapped in `Zeroizing` for automatic memory cleanup
///
/// # Errors
///
/// Returns `Error::KdfError` if key derivation fails
pub fn derive_key(password: &[u8], salt: &[u8], output_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    derive_key_with_params(password, salt, SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, output_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SIGNATURE_BYTES, 64);
        assert_eq!(PUBLIC_KEY_BYTES, 32);
        assert_eq!(SECRET_KEY_BYTES, 64);
        assert_eq!(KEYNUM_BYTES, 8);
        assert_eq!(KDF_SALT_BYTES, 32);
        assert_eq!(CHECKSUM_BYTES, 32);
    }

    #[test]
    fn test_keynum_generation() {
        let kn1 = KeyNum::generate().expect("RNG should work");
        let kn2 = KeyNum::generate().expect("RNG should work");
        // Should be extremely unlikely to be equal
        assert_ne!(kn1, kn2);
    }

    #[test]
    fn test_keynum_hex() {
        let keynum = KeyNum::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        assert_eq!(keynum.to_hex(), "0123456789ABCDEF");
    }

    #[test]
    fn test_secret_key_debug() {
        let sk = SecretKey::from_bytes([42u8; SECRET_KEY_BYTES]);
        let debug_str = format!("{sk:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_blake2b_256_known_vector() {
        // Test vector: empty input (Blake2b-256)
        let hash = blake2b_256(b"");
        let expected =
            hex::decode("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
                .expect("invalid hex");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_blake2b_256_hello() {
        // Test vector: "hello" (Blake2b-256)
        let hash = blake2b_256(b"hello");
        let expected =
            hex::decode("324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf")
                .expect("invalid hex");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_blake2b_512_known_vector() {
        // Test vector: empty input
        let hash = blake2b_512(b"");
        let expected = hex::decode(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
        )
        .expect("invalid hex");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_blake2b_512_hello() {
        // Test vector: "hello"
        let hash = blake2b_512(b"hello");
        let expected = hex::decode(
            "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94",
        )
        .expect("invalid hex");
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (secret_key, public_key, _keynum) = generate_keypair().expect("RNG should work");
        let message = b"test message";

        let signature = sign(&secret_key, message).expect("signing failed");
        verify(&public_key, message, &signature).expect("verification failed");
    }

    #[test]
    fn test_verify_wrong_message() {
        let (secret_key, public_key, _keynum) = generate_keypair().expect("RNG should work");
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = sign(&secret_key, message).expect("signing failed");
        let result = verify(&public_key, wrong_message, &signature);
        assert!(matches!(result, Err(Error::VerificationFailed)));
    }

    #[test]
    fn test_verify_wrong_key() {
        let (secret_key, _public_key, _keynum) = generate_keypair().expect("RNG should work");
        let (_, wrong_public_key, _) = generate_keypair().expect("RNG should work");
        let message = b"test message";

        let signature = sign(&secret_key, message).expect("signing failed");
        let result = verify(&wrong_public_key, message, &signature);
        assert!(matches!(result, Err(Error::VerificationFailed)));
    }

    // Note: These tests use reduced Scrypt parameters (log_n=10) for speed.
    // The production parameters (log_n=20) are tested in integration tests.
    const TEST_LOG_N: u8 = 10; // N=1024 for fast testing

    // Test constants for scrypt parameters
    const TEST_SCRYPT_R: u32 = 8;
    const TEST_SCRYPT_P: u32 = 1;

    #[test]
    fn test_derive_key_output_length() {
        let password = b"test password";
        let salt = [0u8; 32];

        // Test 32-byte output (used for encryption keys)
        let key_32 = derive_key_with_params(
            password,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");
        assert_eq!(key_32.len(), 32);

        // Test 64-byte output (if needed for other purposes)
        let key_64 = derive_key_with_params(
            password,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            64,
        )
        .expect("derivation failed");
        assert_eq!(key_64.len(), 64);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let password = b"test password";
        let salt = [0u8; 32];

        let key1 = derive_key_with_params(
            password,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");
        let key2 = derive_key_with_params(
            password,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let password1 = b"password1";
        let password2 = b"password2";
        let salt = [0u8; 32];

        let key1 = derive_key_with_params(
            password1,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");
        let key2 = derive_key_with_params(
            password2,
            &salt,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = b"test password";
        let salt1 = [0u8; 32];
        let mut salt2 = [0u8; 32];
        salt2[0] = 1;

        let key1 = derive_key_with_params(
            password,
            &salt1,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");
        let key2 = derive_key_with_params(
            password,
            &salt2,
            TEST_LOG_N,
            TEST_SCRYPT_R,
            TEST_SCRYPT_P,
            32,
        )
        .expect("derivation failed");

        assert_ne!(key1, key2);
    }

    /// Test with full production parameters (marked ignore for normal test runs)
    #[test]
    #[ignore = "slow test with full scrypt parameters"]
    fn test_derive_key_full_params() {
        let password = b"test password";
        let salt = [0u8; 32];

        // This uses the full SENSITIVE parameters and will be slow
        let key = derive_key(password, &salt, 32).expect("derivation with full params failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_blake2b_512_stream() {
        use std::io::Cursor;

        // Test with empty input
        let empty = Cursor::new(Vec::<u8>::new());
        let hash = blake2b_512_stream(empty).expect("streaming hash failed");
        let expected = blake2b_512(b"");
        assert_eq!(hash, expected);

        // Test with "hello"
        let hello = Cursor::new(b"hello".to_vec());
        let hash = blake2b_512_stream(hello).expect("streaming hash failed");
        let expected = blake2b_512(b"hello");
        assert_eq!(hash, expected);

        // Test with larger data (10KB)
        let large_data = vec![42u8; 10 * 1024];
        let cursor = Cursor::new(large_data.clone());
        let hash_stream = blake2b_512_stream(cursor).expect("streaming hash failed");
        let hash_direct = blake2b_512(&large_data);
        assert_eq!(hash_stream, hash_direct);
    }
}
