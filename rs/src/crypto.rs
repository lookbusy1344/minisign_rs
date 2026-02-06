//! Cryptographic primitives for minisign
//!
//! This module provides wrappers around `RustCrypto` implementations that match
//! the behavior of libsodium (used by C minisign).

use crate::errors::{Error, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use scrypt::{Params as ScryptParams, scrypt};
use std::io::Read;
use subtle::ConstantTimeEq;
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
pub struct SecretKey([u8; SECRET_KEY_BYTES]);

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
pub struct PublicKey([u8; PUBLIC_KEY_BYTES]);

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
pub struct Signature([u8; SIGNATURE_BYTES]);

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
///
/// # Security Note
///
/// `KeyNum` implements both `PartialEq` (standard comparison) and `ConstantTimeEq`
/// (constant-time comparison via the `subtle` crate). While keynums appear in
/// plaintext in signature files and are not secret, the verification path uses
/// constant-time comparison to prevent potential timing side-channels during
/// signature validation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyNum([u8; KEYNUM_BYTES]);

// H5: Implement ConstantTimeEq for KeyNum to enable constant-time comparison
// in the verification path, preventing timing side-channels
impl ConstantTimeEq for KeyNum {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

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

    /// Convert to hexadecimal key ID string (matches C minisign format)
    ///
    /// Formats the keynum as a 16-character uppercase hexadecimal string
    /// by interpreting the 8 bytes as a little-endian u64, matching the
    /// C minisign implementation's `le64_load()` + `%016PRIX64` format.
    #[must_use]
    pub fn to_key_id(&self) -> String {
        use crate::formats::read_u64_le;
        // KeyNum is always 8 bytes, so this should never fail
        let value = read_u64_le(&self.0).expect("KeyNum is always 8 bytes");
        format!("{value:016X}")
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

/// Calculate scrypt KDF parameters from `log_n` value
///
/// Converts a scrypt N parameter (expressed as log2(N)) into libsodium-compatible
/// opslimit and memlimit values using the standard formulas:
/// - opslimit = `LIBSODIUM_OPSLIMIT_MULTIPLIER` * N * r
/// - memlimit = `LIBSODIUM_MEMLIMIT_MULTIPLIER` * N * r
///
/// # Arguments
///
/// * `log_n` - The log2 of the scrypt N parameter
/// * `force_weak_kdf` - If true, use weaker parameters for testing (debug builds only)
///
/// # Returns
///
/// A tuple of (opslimit, memlimit) for use with scrypt
///
/// # Debug Mode
///
/// When compiled with debug assertions and `force_weak_kdf` is true, returns
/// deliberately weakened parameters (N=2^17) for faster testing. This prints
/// a warning to stderr.
///
/// # Errors
///
/// Returns `Error::ScryptParamError` if:
/// - `log_n >= 64` (would cause undefined behavior in bit shift)
/// - Arithmetic overflow occurs during parameter calculation
///
/// # Panics
///
/// Panics if `force_weak_kdf` is true in release builds (enforced by assertion).
pub fn calculate_kdf_params(log_n: u8, force_weak_kdf: bool) -> Result<(u64, u64)> {
    #[cfg(debug_assertions)]
    if force_weak_kdf {
        // DEBUG ONLY: Force weak parameters (N=2^17, 8x weaker than production)
        eprintln!("\n*** DEBUG WARNING: INTENTIONALLY INSECURE KEY ***");
        eprintln!("--force-weak-kdf creates keys that are 8x easier to brute-force.");
        eprintln!("NEVER use in production. For testing purposes only.\n");
        return Ok((4_194_304_u64, 134_217_728_u64)); // N=2^17, r=8
    }

    #[cfg(not(debug_assertions))]
    assert!(
        !force_weak_kdf,
        "force_weak_kdf must be false in release builds"
    );

    // M1: Bounds check to prevent undefined behavior
    // 1u64 << log_n requires log_n < 64
    if log_n >= 64 {
        return Err(Error::ScryptParamError(format!(
            "log_n must be < 64, got {log_n}"
        )));
    }

    let n = 1u64 << log_n;
    let r = u64::from(SCRYPT_R);

    // M1: Use checked arithmetic to prevent silent overflow
    let opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER
        .checked_mul(n)
        .and_then(|v| v.checked_mul(r))
        .ok_or_else(|| {
            Error::ScryptParamError(format!("overflow calculating opslimit for log_n={log_n}"))
        })?;

    let memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER
        .checked_mul(n)
        .and_then(|v| v.checked_mul(r))
        .ok_or_else(|| {
            Error::ScryptParamError(format!("overflow calculating memlimit for log_n={log_n}"))
        })?;

    Ok((opslimit, memlimit))
}

/// Convert libsodium-style opslimit/memlimit to scrypt parameters (`log_n`, r, p)
///
/// The C minisign implementation uses libsodium's scrypt interface, which
/// expresses work factors as `opslimit` and `memlimit`. These map to scrypt's
/// native parameters via:
/// - opslimit = `LIBSODIUM_OPSLIMIT_MULTIPLIER` * N * r
/// - memlimit = `LIBSODIUM_MEMLIMIT_MULTIPLIER` * N * r
///
/// # Algorithm
///
/// 1. Derives N from memlimit assuming standard r=8, p=1
/// 2. Computes `log_n` via checked integer log2
/// 3. Cross-validates against opslimit; falls back to deriving r from opslimit
///    if they disagree (handles non-standard parameters)
///
/// # Errors
///
/// Returns `Error::ScryptParamError` if N is zero, `log_n` overflows u8, or
/// arithmetic overflow occurs.
pub fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
    let r = SCRYPT_R;
    let p = SCRYPT_P;

    // N = memlimit / (LIBSODIUM_MEMLIMIT_MULTIPLIER * r)
    let divisor = LIBSODIUM_MEMLIMIT_MULTIPLIER
        .checked_mul(u64::from(r))
        .ok_or_else(|| Error::ScryptParamError("overflow calculating divisor".into()))?;

    let n = memlimit
        .checked_div(divisor)
        .ok_or_else(|| Error::ScryptParamError("division by zero".into()))?;

    if n == 0 {
        return Err(Error::ScryptParamError("N cannot be zero".into()));
    }

    let log_n = n
        .checked_ilog2()
        .and_then(|v| u8::try_from(v).ok())
        .ok_or_else(|| Error::ScryptParamError("log_n out of valid range".into()))?;

    // Verify consistency with opslimit
    let expected_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER
        .checked_mul(n)
        .and_then(|v| v.checked_mul(u64::from(r)))
        .ok_or_else(|| Error::ScryptParamError("overflow calculating expected opslimit".into()))?;

    if expected_opslimit != opslimit {
        // Non-standard parameters: derive r from opslimit
        // H3: Explicit error instead of silent fallback to prevent processing
        // corrupted/malicious keys with weaker-than-intended KDF parameters
        let derived_r = opslimit
            .checked_div(
                LIBSODIUM_OPSLIMIT_MULTIPLIER
                    .checked_mul(n)
                    .ok_or_else(|| {
                        Error::ScryptParamError("overflow calculating derived r".into())
                    })?,
            )
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| {
                Error::ScryptParamError(
                    "failed to derive r from opslimit: overflow or invalid value".into(),
                )
            })?;
        return Ok((log_n, derived_r, p));
    }

    Ok((log_n, r, p))
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
