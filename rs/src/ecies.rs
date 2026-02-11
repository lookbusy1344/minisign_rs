//! ECIES (Elliptic Curve Integrated Encryption Scheme) primitives
//!
//! Pure Rust cryptographic building blocks for hardware-backed key protection.
//! Uses P-256 ECDH + HKDF-SHA256 + AES-256-GCM.
//!
//! ## Security Properties
//!
//! - Ephemeral keys are generated fresh for each encryption
//! - ECDH shared secrets never leave this module
//! - All intermediate secrets are wrapped in `Zeroizing<>` for automatic memory wiping
//! - AES-256-GCM provides authenticated encryption (confidentiality + integrity)
//! - HKDF-SHA256 derives cryptographically independent keys from ECDH output
//!
//! ## ECIES Flow
//!
//! **Encryption:**
//! ```text
//! 1. Generate ephemeral P-256 keypair (e, E = eG)
//! 2. shared_secret = ECDH(e, peer_public)
//! 3. wrapping_key = HKDF-SHA256(shared_secret, salt="minisign-ecies-v1")
//! 4. (nonce, ciphertext, tag) = AES-256-GCM(wrapping_key, plaintext)
//! 5. Zeroize: e, shared_secret, wrapping_key
//! ```
//!
//! **Decryption:**
//! ```text
//! 1. shared_secret = ECDH(private_key, ephemeral_public)
//! 2. wrapping_key = HKDF-SHA256(shared_secret, salt="minisign-ecies-v1")
//! 3. plaintext = AES-256-GCM_decrypt(wrapping_key, nonce, ciphertext, tag)
//! 4. Zeroize: shared_secret, wrapping_key
//! ```

use crate::errors::{Error, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF context string for minisign ECIES key derivation
///
/// This string is used as the "info" parameter in HKDF to domain-separate
/// the derived wrapping key from other potential uses of the ECDH shared secret.
const HKDF_INFO: &[u8] = b"minisign-ecies-v1";

/// AES-256-GCM nonce size (12 bytes is standard)
pub const NONCE_SIZE: usize = 12;

/// AES-256-GCM authentication tag size
pub const TAG_SIZE: usize = 16;

/// AES-256 key size (256 bits = 32 bytes)
pub const WRAPPING_KEY_SIZE: usize = 32;

/// Generate an ephemeral P-256 keypair for ECIES encryption
///
/// The secret key should be used immediately for ECDH and then discarded.
/// The public key is included in the ciphertext for the recipient to perform ECDH.
///
/// # Returns
///
/// Returns `(secret, public)` where:
/// - `secret`: Ephemeral secret key (will be zeroized after ECDH)
/// - `public`: Ephemeral public key (included in ciphertext)
///
/// # Errors
///
/// Returns `Error::RngError` if the system RNG fails.
pub fn generate_ephemeral_p256() -> Result<(EphemeralSecret, PublicKey)> {
    let secret = EphemeralSecret::random(&mut rand_core::OsRng);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

/// Perform ECDH key agreement between an ephemeral secret and a peer's public key
///
/// This is the core primitive used in both encryption (with ephemeral secret)
/// and decryption (with hardware-held private key in Phase 2).
///
/// # Arguments
///
/// * `secret` - The ephemeral secret key (encryption) or hardware private key (decryption)
/// * `peer_public` - The peer's public key
///
/// # Returns
///
/// Returns the ECDH shared secret wrapped in `Zeroizing<>` for automatic memory wiping.
///
/// # Security
///
/// The shared secret is cryptographically sensitive and must not be used directly.
/// Always pass it to `derive_wrapping_key()` before use.
#[must_use]
pub fn ecdh(secret: &EphemeralSecret, peer_public: &PublicKey) -> Zeroizing<[u8; 32]> {
    let shared_secret = secret.diffie_hellman(peer_public);
    // Convert to raw bytes (zeroizing)
    Zeroizing::new(*shared_secret.raw_secret_bytes().as_ref())
}

/// Derive an AES-256 wrapping key from an ECDH shared secret using HKDF-SHA256
///
/// Uses a fixed salt ("minisign-ecies-v1") to domain-separate this key derivation
/// from other potential uses of the shared secret.
///
/// # Arguments
///
/// * `shared_secret` - The ECDH shared secret (32 bytes)
///
/// # Returns
///
/// Returns a 32-byte AES-256 key wrapped in `Zeroizing<>`.
///
/// # Security
///
/// HKDF ensures the derived key is cryptographically independent from the shared secret,
/// even if the shared secret has low entropy in some scenarios.
///
/// # Panics
///
/// Never panics. `WRAPPING_KEY_SIZE` (32 bytes) is always valid for HKDF-SHA256 output.
#[must_use]
pub fn derive_wrapping_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; WRAPPING_KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut wrapping_key = Zeroizing::new([0u8; WRAPPING_KEY_SIZE]);
    hkdf.expand(HKDF_INFO, &mut *wrapping_key)
        .expect("WRAPPING_KEY_SIZE is valid for HKDF-SHA256");
    wrapping_key
}

/// Encrypt plaintext using AES-256-GCM with a derived wrapping key
///
/// Generates a random nonce for each encryption. The nonce must be included
/// in the ciphertext for decryption.
///
/// # Arguments
///
/// * `wrapping_key` - 32-byte AES-256 key derived from ECDH
/// * `plaintext` - Data to encrypt (typically 104 bytes: keynum + `ed25519_sk` + checksum)
///
/// # Returns
///
/// Returns `(nonce, ciphertext, tag)` where:
/// - `nonce`: 12-byte random nonce
/// - `ciphertext`: Encrypted data (same length as plaintext)
/// - `tag`: 16-byte authentication tag
///
/// # Errors
///
/// Returns `Error::Other` if encryption fails (should never happen with valid inputs).
///
/// # Security
///
/// - Nonce is randomly generated (never reused with same key)
/// - GCM tag provides authenticated encryption (detects tampering)
/// - No additional authenticated data (AAD) is used
pub fn ecies_encrypt(
    wrapping_key: &[u8; WRAPPING_KEY_SIZE],
    plaintext: &[u8],
) -> Result<([u8; NONCE_SIZE], Vec<u8>, [u8; TAG_SIZE])> {
    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| Error::RngError(format!("Failed to generate nonce: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new(wrapping_key.into());

    // Encrypt (AES-GCM returns ciphertext || tag)
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| Error::other(format!("AES-GCM encryption failed: {e}")))?;

    // Split ciphertext and tag
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(Error::other("AES-GCM output too short"));
    }
    let (ciphertext, tag_slice) =
        ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG_SIZE);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    Ok((nonce_bytes, ciphertext.to_vec(), tag))
}

/// Decrypt ciphertext using AES-256-GCM with a derived wrapping key
///
/// Verifies the authentication tag to ensure ciphertext integrity.
///
/// # Arguments
///
/// * `wrapping_key` - 32-byte AES-256 key derived from ECDH
/// * `nonce` - 12-byte nonce used during encryption
/// * `ciphertext` - Encrypted data
/// * `tag` - 16-byte authentication tag
///
/// # Returns
///
/// Returns the decrypted plaintext wrapped in `Zeroizing<>`.
///
/// # Errors
///
/// Returns `Error::DecryptionFailed` if:
/// - Authentication tag verification fails (ciphertext was tampered with)
/// - Wrong key was used
/// - Nonce doesn't match
///
/// # Security
///
/// GCM tag verification is constant-time to prevent timing attacks.
pub fn ecies_decrypt(
    wrapping_key: &[u8; WRAPPING_KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    tag: &[u8; TAG_SIZE],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce_obj = Nonce::from_slice(nonce);

    // Create cipher
    let cipher = Aes256Gcm::new(wrapping_key.into());

    // Concatenate ciphertext and tag for aes-gcm crate
    let mut ciphertext_with_tag = ciphertext.to_vec();
    ciphertext_with_tag.extend_from_slice(tag);

    // Decrypt and verify tag
    let plaintext = cipher
        .decrypt(nonce_obj, ciphertext_with_tag.as_ref())
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ephemeral_p256() {
        // Should generate valid keypair
        let (_secret, public) = generate_ephemeral_p256().unwrap();

        // Public key should be valid (non-trivial test: can be used in ECDH)
        let (other_secret, _other_public) = generate_ephemeral_p256().unwrap();
        let _shared = ecdh(&other_secret, &public); // Should not panic

        // Multiple generations should produce different keys
        let (_, public2) = generate_ephemeral_p256().unwrap();
        assert_ne!(public.to_sec1_bytes(), public2.to_sec1_bytes());
    }

    #[test]
    fn test_ecdh_agreement() {
        // Alice generates keypair
        let (alice_secret, alice_public) = generate_ephemeral_p256().unwrap();

        // Bob generates keypair
        let (bob_secret, bob_public) = generate_ephemeral_p256().unwrap();

        // Both compute shared secret
        let alice_shared = ecdh(&alice_secret, &bob_public);
        let bob_shared = ecdh(&bob_secret, &alice_public);

        // Should match
        assert_eq!(&*alice_shared, &*bob_shared);
    }

    #[test]
    fn test_derive_wrapping_key() {
        let shared_secret = [0x42u8; 32];
        let key1 = derive_wrapping_key(&shared_secret);
        let key2 = derive_wrapping_key(&shared_secret);

        // Deterministic
        assert_eq!(&*key1, &*key2);

        // Non-trivial (not all zeros)
        assert_ne!(&*key1, &[0u8; 32]);

        // Different input produces different key
        let different_secret = [0x43u8; 32];
        let key3 = derive_wrapping_key(&different_secret);
        assert_ne!(&*key1, &*key3);
    }

    #[test]
    fn test_ecies_roundtrip() {
        let plaintext = b"Hello, ECIES!";

        // Generate key
        let shared_secret = [0x42u8; 32];
        let wrapping_key = derive_wrapping_key(&shared_secret);

        // Encrypt
        let (nonce, ciphertext, tag) = ecies_encrypt(&wrapping_key, plaintext).unwrap();

        // Decrypt
        let decrypted = ecies_decrypt(&wrapping_key, &nonce, &ciphertext, &tag).unwrap();

        assert_eq!(&**decrypted, plaintext);
    }

    #[test]
    fn test_ecies_wrong_key() {
        let plaintext = b"Secret message";

        // Encrypt with one key
        let key1 = derive_wrapping_key(&[0x42u8; 32]);
        let (nonce, ciphertext, tag) = ecies_encrypt(&key1, plaintext).unwrap();

        // Try to decrypt with different key
        let key2 = derive_wrapping_key(&[0x43u8; 32]);
        let result = ecies_decrypt(&key2, &nonce, &ciphertext, &tag);

        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_ecies_tampered_ciphertext() {
        let plaintext = b"Secret message";

        let key = derive_wrapping_key(&[0x42u8; 32]);
        let (nonce, mut ciphertext, tag) = ecies_encrypt(&key, plaintext).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = ecies_decrypt(&key, &nonce, &ciphertext, &tag);
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_ecies_tampered_tag() {
        let plaintext = b"Secret message";

        let key = derive_wrapping_key(&[0x42u8; 32]);
        let (nonce, ciphertext, mut tag) = ecies_encrypt(&key, plaintext).unwrap();

        // Tamper with tag
        tag[0] ^= 0xFF;

        let result = ecies_decrypt(&key, &nonce, &ciphertext, &tag);
        assert!(matches!(result, Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_ecies_nonce_uniqueness() {
        // Statistical test: generate N encryptions and check nonce uniqueness
        const N: usize = 100;
        let plaintext = b"Test message";
        let key = derive_wrapping_key(&[0x42u8; 32]);

        let mut nonces = Vec::new();

        for _ in 0..N {
            let (nonce, _, _) = ecies_encrypt(&key, plaintext).unwrap();
            nonces.push(nonce);
        }

        // Check all nonces are unique
        for i in 0..N {
            for j in (i + 1)..N {
                assert_ne!(
                    nonces[i], nonces[j],
                    "Nonce collision detected (extremely unlikely!)"
                );
            }
        }
    }

    #[test]
    fn test_ecies_104_byte_blob() {
        // Test with 104-byte blob (matching ENCRYPTED_BLOB_SIZE from plan)
        let plaintext = [0x42u8; 104];

        let key = derive_wrapping_key(&[0x01u8; 32]);
        let (nonce, ciphertext, tag) = ecies_encrypt(&key, &plaintext).unwrap();

        assert_eq!(ciphertext.len(), 104);
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert_eq!(tag.len(), TAG_SIZE);

        let decrypted = ecies_decrypt(&key, &nonce, &ciphertext, &tag).unwrap();
        assert_eq!(&**decrypted, &plaintext);
    }

    #[test]
    fn test_full_ecies_flow() {
        // Simulate full ECIES: Alice encrypts to Bob's public key
        let plaintext = b"Top secret data";

        // Bob generates keypair (simulating hardware key)
        let (bob_secret, bob_public) = generate_ephemeral_p256().unwrap();

        // Alice encrypts:
        // 1. Generate ephemeral keypair
        let (alice_ephemeral_secret, alice_ephemeral_public) = generate_ephemeral_p256().unwrap();

        // 2. ECDH with Bob's public key
        let alice_shared = ecdh(&alice_ephemeral_secret, &bob_public);

        // 3. Derive wrapping key
        let alice_wrapping_key = derive_wrapping_key(&alice_shared);

        // 4. Encrypt
        let (nonce, ciphertext, tag) = ecies_encrypt(&alice_wrapping_key, plaintext).unwrap();

        // Bob decrypts:
        // 1. ECDH with Alice's ephemeral public key
        let bob_shared = ecdh(&bob_secret, &alice_ephemeral_public);

        // 2. Derive wrapping key (should match Alice's)
        let bob_wrapping_key = derive_wrapping_key(&bob_shared);
        assert_eq!(&*alice_wrapping_key, &*bob_wrapping_key);

        // 3. Decrypt
        let decrypted = ecies_decrypt(&bob_wrapping_key, &nonce, &ciphertext, &tag).unwrap();

        assert_eq!(&**decrypted, plaintext);
    }
}
