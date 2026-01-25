//! Signature creation operations
//!
//! This module implements the core signing logic for minisign.

use crate::{
    Result,
    crypto::{SecretKey, blake2b_512_stream, sign as crypto_sign},
    errors::Error,
    keys::SeckeyStruct,
    signature::{SigStruct, SignatureBox},
};
use std::path::Path;

/// Options for signing files
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Path to the secret key file
    pub secret_key_file: String,
    /// Path to the message file
    pub message_file: String,
    /// Path to output signature file (optional, defaults to `message_file.minisig`)
    pub signature_file: Option<String>,
    /// Use prehashed mode (hash the message with Blake2b-512 before signing)
    pub prehashed: bool,
    /// Trusted comment to include in the signature
    pub trusted_comment: Option<String>,
    /// Untrusted comment to include in the signature
    pub untrusted_comment: Option<String>,
    /// Force overwrite existing signature file
    pub force: bool,
}

/// Result of signing operation
#[derive(Debug, Clone)]
pub struct SignResult {
    /// Path where the signature was written
    pub signature_file: String,
    /// The trusted comment used
    pub trusted_comment: String,
}

/// Sign a file with a secret key
///
/// # Arguments
///
/// * `options` - Signing options including key, message, and comment settings
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `SignResult` containing the signature file path and trusted comment
///
/// # Errors
///
/// Returns an error if:
/// - The secret key cannot be loaded or decrypted
/// - The message file cannot be read
/// - The signature file already exists (unless force is true)
/// - File I/O operations fail
pub fn sign(options: &SignOptions, password: Option<&[u8]>) -> Result<SignResult> {
    // Load and decrypt the secret key
    let seckey = load_secret_key(&options.secret_key_file)?;
    let (secret_key, keynum) = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        (seckey.get_unencrypted_secret_key()?, *seckey.keynum())
    };

    // Determine the signature file path
    let sig_file_path = options
        .signature_file
        .clone()
        .unwrap_or_else(|| format!("{}.minisig", options.message_file));

    // Check if signature file exists (unless force is set)
    if !options.force && Path::new(&sig_file_path).exists() {
        return Err(Error::FileExists(sig_file_path.into()));
    }

    // Create the signature
    let sig_box = create_signature(
        &secret_key,
        keynum,
        &options.message_file,
        options.prehashed,
        options.trusted_comment.as_deref(),
        options.untrusted_comment.as_deref(),
    )?;

    // Write the signature file
    let sig_contents = sig_box.to_file_contents();
    std::fs::write(&sig_file_path, sig_contents)
        .map_err(|e| Error::file_write(&sig_file_path, e))?;

    Ok(SignResult {
        signature_file: sig_file_path,
        trusted_comment: sig_box.trusted_comment().to_string(),
    })
}

/// Load a secret key from a file
fn load_secret_key(path: impl AsRef<Path>) -> Result<SeckeyStruct> {
    let contents =
        std::fs::read_to_string(path.as_ref()).map_err(|e| Error::file_read(path.as_ref(), e))?;
    SeckeyStruct::from_file_contents(&contents)
}

/// Create a signature for a message
fn create_signature(
    secret_key: &SecretKey,
    keynum: crate::crypto::KeyNum,
    message_file: &str,
    prehashed: bool,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
) -> Result<SignatureBox> {
    // Determine what data to sign
    let data_to_sign = if prehashed {
        // Open file and stream hash
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        blake2b_512_stream(file)?.to_vec()
    } else {
        // For non-prehashed mode, we need the full message in memory
        // (Ed25519 requires the full message for signing)
        std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
    };

    // Sign the message
    let signature = crypto_sign(secret_key, &data_to_sign)?;

    // Create the SigStruct
    let sig_struct = SigStruct::new(keynum, signature, prehashed);

    // Generate trusted comment if not provided
    let trusted_comment =
        trusted_comment.map_or_else(generate_default_trusted_comment, String::from);

    // Generate untrusted comment if not provided
    let untrusted_comment = untrusted_comment.map_or_else(
        || "signature from minisign secret key".to_string(),
        String::from,
    );

    // Create global signature (signs: signature_bytes || trusted_comment)
    let global_sig_data = create_global_signature_data(&sig_struct, &trusted_comment);
    let global_signature = crypto_sign(secret_key, &global_sig_data)?;

    Ok(SignatureBox::new(
        untrusted_comment,
        sig_struct,
        trusted_comment,
        global_signature,
    ))
}

/// Create the data that the global signature signs
fn create_global_signature_data(sig_struct: &SigStruct, trusted_comment: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(sig_struct.signature().as_bytes());
    data.extend_from_slice(trusted_comment.as_bytes());
    data
}

/// Generate a default trusted comment with timestamp
fn generate_default_trusted_comment() -> String {
    // Get current timestamp in UTC
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    format!("timestamp:{timestamp}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{blake2b_512, verify as crypto_verify},
        keys::PubkeyStruct,
    };
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_sign_unencrypted_key() {
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");
        let sig_path = temp_dir.path().join("message.txt.minisig");

        // Create a test message
        fs::write(&message_path, b"Hello, World!").unwrap();

        let options = SignOptions {
            secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
            message_file: message_path.display().to_string(),
            signature_file: Some(sig_path.display().to_string()),
            prehashed: true,
            trusted_comment: Some("Test signature".to_string()),
            untrusted_comment: Some("Test".to_string()),
            force: false,
        };

        let result = sign(&options, None).expect("signing should succeed");
        assert_eq!(result.signature_file, sig_path.display().to_string());
        assert_eq!(result.trusted_comment, "Test signature");

        // Verify the signature file was created
        assert!(sig_path.exists());

        // Verify the signature is valid
        let sig_contents = fs::read_to_string(&sig_path).unwrap();
        let sig_box = SignatureBox::from_file_contents(&sig_contents).unwrap();

        let pubkey_contents = fs::read_to_string("tests/fixtures/keys/unencrypted.pub").unwrap();
        let pubkey = PubkeyStruct::from_file_contents(&pubkey_contents).unwrap();

        let message = fs::read(&message_path).unwrap();
        let data_to_verify = blake2b_512(&message);

        crypto_verify(
            pubkey.public_key(),
            &data_to_verify,
            sig_box.sig_struct().signature(),
        )
        .expect("signature should verify");

        sig_box
            .verify_global_signature(pubkey.public_key())
            .expect("global signature should verify");
    }

    #[test]
    #[ignore = "slow test due to scrypt SENSITIVE parameters (N=2^20, ~1-5 seconds)"]
    fn test_sign_encrypted_key() {
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");
        let sig_path = temp_dir.path().join("message.txt.minisig");

        fs::write(&message_path, b"Secret message").unwrap();

        let options = SignOptions {
            secret_key_file: "tests/fixtures/keys/test.key".to_string(),
            message_file: message_path.display().to_string(),
            signature_file: Some(sig_path.display().to_string()),
            prehashed: true,
            trusted_comment: None,
            untrusted_comment: None,
            force: false,
        };

        let password = b"test";
        let result = sign(&options, Some(password)).expect("signing should succeed");
        assert!(sig_path.exists());
        assert!(result.trusted_comment.starts_with("timestamp:"));
    }

    #[test]
    fn test_sign_encrypted_key_fast() {
        // Fast variant using a test fixture with N=2^14 instead of N=2^20
        // First, generate a fast encrypted key for testing
        use crate::crypto::generate_keypair;
        use crate::keys::SeckeyStruct;

        let temp_dir = TempDir::new().unwrap();

        // Generate a test key with weak scrypt parameters
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
        let password = b"testpass";
        let mut kdf_salt = [0u8; 32];
        getrandom::getrandom(&mut kdf_salt).unwrap();

        // Use N=2^14 for fast testing (~50ms)
        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .unwrap();

        // Write the test key file
        let sk_path = temp_dir.path().join("fast_test.key");
        let sk_contents = seckey.to_file_contents("test key");
        fs::write(&sk_path, sk_contents).unwrap();

        // Now test signing with it
        let message_path = temp_dir.path().join("message.txt");
        let sig_path = temp_dir.path().join("message.txt.minisig");
        fs::write(&message_path, b"Fast test message").unwrap();

        let options = SignOptions {
            secret_key_file: sk_path.display().to_string(),
            message_file: message_path.display().to_string(),
            signature_file: Some(sig_path.display().to_string()),
            prehashed: true,
            trusted_comment: Some("Fast test".to_string()),
            untrusted_comment: None,
            force: false,
        };

        let result = sign(&options, Some(password)).expect("signing should succeed");
        assert!(sig_path.exists());
        assert_eq!(result.trusted_comment, "Fast test");
    }

    #[test]
    fn test_sign_without_password_fails() {
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");

        fs::write(&message_path, b"Message").unwrap();

        let options = SignOptions {
            secret_key_file: "tests/fixtures/keys/test.key".to_string(),
            message_file: message_path.display().to_string(),
            signature_file: None,
            prehashed: false,
            trusted_comment: None,
            untrusted_comment: None,
            force: false,
        };

        let result = sign(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
    }

    #[test]
    fn test_sign_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");
        let sig_path = temp_dir.path().join("message.txt.minisig");

        fs::write(&message_path, b"Message").unwrap();
        fs::write(&sig_path, b"Existing signature").unwrap();

        let options = SignOptions {
            secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
            message_file: message_path.display().to_string(),
            signature_file: Some(sig_path.display().to_string()),
            prehashed: false,
            trusted_comment: None,
            untrusted_comment: None,
            force: true,
        };

        sign(&options, None).expect("should overwrite with force=true");
    }

    #[test]
    fn test_sign_without_force_fails() {
        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");
        let sig_path = temp_dir.path().join("message.txt.minisig");

        fs::write(&message_path, b"Message").unwrap();
        fs::write(&sig_path, b"Existing signature").unwrap();

        let options = SignOptions {
            secret_key_file: "tests/fixtures/keys/unencrypted.key".to_string(),
            message_file: message_path.display().to_string(),
            signature_file: Some(sig_path.display().to_string()),
            prehashed: false,
            trusted_comment: None,
            untrusted_comment: None,
            force: false,
        };

        let result = sign(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
    }

    #[test]
    fn test_create_global_signature_data() {
        use crate::crypto::{KeyNum, Signature};

        let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let signature = Signature::from_bytes([42; 64]);
        let sig_struct = SigStruct::new(keynum, signature, false);
        let trusted_comment = "test comment";

        let data = create_global_signature_data(&sig_struct, trusted_comment);

        // Should be signature bytes followed by trusted comment
        assert_eq!(data.len(), 64 + trusted_comment.len());
        assert_eq!(&data[0..64], signature.as_bytes());
        assert_eq!(&data[64..], trusted_comment.as_bytes());
    }

    #[test]
    fn test_generate_default_trusted_comment() {
        let comment = generate_default_trusted_comment();
        assert!(comment.starts_with("timestamp:"));

        // Parse the timestamp to ensure it's valid
        let timestamp_str = comment.strip_prefix("timestamp:").unwrap();
        let timestamp: u64 = timestamp_str.parse().expect("should be valid number");
        assert!(timestamp > 0);
    }

    #[test]
    fn test_load_secret_key() {
        let seckey =
            load_secret_key("tests/fixtures/keys/unencrypted.key").expect("should load secret key");
        assert!(!seckey.is_encrypted());

        let seckey =
            load_secret_key("tests/fixtures/keys/test.key").expect("should load encrypted key");
        assert!(seckey.is_encrypted());
    }

    #[test]
    fn test_sign_prehashed_vs_normal() {
        use crate::crypto::generate_keypair;
        use std::fs;

        let temp_dir = TempDir::new().unwrap();
        let message_path = temp_dir.path().join("message.txt");
        let message = b"Test message for prehashed comparison";
        fs::write(&message_path, message).unwrap();

        // Generate a temporary keypair
        let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

        // Create prehashed signature
        let sig_prehashed = create_signature(
            &secret_key,
            keynum,
            message_path.to_str().unwrap(),
            true,
            Some("test"),
            None,
        )
        .unwrap();

        // Create normal signature
        let sig_normal = create_signature(
            &secret_key,
            keynum,
            message_path.to_str().unwrap(),
            false,
            Some("test"),
            None,
        )
        .unwrap();

        // They should have different sig_alg indicators
        assert!(sig_prehashed.sig_struct().is_prehashed());
        assert!(!sig_normal.sig_struct().is_prehashed());

        // The actual signature bytes should be different
        assert_ne!(
            sig_prehashed.sig_struct().signature().as_bytes(),
            sig_normal.sig_struct().signature().as_bytes()
        );
    }

    #[test]
    fn test_sign_large_file_streaming() {
        use crate::crypto::{blake2b_512_stream, generate_keypair, verify as crypto_verify};
        use std::fs;

        let temp_dir = TempDir::new().unwrap();

        // Generate a 1MB file
        let large_file = temp_dir.path().join("large.bin");
        let data = vec![42u8; 1024 * 1024]; // 1MB
        fs::write(&large_file, data).unwrap();

        // Generate keypair
        let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");

        // Sign in prehashed mode (uses streaming)
        let sig_box = create_signature(
            &secret_key,
            keynum,
            large_file.to_str().unwrap(),
            true,
            Some("large file test"),
            None,
        )
        .expect("signing large file should succeed");

        // Verify we got a valid signature
        assert!(sig_box.sig_struct().is_prehashed());

        // Verify the signature is valid
        let file = fs::File::open(&large_file).unwrap();
        let hash = blake2b_512_stream(file).unwrap();
        crypto_verify(&public_key, &hash, sig_box.sig_struct().signature())
            .expect("signature should verify");
    }
}
