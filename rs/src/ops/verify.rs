//! Signature verification operations
//!
//! This module implements the core verification logic for minisign signatures.

use crate::{
    Result,
    crypto::{blake2b_512_stream, verify as crypto_verify},
    errors::Error,
    keys::PubkeyStruct,
    signature::SignatureBox,
};
use std::path::Path;

/// Options for signature verification
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Public key (either from file or provided directly)
    pub public_key: PublicKeySource,
    /// Path to the signature file
    pub signature_file: String,
    /// Path to the message file
    pub message_file: String,
    /// Output verification result to stdout
    pub output: bool,
    /// Quiet mode (no output)
    pub quiet: bool,
}

/// Source of the public key
#[derive(Debug, Clone)]
pub enum PublicKeySource {
    /// Read from a file
    File(String),
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

    Ok(VerifyResult {
        valid: true,
        trusted_comment: sig_box.trusted_comment().to_string(),
        untrusted_comment: sig_box.untrusted_comment().to_string(),
    })
}

/// Load a public key from the specified source
fn load_public_key(source: &PublicKeySource) -> Result<PubkeyStruct> {
    match source {
        PublicKeySource::File(path) => {
            let contents =
                std::fs::read_to_string(path).map_err(|e| Error::file_read(path.clone(), e))?;
            PubkeyStruct::from_file_contents(&contents)
        }
        PublicKeySource::Base64(base64_str) => {
            // For base64 input, we expect just the encoded PubkeyStruct without comment
            PubkeyStruct::from_base64(base64_str)
        }
    }
}

/// Load a signature from a file
fn load_signature(path: impl AsRef<Path>) -> Result<SignatureBox> {
    let contents =
        std::fs::read_to_string(path.as_ref()).map_err(|e| Error::file_read(path.as_ref(), e))?;
    SignatureBox::from_file_contents(&contents)
}

/// Verify the message signature, handling prehashed mode
fn verify_message_signature(
    pubkey: &PubkeyStruct,
    sig_box: &SignatureBox,
    message_file: &str,
) -> Result<()> {
    // First, verify that the keynum matches
    if pubkey.keynum() != sig_box.sig_struct().keynum() {
        return Err(Error::KeyMismatch {
            sig_keynum: sig_box.sig_struct().keynum().to_hex(),
            pub_keynum: pubkey.keynum().to_hex(),
        });
    }

    // For prehashed signatures, we stream hash the message
    // For non-prehashed, we need the full message in memory
    let data_to_verify = if sig_box.sig_struct().is_prehashed() {
        let file =
            std::fs::File::open(message_file).map_err(|e| Error::file_read(message_file, e))?;
        blake2b_512_stream(file)?.to_vec()
    } else {
        std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?
    };

    // Verify the Ed25519 signature
    crypto_verify(
        pubkey.public_key(),
        &data_to_verify,
        sig_box.sig_struct().signature(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_verify_c_generated_signature() {
        let options = VerifyOptions {
            public_key: PublicKeySource::File("tests/fixtures/keys/unencrypted.pub".to_string()),
            signature_file: "tests/fixtures/signatures/hello.txt.minisig".to_string(),
            message_file: "tests/fixtures/messages/hello.txt".to_string(),
            output: false,
            quiet: false,
        };

        let result = verify(&options).expect("verification should succeed");
        assert!(result.valid);
        assert_eq!(result.trusted_comment, "Signed with Rust test key");
        assert_eq!(result.untrusted_comment, "Test signature");
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        // Create a temporary wrong message file
        let temp_dir = tempfile::tempdir().unwrap();
        let wrong_message_path = temp_dir.path().join("wrong.txt");
        fs::write(&wrong_message_path, b"Wrong message").unwrap();

        let options = VerifyOptions {
            public_key: PublicKeySource::File("tests/fixtures/keys/unencrypted.pub".to_string()),
            signature_file: "tests/fixtures/signatures/hello.txt.minisig".to_string(),
            message_file: wrong_message_path.display().to_string(),
            output: false,
            quiet: false,
        };

        let result = verify(&options);
        assert!(result.is_err(), "should fail with wrong message");
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let options = VerifyOptions {
            public_key: PublicKeySource::File("tests/fixtures/keys/test.pub".to_string()),
            signature_file: "tests/fixtures/signatures/hello.txt.minisig".to_string(),
            message_file: "tests/fixtures/messages/hello.txt".to_string(),
            output: false,
            quiet: false,
        };

        let result = verify(&options);
        assert!(result.is_err(), "should fail with wrong public key");
    }

    #[test]
    fn test_verify_nonexistent_file() {
        let options = VerifyOptions {
            public_key: PublicKeySource::File("tests/fixtures/keys/unencrypted.pub".to_string()),
            signature_file: "tests/fixtures/signatures/hello.txt.minisig".to_string(),
            message_file: "nonexistent.txt".to_string(),
            output: false,
            quiet: false,
        };

        let result = verify(&options);
        assert!(result.is_err(), "should fail with nonexistent message file");
    }

    #[test]
    fn test_load_public_key_from_file() {
        let source = PublicKeySource::File("tests/fixtures/keys/unencrypted.pub".to_string());
        let pubkey = load_public_key(&source).expect("should load public key");
        assert_eq!(pubkey.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_load_signature() {
        let sig_box = load_signature("tests/fixtures/signatures/hello.txt.minisig")
            .expect("should load signature");
        assert_eq!(sig_box.untrusted_comment(), "Test signature");
    }

    #[test]
    fn test_verify_message_signature_prehashed() {
        // Load fixtures
        let pubkey_contents = fs::read_to_string("tests/fixtures/keys/unencrypted.pub").unwrap();
        let pubkey = PubkeyStruct::from_file_contents(&pubkey_contents).unwrap();

        let sig_contents =
            fs::read_to_string("tests/fixtures/signatures/hello.txt.minisig").unwrap();
        let sig_box = SignatureBox::from_file_contents(&sig_contents).unwrap();

        let message_file = "tests/fixtures/messages/hello.txt";

        // Should succeed with correct message
        verify_message_signature(&pubkey, &sig_box, message_file)
            .expect("should verify correct message");

        // Should fail with wrong message (create a temp file with wrong content)
        let temp_dir = tempfile::tempdir().unwrap();
        let wrong_message_file = temp_dir.path().join("wrong.txt");
        fs::write(&wrong_message_file, b"Wrong message").unwrap();

        let result =
            verify_message_signature(&pubkey, &sig_box, wrong_message_file.to_str().unwrap());
        assert!(result.is_err(), "should fail with wrong message");
    }
}

/// Test that verification fails when keynum doesn't match
#[test]
fn test_verify_with_wrong_keynum() {
    use crate::crypto::generate_keypair;
    use crate::keys::{PubkeyStruct, SeckeyStruct};
    use crate::ops::sign::{SignOptions, sign};
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    let secret_key_file = temp_dir.path().join("test.key");
    let public_key_file = temp_dir.path().join("test.pub");
    let wrong_pubkey_file = temp_dir.path().join("wrong.pub");

    // Create a message
    std::fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate first keypair
    let (secret_key1, public_key1, keynum1) = generate_keypair().expect("RNG should work");
    let seckey1 = SeckeyStruct::new_unencrypted(keynum1, &secret_key1);
    let pubkey1 = PubkeyStruct::new(keynum1, public_key1);

    // Generate second keypair with different keynum
    let (_, public_key2, keynum2) = generate_keypair().expect("RNG should work");
    let pubkey2 = PubkeyStruct::new(keynum2, public_key2);

    // Save keys
    std::fs::write(&secret_key_file, seckey1.to_file_contents("test key 1")).expect("write failed");
    std::fs::write(&public_key_file, pubkey1.to_file_contents("test key 1")).expect("write failed");
    std::fs::write(&wrong_pubkey_file, pubkey2.to_file_contents("test key 2"))
        .expect("write failed");

    // Sign with key 1
    let sign_opts = SignOptions {
        secret_key_file: secret_key_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        signature_file: Some(sig_file.to_str().unwrap().to_string()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("sign should succeed");

    // Try to verify with key 2 (different keynum) - should fail
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(wrong_pubkey_file.to_str().unwrap().to_string()),
        signature_file: sig_file.to_str().unwrap().to_string(),
        message_file: message_file.to_str().unwrap().to_string(),
        output: false,
        quiet: false,
    };

    let result = verify(&verify_opts);
    assert!(result.is_err(), "Should fail when keynum doesn't match");

    // Verify the error is KeyMismatch
    if let Err(e) = result {
        match e {
            Error::KeyMismatch { .. } => (), // Expected
            _ => panic!("Expected KeyMismatch error, got: {e:?}"),
        }
    }
}
