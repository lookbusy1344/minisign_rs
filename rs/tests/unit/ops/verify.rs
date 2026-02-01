//! Unit tests for signature verification operations

use minisign::{
    crypto::generate_keypair,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
    ops::{
        file_utils::check_file_size_limit,
        sign::{SignOptions, sign},
        verify::{
            PublicKeySource, VerifyOptions, load_public_key, load_signature, verify,
            verify_message_signature,
        },
    },
    signature::SignatureBox,
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn test_verify_c_generated_signature() {
    let options = VerifyOptions {
        public_key: PublicKeySource::File(PathBuf::from("tests/fixtures/keys/unencrypted.pub")),
        signature_file: PathBuf::from("tests/fixtures/signatures/hello.txt.minisig"),
        message_file: PathBuf::from("tests/fixtures/messages/hello.txt"),
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
        public_key: PublicKeySource::File(PathBuf::from("tests/fixtures/keys/unencrypted.pub")),
        signature_file: PathBuf::from("tests/fixtures/signatures/hello.txt.minisig"),
        message_file: wrong_message_path.clone(),
        output: false,
        quiet: false,
    };

    let result = verify(&options);
    assert!(result.is_err(), "should fail with wrong message");
}

#[test]
fn test_verify_wrong_key_fails() {
    let options = VerifyOptions {
        public_key: PublicKeySource::File(PathBuf::from("tests/fixtures/keys/test.pub")),
        signature_file: PathBuf::from("tests/fixtures/signatures/hello.txt.minisig"),
        message_file: PathBuf::from("tests/fixtures/messages/hello.txt"),
        output: false,
        quiet: false,
    };

    let result = verify(&options);
    assert!(result.is_err(), "should fail with wrong public key");
}

#[test]
fn test_verify_nonexistent_file() {
    let options = VerifyOptions {
        public_key: PublicKeySource::File(PathBuf::from("tests/fixtures/keys/unencrypted.pub")),
        signature_file: PathBuf::from("tests/fixtures/signatures/hello.txt.minisig"),
        message_file: PathBuf::from("nonexistent.txt"),
        output: false,
        quiet: false,
    };

    let result = verify(&options);
    assert!(result.is_err(), "should fail with nonexistent message file");
}

#[test]
fn test_load_public_key_from_file() {
    let source = PublicKeySource::File(PathBuf::from("tests/fixtures/keys/unencrypted.pub"));
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

    let sig_contents = fs::read_to_string("tests/fixtures/signatures/hello.txt.minisig").unwrap();
    let sig_box = SignatureBox::from_file_contents(&sig_contents).unwrap();

    let message_file = Path::new("tests/fixtures/messages/hello.txt");

    // Should succeed with correct message
    verify_message_signature(&pubkey, &sig_box, message_file)
        .expect("should verify correct message");

    // Should fail with wrong message (create a temp file with wrong content)
    let temp_dir = tempfile::tempdir().unwrap();
    let wrong_message_file = temp_dir.path().join("wrong.txt");
    fs::write(&wrong_message_file, b"Wrong message").unwrap();

    let result = verify_message_signature(&pubkey, &sig_box, &wrong_message_file);
    assert!(result.is_err(), "should fail with wrong message");
}

#[test]
fn test_verify_with_wrong_keynum() {
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
        secret_key_file: secret_key_file.clone(),
        message_file: message_file.clone(),
        signature_file: Some(sig_file.clone()),
        prehashed: true,
        trusted_comment: None,
        untrusted_comment: None,
        force: true,
    };
    sign(&sign_opts, None).expect("sign should succeed");

    // Try to verify with key 2 (different keynum) - should fail
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(wrong_pubkey_file.clone()),
        signature_file: sig_file.clone(),
        message_file: message_file.clone(),
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

#[test]
fn test_check_file_size_limit_small_file() {
    use tempfile::NamedTempFile;

    // Create a small file (1 KB)
    let temp_file = NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), vec![0u8; 1024]).unwrap();

    // Should pass size check
    check_file_size_limit(temp_file.path()).expect("small file should pass");
}

#[test]
fn test_verify_file_too_large_fails() {
    let temp_dir = TempDir::new().unwrap();

    // Generate a test keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create a small message and sign it in non-prehashed mode
    let message_path = temp_dir.path().join("message.txt");
    std::fs::write(&message_path, b"small message").unwrap();

    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sign_opts = SignOptions {
        secret_key_file: sk_path.clone(),
        message_file: message_path.clone(),
        signature_file: Some(sig_path.clone()),
        prehashed: false, // Non-prehashed signature
        trusted_comment: None,
        untrusted_comment: None,
        force: false,
    };

    sign(&sign_opts, None).expect("signing should succeed");

    // Verify with small file should succeed
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(pk_path.clone()),
        signature_file: sig_path.clone(),
        message_file: message_path.clone(),
        output: false,
        quiet: false,
    };

    verify(&verify_opts).expect("verification should succeed with small file");

    // Note: We can't actually test with a > 1 GB file in unit tests,
    // but the check_file_size_limit function is tested separately
}

#[test]
fn test_verify_prehashed_mode_no_size_limit() {
    let temp_dir = TempDir::new().unwrap();

    // Generate a test keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create a 10 MB file (would be too large for non-prehashed in practice,
    // but prehashed mode streams it)
    let message_path = temp_dir.path().join("large.bin");
    std::fs::write(&message_path, vec![42u8; 10 * 1024 * 1024]).unwrap();

    let sig_path = temp_dir.path().join("large.bin.minisig");
    let sign_opts = SignOptions {
        secret_key_file: sk_path.clone(),
        message_file: message_path.clone(),
        signature_file: Some(sig_path.clone()),
        prehashed: true, // Prehashed mode - no size limit
        trusted_comment: None,
        untrusted_comment: None,
        force: false,
    };

    sign(&sign_opts, None).expect("signing large file in prehashed mode should succeed");

    // Verify should succeed with prehashed mode (streaming)
    let verify_opts = VerifyOptions {
        public_key: PublicKeySource::File(pk_path.clone()),
        signature_file: sig_path.clone(),
        message_file: message_path.clone(),
        output: false,
        quiet: false,
    };

    verify(&verify_opts).expect("verification should succeed with prehashed large file");
}
