//! Unit tests for signature verification operations

use minisign::{
    crypto::generate_keypair,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
    ops::{
        sign::{SignOptions, sign},
        verify::{
            PublicKeySource, VerifyOptions, load_public_key, load_signature, verify,
            verify_message_signature,
        },
    },
    signature::SignatureBox,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_verify_c_generated_signature() {
    let options = VerifyOptions::builder(
        PublicKeySource::File(Path::new("tests/fixtures/keys/unencrypted.pub")),
        Path::new("tests/fixtures/signatures/hello.txt.minisig"),
        Path::new("tests/fixtures/messages/hello.txt"),
    )
    .build();

    let result = verify(&options).expect("verification should succeed");
    // Note: If verify() succeeds, the signature is valid (failures return Err)
    assert_eq!(result.trusted_comment(), "Signed with Rust test key");
    assert_eq!(result.untrusted_comment(), "Test signature");
}

#[test]
fn test_verify_wrong_message_fails() {
    // Create a temporary wrong message file
    let temp_dir = tempfile::tempdir().unwrap();
    let wrong_message_path = temp_dir.path().join("wrong.txt");
    fs::write(&wrong_message_path, b"Wrong message").unwrap();

    let options = VerifyOptions::builder(
        PublicKeySource::File(Path::new("tests/fixtures/keys/unencrypted.pub")),
        Path::new("tests/fixtures/signatures/hello.txt.minisig"),
        wrong_message_path.as_path(),
    )
    .build();

    let result = verify(&options);
    assert!(result.is_err(), "should fail with wrong message");
}

#[test]
fn test_verify_wrong_key_fails() {
    let options = VerifyOptions::builder(
        PublicKeySource::File(Path::new("tests/fixtures/keys/test.pub")),
        Path::new("tests/fixtures/signatures/hello.txt.minisig"),
        Path::new("tests/fixtures/messages/hello.txt"),
    )
    .build();

    let err = verify(&options).unwrap_err();
    assert!(
        matches!(err, Error::KeyMismatch { .. }),
        "wrong key must fail with KeyMismatch, got: {err}"
    );
}

#[test]
fn test_verify_nonexistent_file() {
    let options = VerifyOptions::builder(
        PublicKeySource::File(Path::new("tests/fixtures/keys/unencrypted.pub")),
        Path::new("tests/fixtures/signatures/hello.txt.minisig"),
        Path::new("nonexistent.txt"),
    )
    .build();

    let err = verify(&options).unwrap_err();
    assert!(
        matches!(err, Error::FileRead { .. }),
        "nonexistent file must fail with FileRead, got: {err}"
    );
}

#[test]
fn test_load_public_key_from_file() {
    let source = PublicKeySource::File(Path::new("tests/fixtures/keys/unencrypted.pub"));
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
    verify_message_signature(&pubkey, &sig_box, message_file, false, false)
        .expect("should verify correct message");

    // Should fail with wrong message (create a temp file with wrong content)
    let temp_dir = tempfile::tempdir().unwrap();
    let wrong_message_file = temp_dir.path().join("wrong.txt");
    fs::write(&wrong_message_file, b"Wrong message").unwrap();

    let result = verify_message_signature(&pubkey, &sig_box, &wrong_message_file, false, false);
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
    let sign_opts = SignOptions::builder(secret_key_file.as_path(), message_file.as_path())
        .signature_file(sig_file.as_path())
        .force(true)
        .quiet(true)
        .build();
    sign(&sign_opts, None).expect("sign should succeed");

    // Try to verify with key 2 (different keynum) - should fail
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(wrong_pubkey_file.as_path()),
        sig_file.as_path(),
        message_file.as_path(),
    )
    .build();

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
fn test_verify_small_file_succeeds() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    let message_path = temp_dir.path().join("message.txt");
    std::fs::write(&message_path, b"small message").unwrap();

    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sign_opts = SignOptions::builder(sk_path.as_path(), message_path.as_path())
        .signature_file(sig_path.as_path())
        .build();
    sign(&sign_opts, None).expect("signing should succeed");

    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .build();

    verify(&verify_opts).expect("verification should succeed with small file");
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
    let sign_opts = SignOptions::builder(sk_path.as_path(), message_path.as_path())
        .signature_file(sig_path.as_path())
        .force(true)
        .build();

    sign(&sign_opts, None).expect("signing large file in prehashed mode should succeed");

    // Verify should succeed with prehashed mode (streaming)
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .build();

    verify(&verify_opts).expect("verification should succeed with prehashed large file");
}

#[test]
fn test_verify_multiple_files_sequential() {
    use minisign::ops::{sign::sign_multiple_files, verify::verify_multiple_files};

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create and sign multiple files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file2, b"Message 2").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    let sign_paths = vec![file1.clone(), file2.clone(), file3.clone()];
    let sign_opts = SignOptions::builder(sk_path.as_path(), Path::new(""))
        .force(true)
        .trusted_comment("Batch verification test")
        .build();

    sign_multiple_files(sign_paths, &sign_opts, None, true).expect("signing should succeed");

    // Now verify multiple files
    let verify_paths = vec![file1.clone(), file2.clone(), file3.clone()];
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        Path::new(""),
        Path::new(""),
    )
    .build();

    let result = verify_multiple_files(verify_paths, &verify_opts, true);
    assert!(result.is_ok(), "verification should succeed for all files");

    // All signature files should still exist
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}

#[test]
fn test_verify_multiple_files_parallel() {
    use minisign::ops::{sign::sign_multiple_files, verify::verify_multiple_files};

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create 10 test files to better test parallelism
    let mut paths = Vec::new();
    for i in 0..10 {
        let file = temp_dir.path().join(format!("file{i}.txt"));
        fs::write(&file, format!("Message {i}").as_bytes()).unwrap();
        paths.push(file);
    }

    let sign_opts = SignOptions::builder(sk_path.as_path(), Path::new(""))
        .force(true)
        .trusted_comment("Parallel verification test")
        .build();

    sign_multiple_files(paths.clone(), &sign_opts, None, false).expect("signing should succeed");

    // Now verify multiple files in parallel
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        Path::new(""),
        Path::new(""),
    )
    .build();

    let result = verify_multiple_files(paths.clone(), &verify_opts, false);
    assert!(result.is_ok(), "verification should succeed for all files");

    // Verify all signature files exist
    for file in &paths {
        let sig_path = format!("{}.minisig", file.display());
        assert!(
            Path::new(&sig_path).exists(),
            "Signature missing for {file:?}"
        );
    }
}

#[test]
fn test_verify_multiple_files_partial_failure() {
    use minisign::ops::{sign::sign_multiple_files, verify::verify_multiple_files};

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create and sign files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file2, b"Message 2").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    let sign_paths = vec![file1.clone(), file2.clone(), file3.clone()];
    let sign_opts = SignOptions::builder(sk_path.as_path(), Path::new(""))
        .force(true)
        .build();

    sign_multiple_files(sign_paths, &sign_opts, None, true).expect("signing should succeed");

    // Corrupt file2's content (signature won't match)
    fs::write(&file2, b"Corrupted message").unwrap();

    // Try to verify all files - should get partial failure
    let verify_paths = vec![file1.clone(), file2.clone(), file3.clone()];
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        Path::new(""),
        Path::new(""),
    )
    .build();

    let result = verify_multiple_files(verify_paths, &verify_opts, true);

    // Should return PartialFailure error
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::PartialFailure)));

    // Signatures still exist for all files
    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}

#[test]
fn test_verify_multiple_files_all_attempted() {
    use minisign::ops::{sign::sign_multiple_files, verify::verify_multiple_files};

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create mix of valid and files that will fail
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("missing1.txt"); // No signature exists
    let file3 = temp_dir.path().join("file3.txt");
    let file4 = temp_dir.path().join("file4.txt");
    let file5 = temp_dir.path().join("file5.txt");

    fs::write(&file1, b"M1").unwrap();
    fs::write(&file3, b"M3").unwrap();
    fs::write(&file4, b"M4").unwrap();
    fs::write(&file5, b"M5").unwrap();

    // Sign file1, file3, file4, file5 (skip file2 - it doesn't exist)
    let sign_paths = vec![file1.clone(), file3.clone(), file4.clone(), file5.clone()];
    let sign_opts = SignOptions::builder(sk_path.as_path(), Path::new(""))
        .force(true)
        .build();

    sign_multiple_files(sign_paths, &sign_opts, None, true).expect("signing should succeed");

    // Now create file2 but don't sign it
    fs::write(&file2, b"M2").unwrap();

    // Corrupt file4's content
    fs::write(&file4, b"Corrupted").unwrap();

    // Try to verify all files
    let verify_paths = vec![
        file1.clone(),
        file2.clone(),
        file3.clone(),
        file4.clone(),
        file5.clone(),
    ];
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        Path::new(""),
        Path::new(""),
    )
    .build();

    let result = verify_multiple_files(verify_paths, &verify_opts, true);

    // Should return PartialFailure (file2 has no signature, file4 corrupted)
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::PartialFailure)));

    // file1, file3, file5 should have successful verification (implicitly tested by PartialFailure)
    // file2 should have no signature
    assert!(!file2.with_extension("txt.minisig").exists());
}

#[test]
fn test_verify_multiple_files_quiet_mode() {
    use minisign::ops::{sign::sign_multiple_files, verify::verify_multiple_files};

    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create and sign files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");

    fs::write(&file1, b"M1").unwrap();
    fs::write(&file2, b"M2").unwrap();

    let sign_paths = vec![file1.clone(), file2.clone()];
    let sign_opts = SignOptions::builder(sk_path.as_path(), Path::new(""))
        .force(true)
        .build();

    sign_multiple_files(sign_paths, &sign_opts, None, true).expect("signing should succeed");

    // Verify with quiet mode (should suppress output)
    let verify_paths = vec![file1.clone(), file2.clone()];
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        Path::new(""),
        Path::new(""),
    )
    .quiet(true)
    .build();

    let result = verify_multiple_files(verify_paths, &verify_opts, true);
    assert!(result.is_ok(), "verification should succeed");
}

#[test]
fn test_verify_summary_shows_only_filenames_not_error_details() {
    use minisign::ops::verify::{FileVerifyResult, format_batch_summary};
    use std::path::PathBuf;

    let error_detail = "key mismatch";
    let results = vec![
        FileVerifyResult {
            file: PathBuf::from("SSMS20.exe"),
            result: Err(Error::KeyMismatch {
                sig_keynum: "AAAAAAAAAAAAAAAA".to_string(),
            }),
        },
        FileVerifyResult {
            file: PathBuf::from("SSMS20B.exe"),
            result: Err(Error::KeyMismatch {
                sig_keynum: "AAAAAAAAAAAAAAAA".to_string(),
            }),
        },
        FileVerifyResult {
            file: PathBuf::from("SSMS20C.exe"),
            result: Err(Error::KeyMismatch {
                sig_keynum: "AAAAAAAAAAAAAAAA".to_string(),
            }),
        },
    ];

    let summary = format_batch_summary(&results).expect("failures should produce a summary");

    // Summary must list the filenames of failed files.
    assert!(summary.contains("SSMS20.exe"), "got:\n{summary}");
    assert!(summary.contains("SSMS20B.exe"), "got:\n{summary}");
    assert!(summary.contains("SSMS20C.exe"), "got:\n{summary}");

    // Summary must not repeat per-file error details — those appear in real-time output.
    assert!(
        !summary.contains(error_detail),
        "summary must not repeat key-mismatch details, got:\n{summary}"
    );
}

#[test]
fn test_verify_rejects_legacy_with_force_prehashed() {
    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create message and sign in LEGACY mode (non-prehashed, "Ed")
    let message_path = temp_dir.path().join("message.txt");
    std::fs::write(&message_path, b"Test message").unwrap();

    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sign_opts = SignOptions::builder(sk_path.as_path(), message_path.as_path())
        .signature_file(sig_path.as_path())
        .prehashed(false) // LEGACY mode (non-prehashed, "Ed")
        .build();

    sign(&sign_opts, None).expect("signing should succeed");

    // Try to verify with force_prehashed=true - should REJECT legacy signature
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .force_prehashed(true)
    .build();

    let result = verify(&verify_opts);
    assert!(
        result.is_err(),
        "Should reject legacy signature with force_prehashed"
    );

    // Verify the error is LegacySignatureRejected
    if let Err(e) = result {
        match e {
            Error::LegacySignatureRejected => (), // Expected
            _ => panic!("Expected LegacySignatureRejected error, got: {e:?}"),
        }
    }
}

#[test]
fn test_verify_accepts_legacy_without_force_prehashed() {
    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create message and sign in LEGACY mode (non-prehashed, "Ed")
    let message_path = temp_dir.path().join("message.txt");
    std::fs::write(&message_path, b"Test message").unwrap();

    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sign_opts = SignOptions::builder(sk_path.as_path(), message_path.as_path())
        .signature_file(sig_path.as_path())
        .prehashed(false) // LEGACY mode (non-prehashed, "Ed")
        .build();

    sign(&sign_opts, None).expect("signing should succeed");

    // Verify with force_prehashed=false - should ACCEPT legacy signature
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .build(); // force_prehashed=false (default)

    let result = verify(&verify_opts);
    assert!(
        result.is_ok(),
        "Should accept legacy signature without force_prehashed"
    );
}

#[test]
fn test_verify_accepts_prehashed_with_force_prehashed() {
    let temp_dir = TempDir::new().unwrap();

    // Generate keypair
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    std::fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    std::fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    // Create message and sign in PREHASHED mode (default, "ED")
    let message_path = temp_dir.path().join("message.txt");
    std::fs::write(&message_path, b"Test message").unwrap();

    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sign_opts = SignOptions::builder(sk_path.as_path(), message_path.as_path())
        .signature_file(sig_path.as_path())
        .force(true) // prehashed=true means PREHASHED mode
        .build();

    sign(&sign_opts, None).expect("signing should succeed");

    // Verify with force_prehashed=true - should ACCEPT prehashed signature
    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .force_prehashed(true)
    .build();

    let result = verify(&verify_opts);
    assert!(
        result.is_ok(),
        "Should accept prehashed signature with force_prehashed"
    );
}

#[test]
fn test_output_uses_content_captured_at_verify_time() {
    // S1 regression guard: the -o buffer must come from the verify call itself,
    // not a second read from the path. Overwriting the file after verify() returns
    // must not change what is emitted.
    let temp_dir = TempDir::new().unwrap();
    let message_path = temp_dir.path().join("message.txt");
    let sig_path = temp_dir.path().join("message.txt.minisig");
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let original = b"original content";
    let tampered = b"tampered - must not appear in output";

    fs::write(&message_path, original).unwrap();

    let (secret_key, public_key, keynum) = generate_keypair().unwrap();
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey = PubkeyStruct::new(keynum, public_key);
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();
    fs::write(&pk_path, pubkey.to_file_contents("test")).unwrap();

    sign(
        &SignOptions::builder(sk_path.as_path(), message_path.as_path())
            .signature_file(sig_path.as_path())
            .prehashed(false) // non-prehashed: content is buffered in memory during verify
            .quiet(true)
            .build(),
        None,
    )
    .unwrap();

    let verify_opts = VerifyOptions::builder(
        PublicKeySource::File(pk_path.as_path()),
        sig_path.as_path(),
        message_path.as_path(),
    )
    .output(true)
    .build();

    let mut result = verify(&verify_opts).expect("verification must succeed");

    // Simulate attacker replacing the file after verification
    fs::write(&message_path, tampered).unwrap();

    let mut out = Vec::new();
    result
        .take_message_output()
        .expect("output must be captured when output=true")
        .write_to(&mut out)
        .unwrap();

    assert_eq!(
        out, original,
        "output must be the verified content, not post-verification disk content"
    );
}
