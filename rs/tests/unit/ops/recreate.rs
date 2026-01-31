use minisign::crypto::generate_keypair;
use minisign::errors::Error;
use minisign::keys::{PubkeyStruct, SeckeyStruct};
use minisign::ops::file_utils::write_public_key_file;
use minisign::ops::recreate::{RecreateOptions, extract_public_key_from_secret, recreate};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_recreate_from_unencrypted_key() {
    let temp_dir = TempDir::new().unwrap();

    // Generate a test keypair and write secret key
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    let sk_contents = seckey.to_file_contents("test secret key");
    fs::write(&sk_path, sk_contents).unwrap();

    // Recreate public key
    let pk_path = temp_dir.path().join("test.pub");
    let options = RecreateOptions {
        secret_key_file: sk_path.clone(),
        public_key_file: pk_path.clone(),
        comment: Some("Recreated key".to_string()),
        force: false,
    };

    let result = recreate(&options, None).expect("recreation should succeed");

    // Verify public key file was created
    assert!(pk_path.exists());
    assert_eq!(result.public_key_file, pk_path);
    assert_eq!(result.keynum_hex, keynum.to_hex());

    // Verify the public key contents
    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    // We provided a custom comment
    assert!(pk_contents.contains("Recreated key"));

    // Verify the public key can be parsed and has correct keynum
    let pubkey_recreated = PubkeyStruct::from_file_contents(&pk_contents).unwrap();
    assert_eq!(pubkey_recreated.keynum().to_hex(), keynum.to_hex());
}

#[test]
fn test_recreate_from_encrypted_key_fast() {
    let temp_dir = TempDir::new().unwrap();

    // Generate a test keypair with fast encryption (N=2^14)
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"testpassword";
    let mut kdf_salt = [0u8; 32];
    getrandom::fill(&mut kdf_salt).unwrap();

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
        false, // allow_fallback - tests use secure defaults
    )
    .unwrap();

    let sk_path = temp_dir.path().join("encrypted.key");
    let sk_contents = seckey.to_file_contents("encrypted secret key");
    fs::write(&sk_path, sk_contents).unwrap();

    // Recreate public key
    let pk_path = temp_dir.path().join("recreated.pub");
    let options = RecreateOptions {
        secret_key_file: sk_path.clone(),
        public_key_file: pk_path.clone(),
        comment: None,
        force: false,
    };

    let result = recreate(&options, Some(password)).expect("recreation should succeed");

    // Verify public key file was created
    assert!(pk_path.exists());
    assert_eq!(result.keynum_hex, keynum.to_hex());
}

#[test]
fn test_recreate_without_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    // Create an encrypted secret key
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"testpassword";
    let mut kdf_salt = [0u8; 32];
    getrandom::fill(&mut kdf_salt).unwrap();

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
        false, // allow_fallback - tests use secure defaults
    )
    .unwrap();

    let sk_path = temp_dir.path().join("encrypted.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Try to recreate without password
    let pk_path = temp_dir.path().join("test.pub");
    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path,
        comment: None,
        force: false,
    };

    let result = recreate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
}

#[test]
fn test_recreate_wrong_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"correctpassword";
    let mut kdf_salt = [0u8; 32];
    getrandom::fill(&mut kdf_salt).unwrap();

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
        false, // allow_fallback - tests use secure defaults
    )
    .unwrap();

    let sk_path = temp_dir.path().join("encrypted.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Try with wrong password
    let pk_path = temp_dir.path().join("test.pub");
    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path,
        comment: None,
        force: false,
    };

    let result = recreate(&options, Some(b"wrongpassword"));
    assert!(result.is_err());
    // Wrong password results in checksum failure when decrypting
    assert!(matches!(
        result.unwrap_err(),
        Error::DecryptionFailed | Error::ChecksumFailed
    ));
}

#[test]
fn test_recreate_file_exists_without_force() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let pk_path = temp_dir.path().join("test.pub");
    fs::write(&pk_path, "existing content").unwrap();

    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path,
        comment: None,
        force: false,
    };

    let result = recreate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
}

#[test]
fn test_recreate_force_overwrite() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let pk_path = temp_dir.path().join("test.pub");
    fs::write(&pk_path, "existing content").unwrap();

    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path.clone(),
        comment: Some("Forced recreation".to_string()),
        force: true,
    };

    recreate(&options, None).expect("should overwrite with force=true");

    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    assert!(pk_contents.contains("Forced recreation"));
}

#[test]
fn test_extract_public_key_from_secret() {
    let (secret_key, expected_public_key, _keynum) = generate_keypair().expect("RNG should work");

    let extracted_public = extract_public_key_from_secret(&secret_key);

    assert_eq!(extracted_public.as_bytes(), expected_public_key.as_bytes());
}

#[test]
fn test_recreate_matches_original_public_key() {
    let temp_dir = TempDir::new().unwrap();

    // Generate keypair and save both keys
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
    let pubkey_original = PubkeyStruct::new(keynum, public_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Recreate public key
    let pk_path = temp_dir.path().join("recreated.pub");
    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path.clone(),
        comment: Some("test".to_string()),
        force: false,
    };

    recreate(&options, None).expect("recreation should succeed");

    // Load the recreated public key and compare
    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    let pubkey_recreated = PubkeyStruct::from_file_contents(&pk_contents).unwrap();

    assert_eq!(pubkey_original.keynum(), pubkey_recreated.keynum());
    assert_eq!(
        pubkey_original.public_key().as_bytes(),
        pubkey_recreated.public_key().as_bytes()
    );
}

#[test]
fn test_recreate_atomic_file_creation() {
    let temp_dir = TempDir::new().unwrap();

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Create existing public key file
    let pk_path = temp_dir.path().join("existing.pub");
    fs::write(&pk_path, "existing public key").unwrap();

    let options = RecreateOptions {
        secret_key_file: sk_path,
        public_key_file: pk_path.clone(),
        comment: None,
        force: false,
    };

    // Should fail due to existing file (atomic check)
    let result = recreate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "existing public key");
}

#[test]
fn test_write_public_key_file_atomic_creation() {
    let temp_dir = TempDir::new().unwrap();
    let pk_path = temp_dir.path().join("new.pub");

    // Should succeed when file doesn't exist
    write_public_key_file(&pk_path, "public key content", false).expect("should create new file");

    // Verify content
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "public key content");
}

#[test]
fn test_write_public_key_file_prevents_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let pk_path = temp_dir.path().join("existing.pub");

    // Create initial file
    fs::write(&pk_path, "original content").unwrap();

    // Try to write without force - should fail
    let result = write_public_key_file(&pk_path, "new content", false);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "original content");
}

#[test]
fn test_write_public_key_file_force_overwrites() {
    let temp_dir = TempDir::new().unwrap();
    let pk_path = temp_dir.path().join("test.pub");

    // Create initial file
    fs::write(&pk_path, "original content").unwrap();

    // Write with force - should succeed
    write_public_key_file(&pk_path, "overwritten content", true)
        .expect("should overwrite with force");

    // Verify content was overwritten
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "overwritten content");
}
