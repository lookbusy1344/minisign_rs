use minisign::crypto::{SecretKey, generate_keypair};
use minisign::errors::Error;
use minisign::keys::{PubkeyStruct, SeckeyStruct};
use minisign::ops::recreate::{RecreateOptions, extract_public_key_from_secret, recreate};
use rand::Rng;
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
    let options = RecreateOptions::new(
        sk_path.as_path(),
        pk_path.as_path(),
        Some("Recreated key"),
        false,
    );

    let result = recreate(&options, None).expect("recreation should succeed");

    // Verify public key file was created
    assert!(pk_path.exists());
    assert_eq!(result.public_key_file(), pk_path);
    assert_eq!(result.keynum_hex(), keynum.to_key_id());

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
    rand::rng().fill(&mut kdf_salt);

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
    let options = RecreateOptions::new(sk_path.as_path(), pk_path.as_path(), None, false);

    let result = recreate(&options, Some(password)).expect("recreation should succeed");

    // Verify public key file was created
    assert!(pk_path.exists());
    assert_eq!(result.keynum_hex(), keynum.to_key_id());
}

#[test]
fn test_recreate_without_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    // Create an encrypted secret key
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"testpassword";
    let mut kdf_salt = [0u8; 32];
    rand::rng().fill(&mut kdf_salt);

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
    let options = RecreateOptions::new(&sk_path, &pk_path, None, false);

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
    rand::rng().fill(&mut kdf_salt);

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
    let options = RecreateOptions::new(&sk_path, &pk_path, None, false);

    let result = recreate(&options, Some(b"wrongpassword"));
    assert!(result.is_err());
    // Wrong password results in checksum failure when decrypting
    assert!(matches!(result.unwrap_err(), Error::ChecksumFailed));
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

    let options = RecreateOptions::new(&sk_path, &pk_path, None, false);

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

    let options =
        RecreateOptions::new(&sk_path, pk_path.as_path(), Some("Forced recreation"), true);

    recreate(&options, None).expect("should overwrite with force=true");

    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    assert!(pk_contents.contains("Forced recreation"));
}

#[test]
fn test_extract_public_key_from_secret() {
    let (secret_key, expected_public_key, _keynum) = generate_keypair().expect("RNG should work");

    let extracted_public =
        extract_public_key_from_secret(&secret_key).expect("valid keypair should succeed");

    assert_eq!(extracted_public.as_bytes(), expected_public_key.as_bytes());
}

#[test]
fn test_extract_public_key_rejects_tampered_stored_bytes() {
    // Build a key where bytes[32..64] (the stored public-key half) are all-zeros,
    // which will not match the scalar at bytes[0..32] for any real key.
    let (secret_key, _, _) = generate_keypair().expect("RNG should work");
    let mut raw = *secret_key.as_bytes();
    raw[32..64].fill(0); // zero out the stored public-key half
    let tampered = SecretKey::from_bytes(raw);

    let result = extract_public_key_from_secret(&tampered);
    assert!(
        result.is_err(),
        "tampered stored public-key bytes must be rejected"
    );
    assert!(matches!(result.unwrap_err(), Error::InvalidSecretKey(_)));
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
    let options = RecreateOptions::new(&sk_path, pk_path.as_path(), Some("test"), false);

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

    let options = RecreateOptions::new(&sk_path, pk_path.as_path(), None, false);

    // Should fail due to existing file (atomic check)
    let result = recreate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "existing public key");
}

// M9: empty --comment "" must be rejected for recreate as well.
#[test]
fn test_recreate_empty_comment_is_rejected() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test secret key")).unwrap();

    let pk_path = temp_dir.path().join("test.pub");
    let options = RecreateOptions::new(sk_path.as_path(), pk_path.as_path(), Some(""), false);

    let result = recreate(&options, None);
    assert!(result.is_err(), "expected error for empty comment, got Ok");
    assert!(
        matches!(result.unwrap_err(), Error::InvalidComment(_)),
        "expected InvalidComment variant"
    );
    assert!(!pk_path.exists(), "public key file must not be created");
}
