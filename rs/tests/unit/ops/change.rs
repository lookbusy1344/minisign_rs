//! Unit tests for password change operations

use minisign::{
    crypto::generate_keypair,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
    ops::{
        change::{ChangeOptions, change_with_log_n},
        sign::create_signature,
        verify::verify_message_signature,
    },
};
use rand::Rng;
use std::fs;
use tempfile::TempDir;

use super::helpers::{TEST_LOG_N, make_fast_encrypted_seckey};

#[test]
fn test_change_password_fast() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let old_password = b"oldpassword";

    let seckey = make_fast_encrypted_seckey(keynum, &secret_key, old_password);
    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let new_password = b"newpassword";
    let options = ChangeOptions::builder(sk_path.as_path()).build();

    let result = change_with_log_n(&options, Some(old_password), Some(new_password), TEST_LOG_N)
        .expect("password change should succeed");

    assert_eq!(result.secret_key_file(), sk_path);
    assert!(result.encrypted());

    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(new_seckey.is_encrypted());
    new_seckey
        .decrypt(new_password)
        .expect("should decrypt with new password");

    let old_result = new_seckey.decrypt(old_password);
    assert!(old_result.is_err());
}

#[test]
fn test_remove_password_from_encrypted_key() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"password";

    let seckey = make_fast_encrypted_seckey(keynum, &secret_key, password);
    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let options = ChangeOptions::builder(sk_path.as_path())
        .remove_password(true)
        .build();

    let result = change_with_log_n(&options, Some(password), None, TEST_LOG_N)
        .expect("password removal should succeed");

    assert_eq!(result.secret_key_file(), sk_path);
    assert!(!result.encrypted());

    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(!new_seckey.is_encrypted());
    new_seckey
        .get_unencrypted_secret_key()
        .expect("should get key without password");
}

#[test]
fn test_add_password_to_unencrypted_key() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let new_password = b"newpassword";
    let options = ChangeOptions::builder(sk_path.as_path()).build();

    let result = change_with_log_n(&options, None, Some(new_password), TEST_LOG_N)
        .expect("adding password should succeed");

    assert!(result.encrypted());

    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(new_seckey.is_encrypted());
    new_seckey
        .decrypt(new_password)
        .expect("should decrypt with new password");
}

#[test]
fn test_change_without_old_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"password";

    let seckey = make_fast_encrypted_seckey(keynum, &secret_key, password);
    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(&options, None, Some(b"newpass"), TEST_LOG_N);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
}

#[test]
fn test_change_with_wrong_old_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"correctpassword";

    let seckey = make_fast_encrypted_seckey(keynum, &secret_key, password);
    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(
        &options,
        Some(b"wrongpassword"),
        Some(b"newpass"),
        TEST_LOG_N,
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, Error::ChecksumFailed),
        "wrong password must fail with ChecksumFailed, got: {err}"
    );
}

#[test]
fn test_encrypt_without_new_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(&options, None, None, TEST_LOG_N);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
}

#[test]
#[cfg(unix)]
fn test_change_preserves_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let metadata = fs::metadata(&sk_path).unwrap();
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&sk_path, permissions).unwrap();

    let options = ChangeOptions::builder(sk_path.as_path()).build();

    change_with_log_n(&options, None, Some(b"password"), TEST_LOG_N)
        .expect("adding password should succeed");

    let metadata = fs::metadata(&sk_path).unwrap();
    let permissions = metadata.permissions();
    assert_eq!(permissions.mode() & 0o777, 0o600);
}

#[test]
#[cfg(debug_assertions)]
fn test_change_password_with_force_weak_kdf() {
    // Test that --force-weak-kdf creates weak keys when changing password
    use minisign::crypto::generate_keypair;

    let temp_dir = TempDir::new().unwrap();
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let old_password = b"oldpassword";

    // Create a key with production-strength params (the test is about what happens
    // AFTER the change, not the initial key strength).
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);
    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        old_password,
        kdf_salt,
        33_554_432,    // opslimit: 4 * 2^20 * 8 = N=2^20
        1_073_741_824, // memlimit: 128 * 2^20 * 8
        false,
    )
    .unwrap();

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    let new_password = b"newpassword";
    let options = ChangeOptions::builder(sk_path.as_path())
        .force_weak_kdf(true)
        .build();

    let result = change_with_log_n(&options, Some(old_password), Some(new_password), 20)
        .expect("password change should succeed");

    assert!(result.encrypted());

    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

    assert!(new_seckey.is_weak_kdf(), "key should be weak after change");
    assert_eq!(new_seckey.kdf_opslimit(), 4_194_304); // N=2^17
    assert_eq!(new_seckey.kdf_memlimit(), 134_217_728); // 128 MB

    let (_sk, _kn) = new_seckey
        .decrypt(new_password)
        .expect("should decrypt with new password");
}

#[test]
fn test_change_password_then_sign_verify_roundtrip() {
    // P6.4: Exercises the full lifecycle: generate → change password → sign → verify.
    // Ensures re-encryption preserves the key material so signatures produced after
    // the change are still accepted by the matching public key.
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let old_password = b"initial-password";

    let seckey = make_fast_encrypted_seckey(keynum, &secret_key, old_password);
    let sk_path = temp_dir.path().join("key.key");
    fs::write(&sk_path, seckey.to_file_contents("roundtrip test")).unwrap();

    let new_password = b"changed-password";
    let change_options = ChangeOptions::builder(sk_path.as_path()).build();
    change_with_log_n(
        &change_options,
        Some(old_password),
        Some(new_password),
        TEST_LOG_N,
    )
    .expect("password change should succeed");

    let message_path = temp_dir.path().join("message.txt");
    fs::write(&message_path, b"test message for roundtrip").unwrap();

    let sig_box = {
        let sk_contents = fs::read_to_string(&sk_path).unwrap();
        let re_encrypted_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
        let (decrypted_sk, decrypted_kn) = re_encrypted_seckey
            .decrypt(new_password)
            .expect("should decrypt with new password");
        create_signature(
            &decrypted_sk,
            decrypted_kn,
            &message_path,
            false,
            Some("roundtrip"),
            None,
        )
        .expect("signing with re-encrypted key should succeed")
    };

    let pubkey_struct = PubkeyStruct::new(keynum, public_key);
    let result = verify_message_signature(&pubkey_struct, &sig_box, &message_path, false);
    assert!(
        result.is_ok(),
        "signature produced after password change must verify against the original public key"
    );
}
