//! Unit tests for password change operations

use minisign::{
    crypto::generate_keypair,
    errors::Error,
    keys::SeckeyStruct,
    ops::change::{ChangeOptions, change_with_log_n},
};
use std::fs;
use tempfile::TempDir;
#[test]
fn test_change_password_fast() {
    let temp_dir = TempDir::new().unwrap();

    // Create an encrypted key with fast parameters (N=2^14)
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let old_password = b"oldpassword";
    let mut kdf_salt = [0u8; 32];
    getrandom::fill(&mut kdf_salt).unwrap();

    let n = 1u64 << 14;
    let r = 8u64;
    let kdf_opslimit = 4 * n * r;
    let kdf_memlimit = 128 * n * r;

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        old_password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false, // allow_fallback - tests use secure defaults
    )
    .unwrap();

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Change to new password
    let new_password = b"newpassword";
    let options = ChangeOptions::builder(sk_path.as_path()).build();

    let result = change_with_log_n(&options, Some(old_password), Some(new_password), 14)
        .expect("password change should succeed");

    assert_eq!(result.secret_key_file, sk_path);
    assert!(result.encrypted);

    // Verify can decrypt with new password
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(new_seckey.is_encrypted());
    new_seckey
        .decrypt(new_password)
        .expect("should decrypt with new password");

    // Verify old password no longer works
    let old_result = new_seckey.decrypt(old_password);
    assert!(old_result.is_err());
}

#[test]
fn test_remove_password_from_encrypted_key() {
    let temp_dir = TempDir::new().unwrap();

    // Create an encrypted key with fast parameters
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"password";
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

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Remove password
    let options = ChangeOptions::builder(sk_path.as_path())
        .remove_password(true)
        .build();

    let result = change_with_log_n(&options, Some(password), None, 14)
        .expect("password removal should succeed");

    assert_eq!(result.secret_key_file, sk_path);
    assert!(!result.encrypted);

    // Verify key is now unencrypted
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

    // Create an unencrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Add password
    let new_password = b"newpassword";
    let options = ChangeOptions::builder(sk_path.as_path()).build();

    let result = change_with_log_n(&options, None, Some(new_password), 14)
        .expect("adding password should succeed");

    assert!(result.encrypted);

    // Verify key is now encrypted
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

    // Create an encrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"password";
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

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Try to change without old password
    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(&options, None, Some(b"newpass"), 14);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
}

#[test]
fn test_change_with_wrong_old_password_fails() {
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

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Try with wrong old password
    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(&options, Some(b"wrongpassword"), Some(b"newpass"), 14);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_without_new_password_fails() {
    let temp_dir = TempDir::new().unwrap();

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Try to encrypt without providing new password
    let options = ChangeOptions::builder(&sk_path).build();

    let result = change_with_log_n(&options, None, None, 14);
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

    // Set initial permissions
    let metadata = fs::metadata(&sk_path).unwrap();
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&sk_path, permissions).unwrap();

    // Add password
    let options = ChangeOptions::builder(sk_path.as_path()).build();

    change_with_log_n(&options, None, Some(b"password"), 14)
        .expect("adding password should succeed");

    // Verify permissions are still 0600
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

    // Create a normal production-strength key
    let mut kdf_salt = [0u8; 32];
    getrandom::fill(&mut kdf_salt).unwrap();
    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        old_password,
        kdf_salt,
        33_554_432, // Production N=2^20
        1_073_741_824,
        false,
    )
    .unwrap();

    let sk_path = temp_dir.path().join("test.key");
    fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

    // Change password with force_weak_kdf
    let new_password = b"newpassword";
    let options = ChangeOptions::new(
        sk_path.as_path(),
        false,
        false,
        true, // Force weak parameters
    );

    let result = change_with_log_n(&options, Some(old_password), Some(new_password), 20)
        .expect("password change should succeed");

    assert!(result.encrypted);

    // Verify the key now has weak parameters
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let new_seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

    assert!(new_seckey.is_weak_kdf(), "key should be weak after change");
    assert_eq!(new_seckey.kdf_opslimit(), 4_194_304); // N=2^17
    assert_eq!(new_seckey.kdf_memlimit(), 134_217_728); // 128 MB

    // Verify it can be decrypted with new password
    let (_sk, _kn) = new_seckey
        .decrypt(new_password)
        .expect("should decrypt with new password");
}
