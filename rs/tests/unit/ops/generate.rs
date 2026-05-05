//! Unit tests for key generation operations

use minisign::ops::file_utils::{write_public_key_file, write_secret_key_file};
use minisign::{
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
    ops::generate::{
        GenerateOptions, ensure_parent_directory, generate, generate_with_log_n,
        inject_commit_failure_before_public_rename, inject_commit_failure_before_secret_rename,
        set_force_overwrite_lock_timeout_for_tests,
    },
};
use std::fs;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn test_generate_encrypted_key() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .comment("Test key")
        .build();

    let password = b"testpassword";
    let result = generate(&options, Some(password)).expect("generation should succeed");

    // Check files were created
    assert!(sk_path.exists());
    assert!(pk_path.exists());

    // Check keynum format
    assert_eq!(result.keynum_hex().len(), 16); // 8 bytes = 16 hex chars

    // Verify secret key can be loaded and decrypted
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(seckey.is_encrypted());
    let (_secret_key, _keynum) = seckey
        .decrypt(password)
        .expect("should decrypt with correct password");

    // Verify wrong password fails
    let wrong_result = seckey.decrypt(b"wrongpassword");
    assert!(wrong_result.is_err());
}

#[test]
fn test_generate_encrypted_key_fast() {
    // Fast variant using N=2^14 (~50ms) instead of N=2^20 (~1-5s)
    // Tests the same logic with weaker security parameters
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test_fast.key");
    let pk_path = temp_dir.path().join("test_fast.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .comment("Fast test key")
        .build();

    let password = b"testpassword";
    let result =
        generate_with_log_n(&options, Some(password), 14).expect("generation should succeed");

    // Check files were created
    assert!(sk_path.exists());
    assert!(pk_path.exists());

    // Check keynum format
    assert_eq!(result.keynum_hex().len(), 16);

    // Verify secret key can be loaded and decrypted
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(seckey.is_encrypted());
    let (_secret_key, _keynum) = seckey
        .decrypt(password)
        .expect("should decrypt with correct password");

    // Verify wrong password fails
    let wrong_result = seckey.decrypt(b"wrongpassword");
    assert!(wrong_result.is_err());
}

#[test]
fn test_generate_unencrypted_key() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .no_password(true)
        .build();

    let result = generate(&options, None).expect("generation should succeed");

    assert!(sk_path.exists());
    assert!(pk_path.exists());

    // Verify secret key is unencrypted
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();
    assert!(!seckey.is_encrypted());

    // Check public key comment contains keynum
    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    assert!(pk_contents.contains(result.keynum_hex()));
}

#[test]
fn test_generate_without_password_fails() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path()).build(); // Password required

    let result = generate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
}

#[test]
fn test_generate_file_exists_without_force() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Create existing files
    fs::write(&sk_path, "existing").unwrap();
    fs::write(&pk_path, "existing").unwrap();

    let options = GenerateOptions::builder(&sk_path, &pk_path)
        .no_password(true)
        .build();

    let result = generate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
}

#[test]
#[cfg_attr(
    not(unix),
    ignore = "atomic secret-key overwrite not yet implemented on Windows"
)]
fn test_generate_force_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Create existing files
    fs::write(&sk_path, "existing").unwrap();
    fs::write(&pk_path, "existing").unwrap();

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .force(true)
        .no_password(true)
        .build();

    generate(&options, None).expect("should overwrite with force=true");

    // Verify files were overwritten
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    assert!(sk_contents.starts_with("untrusted comment:"));
}

#[test]
fn test_generate_creates_parent_directories() {
    let temp_dir = TempDir::new().unwrap();
    let nested_dir = temp_dir.path().join("nested").join("dirs");
    let sk_path = nested_dir.join("test.key");
    let pk_path = nested_dir.join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .no_password(true)
        .build();

    generate(&options, None).expect("should create parent directories");

    assert!(sk_path.exists());
    assert!(pk_path.exists());
    assert!(nested_dir.exists());
}

#[test]
#[cfg(unix)]
fn test_secret_key_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), &pk_path)
        .no_password(true)
        .build();

    generate(&options, None).expect("generation should succeed");

    // Check secret key has mode 0600
    let metadata = fs::metadata(&sk_path).unwrap();
    let permissions = metadata.permissions();
    assert_eq!(permissions.mode() & 0o777, 0o600);
}

#[test]
fn test_ensure_parent_directory() {
    let temp_dir = TempDir::new().unwrap();
    let nested_path = temp_dir
        .path()
        .join("a")
        .join("b")
        .join("c")
        .join("file.txt");

    ensure_parent_directory(&nested_path).expect("should create parent dirs");

    let parent = nested_path.parent().unwrap();
    assert!(parent.exists());
    assert!(parent.is_dir());
}

#[test]
fn test_roundtrip_generated_keys() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .comment("Roundtrip test")
        .no_password(true)
        .build();

    let result = generate(&options, None).expect("generation should succeed");

    // Load and verify the keys
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    let pubkey = PubkeyStruct::from_file_contents(&pk_contents).unwrap();

    // Verify keynums match
    assert_eq!(seckey.keynum(), pubkey.keynum());
    assert_eq!(seckey.keynum().to_key_id(), result.keynum_hex());
}

#[test]
fn test_atomic_file_creation_prevents_race() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Create existing secret key file
    fs::write(&sk_path, "existing secret key").unwrap();

    let options = GenerateOptions::builder(sk_path.as_path(), &pk_path)
        .no_password(true)
        .build();

    // Should fail due to existing file (atomic check)
    let result = generate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&sk_path).unwrap();
    assert_eq!(contents, "existing secret key");
}

#[test]
fn test_atomic_file_creation_pubkey_prevents_race() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Create existing public key file
    fs::write(&pk_path, "existing public key").unwrap();

    let options = GenerateOptions::builder(&sk_path, pk_path.as_path())
        .no_password(true)
        .build();

    // Should fail due to existing file (atomic check)
    let result = generate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&pk_path).unwrap();
    assert_eq!(contents, "existing public key");
}

#[test]
fn test_atomic_file_creation_both_files_check() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Create both files
    fs::write(&sk_path, "existing sk").unwrap();
    fs::write(&pk_path, "existing pk").unwrap();

    let options = GenerateOptions::builder(&sk_path, &pk_path)
        .no_password(true)
        .build();

    // Should fail (doesn't matter which file is checked first)
    let result = generate(&options, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
}

#[test]
fn test_encrypted_keypair_has_matching_key_ids() {
    // Fast variant using N=2^14 for speed
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("encrypted.key");
    let pk_path = temp_dir.path().join("encrypted.pub");

    let options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .comment("Encrypted key ID test")
        .build();

    let password = b"testpassword";
    let result =
        generate_with_log_n(&options, Some(password), 14).expect("generation should succeed");

    // Load both key files
    let sk_contents = fs::read_to_string(&sk_path).unwrap();
    let seckey = SeckeyStruct::from_file_contents(&sk_contents).unwrap();

    let pk_contents = fs::read_to_string(&pk_path).unwrap();
    let pubkey = PubkeyStruct::from_file_contents(&pk_contents).unwrap();

    // Decrypt the secret key to get the real keynum
    let (_secret_key, decrypted_keynum) = seckey
        .decrypt(password)
        .expect("should decrypt with correct password");

    // CRITICAL: Key IDs must match between public and private key files
    // This proves they are from the same keypair
    assert_eq!(
        decrypted_keynum,
        *pubkey.keynum(),
        "Encrypted keypair must have matching key IDs after decryption"
    );
    assert_eq!(decrypted_keynum.to_key_id(), result.keynum_hex());
    assert_eq!(pubkey.keynum().to_key_id(), result.keynum_hex());
}

#[test]
fn test_write_secret_key_file_atomic_creation() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("new.key");

    // Should succeed when file doesn't exist
    write_secret_key_file(&sk_path, "secret key content", false).expect("should create new file");

    // Verify content
    let contents = fs::read_to_string(&sk_path).unwrap();
    assert_eq!(contents, "secret key content");
}

#[test]
fn test_write_secret_key_file_prevents_overwrite() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("existing.key");

    // Create initial file
    fs::write(&sk_path, "original content").unwrap();

    // Try to write without force - should fail
    let result = write_secret_key_file(&sk_path, "new content", false);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::FileExists(_)));

    // Verify original content unchanged
    let contents = fs::read_to_string(&sk_path).unwrap();
    assert_eq!(contents, "original content");
}

#[test]
fn test_write_secret_key_file_force_overwrites() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");

    // Create initial file
    fs::write(&sk_path, "original content").unwrap();

    // Write with force - should succeed
    write_secret_key_file(&sk_path, "overwritten content", true)
        .expect("should overwrite with force");

    // Verify content was overwritten
    let contents = fs::read_to_string(&sk_path).unwrap();
    assert_eq!(contents, "overwritten content");
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

// --- CR-5 regression tests: partial-failure force semantics ---

/// With force=true, if the commit point fails, the original keypair must remain
/// usable and matched. This checks the transaction preserves the pre-existing
/// secret/public pair rather than leaving a split state.
#[test]
#[cfg(debug_assertions)]
fn test_force_pubkey_fail_preserves_secret_key() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let initial_options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .no_password(true)
        .build();
    generate(&initial_options, None).expect("initial keypair generation should succeed");

    let stored_secret_key_text = fs::read_to_string(&sk_path).unwrap();
    let stored_public_key_text = fs::read_to_string(&pk_path).unwrap();

    #[cfg(debug_assertions)]
    let _guard = inject_commit_failure_before_public_rename();

    let result = generate(
        &GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
            .force(true)
            .no_password(true)
            .build(),
        None,
    );

    assert!(result.is_err(), "forced regeneration should fail");

    let restored_secret_key_text = fs::read_to_string(&sk_path).unwrap();
    let restored_public_key_text = fs::read_to_string(&pk_path).unwrap();

    assert_eq!(restored_secret_key_text, stored_secret_key_text);
    assert_eq!(restored_public_key_text, stored_public_key_text);

    let stored_seckey = SeckeyStruct::from_file_contents(&stored_secret_key_text).unwrap();
    let restored_seckey = SeckeyStruct::from_file_contents(&restored_secret_key_text).unwrap();
    let stored_pubkey = PubkeyStruct::from_file_contents(&stored_public_key_text).unwrap();
    let restored_pubkey = PubkeyStruct::from_file_contents(&restored_public_key_text).unwrap();

    assert_eq!(restored_seckey.keynum(), stored_seckey.keynum());
    assert_eq!(restored_pubkey.keynum(), stored_pubkey.keynum());
}

/// With force=true, if the public key has been committed but the secret key
/// commit fails, the original keypair must be restored as a matched pair.
#[test]
#[cfg(debug_assertions)]
fn test_force_secret_key_fail_restores_keypair() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let initial_options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .no_password(true)
        .build();
    generate(&initial_options, None).expect("initial keypair generation should succeed");

    let stored_secret_key_text = fs::read_to_string(&sk_path).unwrap();
    let stored_public_key_text = fs::read_to_string(&pk_path).unwrap();

    let _guard = inject_commit_failure_before_secret_rename();

    let result = generate(
        &GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
            .force(true)
            .no_password(true)
            .build(),
        None,
    );

    assert!(result.is_err(), "forced regeneration should fail");
    assert_eq!(
        fs::read_to_string(&sk_path).unwrap(),
        stored_secret_key_text
    );
    assert_eq!(
        fs::read_to_string(&pk_path).unwrap(),
        stored_public_key_text
    );

    let stored_seckey = SeckeyStruct::from_file_contents(&stored_secret_key_text).unwrap();
    let stored_pubkey = PubkeyStruct::from_file_contents(&stored_public_key_text).unwrap();
    let restored_seckey =
        SeckeyStruct::from_file_contents(&fs::read_to_string(&sk_path).unwrap()).unwrap();
    let restored_pubkey =
        PubkeyStruct::from_file_contents(&fs::read_to_string(&pk_path).unwrap()).unwrap();

    assert_eq!(restored_seckey.keynum(), stored_seckey.keynum());
    assert_eq!(restored_pubkey.keynum(), stored_pubkey.keynum());
}

#[test]
#[cfg(debug_assertions)]
fn test_force_overwrite_stale_lock_times_out() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let lock_path = temp_dir.path().join(".test.key.force.lock");

    let initial_options = GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
        .no_password(true)
        .build();
    generate(&initial_options, None).expect("initial keypair generation should succeed");
    fs::write(&lock_path, "stale lock").unwrap();
    let _timeout_guard = set_force_overwrite_lock_timeout_for_tests(Duration::from_millis(100));

    let started_at = Instant::now();
    let result = generate(
        &GenerateOptions::builder(sk_path.as_path(), pk_path.as_path())
            .force(true)
            .no_password(true)
            .build(),
        None,
    );

    assert!(
        result.is_err(),
        "stale lock should fail instead of blocking"
    );
    assert!(
        started_at.elapsed().as_secs() < 1,
        "debug lock timeout should keep the regression test fast"
    );
    assert!(
        lock_path.exists(),
        "stale lock should not be removed by a non-owner"
    );
}

/// With force=false, if pubkey write fails after a fresh secret key was
/// created, the newly-created secret key should be cleaned up to avoid
/// leaving an orphaned key with no matching public key.
#[test]
fn test_no_force_pubkey_fail_removes_secret_key() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");

    // Use a directory as the pubkey destination
    let pk_dir = temp_dir.path().join("pk_is_a_dir");
    fs::create_dir(&pk_dir).unwrap();

    // No pre-existing secret key — the key is created fresh
    let options = GenerateOptions::builder(sk_path.as_path(), pk_dir.as_path())
        .no_password(true)
        .build();

    let result = generate(&options, None);
    assert!(
        result.is_err(),
        "generate must fail when pubkey destination is a directory"
    );

    // The freshly-created secret key should be removed since it was never paired
    assert!(
        !sk_path.exists(),
        "orphaned secret key should be removed on pubkey write failure in non-force mode"
    );
}
