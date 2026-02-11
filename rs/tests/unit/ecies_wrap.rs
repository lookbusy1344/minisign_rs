//! Tests for ECIES wrapping integration (Phase 4)

use minisign::Error;
use minisign::crypto::{KeyNum, SecretKey};
use minisign::hw_keystore::HardwareKeyStore;
use minisign::hw_keystore::mock::MockKeyStore;
use minisign::keys::{ENCRYPTED_BLOB_SIZE, SeckeyStruct};

/// Test round-trip: wrap → unwrap → verify plaintext matches
#[test]
fn test_ecies_wrap_unwrap_round_trip() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    // Generate hardware key
    let _hw_pubkey = hw.generate_key(label).expect("should generate HW key");

    // Create test plaintext blob (keynum + secret key + checksum)
    let mut plaintext_blob = [0u8; ENCRYPTED_BLOB_SIZE];
    plaintext_blob[0..8].copy_from_slice(&[0xAA; 8]); // keynum
    plaintext_blob[8..72].copy_from_slice(&[0xBB; 64]); // secret key
    plaintext_blob[72..104].copy_from_slice(&[0xCC; 32]); // checksum

    // Wrap the plaintext
    let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Verify HW slot structure
    assert_eq!(hw_slot.hw_version, 1);
    assert_eq!(hw_slot.hw_key_label, label);
    assert_eq!(hw_slot.ephemeral_pubkey.len(), 33);
    assert_eq!(hw_slot.nonce.len(), 12);
    assert_eq!(hw_slot.ciphertext.len(), 104);
    assert_eq!(hw_slot.tag.len(), 16);

    // Unwrap the ciphertext
    let recovered_blob =
        minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot).expect("should unwrap successfully");

    // Verify plaintext matches
    assert_eq!(&*recovered_blob, &plaintext_blob);
}

/// Test that tampered ciphertext fails GCM tag verification
#[test]
fn test_tampered_ciphertext_fails() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let mut hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Tamper with ciphertext (flip one bit)
    hw_slot.ciphertext[0] ^= 0x01;

    // Unwrap should fail due to GCM tag mismatch
    match minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot) {
        Err(Error::DecryptionFailed) => {
            // Expected
        }
        other => panic!("expected decryption failure, got {other:?}"),
    }
}

/// Test that tampered ephemeral public key produces wrong shared secret → GCM failure
#[test]
fn test_tampered_ephemeral_pubkey_fails() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let mut hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Tamper with ephemeral public key (flip one bit)
    hw_slot.ephemeral_pubkey[5] ^= 0x01;

    // Unwrap should fail (either invalid point or GCM tag mismatch)
    let result = minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot);
    assert!(
        result.is_err(),
        "expected error due to tampered ephemeral pubkey"
    );
}

/// Test that tampered tag fails verification
#[test]
fn test_tampered_tag_fails() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let mut hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Tamper with tag (flip one bit)
    hw_slot.tag[0] ^= 0x01;

    // Unwrap should fail due to GCM tag mismatch
    match minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot) {
        Err(Error::DecryptionFailed) => {
            // Expected
        }
        other => panic!("expected decryption failure, got {other:?}"),
    }
}

/// Test that tampered nonce produces wrong decryption → GCM failure
#[test]
fn test_tampered_nonce_fails() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let mut hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Tamper with nonce (flip one bit)
    hw_slot.nonce[0] ^= 0x01;

    // Unwrap should fail due to GCM tag mismatch (wrong nonce)
    match minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot) {
        Err(Error::DecryptionFailed) => {
            // Expected
        }
        other => panic!("expected decryption failure, got {other:?}"),
    }
}

/// Test that wrong HW key label produces error
#[test]
fn test_wrong_hw_key_label() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Create HW slot with wrong label
    let mut wrong_hw_slot = hw_slot.clone();
    wrong_hw_slot.hw_key_label = "minisign:wrong_key".to_string();

    // Unwrap should fail (key not found)
    match minisign::ecies_wrap::ecies_unwrap(&hw, &wrong_hw_slot) {
        Err(Error::HardwareKeyNotFound { label }) => {
            assert_eq!(label, "minisign:wrong_key");
        }
        other => panic!("expected HardwareKeyNotFound error, got {other:?}"),
    }
}

/// Test that wrapping with non-existent HW key fails
#[test]
fn test_wrap_with_missing_hw_key() {
    let hw = MockKeyStore::new();
    let label = "minisign:nonexistent_key";

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    // Wrap should fail (key not found)
    match minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob) {
        Err(Error::HardwareKeyNotFound { label: err_label }) => {
            assert_eq!(err_label, label);
        }
        other => panic!("expected HardwareKeyNotFound error, got {other:?}"),
    }
}

/// Test that auth denied propagates error
#[test]
fn test_auth_denied_unwrap() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Configure mock to deny auth
    hw.set_config(minisign::hw_keystore::mock::MockConfig {
        available: true,
        deny_auth: true,
        simulate_error: false,
    });

    // Unwrap should fail with auth denied
    match minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot) {
        Err(Error::HardwareKeyStoreAuthDenied) => {
            // Expected
        }
        other => panic!("expected auth denied error, got {other:?}"),
    }
}

/// Test `SeckeyStruct::decrypt_with_hw` integration
#[test]
fn test_seckey_decrypt_with_hw() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    // Generate hardware key
    hw.generate_key(label).expect("should generate HW key");

    // Create a secret key
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    // Build the plaintext blob (keynum + secret + checksum)
    let plaintext_blob = SeckeyStruct::build_plaintext_blob(keynum, &secret_key);

    // Wrap with hardware
    let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Decrypt using HW
    let (recovered_secret, recovered_keynum) = seckey
        .decrypt_with_hw(&hw, &hw_slot)
        .expect("should decrypt with HW");

    // Verify key material matches
    assert_eq!(recovered_keynum.as_bytes(), keynum.as_bytes());
    assert_eq!(recovered_secret.as_bytes(), secret_key.as_bytes());
}

/// Test that `decrypt_with_hw` verifies checksum
#[test]
fn test_decrypt_with_hw_verifies_checksum() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    // Create a corrupted plaintext blob (wrong checksum)
    let mut corrupted_blob = [0u8; ENCRYPTED_BLOB_SIZE];
    corrupted_blob[0..8].copy_from_slice(&[0xAA; 8]); // keynum
    corrupted_blob[8..72].copy_from_slice(&[0xBB; 64]); // secret key
    corrupted_blob[72..104].copy_from_slice(&[0xFF; 32]); // WRONG checksum

    // Wrap the corrupted blob
    let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &corrupted_blob)
        .expect("should wrap successfully");

    // Decrypt should fail due to checksum mismatch
    match seckey.decrypt_with_hw(&hw, &hw_slot) {
        Err(Error::ChecksumFailed) => {
            // Expected
        }
        other => panic!("expected checksum mismatch, got {other:?}"),
    }
}

/// Test multiple different plaintexts to ensure no state leakage
#[test]
fn test_multiple_plaintexts_no_leakage() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    // Test multiple different plaintexts
    for i in 0_u8..5 {
        let plaintext_blob = [i; ENCRYPTED_BLOB_SIZE];

        let hw_slot = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
            .expect("should wrap successfully");

        let recovered_blob =
            minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot).expect("should unwrap successfully");

        assert_eq!(&*recovered_blob, &plaintext_blob);
    }
}

/// Test that ephemeral public keys are unique for each encryption
#[test]
fn test_unique_ephemeral_keys() {
    let hw = MockKeyStore::new();
    let label = "minisign:test_key";

    hw.generate_key(label).expect("should generate HW key");

    let plaintext_blob = [0x42; ENCRYPTED_BLOB_SIZE];

    // Encrypt same plaintext twice
    let hw_slot1 = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    let hw_slot2 = minisign::ecies_wrap::ecies_wrap(&hw, label, &plaintext_blob)
        .expect("should wrap successfully");

    // Ephemeral keys should be different
    assert_ne!(
        hw_slot1.ephemeral_pubkey, hw_slot2.ephemeral_pubkey,
        "ephemeral keys should be unique"
    );

    // Nonces should be different
    assert_ne!(hw_slot1.nonce, hw_slot2.nonce, "nonces should be unique");

    // Both should decrypt correctly
    let recovered1 =
        minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot1).expect("should unwrap successfully");
    let recovered2 =
        minisign::ecies_wrap::ecies_unwrap(&hw, &hw_slot2).expect("should unwrap successfully");

    assert_eq!(&*recovered1, &plaintext_blob);
    assert_eq!(&*recovered2, &plaintext_blob);
}
