//! Tests for HW slot format and key file extension (Phase 3)

use minisign::Error;
use minisign::keys::{HwSlot, SeckeyStruct};

/// Test that `HwSlot` can be serialized and deserialized (round-trip)
#[test]
fn test_hw_slot_round_trip_serialization() {
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33], // Compressed P-256 point (0x02 prefix)
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: "minisign:a1b2c3d4e5f6g7h8".to_string(),
    };

    let bytes = hw_slot.to_bytes();
    let decoded = HwSlot::from_bytes(&bytes).expect("should decode successfully");

    assert_eq!(decoded.hw_version, 1);
    assert_eq!(decoded.ephemeral_pubkey, [0x02; 33]);
    assert_eq!(decoded.nonce, [0x11; 12]);
    assert_eq!(decoded.ciphertext, [0x22; 104]);
    assert_eq!(decoded.tag, [0x33; 16]);
    assert_eq!(decoded.hw_key_label, "minisign:a1b2c3d4e5f6g7h8");
}

/// Test that `HwSlot` serialization produces correct byte layout
#[test]
fn test_hw_slot_byte_layout() {
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: "test".to_string(),
    };

    let bytes = hw_slot.to_bytes();

    // Check version (little-endian u16)
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[1], 0x00);

    // Check ephemeral pubkey
    assert_eq!(&bytes[2..35], &[0x02; 33]);

    // Check nonce
    assert_eq!(&bytes[35..47], &[0x11; 12]);

    // Check ciphertext
    assert_eq!(&bytes[47..151], &[0x22; 104]);

    // Check tag
    assert_eq!(&bytes[151..167], &[0x33; 16]);

    // Check label
    assert_eq!(&bytes[167..171], b"test");
}

/// Test that empty label is allowed
#[test]
fn test_hw_slot_empty_label() {
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: String::new(),
    };

    let bytes = hw_slot.to_bytes();
    assert_eq!(bytes.len(), 167); // Fixed size, no label

    let decoded = HwSlot::from_bytes(&bytes).expect("should decode successfully");
    assert_eq!(decoded.hw_key_label, "");
}

/// Test that `HwSlot` rejects unknown versions (forward compatibility)
#[test]
fn test_hw_slot_unknown_version() {
    let mut bytes = vec![0x02, 0x00]; // Version 2 (unsupported)
    bytes.extend_from_slice(&[0x02; 33]); // ephemeral_pubkey
    bytes.extend_from_slice(&[0x11; 12]); // nonce
    bytes.extend_from_slice(&[0x22; 104]); // ciphertext
    bytes.extend_from_slice(&[0x33; 16]); // tag
    bytes.extend_from_slice(b"label"); // label

    match HwSlot::from_bytes(&bytes) {
        Err(Error::InvalidSecretKey(msg)) => {
            assert!(msg.contains("unsupported HW slot version"));
        }
        other => panic!("expected unsupported version error, got {other:?}"),
    }
}

/// Test that `HwSlot` rejects data that's too short
#[test]
fn test_hw_slot_too_short() {
    let bytes = vec![0x01, 0x00]; // Only 2 bytes (need at least 167)

    match HwSlot::from_bytes(&bytes) {
        Err(Error::InvalidSecretKey(msg)) => {
            assert!(msg.contains("expected at least 167 bytes"));
        }
        other => panic!("expected size error, got {other:?}"),
    }
}

/// Test that label exceeding max size is rejected
#[test]
fn test_hw_slot_label_too_long() {
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: "a".repeat(65), // 65 bytes (exceeds HW_KEY_LABEL_MAX_BYTES = 64)
    };

    match hw_slot.to_bytes_checked() {
        Err(Error::InvalidSecretKey(msg)) => {
            assert!(msg.contains("label exceeds maximum size"));
        }
        other => panic!("expected label size error, got {other:?}"),
    }
}

/// Test that label with exactly max size is allowed
#[test]
fn test_hw_slot_label_max_size() {
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: "a".repeat(64), // Exactly at max
    };

    let result = hw_slot.to_bytes_checked();
    assert!(result.is_ok(), "should accept max-sized label");
}

/// Test that non-UTF-8 label bytes are rejected
#[test]
fn test_hw_slot_invalid_utf8_label() {
    let mut bytes = vec![0x01, 0x00]; // Version 1
    bytes.extend_from_slice(&[0x02; 33]); // ephemeral_pubkey
    bytes.extend_from_slice(&[0x11; 12]); // nonce
    bytes.extend_from_slice(&[0x22; 104]); // ciphertext
    bytes.extend_from_slice(&[0x33; 16]); // tag
    bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // Invalid UTF-8

    match HwSlot::from_bytes(&bytes) {
        Err(Error::InvalidSecretKey(msg)) => {
            assert!(msg.contains("invalid UTF-8"));
        }
        other => panic!("expected UTF-8 error, got {other:?}"),
    }
}

/// Test key file with HW slot: write → read → verify both slots present
#[test]
fn test_key_file_with_hw_slot() {
    use minisign::crypto::{KeyNum, SecretKey};

    // Create a secret key with encrypted keynum/secret
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    // Create an HW slot
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: "minisign:aaaaaaaaaaaaaaaa".to_string(),
    };

    // Serialize to file contents (with HW slot)
    let file_contents = seckey.to_file_contents_with_hw_slot("test key", Some(&hw_slot));

    // Verify 3 lines
    let lines: Vec<&str> = file_contents.lines().collect();
    assert_eq!(lines.len(), 3, "should have 3 lines with HW slot");

    // Parse back
    let (parsed_seckey, parsed_hw_slot) =
        SeckeyStruct::from_file_contents_with_hw_slot(&file_contents)
            .expect("should parse successfully");

    // Verify the secret key is identical (by checking encrypted bytes)
    assert_eq!(
        seckey.to_bytes(),
        parsed_seckey.to_bytes(),
        "secret key should be identical"
    );

    // Verify HW slot is present and identical
    assert!(parsed_hw_slot.is_some(), "HW slot should be present");
    let parsed_hw = parsed_hw_slot.unwrap();
    assert_eq!(parsed_hw.hw_version, hw_slot.hw_version);
    assert_eq!(parsed_hw.ephemeral_pubkey, hw_slot.ephemeral_pubkey);
    assert_eq!(parsed_hw.nonce, hw_slot.nonce);
    assert_eq!(parsed_hw.ciphertext, hw_slot.ciphertext);
    assert_eq!(parsed_hw.tag, hw_slot.tag);
    assert_eq!(parsed_hw.hw_key_label, hw_slot.hw_key_label);
}

/// Test key file without HW slot: backward-compatible (no third line)
#[test]
fn test_key_file_without_hw_slot() {
    use minisign::crypto::{KeyNum, SecretKey};

    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    // Serialize WITHOUT HW slot (backward compatible)
    let file_contents = seckey.to_file_contents_with_hw_slot("test key", None);

    // Verify only 2 lines
    let lines: Vec<&str> = file_contents.lines().collect();
    assert_eq!(lines.len(), 2, "should have only 2 lines without HW slot");

    // Parse back
    let (parsed_seckey, parsed_hw_slot) =
        SeckeyStruct::from_file_contents_with_hw_slot(&file_contents)
            .expect("should parse successfully");

    // Verify the secret key is identical
    assert_eq!(
        seckey.to_bytes(),
        parsed_seckey.to_bytes(),
        "secret key should be identical"
    );

    // Verify HW slot is absent
    assert!(parsed_hw_slot.is_none(), "HW slot should be absent");
}

/// Test that existing 2-line key files parse correctly (C compatibility)
#[test]
fn test_c_compatible_key_file() {
    use minisign::crypto::{KeyNum, SecretKey};

    // Create a real secret key for testing
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    // Serialize as 2-line file (C-compatible format)
    let c_file_contents = seckey.to_file_contents("test key");

    // Parse as 2-line file (should work)
    let (parsed_seckey, hw_slot) = SeckeyStruct::from_file_contents_with_hw_slot(&c_file_contents)
        .expect("should parse C-compatible file");

    // Verify it's a valid secret key struct
    assert_eq!(parsed_seckey.to_bytes().len(), 158);

    // Verify no HW slot
    assert!(
        hw_slot.is_none(),
        "C-compatible file should have no HW slot"
    );
}

/// Test that the old `from_file_contents` still works for backward compatibility
#[test]
fn test_old_from_file_contents_still_works() {
    use minisign::crypto::{KeyNum, SecretKey};

    // Create a real secret key for testing
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    let c_file_contents = seckey.to_file_contents("test key");

    // Old API should still work (ignore HW slot if present)
    let parsed_seckey =
        SeckeyStruct::from_file_contents(&c_file_contents).expect("old API should still work");

    assert_eq!(parsed_seckey.to_bytes().len(), 158);
}

/// Test that invalid HW slot base64 produces clear error
#[test]
fn test_invalid_hw_slot_base64() {
    use minisign::crypto::{KeyNum, SecretKey};

    // Create a real secret key for testing
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    let file_contents = seckey.to_file_contents("test key");
    let seckey_line = file_contents.lines().nth(1).unwrap();

    let bad_file = format!("untrusted comment: test key\n{seckey_line}\n!!invalid-base64!!\n");

    match SeckeyStruct::from_file_contents_with_hw_slot(&bad_file) {
        Err(Error::InvalidBase64(_)) => {
            // Expected
        }
        other => panic!("expected base64 error, got {other:?}"),
    }
}

/// Test that corrupted HW slot data produces clear error
#[test]
fn test_corrupted_hw_slot_data() {
    use minisign::crypto::{KeyNum, SecretKey};

    // Create a real secret key for testing
    let keynum = KeyNum::from_bytes([0xAA; 8]);
    let secret_key = SecretKey::from_bytes([0xBB; 64]);
    let password = b"test-password";
    let salt = [0xCC; 32];

    let seckey =
        SeckeyStruct::new_encrypted(keynum, &secret_key, password, salt, 1000, 1024, false)
            .expect("should create encrypted key");

    let file_contents = seckey.to_file_contents("test key");
    let seckey_line = file_contents.lines().nth(1).unwrap();

    let corrupted_file = format!("untrusted comment: test key\n{seckey_line}\nAQI=\n"); // Valid base64 but only 2 bytes

    match SeckeyStruct::from_file_contents_with_hw_slot(&corrupted_file) {
        Err(Error::InvalidSecretKey(msg)) => {
            assert!(
                msg.contains("expected at least 167 bytes"),
                "unexpected error message: {msg}"
            );
        }
        other => panic!("expected size error, got {other:?}"),
    }
}
