//! Unit tests for key inspection operations

use minisign::constants::ENCRYPTED_KEYNUM_PLACEHOLDER;
use minisign::crypto::generate_keypair;
use minisign::keys::SeckeyStruct;
use minisign::ops::inspect::{InspectOptions, KeyType, SecurityLevel, inspect, inspect_base64};
use rand::Rng;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

// Helper to create a temporary key file
fn create_temp_key_file(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(contents.as_bytes())
        .expect("Failed to write temp file");
    file.flush().expect("Failed to flush temp file");
    file
}

#[test]
fn test_inspect_production_strength_encrypted_key() {
    // Create a production-strength encrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    // Production parameters: N=2^20
    let kdf_opslimit = 33_554_432;
    let kdf_memlimit = 1_073_741_824;

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options).unwrap();

    // Verify results
    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::High));
    assert!(result.kdf_info.is_some());

    let kdf_info = result.kdf_info.unwrap();
    assert_eq!(kdf_info.opslimit, 33_554_432);
    assert_eq!(kdf_info.memlimit, 1_073_741_824);
    assert_eq!(kdf_info.log_n, 20);
    assert_eq!(kdf_info.r, 8);
    assert_eq!(kdf_info.p, 1);
    assert!(!kdf_info.is_fallback);
    assert_eq!(kdf_info.weakness_multiplier, None);
}

#[test]
fn test_inspect_medium_strength_fallback_key() {
    // Create a key with 1 fallback (N=2^19, 512 MB)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let kdf_opslimit = 16_777_216; // 1 fallback
    let kdf_memlimit = 536_870_912; // 512 MB

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options).unwrap();

    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::Medium));

    let kdf_info = result.kdf_info.unwrap();
    assert_eq!(kdf_info.opslimit, 16_777_216);
    assert_eq!(kdf_info.memlimit, 536_870_912);
    assert_eq!(kdf_info.log_n, 19);
    assert!(kdf_info.is_fallback);
    assert_eq!(kdf_info.weakness_multiplier, Some(2));
}

#[test]
fn test_inspect_low_strength_fallback_key() {
    // Create a key with 3 fallbacks (N=2^17, 128 MB)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let kdf_opslimit = 4_194_304; // 3 fallbacks (8x weaker)
    let kdf_memlimit = 134_217_728; // 128 MB

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options).unwrap();

    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::Low));

    let kdf_info = result.kdf_info.unwrap();
    assert_eq!(kdf_info.opslimit, 4_194_304);
    assert_eq!(kdf_info.memlimit, 134_217_728);
    assert_eq!(kdf_info.log_n, 17);
    assert!(kdf_info.is_fallback);
    assert_eq!(kdf_info.weakness_multiplier, Some(8));
}

#[test]
fn test_inspect_unencrypted_secret_key() {
    // Create an unencrypted secret key
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let file_contents = seckey.to_file_contents("unencrypted test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options).unwrap();

    assert_eq!(result.key_type, KeyType::SecretUnencrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::None));
    assert!(result.kdf_info.is_none());
}

#[test]
fn test_inspect_public_key() {
    // Load a real public key from fixtures
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");

    let temp_file = create_temp_key_file(&contents);

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options).unwrap();

    assert_eq!(result.key_type, KeyType::Public);
    assert_eq!(result.security_level, None);
    assert!(result.kdf_info.is_none());
    assert!(!result.key_id.is_empty());
    assert!(!result.key_id_words.is_empty());
    // Should have exactly 8 words (one per byte in keynum)
    assert_eq!(result.key_id_words.split_whitespace().count(), 8);
}

#[test]
fn test_inspect_invalid_file() {
    let temp_file = create_temp_key_file("not a valid key file\n");

    let options = InspectOptions::new(temp_file.path());

    let result = inspect(&options);
    assert!(result.is_err());
}

#[test]
fn test_inspect_missing_file() {
    let options = InspectOptions::new(std::path::Path::new("/nonexistent/path/to/key.file"));

    let result = inspect(&options);
    assert!(result.is_err());
}

#[test]
fn test_security_level_classification() {
    // Test the security level boundaries

    // High: Production strength (N=2^20)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test";
    let mut salt = [0u8; 32];
    rand::thread_rng().fill(&mut salt);

    let high_key = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        33_554_432,
        1_073_741_824,
        false,
    )
    .unwrap();

    let high_contents = high_key.to_file_contents("high");
    let high_file = create_temp_key_file(&high_contents);
    let result = inspect(&InspectOptions::new(high_file.path())).unwrap();
    assert_eq!(result.security_level, Some(SecurityLevel::High));

    // Medium: After 1 fallback (N=2^19, 512 MB)
    rand::thread_rng().fill(&mut salt);
    let medium_key = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        16_777_216,
        536_870_912,
        false,
    )
    .unwrap();

    let medium_contents = medium_key.to_file_contents("medium");
    let medium_file = create_temp_key_file(&medium_contents);
    let result = inspect(&InspectOptions::new(medium_file.path())).unwrap();
    assert_eq!(result.security_level, Some(SecurityLevel::Medium));

    // Low: After 3 fallbacks (N=2^17, 128 MB)
    rand::thread_rng().fill(&mut salt);
    let low_key = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        4_194_304,
        134_217_728,
        false,
    )
    .unwrap();

    let low_contents = low_key.to_file_contents("low");
    let low_file = create_temp_key_file(&low_contents);
    let result = inspect(&InspectOptions::new(low_file.path())).unwrap();
    assert_eq!(result.security_level, Some(SecurityLevel::Low));
}

#[test]
fn test_weakness_multiplier_calculation() {
    // Test the weakness multiplier calculation for different fallback levels
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test";

    // Test cases: (memlimit, expected_multiplier)
    let test_cases = vec![
        (1_073_741_824, None),  // Production: no weakness
        (536_870_912, Some(2)), // 1 fallback: 2x weaker
        (268_435_456, Some(4)), // 2 fallbacks: 4x weaker
        (134_217_728, Some(8)), // 3 fallbacks: 8x weaker
        (67_108_864, Some(16)), // 4 fallbacks: 16x weaker
        (33_554_432, Some(32)), // 5 fallbacks: 32x weaker
        (16_777_216, Some(64)), // 6 fallbacks (minimum): 64x weaker
    ];

    for (memlimit, expected_multiplier) in test_cases {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill(&mut salt);

        // Calculate corresponding opslimit
        let n = memlimit / 1024; // memlimit = 128 * N * r, so N = memlimit / (128 * 8)
        let opslimit = n * 32; // opslimit = 4 * N * r = 4 * N * 8

        let key = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            salt,
            opslimit,
            memlimit,
            false,
        )
        .unwrap();

        let contents = key.to_file_contents("test");
        let file = create_temp_key_file(&contents);

        let result = inspect(&InspectOptions::new(file.path())).unwrap();

        let kdf_info = result.kdf_info.unwrap();
        assert_eq!(
            kdf_info.weakness_multiplier, expected_multiplier,
            "Failed for memlimit={memlimit}"
        );
    }
}

#[test]
fn test_inspect_c_generated_production_key() {
    // Test inspecting a real C-generated key with production parameters
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");

    let temp_file = create_temp_key_file(&contents);

    let result = inspect(&InspectOptions::new(temp_file.path())).unwrap();

    // C-generated test key should be production strength
    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::High));

    let kdf_info = result.kdf_info.unwrap();
    assert_eq!(kdf_info.opslimit, 33_554_432);
    assert_eq!(kdf_info.memlimit, 1_073_741_824);
    assert!(!kdf_info.is_fallback);
}

#[test]
fn test_inspect_c_generated_unencrypted_key() {
    // Test inspecting a C-generated unencrypted key
    let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
        .expect("Failed to read unencrypted.key fixture");

    let temp_file = create_temp_key_file(&contents);

    let result = inspect(&InspectOptions::new(temp_file.path())).unwrap();

    assert_eq!(result.key_type, KeyType::SecretUnencrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::None));
    assert!(result.kdf_info.is_none());
}

#[test]
fn test_inspect_c_generated_public_key() {
    // Test inspecting a C-generated public key
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");

    let temp_file = create_temp_key_file(&contents);

    let result = inspect(&InspectOptions::new(temp_file.path())).unwrap();

    assert_eq!(result.key_type, KeyType::Public);
    assert_eq!(result.security_level, None);
    assert!(result.kdf_info.is_none());
}

#[test]
fn test_inspect_base64_public_key() {
    // Test inspecting a public key from base64 string
    let base64 = "RWTa4nmE9BYWyPMkgjyqrmh+smzESa8GEX0SnJzS2MIWbR1lL79TJ/8b";

    let result = inspect_base64(base64).unwrap();

    assert_eq!(result.key_type, KeyType::Public);
    assert_eq!(result.security_level, None);
    assert!(result.kdf_info.is_none());
    assert!(!result.key_id.is_empty());
    // Key ID should be 16 uppercase hex characters (matches C minisign format)
    assert_eq!(result.key_id.len(), 16);
    assert!(result.key_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!result.key_id_words.is_empty());
    // Should have exactly 8 words (one per byte in keynum)
    assert_eq!(result.key_id_words.split_whitespace().count(), 8);
}

#[test]
fn test_inspect_base64_invalid() {
    // Test that invalid base64 returns an error
    let invalid_base64 = "not-valid-base64!!!";
    let result = inspect_base64(invalid_base64);
    assert!(result.is_err());
}

#[test]
fn test_inspect_base64_wrong_format() {
    // Test that valid base64 but wrong format returns an error
    let wrong_format = "SGVsbG8gV29ybGQh"; // "Hello World!" in base64
    let result = inspect_base64(wrong_format);
    assert!(result.is_err());
}

#[test]
fn test_inspect_private_decrypts_and_shows_real_keyid() {
    use minisign::ops::inspect::{InspectPrivateOptions, inspect_private};

    // Create an encrypted key with known keynum
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    // Use weak parameters for fast test
    let kdf_opslimit = 4_194_304; // N=2^17
    let kdf_memlimit = 134_217_728; // 128 MB

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test encrypted key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectPrivateOptions::new(temp_file.path());

    // Decrypt and inspect
    let result = inspect_private(&options, password).unwrap();

    // Verify the real keynum is shown (not zeros)
    let expected_key_id = keynum.to_key_id();
    assert_eq!(result.key_id, expected_key_id);
    assert_ne!(result.key_id, ENCRYPTED_KEYNUM_PLACEHOLDER);

    // Verify key type and security level
    assert_eq!(result.key_type, KeyType::SecretEncrypted);
    assert_eq!(result.security_level, Some(SecurityLevel::Low));
}

#[test]
fn test_inspect_private_fails_with_wrong_password() {
    use minisign::ops::inspect::{InspectPrivateOptions, inspect_private};

    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"correct_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        4_194_304,
        134_217_728,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectPrivateOptions::new(temp_file.path());

    // Try with wrong password
    let result = inspect_private(&options, b"wrong_password");
    assert!(result.is_err());
}

#[test]
fn test_inspect_private_works_with_unencrypted_key() {
    use minisign::ops::inspect::{InspectPrivateOptions, inspect_private};

    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    let file_contents = seckey.to_file_contents("unencrypted test key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectPrivateOptions::new(temp_file.path());

    // Should work without password (password is ignored for unencrypted keys)
    let result = inspect_private(&options, b"").unwrap();

    assert_eq!(result.key_type, KeyType::SecretUnencrypted);
    assert_eq!(result.key_id, keynum.to_key_id());
}

#[test]
fn test_inspect_private_works_with_public_key() {
    use minisign::keys::PubkeyStruct;
    use minisign::ops::inspect::{InspectPrivateOptions, inspect_private};

    let (_secret_key, public_key, keynum) = generate_keypair().unwrap();
    let pubkey = PubkeyStruct::new(keynum, public_key);

    let file_contents = pubkey.to_file_contents("test public key");
    let temp_file = create_temp_key_file(&file_contents);

    let options = InspectPrivateOptions::new(temp_file.path());

    // Should work with public key (password is ignored)
    let result = inspect_private(&options, b"").unwrap();

    assert_eq!(result.key_type, KeyType::Public);
    assert_eq!(result.key_id, keynum.to_key_id());
}

// Tests for signature inspection

#[test]
fn test_inspect_signature_normal() {
    use minisign::crypto::{generate_keypair, sign};
    use minisign::ops::inspect::inspect_signature;
    use minisign::signature::{SigStruct, SignatureBox};

    // Create a normal (non-prehashed) signature
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let message = b"test message";
    let signature = sign(&secret_key, message).unwrap();
    let sig_struct = SigStruct::new(keynum, signature, false); // false = normal

    let sig_box = SignatureBox::with_global_signature(
        "test signature".to_string(),
        sig_struct,
        "timestamp: 123456".to_string(),
        &secret_key,
    )
    .unwrap();

    let sig_contents = sig_box.to_file_contents();
    let temp_file = create_temp_key_file(&sig_contents);

    let result = inspect_signature(temp_file.path()).unwrap();

    // Should extract key ID matching the keynum
    assert_eq!(result.key_id, keynum.to_key_id());
    assert_eq!(result.key_id.len(), 16); // 16 hex chars

    // Should have word list matching the keynum
    assert_eq!(result.key_id_words.split_whitespace().count(), 8);

    // Should detect normal algorithm
    assert_eq!(
        result.algorithm,
        minisign::signature::SignatureAlgorithm::Normal
    );
}

#[test]
fn test_inspect_signature_prehashed() {
    use minisign::ops::inspect::inspect_signature;

    // Use existing signature fixture (this one is prehashed)
    let result =
        inspect_signature(Path::new("tests/fixtures/signatures/hello.txt.minisig")).unwrap();

    // Should extract key ID
    assert!(!result.key_id.is_empty());
    assert_eq!(result.key_id.len(), 16); // 16 hex chars
    assert!(result.key_id.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(
        result
            .key_id
            .chars()
            .all(|c| c.is_uppercase() || c.is_ascii_digit())
    );

    // Should have word list
    assert!(!result.key_id_words.is_empty());
    assert_eq!(result.key_id_words.split_whitespace().count(), 8);

    // Should detect prehashed algorithm
    assert_eq!(
        result.algorithm,
        minisign::signature::SignatureAlgorithm::Prehashed
    );
}

#[test]
fn test_inspect_signature_invalid_file() {
    use minisign::ops::inspect::inspect_signature;

    let temp_file = create_temp_key_file("not a valid signature\n");

    let result = inspect_signature(temp_file.path());
    assert!(result.is_err());
}

#[test]
fn test_inspect_signature_nonexistent_file() {
    use minisign::ops::inspect::inspect_signature;

    let result = inspect_signature(Path::new("/nonexistent/signature.minisig"));
    assert!(result.is_err());
}

// Tests for hardware key inspection

#[test]
fn test_inspect_key_with_hw_slot_available_hardware() {
    use minisign::hw_keystore::HardwareKeyStore;
    use minisign::hw_keystore::mock::MockKeyStore;
    use minisign::keys::HwSlot;
    use minisign::ops::inspect::{InspectOptionsWithHw, inspect_with_hw};

    // Create a production-strength encrypted key
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let kdf_opslimit = 33_554_432;
    let kdf_memlimit = 1_073_741_824;

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false,
    )
    .unwrap();

    // Create a mock HW slot
    let hw_label = format!("minisign:{}", hex::encode(keynum.as_bytes()));
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: hw_label.clone(),
    };

    // Write key file with HW slot
    let file_contents = seckey.to_file_contents_with_hw_slot("test key", Some(&hw_slot));
    let temp_file = create_temp_key_file(&file_contents);

    // Create mock hardware key store with the key available
    let mock_hw = MockKeyStore::new();
    mock_hw.generate_key(&hw_label).unwrap();

    let options = InspectOptionsWithHw::new(temp_file.path(), &mock_hw);
    let result = inspect_with_hw(&options).unwrap();

    // Verify HW enrollment status
    assert!(result.hw_enrolled);
    assert_eq!(result.hw_label, Some(hw_label));
    assert_eq!(result.hw_backend_name, Some("Mock Hardware Key Store"));
    assert_eq!(result.hw_key_available, Some(true));
    assert!(!result.hw_unavailable_warning);
}

#[test]
fn test_inspect_key_with_hw_slot_unavailable_hardware() {
    use minisign::hw_keystore::unsupported::UnsupportedKeyStore;
    use minisign::keys::HwSlot;
    use minisign::ops::inspect::{InspectOptionsWithHw, inspect_with_hw};

    // Create encrypted key with HW slot
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        4_194_304,
        134_217_728,
        false,
    )
    .unwrap();

    let hw_label = format!("minisign:{}", hex::encode(keynum.as_bytes()));
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: hw_label.clone(),
    };

    let file_contents = seckey.to_file_contents_with_hw_slot("test key", Some(&hw_slot));
    let temp_file = create_temp_key_file(&file_contents);

    // Use unsupported hardware key store
    let hw = UnsupportedKeyStore;
    let options = InspectOptionsWithHw::new(temp_file.path(), &hw);
    let result = inspect_with_hw(&options).unwrap();

    // Verify HW enrollment status with unavailable hardware
    assert!(result.hw_enrolled);
    assert_eq!(result.hw_label, Some(hw_label));
    assert_eq!(result.hw_backend_name, Some("Unsupported"));
    assert_eq!(result.hw_key_available, None); // Can't check if unavailable
    assert!(result.hw_unavailable_warning); // Should show warning
}

#[test]
fn test_inspect_key_without_hw_slot() {
    use minisign::hw_keystore::mock::MockKeyStore;
    use minisign::ops::inspect::{InspectOptionsWithHw, inspect_with_hw};

    // Create standard encrypted key without HW slot
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        33_554_432,
        1_073_741_824,
        false,
    )
    .unwrap();

    let file_contents = seckey.to_file_contents("test key");
    let temp_file = create_temp_key_file(&file_contents);

    let hw = MockKeyStore::new();
    let options = InspectOptionsWithHw::new(temp_file.path(), &hw);
    let result = inspect_with_hw(&options).unwrap();

    // Verify no HW enrollment
    assert!(!result.hw_enrolled);
    assert_eq!(result.hw_label, None);
    assert_eq!(result.hw_backend_name, None);
    assert_eq!(result.hw_key_available, None);
    assert!(!result.hw_unavailable_warning);
}

#[test]
fn test_inspect_key_with_hw_slot_key_not_found() {
    use minisign::hw_keystore::mock::MockKeyStore;
    use minisign::keys::HwSlot;
    use minisign::ops::inspect::{InspectOptionsWithHw, inspect_with_hw};

    // Create encrypted key with HW slot
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        4_194_304,
        134_217_728,
        false,
    )
    .unwrap();

    let hw_label = format!("minisign:{}", hex::encode(keynum.as_bytes()));
    let hw_slot = HwSlot {
        hw_version: 1,
        ephemeral_pubkey: [0x02; 33],
        nonce: [0x11; 12],
        ciphertext: [0x22; 104],
        tag: [0x33; 16],
        hw_key_label: hw_label.clone(),
    };

    let file_contents = seckey.to_file_contents_with_hw_slot("test key", Some(&hw_slot));
    let temp_file = create_temp_key_file(&file_contents);

    // Mock hardware is available but key doesn't exist
    let hw = MockKeyStore::new();
    let options = InspectOptionsWithHw::new(temp_file.path(), &hw);
    let result = inspect_with_hw(&options).unwrap();

    // Verify HW enrollment but key not available
    assert!(result.hw_enrolled);
    assert_eq!(result.hw_label, Some(hw_label));
    assert_eq!(result.hw_backend_name, Some("Mock Hardware Key Store"));
    assert_eq!(result.hw_key_available, Some(false)); // Key not found
    assert!(!result.hw_unavailable_warning);
}
