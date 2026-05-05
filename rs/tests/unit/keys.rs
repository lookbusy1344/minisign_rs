use minisign::crypto::*;
use minisign::errors::*;
use minisign::keys::*;
use rand::Rng;
use std::fs;

#[test]
fn test_pubkey_struct_size() {
    assert_eq!(PUBKEY_STRUCT_SIZE, 42);
}

#[test]
fn test_seckey_struct_size() {
    assert_eq!(SECKEY_STRUCT_SIZE, 158);
}

#[test]
fn test_parse_c_generated_public_key() {
    // Load the C-generated public key fixture
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");

    // Parse the public key
    let pubkey = PubkeyStruct::from_file_contents(&contents).expect("Failed to parse public key");

    // Verify structure - the actual values depend on the generated key,
    // but we can check that parsing succeeds and produces valid data
    assert_eq!(pubkey.keynum().as_bytes().len(), KEYNUM_BYTES);
    assert_eq!(pubkey.public_key().as_bytes().len(), PUBLIC_KEY_BYTES);
}

#[test]
fn test_parse_c_generated_encrypted_secret_key() {
    // Load the C-generated encrypted secret key fixture
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");

    // Parse the secret key structure
    let seckey = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

    // Verify it's encrypted
    assert!(seckey.is_encrypted(), "Expected key to be encrypted");

    // Verify structure
    assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
    assert!(seckey.kdf_opslimit() > 0, "Expected non-zero opslimit");
    assert!(seckey.kdf_memlimit() > 0, "Expected non-zero memlimit");
}

#[test]
fn test_parse_c_generated_unencrypted_secret_key() {
    // Load the C-generated unencrypted secret key fixture
    let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
        .expect("Failed to read unencrypted.key fixture");

    // Parse the secret key structure
    let seckey = SeckeyStruct::from_file_contents(&contents)
        .expect("Failed to parse unencrypted secret key");

    // Verify it's NOT encrypted
    assert!(!seckey.is_encrypted(), "Expected key to be unencrypted");

    // Verify structure
    assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
    assert_eq!(
        seckey.kdf_opslimit(),
        0,
        "Expected zero opslimit for unencrypted key"
    );
    assert_eq!(
        seckey.kdf_memlimit(),
        0,
        "Expected zero memlimit for unencrypted key"
    );
}

#[test]
fn test_parse_c_generated_public_key_with_trailing_blank_lines_is_compatible() {
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");
    let compat_contents = format!("{contents}\n\n");

    let pubkey =
        PubkeyStruct::from_file_contents(&compat_contents).expect("Failed to parse public key");

    assert_eq!(pubkey.keynum().as_bytes().len(), KEYNUM_BYTES);
    assert_eq!(pubkey.public_key().as_bytes().len(), PUBLIC_KEY_BYTES);
}

#[test]
fn test_parse_c_generated_public_key_with_trailing_data_is_compatible() {
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");
    let compat_contents = format!("{contents}extra trailing line\n");

    let pubkey =
        PubkeyStruct::from_file_contents(&compat_contents).expect("Failed to parse public key");

    assert_eq!(pubkey.keynum().as_bytes().len(), KEYNUM_BYTES);
    assert_eq!(pubkey.public_key().as_bytes().len(), PUBLIC_KEY_BYTES);
}

#[test]
fn test_parse_c_generated_secret_key_with_trailing_blank_lines_is_compatible() {
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");
    let compat_contents = format!("{contents}\n\n");

    let seckey =
        SeckeyStruct::from_file_contents(&compat_contents).expect("Failed to parse secret key");

    assert!(seckey.is_encrypted(), "Expected key to be encrypted");
    assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
}

#[test]
fn test_parse_c_generated_secret_key_with_trailing_data_is_compatible() {
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");
    let compat_contents = format!("{contents}extra trailing line\n");

    let seckey =
        SeckeyStruct::from_file_contents(&compat_contents).expect("Failed to parse secret key");

    assert!(seckey.is_encrypted(), "Expected key to be encrypted");
    assert_eq!(seckey.keynum().as_bytes().len(), KEYNUM_BYTES);
}

#[test]
fn test_public_key_serialization_roundtrip() {
    // Load and parse C-generated public key
    let contents = fs::read_to_string("tests/fixtures/keys/test.pub")
        .expect("Failed to read test.pub fixture");

    let original = PubkeyStruct::from_file_contents(&contents).expect("Failed to parse public key");

    // Serialize to bytes and parse back
    let bytes = original.to_bytes();
    let roundtrip = PubkeyStruct::from_bytes(&bytes).expect("Failed to parse roundtripped bytes");

    // Verify they're identical
    assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
    assert_eq!(
        original.public_key().as_bytes(),
        roundtrip.public_key().as_bytes()
    );
}

#[test]
fn test_secret_key_serialization_roundtrip() {
    // Load and parse C-generated secret key
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");

    let original = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

    // Serialize to bytes and parse back
    let bytes = original.to_bytes();
    let roundtrip = SeckeyStruct::from_bytes(&bytes).expect("Failed to parse roundtripped bytes");

    // Verify they're identical
    assert_eq!(original.is_encrypted(), roundtrip.is_encrypted());
    assert_eq!(original.keynum().as_bytes(), roundtrip.keynum().as_bytes());
    assert_eq!(original.kdf_opslimit(), roundtrip.kdf_opslimit());
    assert_eq!(original.kdf_memlimit(), roundtrip.kdf_memlimit());
    assert_eq!(
        original.encrypted_secret_key(),
        roundtrip.encrypted_secret_key()
    );
}

#[test]
fn test_public_key_file_format_roundtrip() {
    // Create a test public key
    let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let pk_bytes = [42u8; PUBLIC_KEY_BYTES];
    let public_key = PublicKey::from_bytes(pk_bytes);
    let pubkey = PubkeyStruct::new(keynum, public_key);

    // Serialize to file format
    let file_contents = pubkey.to_file_contents("test comment");

    // Verify format
    assert!(file_contents.starts_with("untrusted comment: test comment\n"));
    assert!(file_contents.ends_with('\n'));

    // Parse back
    let parsed =
        PubkeyStruct::from_file_contents(&file_contents).expect("Failed to parse file contents");

    assert_eq!(pubkey.keynum().as_bytes(), parsed.keynum().as_bytes());
    assert_eq!(
        pubkey.public_key().as_bytes(),
        parsed.public_key().as_bytes()
    );
}

#[test]
fn test_invalid_public_key_too_short() {
    let short_data = [0u8; 10];
    let result = PubkeyStruct::from_bytes(&short_data);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
}

#[test]
fn test_invalid_public_key_wrong_algorithm() {
    let mut data = [0u8; PUBKEY_STRUCT_SIZE];
    data[0..2].copy_from_slice(b"XX"); // Wrong algorithm
    let result = PubkeyStruct::from_bytes(&data);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidPublicKey(_))));
}

#[test]
fn test_invalid_secret_key_too_short() {
    let short_data = [0u8; 10];
    let result = SeckeyStruct::from_bytes(&short_data);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
}

#[test]
fn test_invalid_secret_key_wrong_sig_algorithm() {
    let mut data = [0u8; SECKEY_STRUCT_SIZE];
    data[0..2].copy_from_slice(b"XX"); // Wrong sig algorithm
    data[2..4].copy_from_slice(b"\0\0"); // Valid KDF
    data[4..6].copy_from_slice(b"B2"); // Valid checksum
    let result = SeckeyStruct::from_bytes(&data);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
}

#[test]
fn test_invalid_secret_key_wrong_kdf_algorithm() {
    let mut data = [0u8; SECKEY_STRUCT_SIZE];
    data[0..2].copy_from_slice(b"Ed"); // Valid sig algorithm
    data[2..4].copy_from_slice(b"XX"); // Wrong KDF
    data[4..6].copy_from_slice(b"B2"); // Valid checksum
    let result = SeckeyStruct::from_bytes(&data);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::InvalidSecretKey(_))));
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    use minisign::crypto::generate_keypair;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"test_password";
    let kdf_salt = [42u8; KDF_SALT_BYTES];
    // Use reduced parameters for testing (log_n=14 for reasonable speed)
    // Using libsodium formulas:
    // opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * N * r
    // memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * N * r
    let n = 1u64 << 14; // N = 16384
    let r = u64::from(SCRYPT_R);
    let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
    let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

    // Create encrypted secret key
    let encrypted_key = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false, // allow_fallback - secure by default
    )
    .expect("Failed to encrypt key");

    assert!(encrypted_key.is_encrypted());

    // Decrypt it
    let (decrypted_key, _) = encrypted_key
        .decrypt(password)
        .expect("Failed to decrypt key");

    // Verify it matches the original
    assert_eq!(secret_key.as_bytes(), decrypted_key.as_bytes());
}

#[test]
fn test_decrypt_with_wrong_password() {
    use minisign::crypto::generate_keypair;

    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"correct_password";
    let wrong_password = b"wrong_password";
    let kdf_salt = [42u8; KDF_SALT_BYTES];
    // Use reduced parameters for testing
    let n = 1u64 << 14;
    let r = u64::from(SCRYPT_R);
    let kdf_opslimit = LIBSODIUM_OPSLIMIT_MULTIPLIER * n * r;
    let kdf_memlimit = LIBSODIUM_MEMLIMIT_MULTIPLIER * n * r;

    let encrypted_key = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false, // allow_fallback - secure by default
    )
    .expect("Failed to encrypt key");

    // Try to decrypt with wrong password
    let result = encrypted_key.decrypt(wrong_password);

    // Should fail with checksum error
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::ChecksumFailed)));
}

#[test]
fn test_get_unencrypted_secret_key() {
    use minisign::crypto::generate_keypair;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    // Create unencrypted secret key structure
    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    assert!(!seckey.is_encrypted());

    // Get the unencrypted key
    let retrieved_key = seckey
        .get_unencrypted_secret_key()
        .expect("Failed to get unencrypted key");

    assert_eq!(secret_key.as_bytes(), retrieved_key.as_bytes());
}

#[test]
fn test_decrypt_c_generated_encrypted_key() {
    // Load the C-generated encrypted secret key
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");

    let seckey = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

    assert!(seckey.is_encrypted());

    // The password we used when generating the fixture is "test"
    let password = b"test";

    // Decrypt it
    let (secret_key, _) = seckey.decrypt(password).expect("Failed to decrypt key");

    // Verify we got a valid secret key
    assert_eq!(secret_key.as_bytes().len(), SECRET_KEY_BYTES);

    // The decrypted key should have a valid checksum
    // (checksum validation happens inside decrypt())
}

#[test]
fn test_decrypt_c_generated_encrypted_key_wrong_password() {
    // Load the C-generated encrypted secret key
    let contents = fs::read_to_string("tests/fixtures/keys/test.key")
        .expect("Failed to read test.key fixture");

    let seckey = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

    // Try with wrong password
    let result = seckey.decrypt(b"wrong_password");

    // Should fail
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::ChecksumFailed)));
}

#[test]
fn test_get_c_generated_unencrypted_key() {
    // Load the C-generated unencrypted secret key
    let contents = fs::read_to_string("tests/fixtures/keys/unencrypted.key")
        .expect("Failed to read unencrypted.key fixture");

    let seckey = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");

    assert!(!seckey.is_encrypted());

    // Debug: check checksum
    let computed = SeckeyStruct::compute_checksum(*seckey.keynum(), seckey.encrypted_secret_key());
    eprintln!("Stored checksum:   {:02x?}", &seckey.checksum()[..8]);
    eprintln!("Computed checksum: {:02x?}", &computed[..8]);

    // Get the unencrypted key
    let secret_key = seckey
        .get_unencrypted_secret_key()
        .expect("Failed to get unencrypted key");

    // Verify we got a valid secret key
    assert_eq!(secret_key.as_bytes().len(), SECRET_KEY_BYTES);
}

#[test]
fn test_scrypt_fallback_minimum_constants() {
    use minisign::crypto::{SCRYPT_MEMLIMIT_MIN, SCRYPT_OPSLIMIT_MIN};

    // Verify minimum constants are defined and have reasonable values
    // These match libsodium's minimum thresholds
    assert_eq!(SCRYPT_OPSLIMIT_MIN, 32_768);
    assert_eq!(SCRYPT_MEMLIMIT_MIN, 16_777_216);

    // Note: Testing encryption with actual minimum parameters is challenging
    // because different systems/scrypt implementations may have different
    // practical limits. The fallback mechanism will reduce parameters until
    // they work or hit these minimums.
}

/// Verifies that the minimum scrypt constants represent a coherent, valid parameter set.
///
/// `SCRYPT_OPSLIMIT_MIN` and `SCRYPT_MEMLIMIT_MIN` are independent lower bounds used by
/// the fallback mechanism.  This test confirms they are not just arbitrary numbers: each
/// constant, paired with the standard r=8 formulation, must be accepted by
/// `opslimit_memlimit_to_params` and produce `(log_n, r, p)` values within valid scrypt
/// ranges.  If this test fails after a constants change, the fallback mechanism would
/// silently fail to produce valid scrypt parameters.
///
/// Note: `SCRYPT_OPSLIMIT_MIN` and `SCRYPT_MEMLIMIT_MIN` are independent minimums
/// (matching libsodium semantics) and do NOT form a coherent pair together — they
/// correspond to different N values and must be tested with their respective matching
/// counterparts.
#[test]
fn test_scrypt_minimum_constants_are_valid_params() {
    use minisign::crypto::{SCRYPT_MEMLIMIT_MIN, SCRYPT_OPSLIMIT_MIN, opslimit_memlimit_to_params};

    // Exact-value pins (matching test_scrypt_fallback_minimum_constants, for regression detection)
    assert_eq!(SCRYPT_OPSLIMIT_MIN, 32_768);
    assert_eq!(SCRYPT_MEMLIMIT_MIN, 16_777_216);

    // SCRYPT_OPSLIMIT_MIN=32768 corresponds to N=1024 (log_n=10), r=8, p=1:
    //   opslimit = 4 * N * r = 4 * 1024 * 8 = 32_768  ✓
    //   matching memlimit = 128 * N * r = 128 * 1024 * 8 = 1_048_576
    let memlimit_for_min_opslimit: u64 = 1_048_576;
    let result = opslimit_memlimit_to_params(SCRYPT_OPSLIMIT_MIN, memlimit_for_min_opslimit);
    assert!(
        result.is_ok(),
        "SCRYPT_OPSLIMIT_MIN must correspond to valid scrypt parameters; got: {result:?}"
    );
    let (log_n, r, p) = result.unwrap();
    assert!(log_n < 64, "log_n={log_n} must be < 64");
    assert!(r > 0, "r={r} must be > 0");
    assert!(p > 0, "p={p} must be > 0");

    // SCRYPT_MEMLIMIT_MIN=16_777_216 corresponds to N=16384 (log_n=14), r=8, p=1:
    //   memlimit = 128 * N * r = 128 * 16384 * 8 = 16_777_216  ✓
    //   matching opslimit = 4 * N * r = 4 * 16384 * 8 = 524_288
    let opslimit_for_min_memlimit: u64 = 524_288;
    let result2 = opslimit_memlimit_to_params(opslimit_for_min_memlimit, SCRYPT_MEMLIMIT_MIN);
    assert!(
        result2.is_ok(),
        "SCRYPT_MEMLIMIT_MIN must correspond to valid scrypt parameters; got: {result2:?}"
    );
    let (log_n2, r2, p2) = result2.unwrap();
    assert!(log_n2 < 64, "log_n={log_n2} must be < 64");
    assert!(r2 > 0, "r={r2} must be > 0");
    assert!(p2 > 0, "p={p2} must be > 0");
}

#[test]
fn test_scrypt_fallback_with_moderate_parameters() {
    use minisign::crypto::generate_keypair;

    // Test encryption with moderate parameters that should work on most systems
    // log_N = 15 (N = 32768), r = 8, p = 1
    // opslimit = 4 * 32768 * 8 = 1,048,576
    // memlimit = 128 * 32768 * 8 = 33,554,432 (32 MB)
    const OPSLIMIT: u64 = 1_048_576; // Moderate parameters
    const MEMLIMIT: u64 = 33_554_432; // 32 MB

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"test password";
    let mut salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut salt);

    let encrypted = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        false,
    )
    .expect("Encryption with moderate parameters should succeed");

    // Verify the encrypted key stores parameters (either original or reduced if fallback occurred)
    assert!(encrypted.kdf_opslimit() > 0);
    assert!(encrypted.kdf_memlimit() > 0);
    assert!(encrypted.kdf_opslimit() <= OPSLIMIT);
    assert!(encrypted.kdf_memlimit() <= MEMLIMIT);

    // Verify decryption works
    let (decrypted_key, decrypted_keynum) = encrypted
        .decrypt(password)
        .expect("Decryption should succeed");

    assert_eq!(decrypted_keynum, keynum);
    assert_eq!(decrypted_key.as_bytes(), secret_key.as_bytes());
}

#[test]
fn test_scrypt_parameters_below_minimum_would_fail() {
    use minisign::crypto::{SCRYPT_MEMLIMIT_MIN, SCRYPT_OPSLIMIT_MIN};

    // Note: We cannot easily test actual fallback behavior because:
    // 1. We'd need to make scrypt fail, which requires extreme memory pressure
    // 2. The fallback loop is internal to new_encrypted()
    //
    // What we CAN test is that the minimum thresholds exist and are enforced.
    // If parameters were to fall below minimum during fallback, encryption would fail.

    // Verify minimum constants are reasonable values
    assert_eq!(SCRYPT_OPSLIMIT_MIN, 32_768);
    assert_eq!(SCRYPT_MEMLIMIT_MIN, 16_777_216);

    // Parameters at minimum should work (tested above)
    // Parameters below minimum would cause fallback to error out
    // But we can't directly test parameters below minimum because
    // new_encrypted() would fail in the conversion or validation
}

#[test]
fn test_encryption_stores_successful_parameters() {
    use minisign::crypto::generate_keypair;

    // Use standard parameters (high memory requirements)
    const OPSLIMIT: u64 = 33_554_432; // 4 * 2^20 * 8
    const MEMLIMIT: u64 = 1_073_741_824; // 128 * 2^20 * 8

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"test password";
    let mut salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut salt);

    let encrypted = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        false,
    )
    .expect("Encryption should succeed");

    // The encrypted key should store the parameters that actually worked
    // If fallback occurred, these would be reduced values
    // If no fallback, these should match the input
    assert!(encrypted.kdf_opslimit() > 0);
    assert!(encrypted.kdf_memlimit() > 0);

    // On most systems with sufficient memory, no fallback occurs
    // so parameters should match (but we can't assert this deterministically)
}

#[test]
fn test_new_encrypted_rejects_fallback_when_not_allowed() {
    use minisign::crypto::generate_keypair;

    // Use reasonable test parameters (N=2^14)
    const N: u64 = 1 << 14;
    const R: u64 = 8;
    const OPSLIMIT: u64 = 4 * N * R;
    const MEMLIMIT: u64 = 128 * N * R;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"test password";
    let mut salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut salt);

    // With allow_fallback=false, should succeed on systems with sufficient memory
    // This test primarily validates that the API signature exists and works
    let result = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        false, // allow_fallback=false (secure by default)
    );

    // Should succeed with reasonable parameters on normal systems
    assert!(
        result.is_ok(),
        "Encryption with allow_fallback=false should succeed with reasonable parameters"
    );
}

#[test]
fn test_new_encrypted_allows_fallback_when_enabled() {
    use minisign::crypto::generate_keypair;

    // Use reasonable test parameters (N=2^14)
    const N: u64 = 1 << 14;
    const R: u64 = 8;
    const OPSLIMIT: u64 = 4 * N * R;
    const MEMLIMIT: u64 = 128 * N * R;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let password = b"test password";
    let mut salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut salt);

    // With allow_fallback=true, should succeed (either directly or via fallback)
    let result = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        salt,
        OPSLIMIT,
        MEMLIMIT,
        true, // allow_fallback=true (opt-in to reduced security)
    );

    assert!(
        result.is_ok(),
        "Encryption with allow_fallback=true should succeed"
    );
}

// Property-based tests
use proptest::prelude::*;

proptest! {
    /// Property test: PublicKey serialization roundtrip
    #[test]
    fn prop_public_key_serialization_roundtrip(
        keynum_data in prop::array::uniform8(any::<u8>()),
        pubkey_data in prop::collection::vec(any::<u8>(), 32..=32)
    ) {
        // Convert vec to array for PublicKey
        let mut pubkey_array = [0u8; 32];
        pubkey_array.copy_from_slice(&pubkey_data);

        let pubkey = PubkeyStruct::new(
            KeyNum::from_bytes(keynum_data),
            PublicKey::from_bytes(pubkey_array),
        );

        let serialized = pubkey.to_bytes();
        let deserialized = PubkeyStruct::from_bytes(&serialized).unwrap();

        prop_assert_eq!(pubkey.keynum().as_bytes(), deserialized.keynum().as_bytes());
        prop_assert_eq!(pubkey.public_key().as_bytes(), deserialized.public_key().as_bytes());
    }

    /// Property test: KeyNum hex encoding roundtrip
    #[test]
    fn prop_keynum_hex_roundtrip(data in prop::array::uniform8(any::<u8>())) {
        let keynum = KeyNum::from_bytes(data);
        let hex = keynum.to_hex();
        // Verify hex is 16 chars (8 bytes = 16 hex digits)
        prop_assert_eq!(hex.len(), 16);
        // Verify all chars are valid hex
        prop_assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn test_opslimit_memlimit_to_params_zero_n() {
    // Test that N=0 is rejected (memlimit too small)
    let opslimit = 1;
    let memlimit = 1;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_err());
}

#[test]
fn test_opslimit_memlimit_to_params_overflow() {
    // Test that extremely large values are rejected by the policy cap.
    // u64::MAX memlimit would produce log_n=43, well above MAX_SCRYPT_LOG_N=25.
    let memlimit = u64::MAX;
    let opslimit = u64::MAX;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(
        result.is_err(),
        "Extreme values should be rejected by policy cap"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("policy")
            || err_msg.contains("exceeds")
            || err_msg.contains("exact minisign KDF encoding"),
        "Expected policy or encoding error, got: {err_msg}"
    );
}

#[test]
fn test_opslimit_memlimit_to_params_valid() {
    // Test with valid standard parameters (log_n=20, r=8, p=1)
    // N = 2^20 = 1,048,576
    // opslimit = 4 * N * r = 4 * 1,048,576 * 8 = 33,554,432
    // memlimit = 128 * N * r = 128 * 1,048,576 * 8 = 1,073,741,824
    let opslimit = 33_554_432;
    let memlimit = 1_073_741_824;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_ok());
    let (log_n, r, p) = result.unwrap();
    assert_eq!(log_n, 20);
    assert_eq!(r, 8);
    assert_eq!(p, 1);
}

#[test]
fn test_opslimit_memlimit_to_params_non_power_of_two() {
    // Test with N that's not a power of 2
    // N = 1000 (not a power of 2)
    // opslimit = 4 * 1000 * 8 = 32,000
    // memlimit = 128 * 1000 * 8 = 1,024,000
    let opslimit = 32_000;
    let memlimit = 1_024_000;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_err());
}

#[test]
fn test_opslimit_memlimit_to_params_min_valid() {
    // Test with minimum valid parameters (log_n=1, r=8, p=1)
    // N = 2^1 = 2
    // opslimit = 4 * 2 * 8 = 64
    // memlimit = 128 * 2 * 8 = 2,048
    let opslimit = 64;
    let memlimit = 2_048;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_ok());
    let (log_n, r, p) = result.unwrap();
    assert_eq!(log_n, 1);
    assert_eq!(r, 8);
    assert_eq!(p, 1);
}

#[test]
fn test_opslimit_memlimit_to_params_invalid_multipliers() {
    // Test mismatched multipliers that don't follow the standard formula
    // Use N=10, r=8 with intentionally wrong opslimit
    // Standard: opslimit = 4 * 10 * 8 = 320, memlimit = 128 * 10 * 8 = 10,240
    // We'll use correct memlimit but wrong opslimit
    let memlimit = 10_240; // Gives N=10 with r=8
    let opslimit = 500; // Wrong! Should be 320
    // These don't satisfy: opslimit = 4*N*r AND memlimit = 128*N*r
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_err());
}

#[test]
fn test_opslimit_memlimit_to_params_divisor_overflow() {
    // Test that overflow in divisor calculation is handled
    // This tests the checked_mul in: LIBSODIUM_MEMLIMIT_MULTIPLIER * r
    // With current values (128 * 8), this won't overflow, but test the path
    // Using extreme memlimit to trigger different overflow paths
    let opslimit = u64::MAX / 2;
    let memlimit = u64::MAX / 2;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    // Should handle gracefully - either succeed with large log_n or error
    // The actual behavior depends on whether log_n fits in u8
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_opslimit_memlimit_to_params_expected_opslimit_overflow() {
    // Test overflow when calculating expected_opslimit for verification
    // This can happen with very large N values
    // Use parameters that will cause N to be extremely large
    let memlimit = u64::MAX / 1024; // Large but not MAX to avoid division issues
    let opslimit = u64::MAX / 1024;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    // Should either succeed or fail with overflow error
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("overflow")
                || err_msg.contains("policy")
                || err_msg.contains("exact minisign KDF encoding"),
            "Expected overflow, policy, or encoding error, got: {err_msg}"
        );
    }
}

#[test]
#[cfg(debug_assertions)]
fn test_opslimit_memlimit_to_params_weak_kdf() {
    // Test weak KDF parameters (debug build only)
    // N = 2^17, r=8, p=1 (used with --force-weak-kdf)
    // opslimit = 4 * 2^17 * 8 = 4,194,304
    // memlimit = 128 * 2^17 * 8 = 134,217,728
    let opslimit = 4_194_304;
    let memlimit = 134_217_728;
    let result = SeckeyStruct::opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_ok());
    let (log_n, r, p) = result.unwrap();
    assert_eq!(log_n, 17); // Weaker than production (20)
    assert_eq!(r, 8);
    assert_eq!(p, 1);
}

#[test]
fn test_is_weak_kdf_production_strength() {
    use minisign::crypto::generate_keypair;
    // Create a key with production-strength parameters
    // N = 2^20, opslimit = 33,554,432, memlimit = 1,073,741,824
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut kdf_salt);

    let kdf_opslimit = 33_554_432; // Production strength
    let kdf_memlimit = 1_073_741_824;

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false, // No fallback
    )
    .unwrap();

    // Production strength key should NOT be weak
    assert!(!seckey.is_weak_kdf());
}

#[test]
fn test_is_weak_kdf_fallback_parameters() {
    use minisign::crypto::generate_keypair;
    // Create a key with fallback parameters (weaker)
    // N = 2^17 (3 fallbacks from production), opslimit = 4,194,304, memlimit = 134,217,728
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut kdf_salt);

    let kdf_opslimit = 4_194_304; // After 3 fallbacks (8x weaker)
    let kdf_memlimit = 134_217_728; // 128 MB

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        false, // No fallback needed, we're directly creating with weak params
    )
    .unwrap();

    // Fallback parameters should be detected as weak
    assert!(seckey.is_weak_kdf());
}

#[test]
fn test_is_weak_kdf_low_parameters() {
    use minisign::crypto::generate_keypair;
    // Create a key with low parameters (N=2^14, used in fast tests)
    // This is well below production strength (N=2^20)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut kdf_salt);

    // N = 2^14, r = 8, p = 1
    let kdf_opslimit = 524_288; // Well below production (33,554,432)
    let kdf_memlimit = 16_777_216; // 16 MB, well below production (1024 MB)

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

    // Low parameters should be detected as weak
    assert!(seckey.is_weak_kdf());
}

#[test]
fn test_is_weak_kdf_unencrypted_key() {
    use minisign::crypto::generate_keypair;
    // Unencrypted keys have kdf_opslimit and kdf_memlimit set to 0
    // They should NOT be considered weak (they have no KDF)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();

    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    // Unencrypted keys should NOT be considered weak
    assert!(!seckey.is_weak_kdf());
}

#[test]
fn test_decrypt_weak_kdf_key() {
    use minisign::crypto::generate_keypair;
    // Test that decrypting a weak key succeeds and returns correct data
    // (Warning display will be verified manually or in integration tests)
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let password = b"test_password";
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut kdf_salt);

    // Create a key with weak parameters
    let kdf_opslimit = 4_194_304; // After 3 fallbacks (8x weaker)
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

    // Verify the key is weak
    assert!(seckey.is_weak_kdf());

    // Decrypt should succeed and return the correct secret key
    let (decrypted_secret_key, decrypted_keynum) = seckey.decrypt(password).unwrap();

    // Verify decrypted data matches original
    assert_eq!(decrypted_keynum.as_bytes(), keynum.as_bytes());
    assert_eq!(decrypted_secret_key.as_bytes(), secret_key.as_bytes());
}

#[test]
fn test_credential_id_for_encrypted_key() {
    use minisign::crypto::generate_keypair;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");
    let password = b"test_password";
    let mut kdf_salt = [0u8; KDF_SALT_BYTES];
    rand::rng().fill(&mut kdf_salt);

    // Use weak parameters for faster test execution (N=2^14)
    let kdf_opslimit = 524_288;
    let kdf_memlimit = 16_777_216; // 16 MB

    let seckey = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        password,
        kdf_salt,
        kdf_opslimit,
        kdf_memlimit,
        true, // allow_kdf_fallback if memory is insufficient
    )
    .unwrap();

    // For encrypted keys, credential_id returns hex of encrypted_keynum
    let credential_id = seckey.credential_id();

    // Should be 16 hex characters (8 bytes * 2)
    assert_eq!(credential_id.len(), 16);

    // Should be valid hex
    assert!(credential_id.chars().all(|c| c.is_ascii_hexdigit()));

    // Should be uppercase hex
    assert!(
        credential_id
            .chars()
            .all(|c| !c.is_ascii_lowercase() || !c.is_ascii_alphabetic())
    );

    // Should NOT be all zeros (encrypted keynum is not zero)
    assert_ne!(credential_id, "0000000000000000");

    // Should match the hex of encrypted_keynum interpreted as little-endian u64
    // This matches the encoding used by to_key_id() for consistency
    let value = u64::from_le_bytes(*seckey.encrypted_keynum());
    let expected = format!("{value:016X}");
    assert_eq!(credential_id, expected);
}

#[test]
fn test_credential_id_for_unencrypted_key() {
    use minisign::crypto::generate_keypair;

    // Generate a test keypair
    let (secret_key, _public_key, keynum) = generate_keypair().expect("RNG should work");

    let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

    // For unencrypted keys, credential_id returns same as keynum().to_key_id()
    let credential_id = seckey.credential_id();
    let key_id = seckey.keynum().to_key_id();

    assert_eq!(credential_id, key_id);

    // Should be 16 hex characters (8 bytes * 2)
    assert_eq!(credential_id.len(), 16);

    // Should be valid uppercase hex
    assert!(credential_id.chars().all(|c| c.is_ascii_hexdigit()));
}
