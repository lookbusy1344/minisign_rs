use minisign::crypto::*;
use minisign::errors::Error;

#[test]
fn test_constants() {
    assert_eq!(SIGNATURE_BYTES, 64);
    assert_eq!(PUBLIC_KEY_BYTES, 32);
    assert_eq!(SECRET_KEY_BYTES, 64);
    assert_eq!(KEYNUM_BYTES, 8);
    assert_eq!(KDF_SALT_BYTES, 32);
    assert_eq!(CHECKSUM_BYTES, 32);
}

#[test]
fn test_keynum_generation() {
    let kn1 = KeyNum::generate().expect("RNG should work");
    let kn2 = KeyNum::generate().expect("RNG should work");
    // Should be extremely unlikely to be equal
    assert_ne!(kn1, kn2);
}

#[test]
fn test_keynum_hex() {
    let keynum = KeyNum::from_bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    assert_eq!(keynum.to_hex(), "0123456789ABCDEF");
}

#[test]
fn test_keynum_to_key_id_little_endian() {
    // Verify that to_key_id() converts bytes to little-endian u64, matching C minisign
    // Bytes: E0 BC 3A E3 30 23 02 DD
    // As little-endian u64: DD022330E33ABCE0 (matches C minisign le64_load() + %016PRIX64)
    let keynum = KeyNum::from_bytes([0xE0, 0xBC, 0x3A, 0xE3, 0x30, 0x23, 0x02, 0xDD]);
    assert_eq!(keynum.to_key_id(), "DD022330E33ABCE0");

    // to_hex() should return bytes in order (different from to_key_id())
    assert_eq!(keynum.to_hex(), "E0BC3AE3302302DD");
}

#[test]
fn test_secret_key_debug() {
    let sk = SecretKey::from_bytes([42u8; SECRET_KEY_BYTES]);
    let debug_str = format!("{sk:?}");
    assert!(debug_str.contains("REDACTED"));
    assert!(!debug_str.contains("42"));
}

#[test]
fn test_blake2b_256_known_vector() {
    // Test vector: empty input (Blake2b-256)
    let hash = blake2b_256(b"");
    let expected = hex::decode("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
        .expect("invalid hex");
    assert_eq!(hash.as_slice(), expected.as_slice());
}

#[test]
fn test_blake2b_256_hello() {
    // Test vector: "hello" (Blake2b-256)
    let hash = blake2b_256(b"hello");
    let expected = hex::decode("324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf")
        .expect("invalid hex");
    assert_eq!(hash.as_slice(), expected.as_slice());
}

#[test]
fn test_blake2b_512_known_vector() {
    // Test vector: empty input
    let hash = blake2b_512(b"");
    let expected = hex::decode(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    )
    .expect("invalid hex");
    assert_eq!(hash.as_slice(), expected.as_slice());
}

#[test]
fn test_blake2b_512_hello() {
    // Test vector: "hello"
    let hash = blake2b_512(b"hello");
    let expected = hex::decode(
        "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94",
    )
    .expect("invalid hex");
    assert_eq!(hash.as_slice(), expected.as_slice());
}

#[test]
fn test_sign_verify_roundtrip() {
    let (secret_key, public_key, _keynum) = generate_keypair().expect("RNG should work");
    let message = b"test message";

    let signature = sign(&secret_key, message).expect("signing failed");
    verify(&public_key, message, &signature).expect("verification failed");
}

#[test]
fn test_verify_wrong_message() {
    let (secret_key, public_key, _keynum) = generate_keypair().expect("RNG should work");
    let message = b"test message";
    let wrong_message = b"wrong message";

    let signature = sign(&secret_key, message).expect("signing failed");
    let result = verify(&public_key, wrong_message, &signature);
    assert!(matches!(result, Err(Error::VerificationFailed)));
}

#[test]
fn test_verify_wrong_key() {
    let (secret_key, _public_key, _keynum) = generate_keypair().expect("RNG should work");
    let (_, wrong_public_key, _) = generate_keypair().expect("RNG should work");
    let message = b"test message";

    let signature = sign(&secret_key, message).expect("signing failed");
    let result = verify(&wrong_public_key, message, &signature);
    assert!(matches!(result, Err(Error::VerificationFailed)));
}

// Note: These tests use reduced Scrypt parameters (log_n=10) for speed.
// The production parameters (log_n=20) are tested in integration tests.
const TEST_LOG_N: u8 = 10; // N=1024 for fast testing

// Test constants for scrypt parameters
const TEST_SCRYPT_R: u32 = 8;
const TEST_SCRYPT_P: u32 = 1;

#[test]
fn test_derive_key_output_length() {
    let password = b"test password";
    let salt = [0u8; 32];

    // Test 32-byte output (used for encryption keys)
    let key_32 = derive_key_with_params(
        password,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");
    assert_eq!(key_32.len(), 32);

    // Test 64-byte output (if needed for other purposes)
    let key_64 = derive_key_with_params(
        password,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        64,
    )
    .expect("derivation failed");
    assert_eq!(key_64.len(), 64);
}

#[test]
fn test_derive_key_deterministic() {
    let password = b"test password";
    let salt = [0u8; 32];

    let key1 = derive_key_with_params(
        password,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");
    let key2 = derive_key_with_params(
        password,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");

    assert_eq!(key1, key2);
}

#[test]
fn test_derive_key_different_passwords() {
    let password1 = b"password1";
    let password2 = b"password2";
    let salt = [0u8; 32];

    let key1 = derive_key_with_params(
        password1,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");
    let key2 = derive_key_with_params(
        password2,
        &salt,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");

    assert_ne!(key1, key2);
}

#[test]
fn test_derive_key_different_salts() {
    let password = b"test password";
    let salt1 = [0u8; 32];
    let mut salt2 = [0u8; 32];
    salt2[0] = 1;

    let key1 = derive_key_with_params(
        password,
        &salt1,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");
    let key2 = derive_key_with_params(
        password,
        &salt2,
        TEST_LOG_N,
        TEST_SCRYPT_R,
        TEST_SCRYPT_P,
        32,
    )
    .expect("derivation failed");

    assert_ne!(key1, key2);
}

/// Test with full production parameters (marked ignore for normal test runs)
#[test]
#[ignore = "slow test with full scrypt parameters"]
fn test_derive_key_full_params() {
    let password = b"test password";
    let salt = [0u8; 32];

    // This uses the full SENSITIVE parameters and will be slow
    let key = derive_key(password, &salt, 32).expect("derivation with full params failed");
    assert_eq!(key.len(), 32);
}

#[test]
fn test_blake2b_512_stream() {
    use std::io::Cursor;

    // Test with empty input
    let empty = Cursor::new(Vec::<u8>::new());
    let hash = blake2b_512_stream(empty).expect("streaming hash failed");
    let expected = blake2b_512(b"");
    assert_eq!(hash, expected);

    // Test with "hello"
    let hello = Cursor::new(b"hello".to_vec());
    let hash = blake2b_512_stream(hello).expect("streaming hash failed");
    let expected = blake2b_512(b"hello");
    assert_eq!(hash, expected);

    // Test with larger data (10KB)
    let large_data = vec![42u8; 10 * 1024];
    let cursor = Cursor::new(large_data.clone());
    let hash_stream = blake2b_512_stream(cursor).expect("streaming hash failed");
    let hash_direct = blake2b_512(&large_data);
    assert_eq!(hash_stream, hash_direct);
}

/// Test that generating multiple keys produces unique values
///
/// This verifies RNG quality by generating N keys and ensuring:
/// 1. All public keys are distinct
/// 2. All secret keys are distinct
/// 3. All keynums are distinct
///
/// This guards against RNG failures, key reuse bugs, and other
/// uniqueness violations that would compromise security.
#[test]
fn test_keypair_uniqueness() {
    use std::collections::HashSet;

    const NUM_KEYS: usize = 50;

    let mut public_keys = HashSet::new();
    let mut secret_keys = HashSet::new();
    let mut keynums = HashSet::new();

    // Generate NUM_KEYS keypairs
    for _ in 0..NUM_KEYS {
        let (secret_key, public_key, keynum) =
            generate_keypair().expect("key generation should succeed");

        // Insert into sets (returns false if already present)
        assert!(
            public_keys.insert(public_key.as_bytes().to_vec()),
            "Duplicate public key detected - RNG may be compromised"
        );
        assert!(
            secret_keys.insert(secret_key.as_bytes().to_vec()),
            "Duplicate secret key detected - RNG may be compromised"
        );
        assert!(
            keynums.insert(keynum.as_bytes().to_vec()),
            "Duplicate keynum detected - RNG may be compromised"
        );
    }

    // Verify all sets have the expected number of unique entries
    assert_eq!(
        public_keys.len(),
        NUM_KEYS,
        "Not all public keys are unique"
    );
    assert_eq!(
        secret_keys.len(),
        NUM_KEYS,
        "Not all secret keys are unique"
    );
    assert_eq!(keynums.len(), NUM_KEYS, "Not all keynums are unique");
}
