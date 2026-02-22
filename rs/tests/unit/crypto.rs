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

/// Regression test: scrypt must produce exactly 104 bytes output (`ENCRYPTED_BLOB_SIZE`).
///
/// The implementation caps `params_len` at 64 when constructing `ScryptParams` but passes
/// the full 104-byte buffer to the low-level `scrypt()` call. This test pins the exact
/// output so any change in crate internals (e.g., scrypt crate upgrades) that breaks this
/// boundary is caught immediately.
///
/// Uses reduced parameters (`log_n=10`) for fast execution.
#[test]
fn test_derive_key_104_byte_output_regression() {
    const OUTPUT_LEN: usize = 104;
    let password = b"minisign-regression-test-password";
    let salt = [
        0x42u8, 0x1a, 0x9f, 0x3c, 0x77, 0x08, 0xd5, 0xea, 0x23, 0xbc, 0xfe, 0x01, 0x60, 0xab, 0x84,
        0x9d, 0x55, 0xe2, 0x71, 0xcc, 0x3a, 0x4f, 0x18, 0xb6, 0x9e, 0xd7, 0x2c, 0x05, 0xf1, 0x38,
        0x6a, 0x7b,
    ];
    // log_n=10 (N=1024), r=8, p=1 — fast parameters for CI
    let key =
        derive_key_with_params(password, &salt, 10, 8, 1, OUTPUT_LEN).expect("derivation failed");
    assert_eq!(
        key.len(),
        OUTPUT_LEN,
        "scrypt must produce exactly {OUTPUT_LEN} bytes"
    );
    // Known-answer test vector: pre-computed with scrypt =0.11.0, log_n=10, r=8, p=1,
    // output_len=104. The 104-byte output exercises the params_len=min(104,64)=64 cap
    // in the Params constructor while the low-level scrypt() still fills all 104 bytes.
    // If this fails after a crate upgrade, verify the new output is cryptographically
    // correct before updating this constant.
    let expected = hex::decode(concat!(
        "2a55df14dfc617f725a5f1cf7cae4dcb662d7e490d1ff2fb4d596358ed0420c8",
        "3ba34a3242fb83ae2e01a911caa0cb0f4597a11cfd2ad4f4ada60d02262d26fb",
        "7982b6c5b294a7695a74cca14c1aa307e03028346f8e6ee468ce5a60b35a552f",
        "4984052ac6538fcf",
    ))
    .expect("KAT hex is valid");
    assert_eq!(
        key.as_slice(),
        expected.as_slice(),
        "scrypt output must match known-answer test vector — if the scrypt crate was \
         upgraded, re-derive and verify before updating this constant"
    );
}

/// Known-answer test (KAT) for scrypt with full production parameters.
///
/// Verifies that `derive_key` (which uses `log_n=20, r=8, p=1`) produces
/// a specific, pre-computed 32-byte output for a fixed password and salt.
/// This catches any change in scrypt crate output at production parameters,
/// whether from a crate upgrade or an accidental parameter change.
///
/// Pre-computed with `scrypt` v0.11.0, `log_n=20`, `r=8`, `p=1`.
/// If this test fails after a scrypt crate upgrade, re-derive and verify
/// the new output is cryptographically correct before updating the constant.
#[test]
fn test_derive_key_full_params() {
    let password = b"minisign-full-params-kat-password";
    let salt = [0x01u8; 32];

    // This uses the full SENSITIVE parameters (log_n=20) and will take several seconds.
    let key = derive_key(password, &salt, 32).expect("derivation with full params failed");

    let expected = hex::decode("dbe927d87942738ecb120925c349700420d0e8e8e2c8e5fddae038ca8c12efe8")
        .expect("KAT hex is valid");
    assert_eq!(
        key.as_slice(),
        expected.as_slice(),
        "scrypt output must match known-answer test vector — if the scrypt crate was \
         upgraded, re-derive and verify before updating this constant"
    );
}

/// Verifies that `derive_key_with_params` rejects `output_len` values above the 1024-byte cap.
///
/// The guard `if output_len > MAX_KDF_OUTPUT_LEN` is an early-return that prevents
/// resource-exhaustion attacks.  This test pins that the first value over the limit
/// (`output_len = 1025`) is rejected with `Error::KdfError`.
/// Uses fast parameters (`log_n=10`) so the test does not slow down the suite.
#[test]
fn test_derive_key_output_len_too_large() {
    let result = derive_key_with_params(b"password", &[0u8; 32], 10, 8, 1, 1025);
    assert!(
        result.is_err(),
        "output_len > MAX_KDF_OUTPUT_LEN must return Err"
    );
    assert!(
        matches!(result, Err(Error::KdfError(_))),
        "expected Error::KdfError, got {result:?}"
    );
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

#[test]
fn test_debug_implementations() {
    // Test L2: Verify Debug implementations are consistent and appropriate
    let (secret_key, public_key, _keynum) =
        generate_keypair().expect("key generation should succeed");

    // SecretKey should redact sensitive data
    let secret_debug = format!("{secret_key:?}");
    assert!(
        secret_debug.contains("[REDACTED]"),
        "SecretKey Debug should redact sensitive data"
    );
    assert!(
        !secret_debug.contains(&format!("{:02x}", secret_key.as_bytes()[0])),
        "SecretKey Debug should not show any key bytes"
    );

    // PublicKey should show partial data (not sensitive)
    let public_debug = format!("{public_key:?}");
    assert!(
        public_debug.contains("PublicKey"),
        "PublicKey Debug should include type name"
    );
    // Should show at least the first byte
    assert!(
        public_debug.contains(&format!("{:02x}", public_key.as_bytes()[0])),
        "PublicKey Debug should show some key data for debugging"
    );

    // Test Signature Debug format
    let message = b"test message";
    let signature = sign(&secret_key, message).expect("signing should succeed");
    let sig_debug = format!("{signature:?}");
    assert!(
        sig_debug.contains("Signature"),
        "Signature Debug should include type name"
    );
    assert!(
        sig_debug.contains(&format!("{:02x}", signature.as_bytes()[0])),
        "Signature Debug should show some data for debugging"
    );

    // Verify PublicKey and Signature have consistent format (both show data)
    assert!(
        public_debug.contains("..") && sig_debug.contains(".."),
        "PublicKey and Signature should have consistent truncation markers"
    );
}
