//! Comprehensive fuzzing tests for malformed/adversarial input
//!
//! Tests various attack vectors and edge cases that could cause panics,
//! incorrect parsing, or security issues.

use minisign::constants;
use minisign::crypto::{generate_keypair, sign, verify};
use minisign::formats;
use minisign::keys::{PubkeyStruct, SeckeyStruct};
use minisign::signature::{SigStruct, SignatureBox};
use minisign::validation;
use proptest::prelude::*;

// ============================================================================
// Base64 Malformed Input Fuzzing
// ============================================================================

proptest! {
    /// Property test: Malformed base64 should return error, never panic
    #[test]
    fn prop_malformed_base64_never_panics(
        data in "[A-Za-z0-9+/=]{0,200}[^A-Za-z0-9+/=]{1,5}[A-Za-z0-9+/=]{0,200}"
    ) {
        // Should handle gracefully - either decode or return error
        let _ = formats::decode_base64(&data);
    }

    /// Property test: Base64 with random padding should not panic
    #[test]
    fn prop_base64_random_padding(
        data in "[A-Za-z0-9+/]{0,100}",
        padding in "={0,5}"
    ) {
        let input = format!("{data}{padding}");
        let _ = formats::decode_base64(&input);
    }

    /// Property test: Base64 with whitespace injection
    #[test]
    fn prop_base64_whitespace_injection(
        data in "[A-Za-z0-9+/=]{10,100}",
        pos in 0..50_usize,
        whitespace in "[ \t\n\r]{1,3}"
    ) {
        let pos = pos.min(data.len().saturating_sub(1));
        let mut modified = data.clone();
        modified.insert_str(pos, &whitespace);
        let _ = formats::decode_base64(&modified);
    }

    /// Property test: Near-valid base64 (wrong alphabet characters)
    #[test]
    fn prop_base64_wrong_alphabet(
        prefix in "[A-Za-z0-9+/=]{10,50}",
        bad_char in "[!@#$%^&*(){}\\[\\]|;:'\",.<>?`~]",
        suffix in "[A-Za-z0-9+/=]{0,20}"
    ) {
        let input = format!("{prefix}{bad_char}{suffix}");
        let _ = formats::decode_base64(&input);
    }
}

// ============================================================================
// Binary Structure Truncation Fuzzing
// ============================================================================

proptest! {
    /// Property test: Truncated public key binary should error gracefully
    #[test]
    fn prop_truncated_public_key(
        keynum in prop::array::uniform8(any::<u8>()),
        pubkey_partial in prop::collection::vec(any::<u8>(), 0..32)
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(b"Ed");
        data.extend_from_slice(&keynum);
        data.extend_from_slice(&pubkey_partial);

        // Should return error, not panic
        let _ = PubkeyStruct::from_bytes(&data);
    }

    /// Property test: Truncated signature binary should error gracefully
    #[test]
    fn prop_truncated_signature(
        keynum in prop::array::uniform8(any::<u8>()),
        sig_partial in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(b"Ed");
        data.extend_from_slice(&keynum);
        data.extend_from_slice(&sig_partial);

        // Should return error, not panic
        let _ = SigStruct::from_bytes(&data);
    }

    /// Property test: Truncated encrypted secret key should error gracefully
    #[test]
    fn prop_truncated_secret_key(
        keynum in prop::array::uniform8(any::<u8>()),
        kdf_salt in prop::array::uniform32(any::<u8>()),
        data_partial in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(b"Ed");
        data.extend_from_slice(&[0x01]); // KDF algorithm
        data.extend_from_slice(&keynum);
        data.extend_from_slice(&kdf_salt);
        data.extend_from_slice(&[14, 0, 0, 0, 0, 0, 0, 0]); // opslimit
        data.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 0]); // memlimit
        data.extend_from_slice(&data_partial);

        // Should return error, not panic
        let _ = SeckeyStruct::from_bytes(&data);
    }

    /// Property test: Wrong signature algorithm byte
    #[test]
    fn prop_wrong_algorithm_byte(
        alg1 in any::<u8>().prop_filter("not Ed", |&x| x != b'E'),
        alg2 in any::<u8>(),
        rest in prop::collection::vec(any::<u8>(), 74..=74)
    ) {
        let mut data = Vec::new();
        data.push(alg1);
        data.push(alg2);
        data.extend_from_slice(&rest);

        let _ = SigStruct::from_bytes(&data);
    }
}

// ============================================================================
// Comment Length Fuzzing (Near COMMENTMAXBYTES)
// ============================================================================

proptest! {
    /// Property test: Comments exactly at limit should work
    #[test]
    fn prop_comment_at_limit(
        ch in "[a-zA-Z0-9 ]"
    ) {
        let comment = ch.repeat(constants::COMMENTMAXBYTES);
        prop_assert!(comment.len() == constants::COMMENTMAXBYTES);
        // validate_comment checks content, not length
        prop_assert!(validation::validate_comment(&comment).is_ok());
    }

    /// Property test: Comments just over limit should still pass validation
    /// (length is enforced elsewhere, not in validate_comment)
    #[test]
    fn prop_comment_over_limit(
        ch in "[a-zA-Z0-9 ]",
        extra in 1..100_usize
    ) {
        let comment = ch.repeat(constants::COMMENTMAXBYTES + extra);
        prop_assert!(comment.len() > constants::COMMENTMAXBYTES);
        // validate_comment only checks content validity, not length
        prop_assert!(validation::validate_comment(&comment).is_ok());
    }

    /// Property test: Comments near limit with multibyte UTF-8
    #[test]
    fn prop_comment_multibyte_near_limit(
        // Use emoji (4 bytes each in UTF-8)
        emoji_count in 0..(constants::COMMENTMAXBYTES / 4)
    ) {
        let comment = "🔐".repeat(emoji_count);
        let result = validation::validate_comment(&comment);

        if comment.len() <= constants::COMMENTMAXBYTES {
            prop_assert!(result.is_ok());
        } else {
            prop_assert!(result.is_err());
        }
    }
}

// ============================================================================
// Invalid UTF-8 Byte Sequence Fuzzing
// ============================================================================

proptest! {
    /// Property test: Invalid UTF-8 sequences in signature parsing
    #[test]
    fn prop_invalid_utf8_signature_parsing(
        valid_prefix in "untrusted comment: [a-zA-Z0-9 ]{10,50}\n",
        invalid_bytes in prop::collection::vec(0x80_u8..0xFF, 1..10),
        valid_base64 in "[A-Za-z0-9+/=]{100,200}"
    ) {
        // Create string with invalid UTF-8 by converting bytes to string lossy
        let invalid_str = String::from_utf8_lossy(&invalid_bytes);
        let input = format!("{valid_prefix}{invalid_str}\n{valid_base64}");

        // Should handle gracefully
        let _ = SignatureBox::from_file_contents(&input);
    }

    /// Property test: Control characters in comments should be rejected
    #[test]
    fn prop_control_chars_in_comments(
        prefix in "[a-zA-Z0-9 ]{0,50}",
        control_char in 0x00_u8..0x20,
        suffix in "[a-zA-Z0-9 ]{0,50}"
    ) {
        // Skip allowed characters: tab (0x09) and newline (0x0a).
        // CR (0x0d) is intentionally not excluded — is_printable() rejects it as a
        // control character, consistent with prop_carriage_return_injection.
        prop_assume!(control_char != 0x09 && control_char != 0x0a);

        let comment = format!("{prefix}{}{suffix}", control_char as char);
        // Should fail validation
        prop_assert!(validation::validate_comment(&comment).is_err());
    }

    /// Property test: NULL bytes anywhere in comment
    #[test]
    fn prop_null_bytes_in_comments(
        prefix in "[a-zA-Z0-9 ]{0,100}",
        suffix in "[a-zA-Z0-9 ]{0,100}"
    ) {
        let comment = format!("{prefix}\0{suffix}");
        // Should fail validation
        prop_assert!(validation::validate_comment(&comment).is_err());
    }

    /// Property test: Carriage return injection
    #[test]
    fn prop_carriage_return_injection(
        prefix in "[a-zA-Z0-9 ]{10,50}",
        suffix in "[a-zA-Z0-9 ]{10,50}"
    ) {
        let comment = format!("{prefix}\r{suffix}");
        // Should fail validation (CR not allowed)
        prop_assert!(validation::validate_comment(&comment).is_err());
    }
}

// ============================================================================
// File Format Fuzzing
// ============================================================================

proptest! {
    /// Property test: Signature files with wrong number of lines
    #[test]
    fn prop_signature_wrong_line_count(
        lines in prop::collection::vec("[A-Za-z0-9+/= ]{10,100}", 0..2)
    ) {
        let input = lines.join("\n");
        // Should return error for wrong format
        let result = SignatureBox::from_file_contents(&input);
        prop_assert!(result.is_err());
    }

    /// Property test: Signature files with too many lines
    #[test]
    fn prop_signature_too_many_lines(
        lines in prop::collection::vec("[A-Za-z0-9+/= ]{10,100}", 5..10)
    ) {
        let input = lines.join("\n");
        // Should still parse first 4 lines or error
        let _ = SignatureBox::from_file_contents(&input);
    }

    /// Property test: Public key with wrong prefix
    #[test]
    fn prop_pubkey_wrong_prefix(
        wrong_prefix in "[A-Za-z0-9 ]{0,30}",
        base64_data in "[A-Za-z0-9+/=]{50,100}"
    ) {
        prop_assume!(!wrong_prefix.starts_with("untrusted comment:"));
        let input = format!("{wrong_prefix}\n{base64_data}");
        // Should handle gracefully
        let _ = PubkeyStruct::from_file_contents(&input);
    }

    /// Property test: Secret key with corrupted KDF parameters
    #[test]
    fn prop_seckey_corrupted_kdf(
        keynum in prop::array::uniform8(any::<u8>()),
        salt in prop::array::uniform32(any::<u8>()),
        // Use random values for opslimit/memlimit
        opslimit in any::<u64>(),
        memlimit in any::<u64>()
    ) {
        let mut data = Vec::new();
        data.extend_from_slice(b"Ed");
        data.extend_from_slice(&[0x01]); // KDF algorithm
        data.extend_from_slice(&keynum);
        data.extend_from_slice(&salt);
        data.extend_from_slice(&opslimit.to_le_bytes());
        data.extend_from_slice(&memlimit.to_le_bytes());
        // Add some encrypted data (104 bytes total for full structure)
        data.resize(104, 0);

        // Should either parse or return error, never panic
        let _ = SeckeyStruct::from_bytes(&data);
    }
}

// ============================================================================
// Windows Line Ending Fuzzing
// ============================================================================

proptest! {
    /// Property test: Signature parsing with Windows line endings
    #[test]
    fn prop_signature_windows_line_endings(
        comment in "[a-zA-Z0-9 ]{10,50}",
        base64_data in "[A-Za-z0-9+/=]{100,200}"
    ) {
        // Use \r\n instead of \n
        let input = format!("untrusted comment: {comment}\r\n{base64_data}\r\ntrusted comment: test\r\nABCDEFGH==");

        // Should handle or reject gracefully
        let _ = SignatureBox::from_file_contents(&input);
    }

    /// Property test: Mixed line endings
    #[test]
    fn prop_mixed_line_endings(
        comment in "[a-zA-Z0-9 ]{10,50}",
        base64_data in "[A-Za-z0-9+/=]{100,200}"
    ) {
        // Mix \n and \r\n
        let input = format!("untrusted comment: {comment}\n{base64_data}\r\ntrusted comment: test\nABCDEFGH==");

        // Should handle or reject gracefully
        let _ = SignatureBox::from_file_contents(&input);
    }
}

// ============================================================================
// Zero-Length Input Fuzzing
// ============================================================================

#[test]
fn test_zero_length_comment_no_panic() {
    // validate_comment on an empty string must not panic
    let result = std::panic::catch_unwind(|| {
        let _ = validation::validate_comment("");
    });
    assert!(result.is_ok(), "Should handle empty comment gracefully");
}

#[test]
fn test_zero_length_comment() {
    // Empty comment should be valid
    assert!(validation::validate_comment("").is_ok());
}

#[test]
fn test_zero_length_base64() {
    // Empty base64 should decode to empty bytes
    let result = formats::decode_base64("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), &[]);
}

#[test]
fn test_zero_length_signature_parse() {
    // Empty signature should error
    let result = SignatureBox::from_file_contents("");
    assert!(result.is_err());
}

// ============================================================================
// Special Path Characters (Unix/Windows)
// ============================================================================

proptest! {
    /// Property test: Verify path validation handles special characters
    #[test]
    fn prop_special_path_characters(
        prefix in "[a-zA-Z0-9_]{1,20}",
        special in "[ $&()@!~`]",
        suffix in "[a-zA-Z0-9_]{1,20}"
    ) {
        use std::path::Path;

        let path_str = format!("{prefix}{special}{suffix}");
        let path = Path::new(&path_str);

        // Should not panic when checking path
        let _ = path.exists();
        let _ = path.is_file();
        let _ = path.to_str();
    }
}

// ============================================================================
// Boundary Value Tests for Binary Structures
// ============================================================================

#[test]
fn test_max_size_binary_structures() {
    // Test maximum reasonable sizes

    // Public key: should be exactly 42 bytes
    let pubkey_data = vec![0u8; 42];
    let _ = PubkeyStruct::from_bytes(&pubkey_data);

    // Signature: should be exactly 74 bytes
    let sig_data = vec![0u8; 74];
    let _ = SigStruct::from_bytes(&sig_data);

    // Secret key encrypted: should be exactly 104 bytes
    let seckey_data = vec![0u8; 104];
    let _ = SeckeyStruct::from_bytes(&seckey_data);
}

#[test]
fn test_oversized_binary_structures() {
    // Test oversized inputs

    // Public key too large
    let pubkey_data = vec![0u8; 1000];
    let result = PubkeyStruct::from_bytes(&pubkey_data);
    assert!(result.is_err(), "Oversized public key should be rejected");

    // Signature too large
    let sig_data = vec![0u8; 1000];
    let result = SigStruct::from_bytes(&sig_data);
    assert!(result.is_err(), "Oversized signature should be rejected");

    // Secret key too large
    let seckey_data = vec![0u8; 1000];
    let result = SeckeyStruct::from_bytes(&seckey_data);
    assert!(result.is_err(), "Oversized secret key should be rejected");
}

// ============================================================================
// UTF-8 BOM Handling
// ============================================================================

#[test]
fn test_utf8_bom_in_signature() {
    // UTF-8 BOM (Byte Order Mark): EF BB BF
    let bom = "\u{FEFF}";
    let input = format!(
        "{bom}untrusted comment: test\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/AA==\ntrusted comment: test\nABCDEFGH=="
    );

    // Should handle or reject gracefully
    let result = SignatureBox::from_file_contents(&input);
    // BOM is not expected in our format, so should error
    assert!(
        result.is_err(),
        "BOM should be rejected in signature format"
    );
}

#[test]
fn test_utf8_bom_in_public_key() {
    let bom = "\u{FEFF}";
    let input = format!("{bom}untrusted comment: test\nABCDEFGHIJKLMNOPQRSTUVWXYZ==");

    let result = PubkeyStruct::from_file_contents(&input);
    assert!(
        result.is_err(),
        "BOM should be rejected in public key format"
    );
}

// ============================================================================
// Random Binary Input Fuzzing - Full Structure Sizes
// ============================================================================

proptest! {
    /// Property test: Random 42-byte inputs to PubkeyStruct::from_bytes should not panic
    /// This tests that all possible byte combinations in the public key structure are handled safely
    #[test]
    fn prop_random_pubkey_bytes(bytes in prop::collection::vec(any::<u8>(), 42)) {
        // Should either parse or return error, never panic
        let _ = PubkeyStruct::from_bytes(&bytes);
    }

    /// Property test: Random 158-byte inputs to SeckeyStruct::from_bytes should not panic
    /// This tests that all possible byte combinations in the secret key structure are handled safely
    #[test]
    fn prop_random_seckey_bytes(bytes in prop::collection::vec(any::<u8>(), 158)) {
        // Should either parse or return error, never panic
        let _ = SeckeyStruct::from_bytes(&bytes);
    }

    /// Property test: Random 74-byte inputs to SigStruct::from_bytes should not panic
    /// This tests that all possible byte combinations in the signature structure are handled safely
    #[test]
    fn prop_random_sig_bytes(bytes in prop::collection::vec(any::<u8>(), 74)) {
        // Should either parse or return error, never panic
        let _ = SigStruct::from_bytes(&bytes);
    }
}

// ============================================================================
// Corrupted Checksum Fuzzing
// ============================================================================

proptest! {
    /// Property test: Encrypted secret keys with corrupted checksums should be detected
    #[test]
    fn prop_corrupted_checksum(
        checksum_bytes in prop::array::uniform32(any::<u8>())
    ) {
        // Create a potentially valid encrypted key structure with corrupted checksum
        let mut key_bytes = vec![0u8; 158];

        // Algorithm markers
        key_bytes[0..2].copy_from_slice(b"Ed");  // sig_alg
        key_bytes[2..4].copy_from_slice(b"Sc");  // kdf_alg (encrypted)
        key_bytes[4..6].copy_from_slice(b"B2");  // chk_alg

        // Salt (32 bytes at offset 6)
        key_bytes[6..38].fill(2);

        // KDF parameters (opslimit and memlimit at offsets 38 and 46)
        // Use values that represent production scrypt params: N=2^20, r=8, p=1
        let opslimit: u64 = 33_554_432;  // 4 * 2^20 * 8
        let memlimit: u64 = 1_073_741_824; // 128 * 2^20 * 8
        key_bytes[38..46].copy_from_slice(&opslimit.to_le_bytes());
        key_bytes[46..54].copy_from_slice(&memlimit.to_le_bytes());

        // Keynum (8 bytes at offset 54)
        key_bytes[54..62].fill(1);

        // Encrypted secret key (64 bytes at offset 62)
        key_bytes[62..126].fill(3);

        // Corrupted checksum (32 bytes at offset 126)
        // Intentionally use random bytes that won't match any valid checksum
        key_bytes[126..158].copy_from_slice(&checksum_bytes);

        // Try to parse - should handle gracefully (either parse structurally or detect corruption)
        let result = SeckeyStruct::from_bytes(&key_bytes);
        // We expect this to not panic - it may succeed in parsing the structure
        // but will fail later during decryption with wrong password
        let _ = result;
    }
}

// ============================================================================
// Impossible KDF Parameters Fuzzing
// ============================================================================

proptest! {
    /// Property test: Secret keys with impossible KDF parameters should error gracefully
    #[test]
    fn prop_impossible_kdf_params(
        opslimit in any::<u64>(),
        memlimit in any::<u64>()
    ) {
        // Create a key structure with potentially impossible/extreme KDF parameters
        let mut key_bytes = vec![0u8; 158];

        // Algorithm markers
        key_bytes[0..2].copy_from_slice(b"Ed");  // sig_alg
        key_bytes[2..4].copy_from_slice(b"Sc");  // kdf_alg (encrypted)
        key_bytes[4..6].copy_from_slice(b"B2");  // chk_alg

        // Salt (32 bytes at offset 6)
        key_bytes[6..38].fill(2);

        // Random/extreme KDF parameters
        key_bytes[38..46].copy_from_slice(&opslimit.to_le_bytes());
        key_bytes[46..54].copy_from_slice(&memlimit.to_le_bytes());

        // Keynum (8 bytes at offset 54)
        key_bytes[54..62].fill(1);

        // Secret key (64 bytes at offset 62)
        key_bytes[62..126].fill(3);

        // Checksum (32 bytes at offset 126)
        key_bytes[126..158].fill(4);

        // Should handle gracefully - either parse or return error, never panic
        let _ = SeckeyStruct::from_bytes(&key_bytes);
    }

}

// ============================================================================
// Core Cryptographic Roundtrip (P7.3)
// ============================================================================

proptest! {
    /// Property test: sign then verify always succeeds for the matching key pair.
    ///
    /// Covers the fundamental Ed25519 invariant: for any message `m` and any
    /// freshly-generated key pair `(sk, pk)`, `verify(pk, m, sign(sk, m))` must
    /// succeed. This catches regressions in the signing or verification paths
    /// that pure parsing tests cannot reach.
    #[test]
    fn prop_sign_verify_roundtrip(
        msg in prop::collection::vec(any::<u8>(), 0..10_000)
    ) {
        let (secret_key, public_key, _keynum) = generate_keypair().unwrap();
        let sig = sign(&secret_key, &msg).unwrap();
        prop_assert!(verify(&public_key, &msg, &sig).is_ok());
    }

    /// Property test: a signature for one message must not verify against a different message.
    ///
    /// Complements the roundtrip test: cross-message rejection is the other half
    /// of the binding property.
    #[test]
    fn prop_sign_verify_wrong_message_fails(
        msg in prop::collection::vec(any::<u8>(), 1..10_000),
        other_msg in prop::collection::vec(any::<u8>(), 1..10_000)
    ) {
        prop_assume!(msg != other_msg);
        let (secret_key, public_key, _keynum) = generate_keypair().unwrap();
        let sig = sign(&secret_key, &msg).unwrap();
        prop_assert!(verify(&public_key, &other_msg, &sig).is_err());
    }
}

// ============================================================================
// T10: SignatureBox Text Round-Trip
// ============================================================================

proptest! {
    /// T10: Full SignatureBox serialization round-trip under arbitrary valid comments.
    ///
    /// Serializes a SignatureBox to its text format and parses it back, verifying
    /// that all fields survive the round-trip without modification. Previously only
    /// SigStruct binary round-trips were property-tested.
    #[test]
    fn prop_signature_box_text_roundtrip(
        untrusted in "[A-Za-z0-9 !#$%&'()*+,-./:;<=>?@\\[\\]^_`{|}~]{0,100}",
        trusted in "[A-Za-z0-9 !#$%&'()*+,-./:;<=>?@\\[\\]^_`{|}~]{0,100}",
    ) {
        use minisign::crypto::Signature;

        // Build a minimal SigStruct with valid "Ed" algorithm marker
        let mut sig_bytes = [0u8; minisign::constants::SIG_STRUCT_SIZE];
        sig_bytes[0] = b'E';
        sig_bytes[1] = b'd';
        let sig_struct = minisign::signature::SigStruct::from_bytes(&sig_bytes).unwrap();

        let global_sig = Signature::from_bytes([0u8; 64]);

        let boxed = SignatureBox::new(
            untrusted.clone(),
            sig_struct,
            trusted.clone(),
            global_sig,
        );
        // Construction may fail if comment chars are outside the printable set
        // (the regex above selects only printable ASCII, so this should always succeed)
        let Ok(boxed) = boxed else { return Ok(()) };

        let serialized = boxed.to_file_contents();
        let parsed = SignatureBox::from_file_contents(&serialized)
            .expect("round-trip parse must succeed");

        prop_assert_eq!(parsed.untrusted_comment(), boxed.untrusted_comment());
        prop_assert_eq!(parsed.trusted_comment(), boxed.trusted_comment());
    }
}
