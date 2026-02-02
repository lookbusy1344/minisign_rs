use minisign::crypto::*;
use minisign::signature::*;
#[test]
fn test_sig_struct_size() {
    assert_eq!(SIG_STRUCT_SIZE, 74);
}
#[test]
fn test_sig_struct_serialization_roundtrip_normal() {
    let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let signature = Signature::from_bytes([42; SIGNATURE_BYTES]);
    let sig = SigStruct::new(keynum, signature, false);
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), SIG_STRUCT_SIZE);
    let parsed = SigStruct::from_bytes(&bytes).expect("should parse");
    assert_eq!(parsed, sig);
    assert!(!parsed.is_prehashed());
}
#[test]
fn test_sig_struct_serialization_roundtrip_prehashed() {
    let keynum = KeyNum::from_bytes([9, 8, 7, 6, 5, 4, 3, 2]);
    let signature = Signature::from_bytes([99; SIGNATURE_BYTES]);
    let sig = SigStruct::new(keynum, signature, true);
    let bytes = sig.to_bytes();
    assert_eq!(bytes.len(), SIG_STRUCT_SIZE);
    let parsed = SigStruct::from_bytes(&bytes).expect("should parse");
    assert_eq!(parsed, sig);
    assert!(parsed.is_prehashed());
}
#[test]
fn test_sig_struct_normal_algorithm_marker() {
    let keynum = KeyNum::from_bytes([0; KEYNUM_BYTES]);
    let signature = Signature::from_bytes([0; SIGNATURE_BYTES]);
    let sig = SigStruct::new(keynum, signature, false);
    let bytes = sig.to_bytes();
    assert_eq!(&bytes[0..2], b"Ed");
}
#[test]
fn test_sig_struct_prehashed_algorithm_marker() {
    let keynum = KeyNum::from_bytes([0; KEYNUM_BYTES]);
    let signature = Signature::from_bytes([0; SIGNATURE_BYTES]);
    let sig = SigStruct::new(keynum, signature, true);
    let bytes = sig.to_bytes();
    assert_eq!(&bytes[0..2], b"ED");
}
#[test]
fn test_invalid_sig_struct_too_short() {
    let bytes = [0u8; 73];
    let result = SigStruct::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_invalid_sig_struct_wrong_algorithm() {
    let mut bytes = [0u8; SIG_STRUCT_SIZE];
    bytes[0..2].copy_from_slice(b"XX");
    let result = SigStruct::from_bytes(&bytes);
    assert!(result.is_err());
}
#[test]
fn test_signature_box_file_format_roundtrip() {
    use minisign::crypto::{generate_keypair, sign};
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let message = b"test message";
    let signature = sign(&secret_key, message).expect("signing should succeed");
    let sig_struct = SigStruct::new(keynum, signature, false);
    let untrusted = "This is untrusted".to_string();
    let trusted = "timestamp:1234567890".to_string();
    let sig_box = SignatureBox::with_global_signature(
        untrusted.clone(),
        sig_struct,
        trusted.clone(),
        &secret_key,
    )
    .expect("should create signature box");
    // Serialize and parse
    let contents = sig_box.to_file_contents();
    let parsed = SignatureBox::from_file_contents(&contents).expect("should parse");
    assert_eq!(parsed.untrusted_comment(), &untrusted);
    assert_eq!(parsed.sig_struct(), &sig_struct);
    assert_eq!(parsed.trusted_comment(), &trusted);
    // Verify global signature
    parsed
        .verify_global_signature(&public_key)
        .expect("global signature should verify");
}
#[test]
fn test_signature_box_global_signature_verification() {
    use minisign::crypto::generate_keypair;
    let (secret_key, public_key, keynum) = generate_keypair().expect("RNG should work");
    let signature = Signature::from_bytes([42; SIGNATURE_BYTES]);
    let sig_struct = SigStruct::new(keynum, signature, false);
    let sig_box = SignatureBox::with_global_signature(
        "untrusted".to_string(),
        sig_struct,
        "trusted".to_string(),
        &secret_key,
    )
    .expect("should create signature box");
    // Should verify with correct key
    sig_box
        .verify_global_signature(&public_key)
        .expect("should verify");
    // Should fail with wrong key
    let (_, wrong_key, _) = generate_keypair().expect("RNG should work");
    assert!(sig_box.verify_global_signature(&wrong_key).is_err());
}
#[test]
fn test_signature_box_invalid_wrong_line_count() {
    let contents = "line1\nline2\nline3";
    let result = SignatureBox::from_file_contents(contents);
    assert!(result.is_err());
}
#[test]
fn test_signature_box_prehashed_mode() {
    use minisign::crypto::generate_keypair;
    let (secret_key, _, keynum) = generate_keypair().expect("RNG should work");
    let signature = Signature::from_bytes([99; SIGNATURE_BYTES]);
    let sig_struct = SigStruct::new(keynum, signature, true);
    let sig_box = SignatureBox::with_global_signature(
        "untrusted".to_string(),
        sig_struct,
        "trusted".to_string(),
        &secret_key,
    )
    .expect("should create signature box");
    let contents = sig_box.to_file_contents();
    let parsed = SignatureBox::from_file_contents(&contents).expect("should parse");
    assert!(parsed.sig_struct().is_prehashed());
}
// Property-based tests
use proptest::prelude::*;
proptest! {
    /// Property test: SigStruct serialization roundtrip for normal mode
    #[test]
    fn prop_sig_struct_roundtrip_normal(
        keynum_data in prop::array::uniform8(any::<u8>()),
        sig_data in prop::collection::vec(any::<u8>(), 64..=64)
    ) {
        let keynum = KeyNum::from_bytes(keynum_data);
        let mut sig_array = [0u8; SIGNATURE_BYTES];
        sig_array.copy_from_slice(&sig_data);
        let signature = Signature::from_bytes(sig_array);
        let sig_struct = SigStruct::new(keynum, signature, false);
        let serialized = sig_struct.to_bytes();
        let deserialized = SigStruct::from_bytes(&serialized).unwrap();
        prop_assert_eq!(sig_struct.keynum(), deserialized.keynum());
        prop_assert_eq!(sig_struct.signature().as_bytes(), deserialized.signature().as_bytes());
        prop_assert_eq!(sig_struct.is_prehashed(), deserialized.is_prehashed());
    }
    /// Property test: SigStruct serialization roundtrip for prehashed mode
    #[test]
    fn prop_sig_struct_roundtrip_prehashed(
        keynum_data in prop::array::uniform8(any::<u8>()),
        sig_data in prop::collection::vec(any::<u8>(), 64..=64)
    ) {
        let keynum = KeyNum::from_bytes(keynum_data);
        let mut sig_array = [0u8; SIGNATURE_BYTES];
        sig_array.copy_from_slice(&sig_data);
        let signature = Signature::from_bytes(sig_array);
        let sig_struct = SigStruct::new(keynum, signature, true);
        let serialized = sig_struct.to_bytes();
        let deserialized = SigStruct::from_bytes(&serialized).unwrap();
        prop_assert_eq!(sig_struct.keynum(), deserialized.keynum());
        prop_assert_eq!(sig_struct.signature().as_bytes(), deserialized.signature().as_bytes());
        prop_assert_eq!(sig_struct.is_prehashed(), deserialized.is_prehashed());
    }
}
#[test]
fn test_untrusted_comment_with_control_characters() {
    // Create a signature box with control characters in untrusted comment
    let sig_box = SignatureBox::new(
        "test\x00null".to_string(), // Embedded null byte
        SigStruct::new(
            KeyNum::from_bytes([0; 8]),
            Signature::from_bytes([0; SIGNATURE_BYTES]),
            false,
        ),
        "valid comment".to_string(),
        Signature::from_bytes([0; SIGNATURE_BYTES]),
    );
    let serialized = sig_box.to_file_contents();
    let result = SignatureBox::from_file_contents(&serialized);
    // Should fail validation due to control character
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid comment"));
}
#[test]
fn test_untrusted_comment_with_carriage_return() {
    // Create a signature box with carriage return in untrusted comment
    let sig_box = SignatureBox::new(
        "test\rcarriage".to_string(),
        SigStruct::new(
            KeyNum::from_bytes([0; 8]),
            Signature::from_bytes([0; SIGNATURE_BYTES]),
            false,
        ),
        "valid comment".to_string(),
        Signature::from_bytes([0; SIGNATURE_BYTES]),
    );
    let serialized = sig_box.to_file_contents();
    let result = SignatureBox::from_file_contents(&serialized);
    // Should fail validation due to carriage return
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // The error message should mention either "carriage return" or just "invalid comment"
    assert!(err_msg.contains("carriage return") || err_msg.contains("invalid comment"));
}
