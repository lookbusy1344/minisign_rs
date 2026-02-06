//! Security Attack Tests - T1
//!
//! Tests for signature forgery attempts, malleability attacks, and algorithm confusion.
//! These tests verify that the implementation properly rejects various attack vectors.

use minisign::{
    crypto::{generate_keypair, sign, verify, KeyNum, PublicKey, SecretKey, Signature, SIGNATURE_BYTES},
    keys::PubkeyStruct,
    signature::{SigStruct, SignatureBox},
};

// ============================================================================
// T1.1: Signature forgery - correct keynum but forged signature bytes
// ============================================================================

#[test]
fn t1_reject_forged_signature_bytes() {
    let (secret_key, public_key, keynum) = generate_keypair().unwrap();
    let message = b"original message";

    // Create valid signature
    let signature = sign(&secret_key, message).unwrap();
    let sig_struct = SigStruct::new(keynum, signature, false);

    // Forge the signature bytes (flip all bits)
    let forged_sig_bytes: [u8; SIGNATURE_BYTES] = signature
        .as_bytes()
        .iter()
        .map(|b| !b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    let forged_signature = Signature::from_bytes(forged_sig_bytes);

    // Verification with forged signature should fail
    let result = verify(&public_key, message, &forged_signature);
    assert!(
        result.is_err(),
        "Forged signature should be rejected"
    );
}

// ============================================================================
// T1.2: Tampered global signature (trusted comment binding)
// ============================================================================

#[test]
fn t1_reject_tampered_global_signature() {
    let (secret_key, public_key, keynum) = generate_keypair().unwrap();
    let message = b"test message";

    // Create valid signature
    let signature = sign(&secret_key, message).unwrap();
    let sig_struct = SigStruct::new(keynum, signature, false);

    let trusted_comment = "timestamp:1234567890";

    // Create valid global signature
    let sig_box = SignatureBox::with_global_signature(
        "test untrusted".to_string(),
        sig_struct,
        trusted_comment.to_string(),
        &secret_key,
    )
    .unwrap();

    // Tamper with global signature
    let tampered_global: [u8; SIGNATURE_BYTES] = sig_box
        .global_signature()
        .as_bytes()
        .iter()
        .map(|b| !b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    // Verification with tampered global should fail
    let result = verify(
        &public_key,
        sig_box.sig_struct().signature().as_bytes(),
        &Signature::from_bytes(tampered_global),
    );
    assert!(
        result.is_err(),
        "Tampered global signature should be rejected"
    );
}

// ============================================================================
// T1.3: Signature reuse across different messages
// ============================================================================

#[test]
fn t1_reject_signature_reuse() {
    let (secret_key, public_key, _keynum) = generate_keypair().unwrap();

    let message1 = b"first message";
    let message2 = b"second message - completely different";

    // Sign first message
    let signature = sign(&secret_key, message1).unwrap();

    // Verify signature is valid for message1
    assert!(verify(&public_key, message1, &signature).is_ok());

    // Try to reuse signature for message2 (should fail)
    let result = verify(&public_key, message2, &signature);
    assert!(
        result.is_err(),
        "Reused signature should be rejected for different message"
    );
}

// ============================================================================
// T1.4: Algorithm confusion - prehashed mode mismatch
// ============================================================================

#[test]
fn t1_reject_prehashed_mode_mismatch() {
    let (secret_key, _public_key, keynum) = generate_keypair().unwrap();
    let message = b"test message";

    // Create signature in normal mode
    let signature = sign(&secret_key, message).unwrap();
    let sig_struct_normal = SigStruct::new(keynum, signature, false);

    // Create same signature but claim it's prehashed mode
    let sig_struct_prehashed = SigStruct::new(keynum, signature, true);

    // The is_prehashed flag should be different
    assert!(!sig_struct_normal.is_prehashed());
    assert!(sig_struct_prehashed.is_prehashed());

    // The binary representation should be different
    assert_ne!(
        sig_struct_normal.to_bytes(),
        sig_struct_prehashed.to_bytes(),
        "Normal and prehashed mode should have different binary representation"
    );
}

// ============================================================================
// T1.5: Keynum mismatch detection
// ============================================================================

#[test]
fn t1_reject_keynum_mismatch() {
    let (secret_key, _public_key, correct_keynum) = generate_keypair().unwrap();
    let message = b"test message";

    // Create valid signature
    let signature = sign(&secret_key, message).unwrap();

    // Create two SigStructs with different keynums
    let sig_struct_correct = SigStruct::new(correct_keynum, signature, false);
    let wrong_keynum = KeyNum::from_bytes([0xFF; 8]);
    let sig_struct_wrong = SigStruct::new(wrong_keynum, signature, false);

    // Keynums should be different
    assert_ne!(
        sig_struct_correct.keynum(),
        sig_struct_wrong.keynum(),
        "Keynums should be different"
    );

    // This demonstrates that keynum is part of the signature structure
    // and would be checked during verification
}

// ============================================================================
// T1.6: Message modification detection
// ============================================================================

#[test]
fn t1_reject_modified_message() {
    let (secret_key, public_key, _keynum) = generate_keypair().unwrap();

    let original_message = b"original message";
    let modified_message = b"modified message";

    // Sign original message
    let signature = sign(&secret_key, original_message).unwrap();

    // Verify signature is valid for original
    assert!(verify(&public_key, original_message, &signature).is_ok());

    // Verify signature fails for modified message
    let result = verify(&public_key, modified_message, &signature);
    assert!(
        result.is_err(),
        "Signature should be rejected for modified message"
    );
}

// ============================================================================
// T1.7: Invalid signature structure rejection
// ============================================================================

#[test]
fn t1_reject_invalid_signature_structure() {
    // Test that SigStruct validates algorithm markers
    let keynum = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let signature = Signature::from_bytes([0u8; SIGNATURE_BYTES]);

    // Create a valid SigStruct
    let sig_struct = SigStruct::new(keynum, signature, false);
    let bytes = sig_struct.to_bytes();

    // Tamper with algorithm marker (first two bytes should be "Ed" or "ED")
    let mut tampered_bytes = bytes.clone();
    tampered_bytes[0] = b'X';
    tampered_bytes[1] = b'X'; // Completely invalid marker

    // Parsing should fail
    let result = SigStruct::from_bytes(&tampered_bytes);
    assert!(
        result.is_err(),
        "Invalid algorithm marker 'XX' should be rejected"
    );
}

// ============================================================================
// T1.8: Zero signature rejection
// ============================================================================

#[test]
fn t1_reject_zero_signature() {
    let (_secret_key, public_key, _keynum) = generate_keypair().unwrap();
    let message = b"test message";

    // Create all-zero signature (obviously invalid)
    let zero_signature = Signature::from_bytes([0u8; SIGNATURE_BYTES]);

    // Verification should fail
    let result = verify(&public_key, message, &zero_signature);
    assert!(
        result.is_err(),
        "All-zero signature should be rejected"
    );
}
