//! Security Attack Tests - T1
//!
//! Tests for signature forgery attempts, malleability attacks, and algorithm confusion.
//! These tests verify that the implementation properly rejects various attack vectors.

use minisign::{
    Error,
    crypto::{
        KeyNum, PublicKey, SIGNATURE_BYTES, Signature, blake2b_512, generate_keypair, sign, verify,
    },
    keys::PubkeyStruct,
    ops::verify::verify_message_signature,
    signature::{SigStruct, SignatureBox},
};
use tempfile::TempDir;

// ============================================================================
// T1.1: Signature forgery - correct keynum but forged signature bytes
// ============================================================================

#[test]
fn t1_reject_forged_signature_bytes() {
    let (secret_key, public_key, _keynum) = generate_keypair().unwrap();
    let message = b"original message";

    // Create valid signature
    let signature = sign(&secret_key, message).unwrap();

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
    assert!(result.is_err(), "Forged signature should be rejected");
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
// T1.3 / T1.6: Signature binds to exact message bytes
// ============================================================================

#[test]
fn t1_reject_signature_for_wrong_message() {
    let (secret_key, public_key, _keynum) = generate_keypair().unwrap();

    // Each pair: (signed_message, wrong_message)
    let cases: &[(&[u8], &[u8])] = &[
        (b"first message", b"second message - completely different"),
        (b"original message", b"modified message"),
    ];

    for (signed, other) in cases {
        let signature = sign(&secret_key, signed).unwrap();
        assert!(verify(&public_key, signed, &signature).is_ok());
        assert!(
            verify(&public_key, other, &signature).is_err(),
            "Signature must be rejected for different message"
        );
    }
}

// ============================================================================
// T1.4: Algorithm confusion - prehashed mode mismatch
// ============================================================================

#[test]
fn t1_reject_prehashed_mode_mismatch() {
    let (secret_key, public_key, keynum) = generate_keypair().unwrap();
    let message = b"test message";

    // Signature created in normal mode: over raw message bytes
    let signature = sign(&secret_key, message).unwrap();
    let sig_struct_normal = SigStruct::new(keynum, signature, false);
    let sig_struct_prehashed = SigStruct::new(keynum, signature, true);

    assert!(!sig_struct_normal.is_prehashed());
    assert!(sig_struct_prehashed.is_prehashed());
    assert_ne!(
        sig_struct_normal.to_bytes(),
        sig_struct_prehashed.to_bytes(),
        "normal and prehashed mode must have different binary representation"
    );

    // Normal mode: verifying against raw message must succeed
    assert!(verify(&public_key, message, &signature).is_ok());

    // Algorithm confusion: if a prehashed verifier receives a normal-mode
    // signature, it will hash the message first and verify against the hash —
    // that hash was never signed, so it must fail.
    let hashed_message = blake2b_512(message);
    assert!(
        verify(&public_key, &hashed_message, &signature).is_err(),
        "normal-mode signature must not verify against blake2b_512(message)"
    );
}

// ============================================================================
// T1.5: Keynum mismatch detection
// ============================================================================

#[test]
fn t1_reject_keynum_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let message_path = temp_dir.path().join("msg.txt");
    std::fs::write(&message_path, b"test message").unwrap();

    let (secret_key, public_key, correct_keynum) = generate_keypair().unwrap();
    let pubkey = PubkeyStruct::new(correct_keynum, public_key);

    // Create a valid signature box for the message
    let raw_sig = sign(&secret_key, b"test message").unwrap();
    let sig_struct_correct = SigStruct::new(correct_keynum, raw_sig, false);
    let dummy_global = Signature::from_bytes([0u8; SIGNATURE_BYTES]);
    let valid_box = SignatureBox::new(
        "untrusted comment".to_string(),
        sig_struct_correct,
        "trusted comment".to_string(),
        dummy_global,
    )
    .unwrap();

    // Correct keynum with valid primary signature: must succeed.
    // verify_message_signature only checks keynum, prehash flag, and the Ed25519
    // primary signature — the global signature is not verified here.
    verify_message_signature(&pubkey, &valid_box, &message_path, false)
        .expect("correct keynum + valid primary sig must succeed");

    // Tampered SigStruct: wrong keynum — must be rejected with KeyMismatch
    let wrong_keynum = KeyNum::from_bytes([0xFF; 8]);
    let sig_struct_wrong = SigStruct::new(wrong_keynum, raw_sig, false);
    let tampered_box = SignatureBox::new(
        "untrusted comment".to_string(),
        sig_struct_wrong,
        "trusted comment".to_string(),
        dummy_global,
    )
    .unwrap();

    let err = verify_message_signature(&pubkey, &tampered_box, &message_path, false).unwrap_err();
    assert!(
        matches!(err, Error::KeyMismatch { .. }),
        "wrong keynum must produce KeyMismatch, got: {err}"
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
    let mut tampered_bytes = bytes;
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
    assert!(result.is_err(), "All-zero signature should be rejected");
}

// ============================================================================
// T1.9: Ed25519 S-value malleability — non-reduced S must be rejected
// ============================================================================

/// Ed25519 group order L in little-endian bytes.
///
/// L = 2^252 + 27742317777372353535851937790883648493
const ED25519_GROUP_ORDER_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Add L to the S scalar (last 32 bytes of signature), producing a non-reduced S.
///
/// For a valid signature (R, S) where S < L, the result (R, S+L) encodes the same
/// group element but S is no longer canonically reduced. A compliant Ed25519
/// implementation must reject it.
fn add_group_order_to_s(sig_bytes: &[u8; SIGNATURE_BYTES]) -> [u8; SIGNATURE_BYTES] {
    let mut result = *sig_bytes;
    let s = &mut result[32..]; // last 32 bytes are the S scalar
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(s[i]) + u16::from(ED25519_GROUP_ORDER_L[i]) + carry;
        s[i] = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    result
}

#[test]
fn t1_reject_non_reduced_s_value() {
    let (secret_key, public_key, _keynum) = generate_keypair().unwrap();
    let message = b"malleable signature target";

    let valid_sig = sign(&secret_key, message).unwrap();
    assert!(
        verify(&public_key, message, &valid_sig).is_ok(),
        "baseline: valid signature must verify"
    );

    // Build (R, S+L): mathematically the same group element, but S is non-canonical
    let malleable_bytes = add_group_order_to_s(valid_sig.as_bytes());
    let malleable_sig = Signature::from_bytes(malleable_bytes);

    let result = verify(&public_key, message, &malleable_sig);
    assert!(
        result.is_err(),
        "non-reduced S (S+L) must be rejected — S must be canonically encoded (S < L)"
    );
}

// ============================================================================
// T1.10: Small subgroup public keys — no signature should verify against them
// ============================================================================

#[test]
fn t1_reject_signature_with_small_subgroup_pubkey() {
    let (secret_key, _real_pk, _keynum) = generate_keypair().unwrap();
    let message = b"small subgroup attack target";
    let valid_sig = sign(&secret_key, message).unwrap();

    // Ed25519 low-order (torsion) points in compressed Edwards form.
    // These are valid curve points but lie in the 8-torsion subgroup.

    // Identity element: y = 1, x = 0
    let identity = {
        let mut b = [0u8; 32];
        b[0] = 0x01;
        b
    };

    // Order-2 point: y = -1 mod p = p - 1, x = 0
    // p = 2^255 - 19, so p - 1 = 2^255 - 20 in little-endian:
    let order_2: [u8; 32] = [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    for (name, small_pk_bytes) in [("identity", identity), ("order-2", order_2)] {
        let small_pk = PublicKey::from_bytes(small_pk_bytes);
        let result = verify(&small_pk, message, &valid_sig);
        assert!(
            result.is_err(),
            "signature must not verify against small-subgroup public key ({name})"
        );
    }
}

// ============================================================================
// T1.11: Valid global signature does not rescue a forged primary signature
// ============================================================================

#[test]
fn t1_reject_valid_global_with_forged_primary() {
    use minisign::{keys::PubkeyStruct, ops::verify::verify_message_signature};
    use tempfile::TempDir;

    let (secret_key, public_key, keynum) = generate_keypair().unwrap();
    let pubkey_struct = PubkeyStruct::new(keynum, public_key);

    let temp_dir = TempDir::new().unwrap();
    let msg1_path = temp_dir.path().join("msg1.txt");
    let msg2_path = temp_dir.path().join("msg2.txt");

    let message1 = b"first message";
    let message2 = b"second message - entirely different content";
    std::fs::write(&msg1_path, message1).unwrap();
    std::fs::write(&msg2_path, message2).unwrap();

    // Sign message2 in non-prehashed mode
    let sig_for_m2 = sign(&secret_key, message2).unwrap();
    let sig_struct_m2 = SigStruct::new(keynum, sig_for_m2, false);

    // Build a complete, internally-consistent signature box for message2:
    // global_sig = sign(sig_for_m2.bytes || trusted_comment)
    let sig_box = SignatureBox::with_global_signature(
        "untrusted comment".to_string(),
        sig_struct_m2,
        "timestamp:9999999999".to_string(),
        &secret_key,
    )
    .unwrap();

    // Sanity check: the global signature is valid for this box
    sig_box
        .verify_global_signature(&public_key)
        .expect("global sig must be internally consistent");

    // Primary signature was computed for message2, not message1.
    // verify_message_signature must reject it regardless of the global sig's validity.
    let result = verify_message_signature(&pubkey_struct, &sig_box, &msg1_path, false);
    assert!(
        result.is_err(),
        "primary sig for message2 must be rejected when verifying against message1, \
         even though the global signature is internally consistent"
    );
}
