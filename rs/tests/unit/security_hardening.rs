// Security Hardening Tests
//
// Tests for findings H1, H2, H3, H4, H6 from the 2026-02-06 security audit:
// comment validation, KDF parameter bounds-checking, and signature file I/O.
//
// CR-2026-02-28-1: Bounded file reads for key/signature/password inputs.
// CR-2026-02-28-2: KDF policy cap on decryption parameters.
// CR-2026-02-28-3: Exclusive temp-file creation in secret-key overwrite path.

use minisign::{
    Error,
    crypto::{SecretKey, opslimit_memlimit_to_params},
    ops::file_utils::{
        MAX_KEY_FILE_BYTES, MAX_PASSWORD_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES, load_secret_key,
    },
    ops::inspect::inspect_signature,
    ops::verify::{PublicKeySource, load_public_key, load_signature},
    signature::{COMMENTMAXBYTES, SigStruct, SignatureBox, TRUSTEDCOMMENTMAXBYTES},
};
use std::fs;
use tempfile::TempDir;

// ============================================================================
// H1: SignatureBox::new() must reject invalid comments
// ============================================================================

#[test]
fn h1_new_rejects_newline_in_untrusted_comment() {
    let sig_struct = create_dummy_sig_struct();
    let global_sig = create_dummy_signature();

    // Attempt to create SignatureBox with newline in untrusted comment
    let result = SignatureBox::new(
        "malicious\ncomment".to_string(),
        sig_struct,
        "valid trusted comment".to_string(),
        global_sig,
    );

    assert!(
        result.is_err(),
        "SignatureBox::new() should reject newlines in untrusted_comment"
    );
}

#[test]
fn h1_new_rejects_newline_in_trusted_comment() {
    let sig_struct = create_dummy_sig_struct();
    let global_sig = create_dummy_signature();

    let result = SignatureBox::new(
        "valid untrusted comment".to_string(),
        sig_struct,
        "malicious\ntrusted comment".to_string(),
        global_sig,
    );

    assert!(
        result.is_err(),
        "SignatureBox::new() should reject newlines in trusted_comment"
    );
}

#[test]
fn h1_new_rejects_unprintable_chars() {
    let sig_struct = create_dummy_sig_struct();
    let global_sig = create_dummy_signature();

    // ANSI escape sequence attack
    let result = SignatureBox::new(
        "malicious\x1b[31mRED TEXT\x1b[0m".to_string(),
        sig_struct,
        "valid".to_string(),
        global_sig,
    );

    assert!(
        result.is_err(),
        "SignatureBox::new() should reject unprintable characters"
    );
}

#[test]
fn h1_new_accepts_valid_comments() {
    let sig_struct = create_dummy_sig_struct();
    let global_sig = create_dummy_signature();

    let result = SignatureBox::new(
        "valid untrusted comment".to_string(),
        sig_struct,
        "valid trusted comment".to_string(),
        global_sig,
    );

    assert!(
        result.is_ok(),
        "SignatureBox::new() should accept valid comments"
    );
}

// ============================================================================
// H2: with_global_signature() must validate comment lengths
// ============================================================================

#[test]
fn h2_with_global_signature_rejects_oversized_untrusted_comment() {
    let sig_struct = create_dummy_sig_struct();
    let secret_key = create_dummy_secret_key();

    // Create comment exceeding COMMENTMAXBYTES
    let oversized_comment = "x".repeat(COMMENTMAXBYTES + 1);

    let result = SignatureBox::with_global_signature(
        oversized_comment,
        sig_struct,
        "valid".to_string(),
        &secret_key,
    );

    assert!(
        result.is_err(),
        "with_global_signature() should reject oversized untrusted_comment"
    );
}

#[test]
fn h2_with_global_signature_rejects_oversized_trusted_comment() {
    let sig_struct = create_dummy_sig_struct();
    let secret_key = create_dummy_secret_key();

    let oversized_comment = "x".repeat(TRUSTEDCOMMENTMAXBYTES + 1);

    let result = SignatureBox::with_global_signature(
        "valid".to_string(),
        sig_struct,
        oversized_comment,
        &secret_key,
    );

    assert!(
        result.is_err(),
        "with_global_signature() should reject oversized trusted_comment"
    );
}

#[test]
fn h2_with_global_signature_rejects_invalid_chars() {
    let sig_struct = create_dummy_sig_struct();
    let secret_key = create_dummy_secret_key();

    let result = SignatureBox::with_global_signature(
        "invalid\ncomment".to_string(),
        sig_struct,
        "valid".to_string(),
        &secret_key,
    );

    assert!(
        result.is_err(),
        "with_global_signature() should reject newlines in comments"
    );
}

// ============================================================================
// H3: opslimit_memlimit_to_params() must reject malformed KDF encodings
// ============================================================================

#[test]
fn h3_kdf_params_reject_malformed_pairs() {
    let cases = [
        (
            "memlimit not divisible by the standard divisor",
            33_554_432u64,
            1_073_741_825u64,
        ),
        (
            "memlimit does not encode a power-of-two N",
            32_000u64,
            1_024_000u64,
        ),
        ("opslimit would derive a zero r", 0u64, 1_073_741_824u64),
        (
            "opslimit overflows the supported range",
            u64::MAX,
            1_073_741_824u64,
        ),
    ];

    for (case, opslimit, memlimit) in cases {
        let result = opslimit_memlimit_to_params(opslimit, memlimit);
        assert!(result.is_err(), "{case}");
    }
}

// ============================================================================
// H4: write_signature_file() writes correct content
// ============================================================================

#[test]
fn h4_signature_file_write_correct_content() {
    let temp_dir = TempDir::new().unwrap();
    let sig_path = temp_dir.path().join("test.minisig");

    let contents =
        "untrusted comment: test\nYmFzZTY0ZGF0YQ==\ntrusted comment: test\nZ2xvYmFsc2ln\n";

    let result = minisign::ops::sign::write_signature_file(&sig_path, contents, false);

    assert!(result.is_ok(), "write_signature_file should succeed");

    let read_contents = fs::read_to_string(&sig_path).unwrap();
    assert_eq!(read_contents, contents, "File contents should match");
}

// ============================================================================
// H6: from_file_contents() must enforce comment length limits
// ============================================================================

#[test]
fn h6_parse_rejects_oversized_untrusted_comment() {
    // Create a malicious signature file with oversized untrusted comment
    let oversized_comment = "x".repeat(COMMENTMAXBYTES + 1);
    let contents = format!(
        "untrusted comment: {oversized_comment}\nYmFzZTY0ZGF0YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ntrusted comment: valid\nZ2xvYmFsc2lnbmF0dXJlYmFzZTY0ZGF0YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    );

    let result = SignatureBox::from_file_contents(&contents);

    assert!(
        result.is_err(),
        "from_file_contents() should reject oversized untrusted comment"
    );
    if let Err(e) = result {
        assert!(
            matches!(e, Error::InvalidComment(_)),
            "Should return InvalidComment error"
        );
    }
}

#[test]
fn h6_parse_rejects_oversized_trusted_comment() {
    let oversized_comment = "x".repeat(TRUSTEDCOMMENTMAXBYTES + 1);
    let contents = format!(
        "untrusted comment: valid\nYmFzZTY0ZGF0YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\ntrusted comment: {oversized_comment}\nZ2xvYmFsc2lnbmF0dXJlYmFzZTY0ZGF0YQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
    );

    let result = SignatureBox::from_file_contents(&contents);

    assert!(
        result.is_err(),
        "from_file_contents() should reject oversized trusted comment"
    );
}

#[test]
fn h6_parse_accepts_maximum_length_comments() {
    // Test boundary: comments at exactly COMMENTMAXBYTES / TRUSTEDCOMMENTMAXBYTES
    // chars in the comment text should be accepted by the parser.
    let max_untrusted = "x".repeat(COMMENTMAXBYTES);
    let max_trusted = "x".repeat(TRUSTEDCOMMENTMAXBYTES);

    // Create valid base64-encoded signature structure (74 bytes = SIG_STRUCT_SIZE)
    // Ed (2 bytes) + keynum (8 bytes) + signature (64 bytes) = 74 bytes
    let mut sig_struct_bytes = vec![0u8; 74];
    sig_struct_bytes[0] = b'E';
    sig_struct_bytes[1] = b'd';
    let sig_struct_b64 = minisign::formats::encode_base64(&sig_struct_bytes);

    // Global signature is 64 bytes
    let global_sig_bytes = vec![0u8; 64]; // Will encode to ~88 chars in base64
    let global_sig_b64 = minisign::formats::encode_base64(&global_sig_bytes);

    let contents = format!(
        "untrusted comment: {max_untrusted}\n{sig_struct_b64}\ntrusted comment: {max_trusted}\n{global_sig_b64}\n"
    );

    let result = SignatureBox::from_file_contents(&contents);

    // Should succeed - we're at the boundary
    assert!(
        result.is_ok(),
        "Should accept comments at maximum length: {:?}",
        result.err()
    );
}

// ============================================================================
// Test Helpers
// ============================================================================

fn create_dummy_sig_struct() -> SigStruct {
    // Create a minimal valid SigStruct for testing
    // This matches the Ed25519 signature format
    let sig_algorithm = [0x45, 0x64]; // "Ed"
    let keynum = [0u8; 8];
    let signature_bytes = [0u8; 64];

    SigStruct::from_bytes(&[&sig_algorithm[..], &keynum[..], &signature_bytes[..]].concat())
        .unwrap()
}

fn create_dummy_signature() -> minisign::crypto::Signature {
    // Create a dummy 64-byte signature
    minisign::crypto::Signature::from_bytes([0u8; 64])
}

fn create_dummy_secret_key() -> SecretKey {
    // Generate a real secret key for testing
    // This requires using the crypto module's key generation
    use minisign::crypto::generate_keypair;
    let (sk, _, _) = generate_keypair().unwrap();
    sk
}

// ============================================================================
// CR-2026-02-28-1: Bounded file reads for key/signature/password inputs
// ============================================================================

#[test]
fn cr1_load_secret_key_rejects_oversized_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.key");
    // Write a file just over the limit
    fs::write(
        &path,
        vec![b'x'; usize::try_from(MAX_KEY_FILE_BYTES + 1).unwrap()],
    )
    .unwrap();

    let result = load_secret_key(&path);
    assert!(result.is_err(), "Should reject oversized key file");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too large") || err_msg.contains("exceeds"),
        "Error should mention file size: {err_msg}"
    );
}

#[test]
fn cr1_load_public_key_rejects_oversized_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.pub");
    fs::write(
        &path,
        vec![b'x'; usize::try_from(MAX_KEY_FILE_BYTES + 1).unwrap()],
    )
    .unwrap();

    let result = load_public_key(&PublicKeySource::File(&path));
    assert!(result.is_err(), "Should reject oversized public key file");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too large") || err_msg.contains("exceeds"),
        "Error should mention file size: {err_msg}"
    );
}

#[test]
fn cr1_load_signature_rejects_oversized_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.sig");
    fs::write(
        &path,
        vec![b'x'; usize::try_from(MAX_SIGNATURE_FILE_BYTES + 1).unwrap()],
    )
    .unwrap();

    let result = load_signature(&path);
    assert!(result.is_err(), "Should reject oversized signature file");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("too large") || err_msg.contains("exceeds"),
        "Error should mention file size: {err_msg}"
    );
}

#[test]
fn cr1_inspect_signature_rejects_oversized_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("huge.sig");
    fs::write(
        &path,
        vec![b'x'; usize::try_from(MAX_SIGNATURE_FILE_BYTES + 1).unwrap()],
    )
    .unwrap();

    let result = inspect_signature(&path);
    assert!(result.is_err(), "Should reject oversized signature file");
}

#[test]
fn cr1_load_secret_key_accepts_normal_sized_file() {
    // A file well under the limit should not be rejected for size reasons
    // (it will fail to parse, but not due to size)
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("normal.key");
    fs::write(&path, b"untrusted comment: test\nYWJj\n").unwrap();

    let result = load_secret_key(&path);
    // Should fail with a parse error, not a size error
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            !err_msg.contains("too large") && !err_msg.contains("exceeds"),
            "Should not be rejected for size: {err_msg}"
        );
    }
}

// CR-2026-02-28-1: MAX_PASSWORD_FILE_BYTES is used to guard the --password-file path.
// That path is in main.rs (not a library function), so we verify the constant is exported.
#[test]
fn cr1_password_file_limit_constant_is_sane() {
    const { assert!(MAX_PASSWORD_FILE_BYTES >= 64) }
    const { assert!(MAX_PASSWORD_FILE_BYTES <= 65536) }
}

// ============================================================================
// CR-2026-02-28-2: KDF policy cap on decryption parameters
// ============================================================================

#[test]
fn cr2_rejects_extreme_kdf_log_n() {
    use minisign::crypto::LIBSODIUM_MEMLIMIT_MULTIPLIER;
    use minisign::crypto::SCRYPT_R;

    // Craft memlimit that would produce log_n = 40 (N = 2^40, ~128 TB RAM)
    // memlimit = N * MEMLIMIT_MULTIPLIER * r = 2^40 * 128 * 8
    let n: u64 = 1u64 << 40;
    let memlimit = n
        .saturating_mul(LIBSODIUM_MEMLIMIT_MULTIPLIER)
        .saturating_mul(u64::from(SCRYPT_R));
    let opslimit = 4 * n * u64::from(SCRYPT_R);

    let result = opslimit_memlimit_to_params(opslimit, memlimit);
    assert!(result.is_err(), "Should reject extreme log_n values");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("policy") || err_msg.contains("exceeds") || err_msg.contains("too high"),
        "Error should explain policy cap: {err_msg}"
    );
}

#[test]
fn cr2_accepts_standard_kdf_params() {
    use minisign::constants::{PRODUCTION_MEMLIMIT, PRODUCTION_OPSLIMIT};

    // Standard production params should not be rejected
    let result = opslimit_memlimit_to_params(PRODUCTION_OPSLIMIT, PRODUCTION_MEMLIMIT);
    assert!(
        result.is_ok(),
        "Standard KDF params should be accepted: {:?}",
        result.err()
    );
    let (log_n, r, p) = result.unwrap();
    assert_eq!(log_n, 20);
    assert_eq!(r, 8);
    assert_eq!(p, 1);
}
