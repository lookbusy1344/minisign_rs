//! Cross-binary integration tests
//!
//! These tests verify behavioral equivalence between the C minisign
//! (installed via homebrew) and the Rust implementation. They dynamically
//! execute both binaries and compare their behavior.

use assert_cmd::Command;
use std::fs;
use std::process::Command as StdCommand;
use tempfile::TempDir;

/// Helper to create a command for the Rust minisign binary
fn rust_minisign() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("minisign"))
}

/// Helper to create a command for the C minisign binary (from homebrew)
fn c_minisign() -> StdCommand {
    StdCommand::new("minisign")
}

/// Verify that the C minisign binary is available
fn check_c_minisign_available() -> bool {
    c_minisign()
        .arg("-v")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Run a test that requires C minisign, skipping if not available
macro_rules! require_c_minisign {
    () => {
        if !check_c_minisign_available() {
            eprintln!("Skipping test: C minisign not found (install via: brew install minisign)");
            return;
        }
    };
}

#[test]
fn test_c_minisign_available() {
    assert!(
        check_c_minisign_available(),
        "C minisign is not available. Install with: brew install minisign\n\
         These tests verify compatibility between C and Rust implementations."
    );
}

#[test]
fn test_version_output_format() {
    require_c_minisign!();

    let rust_output = rust_minisign()
        .arg("-v")
        .output()
        .expect("Failed to run Rust minisign");

    let c_output = c_minisign()
        .arg("-v")
        .output()
        .expect("Failed to run C minisign");

    assert!(rust_output.status.success());
    assert!(c_output.status.success());

    // Both should contain "minisign" in version output
    let rust_version = String::from_utf8_lossy(&rust_output.stdout);
    let c_version = String::from_utf8_lossy(&c_output.stdout);

    assert!(rust_version.contains("minisign"));
    assert!(c_version.contains("minisign"));
}

#[test]
fn test_help_output_similarity() {
    require_c_minisign!();

    let rust_output = rust_minisign()
        .arg("-h")
        .output()
        .expect("Failed to run Rust minisign");

    // C minisign shows help when run with no arguments (exits with error code)
    let c_output = c_minisign().output().expect("Failed to run C minisign");

    assert!(rust_output.status.success());

    let rust_help = String::from_utf8_lossy(&rust_output.stdout);
    // C minisign outputs help to stdout when run with no arguments
    let c_help = String::from_utf8_lossy(&c_output.stdout);

    // Check that both have the main operation flags
    // C minisign shows these in usage lines, Rust shows in detailed help
    for flag in &["-G", "-S", "-V", "-R"] {
        assert!(rust_help.contains(flag), "Rust help missing flag: {flag}");
        assert!(
            c_help.contains(flag),
            "C help missing operation flag: {flag}\nC output: {c_help}"
        );
    }

    // Check for common option flags (may appear in different formats)
    assert!(rust_help.contains("-m") || rust_help.contains("message"));
    assert!(c_help.contains("-m") || c_help.contains("file"));
}

#[test]
fn test_cross_generate_rust_verify_c() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Hello from Rust!").expect("Failed to write message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with Rust
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();

    // Verify with C minisign
    let c_verify = c_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_verify.status.success(),
        "C minisign failed to verify Rust-generated signature: {}",
        String::from_utf8_lossy(&c_verify.stderr)
    );
}

#[test]
fn test_cross_generate_c_verify_rust() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Hello from C!").expect("Failed to write message");

    // Generate keypair with C minisign
    let c_gen = c_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_gen.status.success(),
        "C minisign failed to generate keys: {}",
        String::from_utf8_lossy(&c_gen.stderr)
    );

    // Sign with C minisign
    let c_sign = c_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_sign.status.success(),
        "C minisign failed to sign: {}",
        String::from_utf8_lossy(&c_sign.stderr)
    );

    // Verify with Rust
    rust_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();
}

#[test]
fn test_cross_sign_rust_key_c_signature() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Cross-sign test").expect("Failed to write message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with C minisign using Rust-generated key
    let c_sign = c_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_sign.status.success(),
        "C minisign failed to sign with Rust-generated key: {}",
        String::from_utf8_lossy(&c_sign.stderr)
    );

    // Verify with Rust
    rust_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();
}

#[test]
fn test_cross_sign_c_key_rust_signature() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Cross-sign test").expect("Failed to write message");

    // Generate keypair with C minisign
    let c_gen = c_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_gen.status.success(),
        "C minisign failed to generate keys: {}",
        String::from_utf8_lossy(&c_gen.stderr)
    );

    // Sign with Rust using C-generated key
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();

    // Verify with C minisign
    let c_verify = c_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_verify.status.success(),
        "C minisign failed to verify Rust signature: {}",
        String::from_utf8_lossy(&c_verify.stderr)
    );
}

#[test]
fn test_cross_recreate_rust_key_c_recreate() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key_orig = temp_dir.path().join("test.pub");
    let public_key_recreated = temp_dir.path().join("recreated.pub");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_orig)
        .assert()
        .success();

    // Recreate public key with C minisign
    let c_recreate = c_minisign()
        .arg("-R")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_recreated)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_recreate.status.success(),
        "C minisign failed to recreate public key: {}",
        String::from_utf8_lossy(&c_recreate.stderr)
    );

    // Verify the cryptographic key material is identical
    // (untrusted comment will differ due to random key ID)
    let orig = fs::read_to_string(&public_key_orig).expect("Failed to read original public key");
    let recreated =
        fs::read_to_string(&public_key_recreated).expect("Failed to read recreated public key");

    // Extract the base64 key data (second line)
    let orig_key = orig.lines().nth(1).expect("Missing key data in original");
    let recreated_key = recreated
        .lines()
        .nth(1)
        .expect("Missing key data in recreated");

    assert_eq!(
        orig_key, recreated_key,
        "Public key data doesn't match after recreation"
    );
}

#[test]
fn test_cross_recreate_c_key_rust_recreate() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key_orig = temp_dir.path().join("test.pub");
    let public_key_recreated = temp_dir.path().join("recreated.pub");

    // Generate keypair with C minisign
    let c_gen = c_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_orig)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_gen.status.success(),
        "C minisign failed to generate keys: {}",
        String::from_utf8_lossy(&c_gen.stderr)
    );

    // Recreate public key with Rust
    rust_minisign()
        .arg("-R")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_recreated)
        .assert()
        .success();

    // Verify the cryptographic key material is identical
    // (untrusted comment will differ due to random key ID)
    let orig = fs::read_to_string(&public_key_orig).expect("Failed to read original public key");
    let recreated =
        fs::read_to_string(&public_key_recreated).expect("Failed to read recreated public key");

    // Extract the base64 key data (second line)
    let orig_key = orig.lines().nth(1).expect("Missing key data in original");
    let recreated_key = recreated
        .lines()
        .nth(1)
        .expect("Missing key data in recreated");

    assert_eq!(
        orig_key, recreated_key,
        "Public key data doesn't match after recreation"
    );
}

#[test]
fn test_cross_prehashed_mode() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("large_message.txt");
    let rust_sig = temp_dir.path().join("rust.minisig");
    let c_sig = temp_dir.path().join("c.minisig");

    // Write a larger test message
    fs::write(&message_file, vec![b'A'; 10000]).expect("Failed to write message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with Rust in prehashed mode
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-H")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&rust_sig)
        .assert()
        .success();

    // Sign with C minisign in prehashed mode
    let c_sign = c_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-H")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&c_sig)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_sign.status.success(),
        "C minisign failed to sign: {}",
        String::from_utf8_lossy(&c_sign.stderr)
    );

    // Verify C signature with Rust
    rust_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&c_sig)
        .assert()
        .success();

    // Verify Rust signature with C
    let c_verify = c_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&rust_sig)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_verify.status.success(),
        "C minisign failed to verify Rust signature: {}",
        String::from_utf8_lossy(&c_verify.stderr)
    );
}

#[test]
fn test_cross_trusted_comment() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with Rust using custom trusted comment
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-t")
        .arg("Rust trusted comment")
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();

    // Verify with C minisign - should display trusted comment
    let c_verify = c_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_verify.status.success(),
        "C minisign failed to verify: {}",
        String::from_utf8_lossy(&c_verify.stderr)
    );

    let c_output = String::from_utf8_lossy(&c_verify.stdout);
    assert!(
        c_output.contains("Rust trusted comment"),
        "C minisign output missing trusted comment"
    );
}

#[test]
fn test_cross_invalid_signature_detection() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let wrong_message = temp_dir.path().join("wrong.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write messages
    fs::write(&message_file, b"Original message").expect("Failed to write message");
    fs::write(&wrong_message, b"Tampered message").expect("Failed to write wrong message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign original message with Rust
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();

    // Both implementations should reject verification with wrong message
    rust_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&wrong_message)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .failure();

    let c_verify = c_minisign()
        .arg("-V")
        .arg("-m")
        .arg(&wrong_message)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .output()
        .expect("Failed to run C minisign");

    assert!(
        !c_verify.status.success(),
        "C minisign should have rejected tampered message"
    );
}

#[test]
fn test_cross_quiet_mode_behavior() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    // Write test message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with Rust
    rust_minisign()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success();

    // Verify with both in quiet mode - both should produce no output
    let rust_verify = rust_minisign()
        .arg("-V")
        .arg("-q")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .output()
        .expect("Failed to run Rust minisign");

    let c_verify = c_minisign()
        .arg("-V")
        .arg("-q")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .output()
        .expect("Failed to run C minisign");

    assert!(rust_verify.status.success());
    assert!(c_verify.status.success());

    // Both should have empty stdout in quiet mode
    assert!(
        rust_verify.stdout.is_empty(),
        "Rust minisign should have no output in quiet mode"
    );
    assert!(
        c_verify.stdout.is_empty(),
        "C minisign should have no output in quiet mode"
    );
}
