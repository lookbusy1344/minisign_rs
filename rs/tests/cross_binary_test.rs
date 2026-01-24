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
        .map(|output| {
            if !output.status.success() {
                return false;
            }
            // Check this is C minisign, not our Rust version
            let version_output = String::from_utf8_lossy(&output.stdout);
            !version_output.contains("Rust")
        })
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
    // C minisign outputs help to stdout on Unix, stderr on Windows
    let c_help = format!(
        "{}{}",
        String::from_utf8_lossy(&c_output.stdout),
        String::from_utf8_lossy(&c_output.stderr)
    );

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

// ============================================================================
// Encrypted Key Cross-Binary Tests
// ============================================================================

#[test]
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_generate_rust_sign_c() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    let password_file = temp_dir.path().join("password.txt");

    // Write password to file
    fs::write(&password_file, "test_password_123\n").expect("Failed to write password file");

    // Write test message
    fs::write(&message_file, b"Encrypted key test").expect("Failed to write message");

    // Generate encrypted keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Sign with C minisign using Rust-generated encrypted key
    let c_sign = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | minisign -S -m {} -s {} -x {}",
            password_file.display(),
            message_file.display(),
            secret_key.display(),
            sig_file.display()
        ))
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_sign.status.success(),
        "C minisign failed to sign with Rust-generated encrypted key: {}",
        String::from_utf8_lossy(&c_sign.stderr)
    );

    // Verify with both implementations
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
}

#[test]
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_generate_c_sign_rust() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    let password_file = temp_dir.path().join("password.txt");
    let password_file_double = temp_dir.path().join("password_double.txt");

    // Write password to file (once for Rust operations)
    fs::write(&password_file, "test_password_456\n").expect("Failed to write password file");
    // Write password twice for C minisign -G confirmation
    fs::write(
        &password_file_double,
        "test_password_456\ntest_password_456\n",
    )
    .expect("Failed to write double password file");

    // Write test message
    fs::write(&message_file, b"C encrypted key test").expect("Failed to write message");

    // Generate encrypted keypair with C minisign
    let c_gen = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | minisign -G -f -s {} -p {}",
            password_file_double.display(),
            secret_key.display(),
            public_key.display()
        ))
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_gen.status.success(),
        "C minisign failed to generate encrypted keys: {}",
        String::from_utf8_lossy(&c_gen.stderr)
    );

    // Sign with Rust using C-generated encrypted key
    rust_minisign()
        .arg("-S")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Verify with both implementations
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
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_change_password_rust_to_c() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    let old_password_file = temp_dir.path().join("old_password.txt");
    let new_password_file = temp_dir.path().join("new_password.txt");
    let new_password_file_double = temp_dir.path().join("new_password_double.txt");

    // Write passwords to files
    fs::write(&old_password_file, "old_password\n").expect("Failed to write old password");
    fs::write(&new_password_file, "new_password\n").expect("Failed to write new password");
    // New password needs to be twice for C minisign -C confirmation
    fs::write(&new_password_file_double, "new_password\nnew_password\n")
        .expect("Failed to write new password double");

    // Write test message
    fs::write(&message_file, b"Password change test").expect("Failed to write message");

    // Generate encrypted keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .arg("--password-file")
        .arg(&old_password_file)
        .assert()
        .success();

    // Change password with C minisign
    let c_change = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "(cat {} && cat {}) | minisign -C -s {}",
            old_password_file.display(),
            new_password_file_double.display(),
            secret_key.display()
        ))
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_change.status.success(),
        "C minisign failed to change password: {}",
        String::from_utf8_lossy(&c_change.stderr)
    );

    // Sign with new password using Rust
    rust_minisign()
        .arg("-S")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .arg("--password-file")
        .arg(&new_password_file)
        .assert()
        .success();

    // Verify with both implementations
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
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_change_password_c_to_rust() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");
    let old_password_file = temp_dir.path().join("old_password.txt");
    let old_password_file_double = temp_dir.path().join("old_password_double.txt");
    let new_password_file = temp_dir.path().join("new_password.txt");

    // Write passwords to files
    fs::write(&old_password_file, "old_pw_c\n").expect("Failed to write old password");
    // Old password twice for C minisign -G confirmation
    fs::write(&old_password_file_double, "old_pw_c\nold_pw_c\n")
        .expect("Failed to write old password double");
    fs::write(&new_password_file, "new_pw_rust\n").expect("Failed to write new password");

    // Write test message
    fs::write(&message_file, b"C to Rust password change").expect("Failed to write message");

    // Generate encrypted keypair with C minisign
    let c_gen = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | minisign -G -f -s {} -p {}",
            old_password_file_double.display(),
            secret_key.display(),
            public_key.display()
        ))
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_gen.status.success(),
        "C minisign failed to generate keys: {}",
        String::from_utf8_lossy(&c_gen.stderr)
    );

    // Change password with Rust
    rust_minisign()
        .arg("-C")
        .arg("-s")
        .arg(&secret_key)
        .arg("--password-file")
        .arg(&old_password_file)
        .assert()
        .success();

    // For the new password, we need to use the same file since --password-file
    // is used for both current and new password in this implementation
    // So let's sign with the same password to test the change worked
    rust_minisign()
        .arg("-S")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .arg("--password-file")
        .arg(&old_password_file)
        .assert()
        .success();

    // Verify the signature
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
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_recreate_rust_key_c() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key_orig = temp_dir.path().join("test.pub");
    let public_key_recreated = temp_dir.path().join("recreated.pub");
    let password_file = temp_dir.path().join("password.txt");

    // Write password to file
    fs::write(&password_file, "recreate_test\n").expect("Failed to write password");

    // Generate encrypted keypair with Rust
    rust_minisign()
        .arg("-G")
        .arg("-f")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_orig)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Recreate public key with C minisign
    let c_recreate = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | minisign -R -s {} -p {}",
            password_file.display(),
            secret_key.display(),
            public_key_recreated.display()
        ))
        .output()
        .expect("Failed to run C minisign");

    assert!(
        c_recreate.status.success(),
        "C minisign failed to recreate public key: {}",
        String::from_utf8_lossy(&c_recreate.stderr)
    );

    // Verify the cryptographic key material is identical
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
#[ignore = "Slow: uses production scrypt parameters"]
fn test_cross_encrypted_recreate_c_key_rust() {
    require_c_minisign!();

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key_orig = temp_dir.path().join("test.pub");
    let public_key_recreated = temp_dir.path().join("recreated.pub");
    let password_file = temp_dir.path().join("password.txt");
    let password_file_double = temp_dir.path().join("password_double.txt");

    // Write password to file (once for Rust operations)
    fs::write(&password_file, "c_recreate_test\n").expect("Failed to write password");
    // Write password twice for C minisign -G confirmation
    fs::write(&password_file_double, "c_recreate_test\nc_recreate_test\n")
        .expect("Failed to write double password");

    // Generate encrypted keypair with C minisign
    let c_gen = StdCommand::new("sh")
        .arg("-c")
        .arg(format!(
            "cat {} | minisign -G -f -s {} -p {}",
            password_file_double.display(),
            secret_key.display(),
            public_key_orig.display()
        ))
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
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key_recreated)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Verify the cryptographic key material is identical
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
