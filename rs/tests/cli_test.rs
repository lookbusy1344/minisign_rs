//! End-to-end CLI integration tests using `assert_cmd`
//!
//! These tests verify the complete CLI behavior of the minisign binary.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a test command
fn minisign_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
}

/// RAII guard for credential store cleanup in CLI tests
/// Ensures credentials are removed even if tests panic
#[cfg(feature = "credential_store_tests")]
mod credential_guard {
    use minisign::credential_store;

    pub struct CredentialGuard {
        credential_id: String,
    }

    impl CredentialGuard {
        pub fn new(credential_id: impl Into<String>) -> Self {
            let credential_id = credential_id.into();
            Self { credential_id }
        }

        #[allow(dead_code)]
        pub fn credential_id(&self) -> &str {
            &self.credential_id
        }
    }

    impl Drop for CredentialGuard {
        fn drop(&mut self) {
            // Ensure cleanup happens even if test panics
            let _ = credential_store::forget_password(&self.credential_id);
        }
    }
}

#[test]
fn test_no_arguments() {
    minisign_cmd()
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("No action specified"));
}

#[test]
fn test_help_flag() {
    minisign_cmd()
        .arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "A dead simple Rust tool to sign files",
        ));
}

#[test]
fn test_version_flag() {
    minisign_cmd()
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("minisign_rs"));
}

#[test]
fn test_help_shows_correct_app_name() {
    let output = minisign_cmd()
        .arg("-h")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);

    // Auto-generated help should show "minisign_rs" in the Usage line
    assert!(
        stdout.contains("Usage: minisign_rs"),
        "Help output should contain 'Usage: minisign_rs' but got:\n{stdout}"
    );

    // Should show the description
    assert!(
        stdout.contains("A dead simple Rust tool to sign files"),
        "Help output should contain description but got:\n{stdout}"
    );
}

#[test]
fn test_generate_missing_arguments() {
    let dir = TempDir::new().unwrap();
    let sk = dir.path().join("test.key");
    let pk = dir.path().join("test.pub");

    // Non-interactive: should fail because it can't prompt for a password
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .failure()
        .stderr(predicate::str::contains("password"));
}

#[test]
fn test_sign_missing_message() {
    minisign_cmd()
        .arg("-S")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("Message file"));
}

#[test]
fn test_verify_missing_message() {
    minisign_cmd()
        .arg("-V")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("Message file"));
}

#[test]
fn test_generate_with_force_and_no_password() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret key was saved"));

    // Verify files were created
    assert!(secret_key.exists());
    assert!(public_key.exists());
}

#[test]
fn test_sign_and_verify_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Hello, world!").expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign the message (use -W since key is unencrypted)
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature written"));

    // Verify the signature
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[test]
fn test_verify_wrong_message_fails() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let wrong_message = temp_dir.path().join("wrong.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write messages
    fs::write(&message_file, b"Hello, world!").expect("Failed to write message");
    fs::write(&wrong_message, b"Different message").expect("Failed to write wrong message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign the original message (use -W since key is unencrypted)
    minisign_cmd()
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

    // Try to verify with wrong message
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&wrong_message)
        .arg("-p")
        .arg(&public_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("verification failed"));
}

#[test]
fn test_quiet_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    // Write test message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate with quiet mode
    let output = minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-q")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Quiet mode should produce no output
    assert!(output.is_empty());

    // Sign with quiet mode (use -W since key is unencrypted)
    let output = minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-q")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(output.is_empty());

    // Verify with quiet mode
    let output = minisign_cmd()
        .arg("-V")
        .arg("-q")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(output.is_empty());
}

#[test]
fn test_pretty_quiet_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    // Write test message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with custom trusted comment (use -W since key is unencrypted)
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-t")
        .arg("Custom trusted comment")
        .assert()
        .success();

    // Verify with pretty quiet mode (should only show trusted comment)
    minisign_cmd()
        .arg("-V")
        .arg("-Q")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("Custom trusted comment"))
        .stdout(predicate::str::contains("verified").not());
}

#[test]
fn test_recreate_public_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let recreated_key = temp_dir.path().join("recreated.pub");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Recreate public key (no -W needed - key is unencrypted)
    minisign_cmd()
        .arg("-R")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&recreated_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("Public key recreated"));

    // Verify files match
    let original = fs::read(&public_key).expect("Failed to read original");
    let recreated = fs::read(&recreated_key).expect("Failed to read recreated");
    assert_eq!(original, recreated);
}

#[test]
fn test_trusted_and_untrusted_comments() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Write test message
    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with custom comments (use -W since key is unencrypted)
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("-t")
        .arg("Trusted comment text")
        .arg("-c")
        .arg("Untrusted comment text")
        .assert()
        .success();

    // Verify the signature file contains comments
    let sig_content = fs::read_to_string(&sig_file).expect("Failed to read signature");
    assert!(sig_content.contains("Untrusted comment text"));
    assert!(sig_content.contains("Trusted comment text"));

    // Verify and check trusted comment appears in output
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("Trusted comment text"));
}

#[test]
#[cfg_attr(
    not(unix),
    ignore = "atomic secret-key overwrite not yet implemented on Windows"
)]
fn test_force_flag_allows_overwrite() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Generate again without -f should fail
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    // Generate with -f should succeed
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();
}

#[test]
fn test_prehashed_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("large_message.txt");

    // Write a larger test message
    fs::write(&message_file, vec![b'A'; 10000]).expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with prehashed mode (use -W since key is unencrypted)
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-H")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success();

    // Verify prehashed signature (prehashed mode is detected automatically from signature)
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

/// Test signing with legacy mode (-l flag)
#[test]
fn test_sign_with_legacy_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("test_message.txt");
    let sig_file = temp_dir.path().join("test_message.txt.minisig");

    // Generate an unencrypted key
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Create a test message
    fs::write(&message_file, b"Test message for legacy mode")
        .expect("Failed to write message file");

    // Sign with legacy mode
    minisign_cmd()
        .arg("-S")
        .arg("-l") // Legacy mode flag
        .arg("-W") // No password for unencrypted key
        .arg("-s")
        .arg(&secret_key)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success();

    // Read the signature file and verify it uses non-prehashed mode
    let sig_contents = fs::read_to_string(&sig_file).expect("Failed to read signature file");
    let sig_box = minisign::signature::SignatureBox::from_file_contents(&sig_contents)
        .expect("Failed to parse signature");

    // Legacy mode should NOT be prehashed (should use "Ed" not "ED")
    assert!(
        !sig_box.sig_struct().is_prehashed(),
        "Legacy mode signature should not be prehashed"
    );
}

#[test]
fn test_version_format() {
    // Version output is "minisign_rs X.Y.Z (git-describe)" e.g. "minisign_rs 0.2.0 (v0.2.0-3-gabc1234)"
    let output = minisign_cmd()
        .arg("--version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let version_string = String::from_utf8_lossy(&output);
    let trimmed = version_string.trim();

    assert!(
        trimmed.starts_with("minisign_rs "),
        "Version should start with 'minisign_rs ', got: {trimmed}"
    );
    assert!(
        trimmed.contains(env!("CARGO_PKG_VERSION")),
        "Version should contain the package version, got: {trimmed}"
    );

    // Must include a parenthetical git describe suffix
    assert!(
        trimmed.contains('(') && trimmed.contains(')'),
        "Version should contain a parenthetical git describe suffix, got: {trimmed}"
    );

    let start = trimmed.find('(').expect("opening paren");
    let end = trimmed.find(')').expect("closing paren");
    let in_parens = trimmed[start + 1..end].trim();

    // git describe produces one of:
    //   "v0.2.0"               — exactly on a tag
    //   "v0.2.0-3-gabc1234"    — N commits after tag
    //   "abc1234"              — no tags, bare hash
    //   "unknown"              — git not available at build time
    let is_valid = in_parens == "unknown"
        || (in_parens.starts_with('v') && in_parens.contains('.'))
        || in_parens
            .split('-')
            .next_back()
            .is_some_and(|s| s.starts_with('g') && s.len() >= 8)
        || (in_parens.len() >= 7 && in_parens.chars().all(|c| c.is_ascii_hexdigit()));

    assert!(
        is_valid,
        "Expected valid git describe output in parens, got: {in_parens}"
    );
}

#[test]
fn test_help_shows_version() {
    // The auto-generated help shows --version option, not the actual version number
    minisign_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--version"))
        .stdout(predicate::str::contains("Show version"));
}

#[test]
fn test_inspect_production_key() {
    // Inspect the C-generated production-strength encrypted key
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg("tests/fixtures/keys/test.key")
        .arg("--no-decrypt")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Inspecting: tests/fixtures/keys/test.key",
        ))
        .stdout(predicate::str::contains("Security Level: HIGH"))
        .stdout(predicate::str::contains("opslimit: 33554432"))
        .stdout(predicate::str::contains("memlimit: 1073741824"))
        .stdout(predicate::str::contains("N=2^20"))
        .stdout(predicate::str::contains("Normal (production parameters)"));
}

#[test]
fn test_inspect_unencrypted_key() {
    // Inspect a C-generated unencrypted key
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg("tests/fixtures/keys/unencrypted.key")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Inspecting: tests/fixtures/keys/unencrypted.key",
        ))
        .stdout(predicate::str::contains("Security Level: NONE"))
        .stdout(predicate::str::contains("Encrypted: No"))
        .stdout(predicate::str::contains(
            "WARNING: This key is stored in plaintext",
        ));
}

#[test]
fn test_inspect_public_key() {
    // Inspect a C-generated public key
    minisign_cmd()
        .arg("-I")
        .arg("-p")
        .arg("tests/fixtures/keys/test.pub")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Inspecting: tests/fixtures/keys/test.pub",
        ))
        .stdout(predicate::str::contains("Key ID:"))
        .stdout(predicate::str::contains("Ed25519 Public Key"));
}

#[test]
fn test_inspect_invalid_file() {
    // Inspect an invalid key file
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg("/nonexistent/key.file")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Failed to read"));
}

#[test]
fn test_inspect_uses_default_secret_key_path() {
    // When no key file is specified, should use default secret key path
    // If the default key exists, inspect succeeds; otherwise it fails with a file error
    let result = minisign_cmd().arg("-I").arg("--no-decrypt").assert();

    // Either succeeds (if default key exists) or fails with file read error
    let output = result.get_output();
    let success = output.status.success();

    if success {
        // If default key exists, should show the inspecting line with "(default)"
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Inspecting:") && stdout.contains("(default)"));
        assert!(stdout.contains("Key Information:"));
    } else {
        // If default key doesn't exist, should show file read error
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Failed to read key file") || stderr.contains("No such file"));
    }
}

#[test]
fn test_inspect_public_key_base64() {
    // Test that -I -P <base64> correctly inspects the public key from command line
    minisign_cmd()
        .arg("-I")
        .arg("-P")
        .arg("RWTa4nmE9BYWyPMkgjyqrmh+smzESa8GEX0SnJzS2MIWbR1lL79TJ/8b")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Inspecting: public key from command line (-P)",
        ))
        .stdout(predicate::str::contains("Ed25519 Public Key"))
        .stdout(predicate::str::contains("KDF").not()); // Public keys don't have KDF params
}

#[test]
fn test_inspect_signature_file() {
    // Test inspecting a signature file with -I -x
    minisign_cmd()
        .arg("-I")
        .arg("-x")
        .arg("tests/fixtures/signatures/hello.txt.minisig")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Inspecting: tests/fixtures/signatures/hello.txt.minisig",
        ))
        .stdout(predicate::str::contains("Signature Information:"))
        .stdout(predicate::str::contains("Key ID:"))
        .stdout(predicate::str::contains("Key ID (words):"))
        .stdout(predicate::str::contains("Algorithm:"));
}

#[test]
#[cfg(debug_assertions)]
fn test_force_weak_kdf_creates_weak_key() {
    // Test that --force-weak-kdf creates a key with reduced parameters
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("weak.key");
    let pk_path = temp_dir.path().join("weak.pub");
    let password_file = temp_dir.path().join("password.txt");

    fs::write(&password_file, "testpass").unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "DEBUG WARNING: INTENTIONALLY INSECURE KEY",
        ))
        .stderr(predicate::str::contains("--force-weak-kdf"))
        .stderr(predicate::str::contains("NEVER use in production"));

    // Verify the key was created with weak parameters
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--no-decrypt")
        .assert()
        .success()
        .stdout(predicate::str::contains("Security Level: LOW"))
        .stdout(predicate::str::contains("opslimit: 4194304")) // N=2^17
        .stdout(predicate::str::contains("memlimit: 134217728")) // 128 MB
        .stdout(predicate::str::contains("N=2^17"))
        .stdout(predicate::str::contains("Fallback (reduced parameters)"));
}

#[test]
#[cfg(debug_assertions)]
fn test_force_weak_kdf_requires_no_password_or_password_file() {
    // --force-weak-kdf should work non-interactively (requires --password-file or -W)
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("weak.key");
    let pk_path = temp_dir.path().join("weak.pub");

    // Without password file in non-interactive mode should fail
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot prompt for password"));
}

#[test]
#[cfg(debug_assertions)]
fn test_force_weak_kdf_with_unencrypted_key_ignored() {
    // --force-weak-kdf with -W (no password) should be ignored (no KDF to weaken)
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("unencrypted.key");
    let pk_path = temp_dir.path().join("unencrypted.pub");

    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("-W") // No password
        .arg("--force-weak-kdf")
        .assert()
        .success()
        .stderr(predicate::str::contains("--force-weak-kdf has no effect").not()); // Should not warn

    // Verify key is unencrypted
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("Security Level: NONE"))
        .stdout(predicate::str::contains("Encrypted: No"));
}

#[test]
#[cfg(debug_assertions)]
fn test_force_weak_kdf_creates_usable_key() {
    // Verify that weak keys created with --force-weak-kdf can actually sign and verify
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("weak.key");
    let pk_path = temp_dir.path().join("weak.pub");
    let message_path = temp_dir.path().join("message.txt");
    let password_file = temp_dir.path().join("password.txt");

    fs::write(&message_path, "Test message").unwrap();
    fs::write(&password_file, "testpass").unwrap();

    // Generate weak key
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Sign with weak key
    minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&message_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .stderr(predicate::str::contains("WEAK KEY DETECTED")); // Should warn when signing

    // Verify signature
    minisign_cmd()
        .arg("-V")
        .arg("-p")
        .arg(&pk_path)
        .arg("-m")
        .arg(&message_path)
        .assert()
        .success();
}

// TDD Tests for long argument names
// These tests verify that long argument names work identically to short names

#[test]
fn test_help_long_name() {
    minisign_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "A dead simple Rust tool to sign files",
        ));
}

#[test]
fn test_generate_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    minisign_cmd()
        .arg("--generate")
        .arg("-f")
        .arg("-W")
        .arg("--secretkey-path")
        .arg(&secret_key)
        .arg("--publickey-path")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret key was saved"));

    assert!(secret_key.exists());
    assert!(public_key.exists());
}

#[test]
fn test_sign_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("--sign")
        .arg("-W")
        .arg("--input")
        .arg(&message_file)
        .arg("--secretkey-path")
        .arg(&secret_key)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature written"));
}

#[test]
fn test_verify_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("--verify")
        .arg("--input")
        .arg(&message_file)
        .arg("--publickey-path")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[test]
fn test_recreate_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let recreated_key = temp_dir.path().join("recreated.pub");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("--recreate")
        .arg("--secretkey-path")
        .arg(&secret_key)
        .arg("--publickey-path")
        .arg(&recreated_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("Public key recreated"));
}

#[test]
fn test_change_password_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("--change-password")
        .arg("-W")
        .arg("--secretkey-path")
        .arg(&secret_key)
        .assert()
        .success();
}

#[test]
fn test_legacy_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("-S")
        .arg("--legacy")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success();
}

#[test]
fn test_quiet_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    let output = minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("--quiet")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(output.is_empty());
}

#[test]
fn test_trusted_comment_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("--trusted-comment")
        .arg("Custom comment")
        .assert()
        .success();
}

#[test]
fn test_untrusted_comment_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .arg("--untrusted-comment")
        .arg("Untrusted comment")
        .assert()
        .success();
}

#[test]
fn test_publickey_string_long_name() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success();

    let pubkey_contents = fs::read_to_string(&public_key).expect("Failed to read public key");
    let pubkey_base64 = pubkey_contents
        .lines()
        .nth(1)
        .expect("Public key should have second line");

    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("--publickey")
        .arg(pubkey_base64)
        .assert()
        .success();
}

#[test]
fn test_short_and_long_names_equivalent() {
    // Verify that short and long argument names produce identical behavior
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    fs::write(&message_file, b"Test message").expect("Failed to write message");

    // Generate with short names
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Sign with long names
    minisign_cmd()
        .arg("--sign")
        .arg("-W")
        .arg("--input")
        .arg(&message_file)
        .arg("--secretkey-path")
        .arg(&secret_key)
        .assert()
        .success();

    // Verify with mixed short and long names
    minisign_cmd()
        .arg("--verify")
        .arg("--input")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .stdout(predicate::str::contains("verified"));
}

#[test]
#[cfg_attr(
    not(unix),
    ignore = "atomic secret-key overwrite not yet implemented on Windows"
)]
fn test_force_long_option() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate initial keypair
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Generate again without force should fail
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    // Generate with --force (long option) should succeed
    minisign_cmd()
        .arg("-G")
        .arg("--force")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();
}

// Tests for long option aliases
#[test]
fn test_prehashed_long_option() {
    // Test that --prehashed works the same as -H
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Generate keys
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Create message
    fs::write(&message_file, b"test message").expect("Failed to write message file");

    // Sign with --prehashed (long option)
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("--prehashed")
        .arg("-s")
        .arg(&secret_key)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success();

    // Verify signature exists
    assert!(sig_file.exists());

    // Verify with --prehashed (long option)
    minisign_cmd()
        .arg("-V")
        .arg("--prehashed")
        .arg("-p")
        .arg(&public_key)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success();
}

#[test]
fn test_pretty_quiet_long_option() {
    // Test that --pretty-quiet works the same as -Q
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");

    // Generate keys
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Create and sign message
    fs::write(&message_file, b"test").expect("Failed to write message file");
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-m")
        .arg(&message_file)
        .arg("-t")
        .arg("trusted comment text")
        .assert()
        .success();

    // Verify with --pretty-quiet (long option)
    let output = minisign_cmd()
        .arg("-V")
        .arg("--pretty-quiet")
        .arg("-p")
        .arg(&public_key)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    assert!(stdout.contains("trusted comment text"));
    assert!(!stdout.contains("Signature and comment signature verified"));
}

#[test]
fn test_signature_long_option() {
    // Test that --signature works the same as -x
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let custom_sig = temp_dir.path().join("custom.sig");

    // Generate keys
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Create message
    fs::write(&message_file, b"test").expect("Failed to write message file");

    // Sign with --signature (long option) for custom signature path
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-m")
        .arg(&message_file)
        .arg("--signature")
        .arg(&custom_sig)
        .assert()
        .success();

    // Verify custom signature file exists
    assert!(custom_sig.exists());

    // Verify with --signature (long option)
    minisign_cmd()
        .arg("-V")
        .arg("-p")
        .arg(&public_key)
        .arg("-m")
        .arg(&message_file)
        .arg("--signature")
        .arg(&custom_sig)
        .assert()
        .success();
}

#[test]
fn test_no_password_long_option() {
    // Test that --no-password works the same as -W
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate keys with --no-password (long option)
    minisign_cmd()
        .arg("-G")
        .arg("--no-password")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Keys should exist
    assert!(secret_key.exists());
    assert!(public_key.exists());
}

#[test]
fn test_generate_displays_working_message() {
    // Test that key generation displays "Working..." during the slow scrypt operation
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    let output = minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&output);

    // Should display "Working..." message
    assert!(
        stderr.contains("Working..."),
        "Expected 'Working...' message during key generation but got:\n{stderr}"
    );

    // Keys should exist
    assert!(secret_key.exists());
    assert!(public_key.exists());
}

#[test]
fn test_generate_quiet_suppresses_working_message() {
    // Test that --quiet flag suppresses the working message
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    let output = minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-q")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&output);

    // Should NOT display "Working..." when quiet
    assert!(
        !stderr.contains("Working..."),
        "Expected no 'Working...' message with --quiet flag but got:\n{stderr}"
    );

    // Keys should exist
    assert!(secret_key.exists());
    assert!(public_key.exists());
}

#[test]
fn test_sign_displays_working_message() {
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let msg = temp_dir.path().join("msg.txt");
    fs::write(&msg, b"hello").unwrap();

    // Generate unencrypted key (fast, no scrypt)
    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    let stderr = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk)
        .arg("-W")
        .arg("-m")
        .arg(&msg)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        stderr.contains("Working..."),
        "Expected 'Working...' during sign but got:\n{stderr}"
    );
}

#[test]
fn test_sign_quiet_suppresses_working_message() {
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let msg = temp_dir.path().join("msg.txt");
    fs::write(&msg, b"hello").unwrap();

    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    let stderr = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk)
        .arg("-W")
        .arg("-q")
        .arg("-m")
        .arg(&msg)
        .assert()
        .success()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        !stderr.contains("Working..."),
        "Expected no 'Working...' with --quiet during sign but got:\n{stderr}"
    );
}

#[test]
fn cli_sign_multiple_files() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("msg1.txt");
    let file2 = temp_dir.path().join("msg2.txt");
    let file3 = temp_dir.path().join("msg3.txt");

    fs::write(&file1, b"Message 1").unwrap();
    fs::write(&file2, b"Message 2").unwrap();
    fs::write(&file3, b"Message 3").unwrap();

    // C-compatible syntax: -m first_file extra1 extra2
    minisign_cmd()
        .args([
            "-S",
            "-s",
            "tests/fixtures/keys/unencrypted.key",
            "-W",
            "-q",
            "-m",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            file3.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
    assert!(file3.with_extension("txt.minisig").exists());
}

#[cfg(feature = "parallel")]
#[test]
fn cli_sign_multiple_files_sequential() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("a.txt");
    let file2 = temp_dir.path().join("b.txt");

    fs::write(&file1, b"A").unwrap();
    fs::write(&file2, b"B").unwrap();

    minisign_cmd()
        .args([
            "-S",
            "-s",
            "tests/fixtures/keys/unencrypted.key",
            "--sequential",
            "-W",
            "-q",
            "-m",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(file1.with_extension("txt.minisig").exists());
    assert!(file2.with_extension("txt.minisig").exists());
}

// Legacy (-l) mode buffers each file fully (up to 1 GB). With the parallel feature, the
// implementation must force sequential execution to bound peak RSS to a single buffer. Verify
// that multi-file legacy signing completes correctly when the parallel feature is active.
#[cfg(feature = "parallel")]
#[test]
fn cli_sign_multiple_files_legacy_parallel_falls_back_to_sequential() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("a_legacy.txt");
    let file2 = temp_dir.path().join("b_legacy.txt");
    let file3 = temp_dir.path().join("c_legacy.txt");

    fs::write(&file1, b"legacy content A").unwrap();
    fs::write(&file2, b"legacy content B").unwrap();
    fs::write(&file3, b"legacy content C").unwrap();

    minisign_cmd()
        .args([
            "-S",
            "-l",
            "-s",
            "tests/fixtures/keys/unencrypted.key",
            "-W",
            "-q",
            "-m",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            file3.to_str().unwrap(),
        ])
        .assert()
        .success();

    for file in [&file1, &file2, &file3] {
        let sig_path = file.with_extension("txt.minisig");
        assert!(
            sig_path.exists(),
            "signature missing: {}",
            sig_path.display()
        );

        let sig_contents = fs::read_to_string(&sig_path).unwrap();
        let sig_box = minisign::signature::SignatureBox::from_file_contents(&sig_contents).unwrap();
        assert!(
            !sig_box.sig_struct().is_prehashed(),
            "expected legacy (non-prehashed) signature for {}",
            file.display()
        );
    }
}

#[test]
fn cli_sign_multiple_files_partial_failure_exit_code() {
    let temp_dir = TempDir::new().unwrap();

    let file1 = temp_dir.path().join("exists.txt");
    let file2 = temp_dir.path().join("missing.txt"); // Does not exist on disk

    fs::write(&file1, b"Exists").unwrap();

    minisign_cmd()
        .args([
            "-S",
            "-s",
            "tests/fixtures/keys/unencrypted.key",
            "-W",
            "-q",
            "-m",
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("failed to read"));

    // Valid file should still be signed despite the other failing
    assert!(file1.with_extension("txt.minisig").exists());
}

#[test]
fn cli_sign_single_file_backwards_compatible() {
    let temp_dir = TempDir::new().unwrap();
    let file = temp_dir.path().join("single.txt");
    fs::write(&file, b"Single").unwrap();

    let output = minisign_cmd()
        .args([
            "-S",
            "-s",
            "tests/fixtures/keys/unencrypted.key",
            "-m",
            file.to_str().unwrap(),
            "-W",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);

    // Should show key ID and signature path (original single-file output format)
    assert!(
        stdout.contains("Signing with key:"),
        "Expected 'Signing with key:' in output:\n{stdout}"
    );
    assert!(
        stdout.contains("Signature written to"),
        "Expected 'Signature written to' in output:\n{stdout}"
    );

    assert!(file.with_extension("txt.minisig").exists());
}

#[test]
fn test_verify_multiple_files() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = temp_dir.path().join("test.key");
    let public_key = temp_dir.path().join("test.pub");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-f")
        .arg("-s")
        .arg(&secret_key)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success();

    // Create and sign multiple files
    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");

    fs::write(&file1, b"Message 1").expect("write failed");
    fs::write(&file2, b"Message 2").expect("write failed");
    fs::write(&file3, b"Message 3").expect("write failed");

    // Sign all three files
    minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-m")
        .arg(&file1)
        .arg(&file2)
        .arg(&file3)
        .arg("-s")
        .arg(&secret_key)
        .assert()
        .success();

    // Verify all three files
    let output = minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&file1)
        .arg(&file2)
        .arg(&file3)
        .arg("-p")
        .arg(&public_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);

    // Should see key ID once at the top
    assert!(
        stdout.contains("Verifying with key:"),
        "Expected 'Verifying with key:' in output:\n{stdout}"
    );

    // Should see verification output for all three files (just pass/fail, not full details)
    assert!(
        stdout.contains("file1.txt"),
        "Expected file1.txt in output:\n{stdout}"
    );
    assert!(
        stdout.contains("file2.txt"),
        "Expected file2.txt in output:\n{stdout}"
    );
    assert!(
        stdout.contains("file3.txt"),
        "Expected file3.txt in output:\n{stdout}"
    );
    assert!(
        stdout.contains("Verified:"),
        "Expected 'Verified:' in output:\n{stdout}"
    );

    // Should show "Verifying with key:" exactly once (not repeated per file)
    let verifying_count = stdout.matches("Verifying with key:").count();
    assert_eq!(
        verifying_count, 1,
        "Expected 'Verifying with key:' shown once, found {verifying_count} times:\n{stdout}"
    );

    // Should show trusted comment for each file (can vary per signature)
    let trusted_comment_count = stdout.matches("Trusted comment:").count();
    assert_eq!(
        trusted_comment_count, 3,
        "Expected 3 trusted comments (one per file), found {trusted_comment_count}:\n{stdout}"
    );

    // Should NOT have "Key ID:" label per file (shown once at top)
    let key_id_label_count = stdout.matches("Key ID:").count();
    assert_eq!(
        key_id_label_count, 0,
        "Expected no per-file 'Key ID:' labels, found {key_id_label_count}:\n{stdout}"
    );
}

#[test]
fn test_cli_verify_h_flag_rejects_legacy() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let message_file = temp_dir.path().join("message.txt");
    let secret_key_file = temp_dir.path().join("test.key");
    let public_key_file = temp_dir.path().join("test.pub");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Create a message file
    fs::write(&message_file, b"Test message for -H flag").expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-W") // No password
        .arg("-s")
        .arg(&secret_key_file)
        .arg("-p")
        .arg(&public_key_file)
        .arg("-f")
        .assert()
        .success();

    // Sign in LEGACY mode (non-prehashed, using -l flag)
    minisign_cmd()
        .arg("-S")
        .arg("-l") // Legacy mode
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key_file)
        .arg("-x")
        .arg(&sig_file)
        .arg("-W") // No password
        .assert()
        .success();

    // Verify with -H flag should REJECT legacy signature
    minisign_cmd()
        .arg("-V")
        .arg("-H") // Force prehashed
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key_file)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains(
            "Legacy (non-prehashed) signature found",
        ));

    // Verify WITHOUT -H flag should succeed
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key_file)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();
}

#[test]
fn test_cli_verify_h_flag_accepts_prehashed() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let message_file = temp_dir.path().join("message.txt");
    let secret_key_file = temp_dir.path().join("test.key");
    let public_key_file = temp_dir.path().join("test.pub");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    // Create a message file
    fs::write(&message_file, b"Test message for -H flag").expect("Failed to write message");

    // Generate keypair
    minisign_cmd()
        .arg("-G")
        .arg("-W") // No password
        .arg("-s")
        .arg(&secret_key_file)
        .arg("-p")
        .arg(&public_key_file)
        .arg("-f")
        .assert()
        .success();

    // Sign in PREHASHED mode (default, no -l flag)
    minisign_cmd()
        .arg("-S")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&secret_key_file)
        .arg("-x")
        .arg(&sig_file)
        .arg("-W") // No password
        .assert()
        .success();

    // Verify with -H flag should ACCEPT prehashed signature
    minisign_cmd()
        .arg("-V")
        .arg("-H") // Force prehashed
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&public_key_file)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();
}

#[test]
#[cfg(debug_assertions)]
fn test_change_password_remove_with_w_flag() {
    // Test M9: -W flag with change operation should remove password
    // but still prompt for current password if key is encrypted
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password_file = temp_dir.path().join("password.txt");

    // Generate encrypted key with weak KDF
    fs::write(&password_file, "testpass").unwrap();
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Change to remove password using -K -W
    // This should prompt for current password via --password-file
    // and not prompt for new password (because of -W)
    minisign_cmd()
        .arg("-K") // Change password
        .arg("-W") // No new password (remove encryption)
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Verify the key is now unencrypted by inspecting it
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("-W") // Key should not need password now
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains("Security Level: NONE (UNENCRYPTED)"));
}

#[test]
#[cfg(debug_assertions)]
fn test_change_password_add_with_w_flag_on_unencrypted() {
    // Test that -W on an already unencrypted key during change is a no-op
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Generate unencrypted key
    minisign_cmd()
        .arg("-G")
        .arg("-W") // No password
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("-f")
        .assert()
        .success();

    // Try to "change" password with -W on already unencrypted key
    // Should succeed (no-op: unencrypted -> unencrypted)
    minisign_cmd()
        .arg("-K")
        .arg("-W")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();

    // Verify still unencrypted
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("-W")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains("Security Level: NONE (UNENCRYPTED)"));
}

#[test]
fn test_recreate_rejects_w_flag() {
    // Test M9: -W flag should not be accepted for recreate operation
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    // Generate unencrypted key
    minisign_cmd()
        .arg("-G")
        .arg("-W")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("-f")
        .assert()
        .success();

    // Try recreate with -W flag - should fail with clear error
    minisign_cmd()
        .arg("-R") // Recreate
        .arg("-W") // Should be rejected
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("-f")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no-password"))
        .stderr(predicate::str::contains("not supported"))
        .stderr(predicate::str::contains("recreate"));
}

// ============================================================================
// Credential Store Tests
// ============================================================================

// Removed is_keyring_available_for_cli_tests - tests now use feature flag instead

/// Helper to get `credential_id` from a secret key file
#[cfg(feature = "credential_store_tests")]
fn get_credential_id_from_file(sk_path: &std::path::Path) -> String {
    use minisign::keys::SeckeyStruct;
    let contents = fs::read_to_string(sk_path).expect("Failed to read secret key file");
    let seckey = SeckeyStruct::from_file_contents(&contents).expect("Failed to parse secret key");
    seckey.credential_id()
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_save_password_flag_with_generate() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "test_password_123";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate key with --save-password flag
    let gen_output = minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success()
        .get_output()
        .clone();

    eprintln!(
        "Generate stdout: {}",
        String::from_utf8_lossy(&gen_output.stdout)
    );
    eprintln!(
        "Generate stderr: {}",
        String::from_utf8_lossy(&gen_output.stderr)
    );

    // Extract credential_id for cleanup guard
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    // Extract key ID to verify output
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    eprintln!("Inspect output: {output_str}");

    let key_id = output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .expect("Key ID not found in inspect output");

    eprintln!("Extracted key_id: {key_id}");
    eprintln!("credential_id: {credential_id}");

    // Verify password was saved to credential store
    let saved_password = credential_store::get_password(&credential_id).unwrap();
    let is_some = saved_password.is_some();
    eprintln!("saved_password.is_some(): {is_some}");
    assert!(
        saved_password.is_some(),
        "Password should be saved in credential store for credential_id: {credential_id}"
    );
    assert_eq!(saved_password.as_ref().map(|s| s.as_str()), Some(password));

    // Guard will clean up credential store on drop
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_save_password_short_flag() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "short_flag_test";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Test short flag --sp
    minisign_cmd()
        .arg("-G")
        .arg("--sp")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Extract credential_id for cleanup guard
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    // Extract key ID to verify output
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    let _key_id = output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .expect("Key ID not found");

    // Verify password saved using credential_id
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved
    );

    // Guard will clean up on drop
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_standalone() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "forget_test_pwd";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate key and save password
    minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Extract key ID
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    let _key_id = output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .expect("Key ID not found");

    // Verify password is saved using credential_id
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved
    );

    // Forget password using standalone --forget-password
    minisign_cmd()
        .arg("-K")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();

    // Verify password was removed
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::NotSaved
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_short_flag() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "short_forget_test";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate and save
    minisign_cmd()
        .arg("-G")
        .arg("--sp")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Extract key ID
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    let key_id = output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .expect("Key ID not found");

    // Use short flag --fp to forget
    minisign_cmd()
        .arg("-K")
        .arg("--fp")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();

    // Verify removed
    assert_eq!(
        credential_store::has_password(key_id),
        credential_store::CredentialStatus::NotSaved
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_inspect_shows_password_saved_status() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "inspect_test_pwd";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate without saving password
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Inspect should show password not saved
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("Password saved: No") || output_str.contains("Password saved: no"),
        "Inspect should show password not saved"
    );

    // Extract key ID
    let _key_id = output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(str::trim)
        .expect("Key ID not found");

    // Save password manually using credential store with credential_id
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
    credential_store::save_password(&credential_id, password).unwrap();

    // Inspect should now show password saved
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("Password saved: Yes") || output_str.contains("Password saved: yes"),
        "Inspect should show password saved"
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_is_idempotent() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, "test").unwrap();

    // Generate key without saving password
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Forgetting a non-existent password should succeed (idempotent)
    minisign_cmd()
        .arg("-K")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();

    // Forgetting again should still succeed
    minisign_cmd()
        .arg("-K")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();
}

/// Helper: generate a key with --save-password, return the key ID string.
/// Leaves the password saved in the credential store for subsequent test steps.
#[cfg(feature = "credential_store_tests")]
fn generate_key_with_saved_password(
    sk_path: &std::path::Path,
    pk_path: &std::path::Path,
    password: &str,
) -> String {
    let password_file = sk_path.parent().unwrap().join("password.txt");
    fs::write(&password_file, password).unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(sk_path)
        .arg("-p")
        .arg(pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    // Extract key ID via inspect
    let output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_str = String::from_utf8_lossy(&output);
    output_str
        .lines()
        .find(|line| line.contains("Key ID:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .expect("Key ID not found in inspect output")
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_sign_uses_saved_password_from_credential_store() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    fs::write(&message_file, "test message for credential store signing").unwrap();

    let _key_id =
        generate_key_with_saved_password(&sk_path, &pk_path, "credential_store_sign_test");

    // Sign WITHOUT --password-file — must auto-retrieve from credential store.
    // If credential store retrieval fails, the command will block on stdin
    // (which assert_cmd closes), causing a failure.
    let sign_output = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&sign_output.stderr);
    assert!(
        stderr.contains("Using saved password from credential store"),
        "Expected credential store retrieval message in stderr, got: {stderr}"
    );

    // Verify the signature is valid
    minisign_cmd()
        .arg("-V")
        .arg("-p")
        .arg(&pk_path)
        .arg("-m")
        .arg(&message_file)
        .assert()
        .success();

    // Clean up using credential_id
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_sign_multiple_files_uses_saved_password() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");

    let file1 = temp_dir.path().join("file1.txt");
    let file2 = temp_dir.path().join("file2.txt");
    let file3 = temp_dir.path().join("file3.txt");
    fs::write(&file1, "content one").unwrap();
    fs::write(&file2, "content two").unwrap();
    fs::write(&file3, "content three").unwrap();

    let _key_id =
        generate_key_with_saved_password(&sk_path, &pk_path, "credential_store_multi_sign");

    // Sign multiple files without providing a password
    let sign_output = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&file1)
        .arg(&file2)
        .arg(&file3)
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&sign_output.stderr);
    assert!(
        stderr.contains("Using saved password from credential store"),
        "Expected credential store retrieval message in stderr, got: {stderr}"
    );

    // Verify all three signatures
    for file in [&file1, &file2, &file3] {
        minisign_cmd()
            .arg("-V")
            .arg("-p")
            .arg(&pk_path)
            .arg("-m")
            .arg(file)
            .assert()
            .success();
    }

    // Clean up using credential_id
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_save_password_on_sign_then_reuse() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "save_on_sign_test";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate key WITHOUT --save-password
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    let file1 = temp_dir.path().join("first.txt");
    let file2 = temp_dir.path().join("second.txt");
    fs::write(&file1, "first signing").unwrap();
    fs::write(&file2, "second signing").unwrap();

    // First sign WITH --password-file AND --save-password
    // This should save the password to the credential store
    let first_sign = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&file1)
        .arg("--password-file")
        .arg(&password_file)
        .arg("--save-password")
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&first_sign.stderr);
    assert!(
        stderr.contains("Password saved to OS credential store"),
        "Expected save confirmation in stderr, got: {stderr}"
    );

    // Second sign WITHOUT --password-file — should auto-retrieve
    let second_sign = minisign_cmd()
        .arg("-S")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&file2)
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr = String::from_utf8_lossy(&second_sign.stderr);
    assert!(
        stderr.contains("Using saved password from credential store"),
        "Expected credential store retrieval message in stderr, got: {stderr}"
    );

    // Verify both signatures
    for file in [&file1, &file2] {
        minisign_cmd()
            .arg("-V")
            .arg("-p")
            .arg(&pk_path)
            .arg("-m")
            .arg(file)
            .assert()
            .success();
    }

    // Clean up using credential_id
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_inspect_uses_saved_password_for_decryption() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password_file = temp_dir.path().join("password.txt");

    // Write password to file
    let password = "test-password-123";
    std::fs::write(&password_file, password).unwrap();

    // Generate key
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .assert()
        .success();

    // Get credential ID and save password to credential store
    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);
    credential_store::save_password(&credential_id, password).unwrap();

    // Inspect with decryption (should use saved password, not prompt)
    // This should show the actual key ID, not "[encrypted - password required]"
    let inspect_output = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success()
        .get_output()
        .clone();

    let stdout_str = String::from_utf8_lossy(&inspect_output.stdout);
    let stderr_str = String::from_utf8_lossy(&inspect_output.stderr);

    // Should show "Using saved password from credential store" in stderr
    assert!(
        stderr_str.contains("Using saved password from credential store"),
        "Inspect should use saved password. Stderr:\n{stderr_str}"
    );

    // Should NOT show "[encrypted - password required]"
    assert!(
        !stdout_str.contains("[encrypted - password required]"),
        "Key ID should be decrypted using saved password. Output:\n{stdout_str}"
    );

    // Should show actual key ID (16 hex characters)
    assert!(
        stdout_str.lines().any(|line| {
            line.contains("Key ID:") && line.chars().filter(char::is_ascii_hexdigit).count() >= 16
        }),
        "Should show decrypted key ID. Output:\n{stdout_str}"
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_inspect_save_password_flag() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "inspect_save_test";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate key WITHOUT --save-password
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    #[allow(unused_variables)]
    let credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    // Verify password not saved yet
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::NotSaved,
        "Password should not be saved yet"
    );

    // First inspect WITH --password-file AND --save-password
    // This should save the password to the credential store
    let first_inspect = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("--save-password")
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr_str = String::from_utf8_lossy(&first_inspect.stderr);
    eprintln!("First inspect stderr: {stderr_str}");

    // Should show "Password saved to OS credential store" in stderr
    assert!(
        stderr_str.contains("Password saved to OS credential store"),
        "Inspect should save password when --save-password is used. Stderr:\n{stderr_str}"
    );

    // Verify password is now saved
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved,
        "Password should be saved after --save-password flag"
    );

    // Second inspect WITHOUT --password-file
    // This should auto-retrieve the saved password from credential store
    let second_inspect = minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success()
        .get_output()
        .clone();

    let stderr_str2 = String::from_utf8_lossy(&second_inspect.stderr);
    eprintln!("Second inspect stderr: {stderr_str2}");

    // Should show "Using saved password from credential store"
    assert!(
        stderr_str2.contains("Using saved password from credential store"),
        "Second inspect should use saved password. Stderr:\n{stderr_str2}"
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_change_password_with_credential_store() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let message_file = temp_dir.path().join("message.txt");
    let sig_file = temp_dir.path().join("message.txt.minisig");

    let old_password = "old_password_test";
    let new_password = "new_password_test";
    let old_password_file = temp_dir.path().join("old_password.txt");
    let new_password_file = temp_dir.path().join("new_password.txt");

    fs::write(&old_password_file, old_password).unwrap();
    fs::write(&new_password_file, new_password).unwrap();
    fs::write(&message_file, "test message").unwrap();

    // Generate key with old password and save to credential store
    minisign_cmd()
        .arg("-G")
        .arg("-f")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&old_password_file)
        .arg("--save-password")
        .arg("--force-weak-kdf")
        .assert()
        .success();

    // Get old credential_id
    let old_credential_id = get_credential_id_from_file(&sk_path);

    // Verify old password is saved
    assert_eq!(
        credential_store::has_password(&old_credential_id),
        credential_store::CredentialStatus::Saved,
        "Old password should be saved in credential store"
    );

    // Change password with --save-password for new password
    // The old password will be retrieved from credential store
    // The new password will be read from --password-file
    minisign_cmd()
        .arg("-K")
        .arg("-s")
        .arg(&sk_path)
        .arg("--password-file")
        .arg(&new_password_file)
        .arg("--save-password")
        .arg("--force-weak-kdf")
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using saved password from credential store",
        ));

    // Get new credential_id (should be different after password change)
    let new_credential_id = get_credential_id_from_file(&sk_path);
    #[cfg(feature = "credential_store_tests")]
    let _guard = credential_guard::CredentialGuard::new(&new_credential_id);

    // Verify credential_id changed
    assert_ne!(
        old_credential_id, new_credential_id,
        "Credential ID should change after password change"
    );

    // Verify old credential_id no longer has a password
    assert_eq!(
        credential_store::has_password(&old_credential_id),
        credential_store::CredentialStatus::NotSaved,
        "Old credential should be removed from credential store"
    );

    // Verify new credential_id has the new password saved
    assert_eq!(
        credential_store::has_password(&new_credential_id),
        credential_store::CredentialStatus::Saved,
        "New password should be saved in credential store"
    );

    // Verify signing works without password prompt (uses saved password)
    // This confirms the saved password is correct and functional
    minisign_cmd()
        .arg("-S")
        .arg("-m")
        .arg(&message_file)
        .arg("-s")
        .arg(&sk_path)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using saved password from credential store",
        ));

    // Verify the signature is valid
    minisign_cmd()
        .arg("-V")
        .arg("-m")
        .arg(&message_file)
        .arg("-p")
        .arg(&pk_path)
        .arg("-x")
        .arg(&sig_file)
        .assert()
        .success();

    // Guard will clean up new credential on drop
}

// ============================================================================
// Short password warning (Recommendation 2 from 2026-02-17 security audit)
// ============================================================================

/// Password-file keygen does NOT emit the short-password warning (non-interactive path).
///
/// The warning is only relevant for interactive terminal input; suppressing it for
/// `--password-file` avoids noisy output in CI automation.
#[test]
#[cfg(debug_assertions)]
fn test_short_password_file_no_warning() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let pw_file = temp_dir.path().join("pw.txt");

    // Deliberately short password via file (CI automation scenario)
    fs::write(&pw_file, "abc").unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .arg("--password-file")
        .arg(&pw_file)
        .assert()
        .success()
        .stderr(predicate::str::contains("short password").not());
}

/// Password-file keygen with a long password also produces no short-password warning.
#[test]
#[cfg(debug_assertions)]
fn test_long_password_file_no_warning() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let pw_file = temp_dir.path().join("pw.txt");

    fs::write(&pw_file, "this-is-a-very-long-password").unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--force-weak-kdf")
        .arg("--password-file")
        .arg(&pw_file)
        .assert()
        .success()
        .stderr(predicate::str::contains("short password").not());
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_via_inspect() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let password = "inspect_forget_test_pwd";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    // Generate key and immediately save password to credential store
    minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    let credential_id = get_credential_id_from_file(&sk_path);
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved,
        "password should be saved before forget"
    );

    // Forget via -I rather than -K: this is the reported bug
    minisign_cmd()
        .arg("-I")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .assert()
        .success();

    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::NotSaved,
        "-I --forget-password must remove the saved password"
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_after_sign() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let msg_path = temp_dir.path().join("message.txt");
    let sig_path = temp_dir.path().join("message.txt.minisig");
    let password = "sign_forget_test_pwd";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();
    fs::write(&msg_path, "data to sign").unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    let credential_id = get_credential_id_from_file(&sk_path);
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved,
        "password should be saved before sign"
    );

    // Sign using stored password, then forget the credential
    minisign_cmd()
        .arg("-S")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-m")
        .arg(&msg_path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Password removed from credential store",
        ));

    // Signature must exist — the sign operation must have completed
    assert!(sig_path.exists(), "signature file must be written");

    // Credential must be gone
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::NotSaved,
        "-S --forget-password must remove the saved password after signing"
    );
}

#[test]
#[serial_test::serial]
#[cfg(feature = "credential_store_tests")]
fn test_forget_password_after_recreate() {
    use minisign::credential_store;

    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let recreated_pk_path = temp_dir.path().join("recreated.pub");
    let password = "recreate_forget_test_pwd";
    let password_file = temp_dir.path().join("password.txt");
    fs::write(&password_file, password).unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("--save-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&pk_path)
        .arg("--password-file")
        .arg(&password_file)
        .arg("-f")
        .assert()
        .success();

    let credential_id = get_credential_id_from_file(&sk_path);
    let _guard = credential_guard::CredentialGuard::new(&credential_id);

    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::Saved,
        "password should be saved before recreate"
    );

    // Recreate using stored password, then forget the credential
    minisign_cmd()
        .arg("-R")
        .arg("--forget-password")
        .arg("-s")
        .arg(&sk_path)
        .arg("-p")
        .arg(&recreated_pk_path)
        .arg("-f")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Password removed from credential store",
        ));

    // Public key must exist — the recreate operation must have completed
    assert!(
        recreated_pk_path.exists(),
        "recreated public key must be written"
    );

    // Credential must be gone
    assert_eq!(
        credential_store::has_password(&credential_id),
        credential_store::CredentialStatus::NotSaved,
        "-R --forget-password must remove the saved password after recreating"
    );
}

/// T9: Verify that `-o` causes the verified message content to be written to stdout.
///
/// This was previously untested. The flag is handled in main.rs: after successful
/// verification it reads the message file and writes it to stdout.
#[test]
fn test_verify_output_flag_writes_message_to_stdout() {
    let temp_dir = TempDir::new().unwrap();
    let sk_path = temp_dir.path().join("test.key");
    let pk_path = temp_dir.path().join("test.pub");
    let msg_path = temp_dir.path().join("message.txt");
    let sig_path = temp_dir.path().join("message.txt.minisig");

    let message_content = "hello from the output flag test\n";
    fs::write(&msg_path, message_content).unwrap();

    // Generate key
    minisign_cmd()
        .args([
            "-G",
            "-W",
            "-s",
            sk_path.to_str().unwrap(),
            "-p",
            pk_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Sign (-W because key is unencrypted; avoids interactive password prompt)
    minisign_cmd()
        .args([
            "-S",
            "-W",
            "-s",
            sk_path.to_str().unwrap(),
            "-x",
            sig_path.to_str().unwrap(),
            "-m",
            msg_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Verify with -o — message content should appear on stdout
    minisign_cmd()
        .args([
            "-V",
            "-o",
            "-p",
            pk_path.to_str().unwrap(),
            "-x",
            sig_path.to_str().unwrap(),
            "-m",
            msg_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(message_content.trim()));
}

#[test]
fn test_password_file_rejected_for_verify() {
    // --password-file is only meaningful for operations that decrypt a key.
    // Passing it with -V should produce a usage error rather than being silently ignored.
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let msg = temp_dir.path().join("msg.txt");
    let pw = temp_dir.path().join("pw.txt");
    fs::write(&msg, b"hello").unwrap();
    fs::write(&pw, b"irrelevant").unwrap();

    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    minisign_cmd()
        .args(["-S", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-m")
        .arg(&msg)
        .assert()
        .success();

    minisign_cmd()
        .arg("-V")
        .arg("-p")
        .arg(&pk)
        .arg("-m")
        .arg(&msg)
        .arg("--password-file")
        .arg(&pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("password-file"));
}

#[test]
fn test_password_file_directory_rejected() {
    // Passing a directory as --password-file should fail, not block on read
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    // Use a sub-directory (always a regular directory, never a file)
    let pw_dir = temp_dir.path().join("pw_dir");
    fs::create_dir(&pw_dir).unwrap();

    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    // Re-generate with a directory as the password file — should error
    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .arg("-f")
        .arg("--password-file")
        .arg(&pw_dir)
        .assert()
        .failure();
}

#[test]
fn test_password_file_oversized_rejected() {
    // A password file exceeding MAX_PASSWORD_FILE_BYTES must be rejected before any read.
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let pw_file = temp_dir.path().join("big_password.txt");

    // Generate an unencrypted key to sign with later
    minisign_cmd()
        .args(["-G", "-W", "-f"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    // 1025 bytes — one over MAX_PASSWORD_FILE_BYTES (1024)
    fs::write(&pw_file, vec![b'a'; 1025]).unwrap();

    minisign_cmd()
        .arg("-G")
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .arg("-f")
        .arg("--password-file")
        .arg(&pw_file)
        .assert()
        .failure()
        .stderr(predicate::str::contains("too large").or(predicate::str::contains("exceeds")));
}

#[test]
fn test_sign_batch_failure_summary_visible_in_quiet_mode() {
    // The failure summary (count + file list) must appear even with -q.
    // Per-file errors are always shown; the summary must be too.
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let good = temp_dir.path().join("good.txt");
    let missing = temp_dir.path().join("nonexistent.txt"); // intentionally absent

    fs::write(&good, b"hello").unwrap();

    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    let stderr = minisign_cmd()
        .arg("-S")
        .arg("-W")
        .arg("-q")
        .arg("-s")
        .arg(&sk)
        .arg("-m")
        .arg(&good)
        .arg(&missing)
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        stderr.contains("Summary:"),
        "failure summary must appear even with -q, got:\n{stderr}"
    );
    assert!(
        stderr.contains("nonexistent"),
        "failed file name must appear in summary, got:\n{stderr}"
    );
}

#[test]
fn test_verify_batch_failure_summary_visible_in_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let sk = temp_dir.path().join("test.key");
    let pk = temp_dir.path().join("test.pub");
    let good = temp_dir.path().join("good.txt");
    let bad = temp_dir.path().join("bad.txt");

    fs::write(&good, b"hello").unwrap();
    fs::write(&bad, b"world").unwrap();

    minisign_cmd()
        .args(["-G", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-p")
        .arg(&pk)
        .assert()
        .success();

    // Sign only the good file
    minisign_cmd()
        .args(["-S", "-W"])
        .arg("-s")
        .arg(&sk)
        .arg("-m")
        .arg(&good)
        .assert()
        .success();

    // Verify both — bad.txt has no signature, so it will fail
    let stderr = minisign_cmd()
        .arg("-V")
        .arg("-q")
        .arg("-p")
        .arg(&pk)
        .arg("-m")
        .arg(&good)
        .arg(&bad)
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();

    let stderr = String::from_utf8_lossy(&stderr);
    assert!(
        stderr.contains("Summary:"),
        "failure summary must appear even with -q, got:\n{stderr}"
    );
    assert!(
        stderr.contains("bad"),
        "failed file name must appear in summary, got:\n{stderr}"
    );
}
