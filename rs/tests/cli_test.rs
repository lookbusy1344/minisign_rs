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

    // Should show "minisign_rs" in the header, not just "minisign"
    assert!(
        stdout.contains("minisign_rs"),
        "Help output should contain 'minisign_rs' but got:\n{stdout}"
    );

    // The first line should start with "minisign_rs", not "minisign"
    let first_line = stdout.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("minisign_rs"),
        "First line should start with 'minisign_rs' but got: {first_line}"
    );
}

#[test]
fn test_generate_missing_arguments() {
    minisign_cmd().arg("-G").assert().failure();
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
        .failure();
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

    // Recreate public key (use -W since key is unencrypted)
    minisign_cmd()
        .arg("-R")
        .arg("-W")
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
        .failure();

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
fn test_version_includes_commit_hash() {
    let output = minisign_cmd()
        .arg("--version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let version_string = String::from_utf8_lossy(&output);

    // Version should contain the package version
    assert!(version_string.contains(env!("CARGO_PKG_VERSION")));

    // Version should contain a commit hash in parentheses (e.g., "0.12.0 (abc1234)")
    // Commit hash should be 7-8 hex characters
    assert!(
        version_string.contains('(') && version_string.contains(')'),
        "Version should contain parentheses with commit hash"
    );

    // Extract what's in the parentheses and verify it looks like a commit hash
    let start = version_string.find('(').expect("Should have opening paren");
    let end = version_string.find(')').expect("Should have closing paren");
    let in_parens = &version_string[start + 1..end];

    // Commit info can be:
    // - Pure hex hash: "abc1234" (7-8 chars)
    // - Git describe format: "v0.1.0-6-g347e92d" (when commits after tag)
    // - Tag only: "v0.1.0" (when exactly on tag)
    let is_valid_commit_info = if in_parens.contains('-') && in_parens.contains('g') {
        // Git describe format: extract hash after 'g' prefix
        in_parens
            .split('-')
            .next_back()
            .is_some_and(|hash| hash.starts_with('g') && hash.len() >= 8)
    } else if in_parens.starts_with('v') && in_parens.contains('.') {
        // Tag only format (e.g., "v0.2.0")
        true
    } else {
        // Pure hex hash (legacy format)
        in_parens.len() >= 7 && in_parens.chars().all(|c| c.is_ascii_hexdigit())
    };

    assert!(
        is_valid_commit_info,
        "Expected valid commit info in parentheses, got: {in_parens}"
    );
}

#[test]
fn test_help_shows_version() {
    minisign_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_inspect_production_key() {
    // Inspect the C-generated production-strength encrypted key
    minisign_cmd()
        .arg("-I")
        .arg("-s")
        .arg("tests/fixtures/keys/test.key")
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
        .failure();
}

#[test]
fn test_inspect_uses_default_secret_key_path() {
    // When no key file is specified, should use default secret key path
    // If the default key exists, inspect succeeds; otherwise it fails with a file error
    let result = minisign_cmd().arg("-I").assert();

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
fn test_force_weak_kdf_with_change_password() {
    // Test that --force-weak-kdf works with -C (change password)
    // Note: -C doesn't support --password-file for both old and new passwords,
    // so we test this via the ops module directly in unit tests instead
    // This test is a placeholder showing the intended behavior
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
        .arg("-W")
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
