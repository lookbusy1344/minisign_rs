//! End-to-end CLI integration tests using `assert_cmd`
//!
//! These tests verify the complete CLI behavior of the minisign binary.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a test command
fn minisign_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("minisign"))
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
        .stdout(predicate::str::contains("A dead simple tool to sign files"));
}

#[test]
fn test_version_flag() {
    minisign_cmd()
        .arg("-v")
        .assert()
        .success()
        .stdout(predicate::str::contains("minisign"));
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
