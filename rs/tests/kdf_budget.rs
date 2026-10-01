//! SA-04: scrypt cost from an untrusted key file is capped at the production budget.
//!
//! Over-budget keys must be rejected before password retrieval, credential-store
//! access, or any scrypt allocation. Tests never run scrypt at over-budget cost.

use assert_cmd::Command;
use minisign::{
    Error,
    constants::{PRODUCTION_MEMLIMIT, PRODUCTION_OPSLIMIT},
    crypto::{
        LIBSODIUM_MEMLIMIT_MULTIPLIER, LIBSODIUM_OPSLIMIT_MULTIPLIER, MAX_KDF_MEMLIMIT, SCRYPT_R,
        check_kdf_budget, decode_kdf_params, generate_keypair, opslimit_memlimit_to_params,
    },
    keys::{
        SECKEY_KDF_MEMLIMIT_OFFSET, SECKEY_KDF_MEMLIMIT_SIZE, SECKEY_KDF_OPSLIMIT_OFFSET,
        SECKEY_KDF_OPSLIMIT_SIZE, SeckeyStruct,
    },
    ops::inspect::{InspectOptions, SecurityLevel, inspect, inspect_private_with_key},
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"synthetic password";
/// Cheap parameters used to create the key before its KDF fields are rewritten.
const CHEAP_LOG_N: u8 = 10;
/// One doubling above the production budget (N = 2^21).
const OVER_BUDGET_LOG_N: u8 = 21;
const OPSLIMIT_RANGE: std::ops::Range<usize> =
    SECKEY_KDF_OPSLIMIT_OFFSET..SECKEY_KDF_OPSLIMIT_OFFSET + SECKEY_KDF_OPSLIMIT_SIZE;
const MEMLIMIT_RANGE: std::ops::Range<usize> =
    SECKEY_KDF_MEMLIMIT_OFFSET..SECKEY_KDF_MEMLIMIT_OFFSET + SECKEY_KDF_MEMLIMIT_SIZE;

fn limits_for(log_n: u8) -> (u64, u64) {
    let n_r = (1u64 << log_n) * u64::from(SCRYPT_R);
    (
        LIBSODIUM_OPSLIMIT_MULTIPLIER * n_r,
        LIBSODIUM_MEMLIMIT_MULTIPLIER * n_r,
    )
}

/// An encrypted key whose stored KDF parameters request `log_n`.
fn key_with_log_n(log_n: u8) -> SeckeyStruct {
    let (secret_key, _pk, keynum) = generate_keypair().unwrap();
    let (opslimit, memlimit) = limits_for(CHEAP_LOG_N);
    let cheap = SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        PASSWORD,
        [7u8; 32],
        opslimit,
        memlimit,
        false,
    )
    .unwrap();

    let (opslimit, memlimit) = limits_for(log_n);
    let mut bytes = cheap.to_bytes();
    bytes[OPSLIMIT_RANGE].copy_from_slice(&opslimit.to_le_bytes());
    bytes[MEMLIMIT_RANGE].copy_from_slice(&memlimit.to_le_bytes());
    SeckeyStruct::from_bytes(&bytes).unwrap()
}

fn write_key(dir: &Path, seckey: &SeckeyStruct) -> PathBuf {
    let path = dir.join("over_budget.key");
    fs::write(&path, seckey.to_file_contents("synthetic").unwrap()).unwrap();
    path
}

fn is_over_budget(result: &minisign::Result<impl std::fmt::Debug>) -> bool {
    matches!(result, Err(Error::KdfOverBudget { .. }))
}

// ----------------------------------------------------------------------------
// Policy
// ----------------------------------------------------------------------------

#[test]
fn budget_is_the_production_memlimit() {
    assert_eq!(MAX_KDF_MEMLIMIT, PRODUCTION_MEMLIMIT);
}

#[test]
fn budget_accepts_maximum_and_rejects_one_step_above() {
    let (_, at_limit) = limits_for(20);
    let (_, above) = limits_for(OVER_BUDGET_LOG_N);
    assert_eq!(at_limit, MAX_KDF_MEMLIMIT);
    assert!(check_kdf_budget(at_limit).is_ok());
    assert!(is_over_budget(&check_kdf_budget(above)));
}

#[test]
fn structural_decoding_accepts_over_budget_parameters() {
    for log_n in [OVER_BUDGET_LOG_N, 25, 30] {
        let (opslimit, memlimit) = limits_for(log_n);
        let (decoded, r, _p) = decode_kdf_params(opslimit, memlimit).unwrap();
        assert_eq!((decoded, r), (log_n, SCRYPT_R));
        assert!(is_over_budget(&opslimit_memlimit_to_params(
            opslimit, memlimit
        )));
    }
}

// ----------------------------------------------------------------------------
// Library decryption boundary
// ----------------------------------------------------------------------------

#[test]
fn decrypt_rejects_over_budget_key_before_scrypt() {
    let seckey = key_with_log_n(OVER_BUDGET_LOG_N);
    assert!(is_over_budget(&seckey.decrypt(PASSWORD)));
    assert!(is_over_budget(&seckey.extract_key(Some(PASSWORD))));
    assert!(is_over_budget(&inspect_private_with_key(&seckey, PASSWORD)));
}

#[test]
fn decrypt_accepts_reduced_cost_key_within_budget() {
    let seckey = key_with_log_n(CHEAP_LOG_N);
    seckey.decrypt(PASSWORD).unwrap();
}

// ----------------------------------------------------------------------------
// Inspection
// ----------------------------------------------------------------------------

fn inspect_level(log_n: u8) -> Option<SecurityLevel> {
    let dir = TempDir::new().unwrap();
    let path = write_key(dir.path(), &key_with_log_n(log_n));
    let options = InspectOptions::new(&path).skip_credential_store_check();
    inspect(&options).unwrap().security_level()
}

#[test]
fn inspect_classifies_kdf_parameters() {
    assert_eq!(inspect_level(20), Some(SecurityLevel::High));
    assert_eq!(inspect_level(19), Some(SecurityLevel::Medium));
    assert_eq!(inspect_level(CHEAP_LOG_N), Some(SecurityLevel::Low));
    assert_eq!(
        inspect_level(OVER_BUDGET_LOG_N),
        Some(SecurityLevel::Unsupported)
    );
    assert_eq!(inspect_level(25), Some(SecurityLevel::Unsupported));
}

#[test]
fn production_constants_are_within_budget() {
    let (opslimit, memlimit) = limits_for(20);
    assert_eq!(
        (opslimit, memlimit),
        (PRODUCTION_OPSLIMIT, PRODUCTION_MEMLIMIT)
    );
}

// ----------------------------------------------------------------------------
// CLI: rejection precedes password retrieval
// ----------------------------------------------------------------------------

/// Run the CLI with a password file that does not exist. If password retrieval
/// ran first, the command would fail on the missing file instead.
fn run_with_missing_password_file(args: &[&str], key: &Path, dir: &Path) -> (bool, String) {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
        .args(args)
        .arg("-s")
        .arg(key)
        .arg("--password-file")
        .arg(dir.join("missing-password"))
        .current_dir(dir)
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn cli_decrypting_operations_reject_over_budget_key_before_password() {
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path(), &key_with_log_n(OVER_BUDGET_LOG_N));
    fs::write(dir.path().join("message.txt"), b"message").unwrap();

    for args in [
        &["-S", "-m", "message.txt"][..],
        &["-R", "-p", "out.pub"],
        &["-K"],
        &["-I"],
    ] {
        let (success, stderr) = run_with_missing_password_file(args, &key, dir.path());
        assert!(!success, "{args:?} must fail");
        assert!(
            stderr.contains("scrypt memory") && !stderr.contains("password file"),
            "{args:?} must fail on the KDF budget before reading a password; stderr: {stderr}"
        );
    }
    assert!(!dir.path().join("out.pub").exists());
    assert!(!dir.path().join("message.txt.minisig").exists());
}

#[test]
fn cli_inspect_without_decryption_reports_unsupported() {
    let dir = TempDir::new().unwrap();
    let key = write_key(dir.path(), &key_with_log_n(OVER_BUDGET_LOG_N));

    let output = Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
        .args(["-I", "--no-decrypt", "-s"])
        .arg(&key)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("UNSUPPORTED"), "stdout: {stdout}");
    assert!(!stdout.contains("HIGH"), "stdout: {stdout}");
}
