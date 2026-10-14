//! `-G` creates missing secret key directories as owner-only (`0700`), matching
//! C minisign's `basedir_create_useronly`.
#![cfg(unix)]

use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

const OWNER_ONLY: u32 = 0o700;
const PRE_EXISTING: u32 = 0o755;
const MODE_BITS: u32 = 0o777;

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & MODE_BITS
}

fn generate(secret_key: &Path, public_key: &Path) {
    Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
        .args(["-G", "-W", "-s"])
        .arg(secret_key)
        .arg("-p")
        .arg(public_key)
        .assert()
        .success();
}

#[test]
fn missing_secret_key_directories_are_owner_only() {
    let dir = TempDir::new().unwrap();
    let outer = dir.path().join("outer");
    let inner = outer.join("inner");

    generate(
        &inner.join("minisign.key"),
        &dir.path().join("minisign.pub"),
    );

    assert_eq!(mode(&outer), OWNER_ONLY, "outer directory");
    assert_eq!(mode(&inner), OWNER_ONLY, "inner directory");
}

#[test]
fn existing_secret_key_directory_keeps_its_mode() {
    let dir = TempDir::new().unwrap();
    let existing = dir.path().join("existing");
    fs::create_dir(&existing).unwrap();
    fs::set_permissions(&existing, fs::Permissions::from_mode(PRE_EXISTING)).unwrap();

    generate(
        &existing.join("minisign.key"),
        &dir.path().join("minisign.pub"),
    );

    assert_eq!(mode(&existing), PRE_EXISTING);
}
