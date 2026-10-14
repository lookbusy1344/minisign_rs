//! `-V` without `-p`/`-P` reads `./minisign.pub`, as C minisign does. That file
//! may come from the same untrusted source as the message, so the fallback is
//! announced on stderr.

use assert_cmd::Command;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const WARNING: &str = "Warning: no public key given (-p or -P); using ./minisign.pub";

fn cmd(dir: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"));
    cmd.current_dir(dir);
    cmd
}

/// A directory holding `minisign.pub`, `message.txt` and its signature.
fn signed_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("message.txt"), b"message").unwrap();
    cmd(dir.path())
        .args(["-G", "-W", "-s", "minisign.key", "-p", "minisign.pub"])
        .assert()
        .success();
    cmd(dir.path())
        .args(["-S", "-W", "-s", "minisign.key", "-m", "message.txt"])
        .assert()
        .success();
    dir
}

fn verify_stderr(dir: &Path, extra: &[&str]) -> String {
    let out = cmd(dir)
        .args(["-V", "-m", "message.txt"])
        .args(extra)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "verify failed: {stderr}");
    stderr
}

#[test]
fn default_public_key_fallback_warns() {
    let dir = signed_dir();
    assert!(verify_stderr(dir.path(), &[]).contains(WARNING));
}

#[test]
fn default_public_key_fallback_warns_with_pretty_quiet() {
    let dir = signed_dir();
    assert!(verify_stderr(dir.path(), &["-Q"]).contains(WARNING));
}

#[test]
fn explicit_public_key_file_does_not_warn() {
    let dir = signed_dir();
    assert!(!verify_stderr(dir.path(), &["-p", "minisign.pub"]).contains(WARNING));
}

#[test]
fn explicit_public_key_string_does_not_warn() {
    let dir = signed_dir();
    let contents = fs::read_to_string(dir.path().join("minisign.pub")).unwrap();
    let base64 = contents.lines().nth(1).unwrap();
    assert!(!verify_stderr(dir.path(), &["-P", base64]).contains(WARNING));
}

#[test]
fn quiet_suppresses_the_warning() {
    let dir = signed_dir();
    assert!(!verify_stderr(dir.path(), &["-q"]).contains(WARNING));
}
