//! `-K` reads the current password from `--password-file` and the new one from
//! `--new-password-file`. One file never supplies both.

use assert_cmd::Command;
use minisign::{crypto::generate_keypair, keys::SeckeyStruct};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const OLD_PASSWORD: &str = "synthetic old password";
const NEW_PASSWORD: &str = "synthetic new password";
const CHEAP_LOG_N: u64 = 10;
const SCRYPT_R: u64 = 8;
const USAGE_EXIT_CODE: i32 = 2;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

struct Fixture {
    dir: TempDir,
    key: PathBuf,
    old_password: PathBuf,
    new_password: PathBuf,
}

impl Fixture {
    fn encrypted() -> Self {
        let fx = Self::empty();
        let (secret_key, _pk, keynum) = generate_keypair().unwrap();
        let n_r = (1u64 << CHEAP_LOG_N) * SCRYPT_R;
        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            OLD_PASSWORD.as_bytes(),
            [7u8; 32],
            4 * n_r,
            128 * n_r,
            false,
        )
        .unwrap();
        fs::write(
            &fx.key,
            seckey
                .to_file_contents("minisign encrypted secret key")
                .unwrap(),
        )
        .unwrap();
        fx
    }

    fn unencrypted() -> Self {
        let fx = Self::empty();
        let (secret_key, _pk, keynum) = generate_keypair().unwrap();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
        fs::write(
            &fx.key,
            seckey.to_file_contents("minisign secret key").unwrap(),
        )
        .unwrap();
        fx
    }

    fn empty() -> Self {
        let dir = TempDir::new().unwrap();
        let key = dir.path().join("test.key");
        let old_password = dir.path().join("old.txt");
        let new_password = dir.path().join("new.txt");
        fs::write(&old_password, OLD_PASSWORD).unwrap();
        fs::write(&new_password, NEW_PASSWORD).unwrap();
        fs::write(dir.path().join("message.txt"), b"message").unwrap();
        Self {
            dir,
            key,
            old_password,
            new_password,
        }
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
            .current_dir(self.dir.path())
            .args(args)
            .arg("-s")
            .arg(&self.key)
            .timeout(COMMAND_TIMEOUT)
            .output()
            .unwrap()
    }

    fn change(&self, args: &[&OsStr]) -> std::process::Output {
        Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
            .current_dir(self.dir.path())
            .arg("-K")
            .arg("-s")
            .arg(&self.key)
            .args(args)
            .timeout(COMMAND_TIMEOUT)
            .output()
            .unwrap()
    }

    /// Sign with the password in `password_file`; returns (success, stderr).
    fn sign_with(&self, password_file: &Path) -> (bool, String) {
        let out = self.run(&[
            "-S",
            "-f",
            "-m",
            "message.txt",
            "--password-file",
            password_file.to_str().unwrap(),
        ]);
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
#[cfg(debug_assertions)]
fn change_uses_new_password_file_for_new_password() {
    let fx = Fixture::encrypted();
    let out = fx.change(&[
        "--force-weak-kdf".as_ref(),
        "--password-file".as_ref(),
        fx.old_password.as_os_str(),
        "--new-password-file".as_ref(),
        fx.new_password.as_os_str(),
    ]);
    assert!(out.status.success(), "change failed: {}", stderr(&out));

    let (ok, err) = fx.sign_with(&fx.new_password);
    assert!(ok, "new password must decrypt the key: {err}");
    let (ok, err) = fx.sign_with(&fx.old_password);
    assert!(!ok, "old password must no longer decrypt the key");
    assert!(err.contains("checksum"), "stderr: {err}");
}

#[test]
fn change_with_only_password_file_is_rejected_and_key_unchanged() {
    let fx = Fixture::encrypted();
    let before = fs::read(&fx.key).unwrap();

    let out = fx.change(&["--password-file".as_ref(), fx.old_password.as_os_str()]);

    assert_eq!(out.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--new-password-file"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(&fx.key).unwrap(),
        before,
        "key file must not change"
    );
}

#[test]
fn change_unencrypted_key_with_password_file_is_rejected() {
    let fx = Fixture::unencrypted();
    let before = fs::read(&fx.key).unwrap();

    let out = fx.change(&["--password-file".as_ref(), fx.old_password.as_os_str()]);

    assert_eq!(out.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("not encrypted"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(&fx.key).unwrap(),
        before,
        "key file must not change"
    );
}

#[test]
#[cfg(debug_assertions)]
fn change_unencrypted_key_with_new_password_file_encrypts_it() {
    let fx = Fixture::unencrypted();

    let out = fx.change(&[
        "--force-weak-kdf".as_ref(),
        "--new-password-file".as_ref(),
        fx.new_password.as_os_str(),
    ]);
    assert!(out.status.success(), "change failed: {}", stderr(&out));

    let (ok, err) = fx.sign_with(&fx.new_password);
    assert!(ok, "new password must decrypt the key: {err}");
    let (ok, _) = fx.sign_with(&fx.old_password);
    assert!(!ok, "a different password must not decrypt the key");
}

#[test]
fn new_password_file_with_no_password_is_rejected() {
    let fx = Fixture::encrypted();
    let before = fs::read(&fx.key).unwrap();

    let out = fx.change(&[
        "-W".as_ref(),
        "--password-file".as_ref(),
        fx.old_password.as_os_str(),
        "--new-password-file".as_ref(),
        fx.new_password.as_os_str(),
    ]);

    assert_eq!(out.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&out));
    assert_eq!(
        fs::read(&fx.key).unwrap(),
        before,
        "key file must not change"
    );
}

#[test]
fn new_password_file_outside_change_is_rejected() {
    let fx = Fixture::encrypted();
    let out = fx.run(&[
        "-S",
        "-m",
        "message.txt",
        "--password-file",
        fx.old_password.to_str().unwrap(),
        "--new-password-file",
        fx.new_password.to_str().unwrap(),
    ]);

    assert_eq!(out.status.code(), Some(USAGE_EXIT_CODE), "{}", stderr(&out));
    assert!(
        !fx.dir.path().join("message.txt.minisig").exists(),
        "no signature may be written"
    );
}
