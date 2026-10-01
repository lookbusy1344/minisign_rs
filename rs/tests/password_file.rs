//! SA-06: `--password-file` must reject non-regular files without blocking.

use assert_cmd::Command;
use minisign::{crypto::generate_keypair, keys::SeckeyStruct};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

const PASSWORD: &str = "synthetic password";
const CHEAP_LOG_N: u64 = 10;
const SCRYPT_R: u64 = 8;
/// Upper bound for a command that must not block on its password source.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

struct Fixture {
    dir: TempDir,
    key: PathBuf,
    message: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (secret_key, _pk, keynum) = generate_keypair().unwrap();
        let n_r = (1u64 << CHEAP_LOG_N) * SCRYPT_R;
        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            PASSWORD.as_bytes(),
            [3u8; 32],
            4 * n_r,
            128 * n_r,
            false,
        )
        .unwrap();
        let key = dir.path().join("test.key");
        fs::write(
            &key,
            seckey
                .to_file_contents("minisign encrypted secret key")
                .unwrap(),
        )
        .unwrap();
        let message = dir.path().join("message.txt");
        fs::write(&message, b"message").unwrap();
        Self { dir, key, message }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Sign with `password_file`; returns (success, stderr).
    fn sign(&self, password_file: &Path) -> (bool, String) {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
            .args(["-S", "-f", "-s"])
            .arg(&self.key)
            .arg("-m")
            .arg(&self.message)
            .arg("--password-file")
            .arg(password_file)
            .timeout(COMMAND_TIMEOUT)
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

#[cfg(unix)]
fn assert_rejected_as_not_regular(fx: &Fixture, path: &Path) {
    let (success, stderr) = fx.sign(path);
    assert!(!success, "{} must be rejected", path.display());
    assert!(
        stderr.contains("not a regular file"),
        "{}: expected regular-file rejection, stderr: {stderr}",
        path.display()
    );
}

#[cfg(unix)]
#[test]
fn fifo_is_rejected_without_blocking() {
    let fx = Fixture::new();
    let fifo = fx.path("password.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success(), "mkfifo failed");

    assert_rejected_as_not_regular(&fx, &fifo);
}

#[cfg(unix)]
#[test]
fn unix_socket_is_rejected() {
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let socket = fx.path("password.sock");
    let _listener = UnixListener::bind(&socket).unwrap();

    let (success, _stderr) = fx.sign(&socket);
    assert!(!success, "socket must be rejected");
}

#[cfg(unix)]
#[test]
fn device_is_rejected() {
    let fx = Fixture::new();
    assert_rejected_as_not_regular(&fx, Path::new("/dev/zero"));
}

#[test]
fn directory_is_rejected() {
    let fx = Fixture::new();
    let dir = fx.path("password.d");
    fs::create_dir(&dir).unwrap();

    let (success, _stderr) = fx.sign(&dir);
    assert!(!success, "directory must be rejected");
}

#[cfg(unix)]
#[test]
fn symlink_to_regular_file_is_accepted() {
    let fx = Fixture::new();
    let target = fx.path("password.txt");
    fs::write(&target, PASSWORD).unwrap();
    let link = fx.path("password.link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let (success, stderr) = fx.sign(&link);
    assert!(
        success,
        "symlinked password file must work; stderr: {stderr}"
    );
}

#[test]
fn empty_file_is_read_as_empty_password() {
    let fx = Fixture::new();
    let empty = fx.path("empty.txt");
    fs::write(&empty, b"").unwrap();

    let (success, stderr) = fx.sign(&empty);
    assert!(!success, "empty password must not decrypt the key");
    assert!(stderr.contains("checksum"), "stderr: {stderr}");
}

#[test]
fn maximum_length_file_is_read() {
    use minisign::ops::file_utils::MAX_PASSWORD_FILE_BYTES;

    let fx = Fixture::new();
    let limit = usize::try_from(MAX_PASSWORD_FILE_BYTES).unwrap();
    let at_limit = fx.path("max.txt");
    fs::write(&at_limit, "a".repeat(limit)).unwrap();
    let over_limit = fx.path("over.txt");
    fs::write(&over_limit, "a".repeat(limit + 1)).unwrap();

    let (_, stderr) = fx.sign(&at_limit);
    assert!(stderr.contains("checksum"), "at limit is read: {stderr}");
    let (success, stderr) = fx.sign(&over_limit);
    assert!(!success);
    assert!(stderr.contains("too large"), "over limit: {stderr}");
}
