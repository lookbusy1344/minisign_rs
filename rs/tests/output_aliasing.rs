//! SA-03: output files must never overwrite an input through an alias.
//!
//! Force-writes replace the destination directory entry with a staged file. A
//! distinct hard-link name for an input is therefore safe to replace: the input
//! name keeps its inode and bytes. An output path that resolves to an input path,
//! or an output that is a symlink, is rejected before any write.
//!
//! Symlink cases and inode checks are Unix-only; the rest also run on Windows.

use minisign::{
    Error,
    keys::PubkeyStruct,
    ops::{
        generate::{GenerateOptions, generate},
        recreate::{RecreateOptions, recreate},
        sign::{SignOptions, sign},
    },
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Fixture {
    dir: TempDir,
    secret_key: PathBuf,
    public_key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let secret_key = dir.path().join("test.key");
        let public_key = dir.path().join("test.pub");
        let options = GenerateOptions::builder(&secret_key, &public_key)
            .no_password(true)
            .build();
        generate(&options, None).unwrap();
        Self {
            dir,
            secret_key,
            public_key,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn message(&self) -> PathBuf {
        let path = self.path("message.txt");
        fs::write(&path, b"message content").unwrap();
        path
    }

    fn recreate_to(&self, output: &Path) -> minisign::Result<()> {
        let options = RecreateOptions::new(&self.secret_key, output, None, true);
        recreate(&options, None).map(drop)
    }

    fn sign_to(&self, message: &Path, output: &Path) -> minisign::Result<()> {
        let options = SignOptions::builder(&self.secret_key, message)
            .signature_file(output)
            .force(true)
            .quiet(true)
            .build();
        sign(&options, None).map(drop)
    }

    fn staged_files(&self) -> Vec<PathBuf> {
        fs::read_dir(self.dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext == "tmp" || ext == "bak")
            })
            .collect()
    }
}

fn assert_alias_rejected(result: &minisign::Result<()>) {
    assert!(
        matches!(
            result,
            Err(Error::OutputAlias { .. } | Error::OutputIsSymlink(_))
        ),
        "expected alias rejection, got {result:?}"
    );
}

// ----------------------------------------------------------------------------
// recreate
// ----------------------------------------------------------------------------

#[test]
fn recreate_force_through_hard_link_preserves_secret_key() {
    let fx = Fixture::new();
    let original = fs::read(&fx.secret_key).unwrap();
    let alias = fx.path("alias.pub");
    fs::hard_link(&fx.secret_key, &alias).unwrap();

    fx.recreate_to(&alias).unwrap();

    assert_eq!(fs::read(&fx.secret_key).unwrap(), original);
    let written = fs::read_to_string(&alias).unwrap();
    PubkeyStruct::from_file_contents(&written).unwrap();
    #[cfg(unix)]
    assert_ne!(
        fs::metadata(&alias).unwrap().ino(),
        fs::metadata(&fx.secret_key).unwrap().ino(),
        "output name must be detached from the secret key inode"
    );
}

#[test]
fn recreate_force_rejects_output_equal_to_secret_key() {
    let fx = Fixture::new();
    let original = fs::read(&fx.secret_key).unwrap();
    let relative_alias = fx.dir.path().join(".").join("test.key");
    let dotdot_alias = fx.path("sub").join("..").join("test.key");
    fs::create_dir(fx.path("sub")).unwrap();

    for output in [fx.secret_key.clone(), relative_alias, dotdot_alias] {
        assert_alias_rejected(&fx.recreate_to(&output));
        assert_eq!(fs::read(&fx.secret_key).unwrap(), original, "{output:?}");
    }
}

#[cfg(unix)]
#[test]
fn recreate_force_rejects_output_symlink_to_secret_key() {
    let fx = Fixture::new();
    let original = fs::read(&fx.secret_key).unwrap();
    let link = fx.path("link.pub");
    symlink(&fx.secret_key, &link).unwrap();

    assert_alias_rejected(&fx.recreate_to(&link));
    assert_eq!(fs::read(&fx.secret_key).unwrap(), original);
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
}

#[test]
fn recreate_force_replaces_existing_public_key() {
    let fx = Fixture::new();
    fs::write(&fx.public_key, "stale").unwrap();

    fx.recreate_to(&fx.public_key).unwrap();

    PubkeyStruct::from_file_contents(&fs::read_to_string(&fx.public_key).unwrap()).unwrap();
    assert!(fx.staged_files().is_empty());
}

// ----------------------------------------------------------------------------
// sign
// ----------------------------------------------------------------------------

#[test]
fn sign_force_rejects_output_equal_to_inputs() {
    let fx = Fixture::new();
    let message = fx.message();
    let secret_before = fs::read(&fx.secret_key).unwrap();
    let message_before = fs::read(&message).unwrap();

    for output in [
        message.clone(),
        fx.secret_key.clone(),
        fx.path("sub").join("..").join("message.txt"),
        fx.dir.path().join(".").join("test.key"),
    ] {
        fs::create_dir_all(fx.path("sub")).unwrap();
        assert_alias_rejected(&fx.sign_to(&message, &output));
        assert_eq!(fs::read(&fx.secret_key).unwrap(), secret_before);
        assert_eq!(fs::read(&message).unwrap(), message_before);
    }
}

#[cfg(unix)]
#[test]
fn sign_force_rejects_output_symlinks_to_inputs() {
    let fx = Fixture::new();
    let message = fx.message();
    let secret_before = fs::read(&fx.secret_key).unwrap();
    let message_before = fs::read(&message).unwrap();

    for (name, target) in [("msg.link", &message), ("key.link", &fx.secret_key)] {
        let link = fx.path(name);
        symlink(target, &link).unwrap();
        assert_alias_rejected(&fx.sign_to(&message, &link));
    }
    assert_eq!(fs::read(&fx.secret_key).unwrap(), secret_before);
    assert_eq!(fs::read(&message).unwrap(), message_before);
}

#[test]
fn sign_force_through_hard_links_preserves_inputs() {
    let fx = Fixture::new();
    let message = fx.message();
    let secret_before = fs::read(&fx.secret_key).unwrap();
    let message_before = fs::read(&message).unwrap();

    for (name, target) in [("msg.hard", &message), ("key.hard", &fx.secret_key)] {
        let alias = fx.path(name);
        fs::hard_link(target, &alias).unwrap();
        fx.sign_to(&message, &alias).unwrap();
        assert!(
            fs::read_to_string(&alias)
                .unwrap()
                .starts_with("untrusted comment:")
        );
    }
    assert_eq!(fs::read(&fx.secret_key).unwrap(), secret_before);
    assert_eq!(fs::read(&message).unwrap(), message_before);
}

#[test]
fn batch_sign_rejects_outputs_aliasing_any_input_before_writing() {
    use minisign::ops::sign::sign_multiple_files;

    for sequential in [true, false] {
        let fx = Fixture::new();
        let first = fx.message();
        let second = fx.path("message.txt.minisig");
        fs::write(&second, b"second input").unwrap();
        let options = SignOptions::builder(&fx.secret_key, &first)
            .force(true)
            .quiet(true)
            .build();

        let result =
            sign_multiple_files(&[first.clone(), second.clone()], &options, None, sequential);

        assert!(
            matches!(result, Err(Error::OutputAlias { .. })),
            "{result:?}"
        );
        assert_eq!(fs::read(&first).unwrap(), b"message content");
        assert_eq!(fs::read(&second).unwrap(), b"second input");
        assert!(!fx.path("message.txt.minisig.minisig").exists());
        assert!(fx.staged_files().is_empty());
    }
}

#[test]
fn cli_batch_sign_rejects_output_alias_before_writing() {
    let fx = Fixture::new();
    let first = fx.message();
    let second = fx.path("message.txt.minisig");
    fs::write(&second, b"second input").unwrap();

    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("minisign_rs"))
        .args(["-S", "-W", "--force", "-q", "-s"])
        .arg(&fx.secret_key)
        .arg("-m")
        .arg(&first)
        .arg(&second)
        .assert()
        .failure()
        .stderr(predicates::str::contains("names the same file"));

    assert_eq!(fs::read(&first).unwrap(), b"message content");
    assert_eq!(fs::read(&second).unwrap(), b"second input");
    assert!(!fx.path("message.txt.minisig.minisig").exists());
}

#[test]
fn sign_force_failure_before_replacement_preserves_destination() {
    let fx = Fixture::new();
    let message = fx.message();
    // A directory cannot be replaced by a regular file, so the commit fails.
    let output = fx.path("occupied");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("keep"), b"keep").unwrap();

    let result = fx.sign_to(&message, &output);

    assert!(result.is_err(), "expected failure, got {result:?}");
    assert_eq!(fs::read(output.join("keep")).unwrap(), b"keep");
    assert!(
        fx.staged_files().is_empty(),
        "staged files must be removed: {:?}",
        fx.staged_files()
    );
}

// ----------------------------------------------------------------------------
// generate
// ----------------------------------------------------------------------------

fn generate_pair(secret_key: &Path, public_key: &Path, force: bool) -> minisign::Result<()> {
    let options = GenerateOptions::builder(secret_key, public_key)
        .no_password(true)
        .force(force)
        .build();
    generate(&options, None).map(drop)
}

#[test]
fn generate_rejects_same_destination_for_both_outputs() {
    let dir = TempDir::new().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();

    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases = vec![
        (real.join("k"), real.join("k")),
        (real.join("k"), real.join(".").join("k")),
        (real.join("k"), real.join("missing").join("..").join("k")),
        (
            dir.path().join("new").join("k"),
            dir.path().join("new").join(".").join("k"),
        ),
    ];
    #[cfg(unix)]
    {
        let linked = dir.path().join("linked");
        symlink(&real, &linked).unwrap();
        cases.push((real.join("k"), linked.join("k")));
    }

    for force in [false, true] {
        for (secret_key, public_key) in &cases {
            let result = generate_pair(secret_key, public_key, force);
            assert!(
                matches!(result, Err(Error::OutputAlias { .. })),
                "{secret_key:?} vs {public_key:?} (force={force}): got {result:?}"
            );
            assert!(!real.join("k").exists());
        }
    }
    assert!(
        !dir.path().join("new").exists(),
        "rejection must precede directory creation"
    );
}

// Windows refuses --force over an existing secret key.
#[cfg(unix)]
#[test]
fn generate_force_over_hard_linked_outputs_writes_distinct_files() {
    let dir = TempDir::new().unwrap();
    let secret_key = dir.path().join("test.key");
    let public_key = dir.path().join("test.pub");
    fs::write(&secret_key, b"old").unwrap();
    fs::hard_link(&secret_key, &public_key).unwrap();

    generate_pair(&secret_key, &public_key, true).unwrap();

    let secret = fs::read_to_string(&secret_key).unwrap();
    let public = fs::read_to_string(&public_key).unwrap();
    assert!(secret.starts_with("untrusted comment: minisign secret key"));
    PubkeyStruct::from_file_contents(&public).unwrap();
    assert_ne!(
        fs::metadata(&secret_key).unwrap().ino(),
        fs::metadata(&public_key).unwrap().ino()
    );
}
