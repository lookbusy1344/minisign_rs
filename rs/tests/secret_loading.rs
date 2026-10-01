//! SA-05: secret-key files are read and decoded into guarded buffers.
//!
//! These tests pin the guarded reader and decoder types and the parsing and error
//! behaviour of every secret-key loading path. They prove rejection and ownership,
//! not erasure: wiping is guaranteed by the `Zeroizing` types, not inspected here.

use minisign::{
    Error,
    crypto::generate_keypair,
    formats::decode_base64_into,
    keys::{SECKEY_STRUCT_SIZE, SeckeyStruct},
    ops::{
        file_utils::{MAX_KEY_FILE_BYTES, load_secret_key, read_secret_file_bounded},
        inspect::{InspectOptions, KeyType, inspect, inspect_private},
        recreate::{RecreateOptions, recreate},
        sign::{SignOptions, sign},
    },
};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zeroize::Zeroizing;

const PASSWORD: &[u8] = b"synthetic password";
const CHEAP_LOG_N: u64 = 10;
const SCRYPT_R: u64 = 8;

fn encrypted_key() -> SeckeyStruct {
    let (secret_key, _pk, keynum) = generate_keypair().unwrap();
    let n_r = (1u64 << CHEAP_LOG_N) * SCRYPT_R;
    SeckeyStruct::new_encrypted(
        keynum,
        &secret_key,
        PASSWORD,
        [9u8; 32],
        4 * n_r,
        128 * n_r,
        false,
    )
    .unwrap()
}

fn unencrypted_key() -> SeckeyStruct {
    let (secret_key, _pk, keynum) = generate_keypair().unwrap();
    SeckeyStruct::new_unencrypted(keynum, &secret_key)
}

fn write(dir: &Path, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path
}

fn data_line(seckey: &SeckeyStruct) -> String {
    seckey
        .to_file_contents("x")
        .unwrap()
        .lines()
        .nth(1)
        .unwrap()
        .to_string()
}

// ----------------------------------------------------------------------------
// Guarded reader and decoder
// ----------------------------------------------------------------------------

#[test]
fn secret_reader_returns_guarded_bytes() {
    let dir = TempDir::new().unwrap();
    let contents = unencrypted_key().to_file_contents("guarded").unwrap();
    let path = write(dir.path(), "k", contents.as_bytes());

    let bytes: Zeroizing<Vec<u8>> = read_secret_file_bounded(&path, MAX_KEY_FILE_BYTES).unwrap();

    assert_eq!(&bytes[..], contents.as_bytes());
}

#[test]
fn secret_reader_enforces_size_limit() {
    let dir = TempDir::new().unwrap();
    let limit = usize::try_from(MAX_KEY_FILE_BYTES).unwrap();
    let at_limit = write(dir.path(), "at", vec![b'a'; limit]);
    let over_limit = write(dir.path(), "over", vec![b'a'; limit + 1]);

    assert_eq!(
        read_secret_file_bounded(&at_limit, MAX_KEY_FILE_BYTES)
            .unwrap()
            .len(),
        limit
    );
    let err = read_secret_file_bounded(&over_limit, MAX_KEY_FILE_BYTES).unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

#[test]
fn guarded_decoder_fills_exact_size_buffer() {
    let seckey = unencrypted_key();
    let mut out = Zeroizing::new([0u8; SECKEY_STRUCT_SIZE]);

    let len = decode_base64_into(data_line(&seckey), &mut *out).unwrap();

    assert_eq!(len, SECKEY_STRUCT_SIZE);
    assert_eq!(*out, seckey.to_bytes());
}

#[test]
fn guarded_decoder_rejects_oversized_input() {
    let mut out = [0u8; SECKEY_STRUCT_SIZE];
    let oversized = minisign::formats::encode_base64([0u8; SECKEY_STRUCT_SIZE + 1]);
    assert!(decode_base64_into(oversized, &mut out).is_err());
}

// ----------------------------------------------------------------------------
// Parsing and error behaviour across loading paths
// ----------------------------------------------------------------------------

#[test]
fn wrong_password_fails_checksum() {
    assert!(matches!(
        encrypted_key().decrypt(b"wrong password"),
        Err(Error::ChecksumFailed)
    ));
}

#[test]
fn invalid_utf8_is_rejected_by_every_loader() {
    let dir = TempDir::new().unwrap();
    let mut contents = b"untrusted comment: minisign secret key \xff\n".to_vec();
    contents.extend_from_slice(data_line(&unencrypted_key()).as_bytes());
    contents.push(b'\n');
    let path = write(dir.path(), "utf8.key", &contents);

    assert!(matches!(
        load_secret_key(&path),
        Err(Error::InvalidUtf8 { .. })
    ));
    for err in [
        inspect(&InspectOptions::new(&path).skip_credential_store_check()).unwrap_err(),
        inspect_private(&path, PASSWORD).unwrap_err(),
    ] {
        assert!(err.to_string().contains("UTF-8"), "{err}");
    }
}

#[test]
fn malformed_data_line_is_rejected_by_every_loader() {
    let dir = TempDir::new().unwrap();
    let wrong_length = minisign::formats::encode_base64([0u8; SECKEY_STRUCT_SIZE + 1]);
    let short = minisign::formats::encode_base64([0u8; SECKEY_STRUCT_SIZE - 1]);

    for (name, line) in [
        ("bad_b64.key", "not*base64".to_string()),
        ("long.key", wrong_length),
        ("short.key", short),
    ] {
        let path = write(
            dir.path(),
            name,
            format!("untrusted comment: minisign secret key\n{line}\n"),
        );
        assert!(
            matches!(
                load_secret_key(&path),
                Err(Error::InvalidBase64(_) | Error::InvalidSecretKey(_))
            ),
            "{name}: {:?}",
            load_secret_key(&path).err()
        );
        assert!(inspect(&InspectOptions::new(&path).skip_credential_store_check()).is_err());
        assert!(inspect_private(&path, PASSWORD).is_err());
    }
}

#[test]
fn nonstandard_comment_secret_key_loads_through_every_path() {
    let dir = TempDir::new().unwrap();
    let seckey = encrypted_key();
    let path = write(
        dir.path(),
        "odd.key",
        format!("untrusted comment: my laptop\n{}\n", data_line(&seckey)),
    );
    let expected = seckey.decrypt(PASSWORD).unwrap().1.to_key_id();

    assert!(load_secret_key(&path).unwrap().is_encrypted());
    let inspected = inspect(&InspectOptions::new(&path).skip_credential_store_check()).unwrap();
    assert_eq!(inspected.key_type(), KeyType::SecretEncrypted);
    assert_eq!(inspect_private(&path, PASSWORD).unwrap().key_id(), expected);

    let message = write(dir.path(), "msg.txt", b"message");
    let sign_options = SignOptions::builder(&path, &message).quiet(true).build();
    sign(&sign_options, Some(PASSWORD)).unwrap();

    let pubkey = dir.path().join("odd.pub");
    recreate(
        &RecreateOptions::new(&path, &pubkey, None, false),
        Some(PASSWORD),
    )
    .unwrap();
    assert!(pubkey.exists());
}

#[test]
fn change_password_round_trips_through_guarded_loader() {
    use minisign::ops::change::{ChangeOptions, change_with_log_n};

    let dir = TempDir::new().unwrap();
    let seckey = encrypted_key();
    let expected = seckey.decrypt(PASSWORD).unwrap().1.to_key_id();
    let path = write(
        dir.path(),
        "k",
        seckey
            .to_file_contents("minisign encrypted secret key")
            .unwrap(),
    );

    let options = ChangeOptions::builder(&path).build();
    change_with_log_n(&options, Some(PASSWORD), Some(b"new password"), 10).unwrap();

    let reloaded = load_secret_key(&path).unwrap();
    assert_eq!(
        reloaded.decrypt(b"new password").unwrap().1.to_key_id(),
        expected
    );
}
