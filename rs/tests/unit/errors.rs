use minisign::errors::*;
use std::io;
use std::path::PathBuf;

#[test]
fn test_error_display() {
    let err = Error::VerificationFailed;
    assert_eq!(err.to_string(), "signature verification failed");

    let err = Error::FileNotFound(PathBuf::from("/test/path"));
    assert!(err.to_string().contains("/test/path"));

    let err = Error::KeyMismatch {
        sig_keynum: "ABCD1234".into(),
        pub_keynum: "EFGH5678".into(),
    };
    assert!(err.to_string().contains("ABCD1234"));
    assert!(err.to_string().contains("EFGH5678"));
}

#[test]
fn test_error_constructors() {
    let path = PathBuf::from("/test");
    let io_err = io::Error::new(io::ErrorKind::NotFound, "test");

    let err = Error::file_read(&path, io_err);
    assert!(matches!(err, Error::FileRead { .. }));

    let err = Error::other("test message");
    assert!(matches!(err, Error::Other(_)));
}

#[test]
fn test_base64_error_conversion() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    // Test that base64::DecodeError converts to our Error type
    let result: Result<Vec<u8>> = STANDARD.decode("!invalid base64!").map_err(Error::from);

    assert!(matches!(result, Err(Error::InvalidBase64(_))));
}
