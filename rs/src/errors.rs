//! Error types for minisign operations

use std::io;
use std::path::PathBuf;
use thiserror::Error;

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Minisign error types
#[derive(Error, Debug)]
pub enum Error {
    // I/O errors
    #[error("failed to read file {path:?}: {source}")]
    FileRead { path: PathBuf, source: io::Error },

    #[error("failed to write file {path:?}: {source}")]
    FileWrite { path: PathBuf, source: io::Error },

    #[error("file not found: {0:?}")]
    FileNotFound(PathBuf),

    #[error("file already exists: {0:?}")]
    FileExists(PathBuf),

    // Parsing errors
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    #[error("invalid file format: expected {expected}, found {found}")]
    InvalidFileFormat { expected: String, found: String },

    #[error("missing field: {0}")]
    MissingField(String),

    #[error("invalid UTF-8 in {context}: {source}")]
    InvalidUtf8 {
        context: String,
        source: std::string::FromUtf8Error,
    },

    // Cryptographic errors
    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid signature")]
    InvalidSignature,

    #[error(
        "key mismatch: signature keynum {sig_keynum} doesn't match public key keynum {pub_keynum}"
    )]
    KeyMismatch {
        sig_keynum: String,
        pub_keynum: String,
    },

    #[error("checksum verification failed")]
    ChecksumFailed,

    #[error("decryption failed: wrong password")]
    DecryptionFailed,

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedSigAlg(String),

    #[error("unsupported KDF algorithm: {0}")]
    UnsupportedKdfAlg(String),

    #[error("unsupported checksum algorithm: {0}")]
    UnsupportedChkAlg(String),

    // Key derivation errors
    #[error("key derivation failed: {0}")]
    KdfError(String),

    #[error("random number generator failed: {0}")]
    RngError(String),

    #[error("password required but not provided")]
    PasswordRequired,

    #[error("scrypt parameter out of range: {0}")]
    ScryptParamError(String),

    // User input errors
    #[error("Passwords don't match")]
    PasswordMismatch,

    #[error("invalid path: {0:?}")]
    InvalidPath(PathBuf),

    #[error("missing required argument: {0}")]
    MissingArgument(String),

    #[error("invalid comment: {0}")]
    InvalidComment(String),

    // CLI usage errors
    #[error("usage: {0}")]
    Usage(String),

    // I/O errors (general)
    #[error("I/O error: {0}")]
    Io(String),

    // Generic errors
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Create a file read error
    pub fn file_read(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::FileRead {
            path: path.into(),
            source,
        }
    }

    /// Create a file write error
    pub fn file_write(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::FileWrite {
            path: path.into(),
            source,
        }
    }

    /// Create a generic error from a string
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
