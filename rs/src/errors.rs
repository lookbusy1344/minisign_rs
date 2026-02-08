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

    #[error("Legacy (non-prehashed) signature found")]
    LegacySignatureRejected,

    #[error("key mismatch: signature keyid {sig_keynum} doesn't match")]
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

    // Multi-file batch operation errors
    // Error message provides high-level context; detailed per-file errors are printed by the caller
    #[error("some files in batch operation failed")]
    PartialFailure,

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
