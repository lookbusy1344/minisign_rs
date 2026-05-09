//! High-level operations for minisign
//!
//! This module contains the main operations: verify, sign, generate, recreate, change, and inspect.

pub mod file_utils;

pub mod change;
pub mod generate;
pub mod inspect;
pub mod recreate;
pub mod sign;
pub mod verify;

pub use crate::credential_store::CredentialStatus;
pub use change::{ChangeOptions, ChangeResult, change};
pub use generate::{GenerateOptions, GenerateResult, generate};
pub use inspect::{
    InspectOptions, InspectResult, KeyType, SecurityLevel, SignatureInspectResult, inspect,
    inspect_base64, inspect_private, inspect_private_with_key, inspect_signature, inspect_with_key,
};
pub use recreate::{RecreateOptions, RecreateResult, recreate, recreate_with_key};
pub use sign::{SignOptions, SignResult, sign, sign_with_key};
pub use verify::{MessageSource, PublicKeySource, VerifyOptions, VerifyResult, verify};

/// Controls whether an existing key file may be overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverwritePolicy {
    /// Preserve existing files — fail if the target path already exists.
    Preserve,
    /// Overwrite existing files unconditionally.
    Overwrite,
}

/// Controls whether a secret key is stored with password-based encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    /// Encrypt the secret key with a password (normal operation).
    Protected,
    /// Store the secret key in plaintext (no password).
    Unprotected,
}
