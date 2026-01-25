//! High-level operations for minisign
//!
//! This module contains the main operations: verify, sign, generate, recreate, and change.

mod file_utils;

pub mod change;
pub mod generate;
pub mod recreate;
pub mod sign;
pub mod verify;

pub use change::{ChangeOptions, ChangeResult, change};
pub use generate::{GenerateOptions, GenerateResult, generate};
pub use recreate::{RecreateOptions, RecreateResult, recreate};
pub use sign::{SignOptions, SignResult, sign};
pub use verify::{PublicKeySource, VerifyOptions, VerifyResult, verify};
