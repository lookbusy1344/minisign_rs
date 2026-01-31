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

pub use change::{ChangeOptions, ChangeResult, change};
pub use generate::{GenerateOptions, GenerateResult, generate};
pub use inspect::{InspectOptions, InspectResult, KeyType, SecurityLevel, inspect, inspect_base64};
pub use recreate::{RecreateOptions, RecreateResult, recreate};
pub use sign::{SignOptions, SignResult, sign};
pub use verify::{PublicKeySource, VerifyOptions, VerifyResult, verify};
