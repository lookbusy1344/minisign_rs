//! High-level operations for minisign
//!
//! This module contains the main operations: verify, sign, generate, recreate, and change.

pub mod generate;
pub mod sign;
pub mod verify;

pub use generate::{generate, GenerateOptions, GenerateResult};
pub use sign::{sign, SignOptions, SignResult};
pub use verify::{verify, PublicKeySource, VerifyOptions, VerifyResult};
