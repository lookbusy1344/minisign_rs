//! High-level operations for minisign
//!
//! This module contains the main operations: verify, sign, generate, recreate, and change.

pub mod verify;

pub use verify::{verify, PublicKeySource, VerifyOptions, VerifyResult};
