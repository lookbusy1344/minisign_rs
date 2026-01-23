//! High-level operations for minisign
//!
//! This module contains the main operations: verify, sign, generate, recreate, and change.

pub mod change;
pub mod generate;
pub mod recreate;
pub mod sign;
pub mod verify;

pub use change::{change, ChangeOptions, ChangeResult};
pub use generate::{generate, GenerateOptions, GenerateResult};
pub use recreate::{recreate, RecreateOptions, RecreateResult};
pub use sign::{sign, SignOptions, SignResult};
pub use verify::{verify, PublicKeySource, VerifyOptions, VerifyResult};
