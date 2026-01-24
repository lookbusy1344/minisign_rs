//! Minisign - A dead simple Rust tool to sign files and verify signatures
//!
//! This is a pure Rust implementation of minisign, maintaining byte-level
//! compatibility with the original C implementation.

pub mod cli;
pub mod crypto;
pub mod errors;
pub mod formats;
pub mod keys;
pub mod ops;
pub mod signature;

// Re-export commonly used types
pub use errors::Error;
pub type Result<T> = std::result::Result<T, Error>;
