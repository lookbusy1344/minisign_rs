//! Minisign - A dead simple Rust tool to sign files and verify signatures
//!
//! This is a pure Rust implementation of minisign, maintaining byte-level
//! compatibility with the original C implementation.
//!
//! ## Module Organization
//!
//! - [`constants`] - Centralized reference for all size and parameter constants
//! - [`crypto`] - Cryptographic primitives (Ed25519, Blake2b, Scrypt)
//! - [`ecies`] - ECIES crypto primitives (P-256 ECDH + AES-256-GCM)
//! - [`hw_keystore`] - Hardware key store abstraction (Secure Enclave, TPM)
//! - [`keys`] - Key generation, encryption, and management
//! - [`signature`] - Signature creation and verification structures
//! - [`validation`] - Comment and input validation (C compatibility)
//! - [`ops`] - High-level operations (sign, verify, generate, etc.)
//! - [`formats`] - Binary and base64 encoding/decoding
//! - [`wordlist`] - PGP Word List encoding for human-readable key IDs
//! - [`errors`] - Error types and Result alias
//! - [`cli`] - Command-line interface (for binary)

pub mod cli;
pub mod constants;
pub mod crypto;
pub mod ecies;
pub mod ecies_wrap;
pub mod errors;
pub mod formats;
pub mod hw_keystore;
pub mod keys;
pub mod ops;
pub mod signature;
pub mod validation;
pub mod wordlist;

// Re-export commonly used types
pub use errors::{Error, Result};
