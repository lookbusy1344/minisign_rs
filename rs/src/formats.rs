//! Base64 encoding and binary format helpers

use crate::errors::{Error, Result};
use base64::{Engine, engine::general_purpose::STANDARD};

/// Encode bytes to base64 string (standard encoding)
pub fn encode_base64(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

/// Decode base64 string to bytes
///
/// # Errors
///
/// Returns `Error::InvalidBase64` if the input is not valid base64
pub fn decode_base64(data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    STANDARD.decode(data).map_err(Error::from)
}

/// Read a little-endian u64 from bytes
///
/// # Panics
///
/// Panics if the slice is shorter than 8 bytes.
/// Callers MUST validate length before calling this function.
#[must_use]
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    debug_assert!(
        bytes.len() >= 8,
        "read_u64_le requires at least 8 bytes, got {}",
        bytes.len()
    );
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Write a little-endian u64 to a mutable byte slice
///
/// # Panics
///
/// Panics if the slice is shorter than 8 bytes.
/// Callers MUST validate length before calling this function.
pub fn write_u64_le(bytes: &mut [u8], value: u64) {
    debug_assert!(
        bytes.len() >= 8,
        "write_u64_le requires at least 8 bytes, got {}",
        bytes.len()
    );
    bytes[..8].copy_from_slice(&value.to_le_bytes());
}

/// Read a little-endian u16 from bytes
///
/// # Panics
///
/// Panics if the slice is shorter than 2 bytes.
/// Callers MUST validate length before calling this function.
#[must_use]
pub fn read_u16_le(bytes: &[u8]) -> u16 {
    debug_assert!(
        bytes.len() >= 2,
        "read_u16_le requires at least 2 bytes, got {}",
        bytes.len()
    );
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[..2]);
    u16::from_le_bytes(buf)
}

/// Write a little-endian u16 to a mutable byte slice
///
/// # Panics
///
/// Panics if the slice is shorter than 2 bytes.
/// Callers MUST validate length before calling this function.
pub fn write_u16_le(bytes: &mut [u8], value: u16) {
    debug_assert!(
        bytes.len() >= 2,
        "write_u16_le requires at least 2 bytes, got {}",
        bytes.len()
    );
    bytes[..2].copy_from_slice(&value.to_le_bytes());
}
