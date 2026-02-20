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
/// # Errors
///
/// Returns error if the slice is shorter than 8 bytes.
///
/// # Panics
///
/// Never panics - the conversion from slice to array is guaranteed to succeed
/// after the length check.
pub fn read_u64_le(bytes: &[u8]) -> Result<u64> {
    let buf: [u8; 8] = bytes
        .get(..8)
        .ok_or_else(|| {
            Error::Other(format!(
                "read_u64_le requires at least 8 bytes, got {}",
                bytes.len()
            ))
        })?
        .try_into()
        .map_err(|_| Error::Other("slice conversion to [u8; 8] failed".into()))?;
    Ok(u64::from_le_bytes(buf))
}

/// Write a little-endian u64 to a mutable byte slice
///
/// # Errors
///
/// Returns error if the slice is shorter than 8 bytes.
pub fn write_u64_le(bytes: &mut [u8], value: u64) -> Result<()> {
    if bytes.len() < 8 {
        return Err(Error::Other(format!(
            "write_u64_le requires at least 8 bytes, got {}",
            bytes.len()
        )));
    }
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}
