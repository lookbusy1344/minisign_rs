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

/// Decode base64 into a caller-provided buffer, returning the decoded length
///
/// Use for secret material: the output goes into storage the caller guards (for
/// example `Zeroizing<[u8; N]>`), and no intermediate buffer grows or reallocates.
///
/// # Errors
///
/// Returns `Error::InvalidBase64` if the input is not valid base64, or
/// `Error::InvalidKeyFormat` if the decoded data does not fit in `output`.
pub fn decode_base64_into(data: impl AsRef<[u8]>, output: &mut [u8]) -> Result<usize> {
    STANDARD.decode_slice(data, output).map_err(|e| match e {
        base64::DecodeSliceError::DecodeError(e) => Error::InvalidBase64(e),
        base64::DecodeSliceError::OutputSliceTooSmall => {
            Error::InvalidKeyFormat(format!("decoded data exceeds {} bytes", output.len()))
        }
    })
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
