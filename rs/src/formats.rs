//! Base64 encoding and binary format helpers

use crate::errors::{Error, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

/// Encode bytes to base64 string (standard encoding)
pub fn encode_base64(data: impl AsRef<[u8]>) -> String {
    STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn decode_base64(data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    STANDARD.decode(data).map_err(Error::from)
}

/// Read a little-endian u64 from bytes
///
/// # Panics
///
/// Panics if the slice is shorter than 8 bytes
pub fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Write a little-endian u64 to a mutable byte slice
///
/// # Panics
///
/// Panics if the slice is shorter than 8 bytes
pub fn write_u64_le(bytes: &mut [u8], value: u64) {
    bytes[..8].copy_from_slice(&value.to_le_bytes());
}

/// Read a little-endian u16 from bytes
///
/// # Panics
///
/// Panics if the slice is shorter than 2 bytes
pub fn read_u16_le(bytes: &[u8]) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[..2]);
    u16::from_le_bytes(buf)
}

/// Write a little-endian u16 to a mutable byte slice
///
/// # Panics
///
/// Panics if the slice is shorter than 2 bytes
pub fn write_u16_le(bytes: &mut [u8], value: u16) {
    bytes[..2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let sequential = (0..128).collect::<Vec<u8>>();
        let test_data = vec![
            b"".as_slice(),
            b"hello",
            b"minisign test data",
            &[0u8; 32],
            &[0xff; 64],
            sequential.as_slice(),
        ];

        for data in test_data {
            let encoded = encode_base64(data);
            let decoded = decode_base64(&encoded).expect("decode failed");
            assert_eq!(
                data, decoded,
                "roundtrip failed for {} bytes",
                data.len()
            );
        }
    }

    #[test]
    fn test_base64_invalid() {
        let invalid_inputs = vec![
            "!@#$%^&*()",
            "invalid base64",
            "====",
        ];

        for input in invalid_inputs {
            let result = decode_base64(input);
            assert!(result.is_err(), "should fail for input: {}", input);
        }
    }

    #[test]
    fn test_u64_le_roundtrip() {
        let test_values = vec![
            0u64,
            1,
            255,
            256,
            65535,
            65536,
            u64::MAX,
            0x0123456789ABCDEF,
        ];

        for value in test_values {
            let mut buf = [0u8; 8];
            write_u64_le(&mut buf, value);
            let read_value = read_u64_le(&buf);
            assert_eq!(value, read_value, "u64 roundtrip failed for {:#x}", value);
        }
    }

    #[test]
    fn test_u64_le_known_values() {
        // Test specific byte patterns to ensure correct endianness
        let test_cases = vec![
            (0x0102030405060708u64, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            (0x0000000000000001u64, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            (0x0100000000000000u64, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        ];

        for (value, expected_bytes) in test_cases {
            let mut buf = [0u8; 8];
            write_u64_le(&mut buf, value);
            assert_eq!(
                buf, expected_bytes,
                "write_u64_le produced wrong bytes for {:#x}",
                value
            );

            let read_value = read_u64_le(&expected_bytes);
            assert_eq!(
                read_value, value,
                "read_u64_le read wrong value from bytes"
            );
        }
    }

    #[test]
    fn test_u16_le_roundtrip() {
        let test_values = vec![0u16, 1, 255, 256, u16::MAX];

        for value in test_values {
            let mut buf = [0u8; 2];
            write_u16_le(&mut buf, value);
            let read_value = read_u16_le(&buf);
            assert_eq!(value, read_value, "u16 roundtrip failed for {:#x}", value);
        }
    }

    #[test]
    fn test_u16_le_known_values() {
        // Test specific byte patterns to ensure correct endianness
        let test_cases = vec![
            (0x0102u16, [0x02, 0x01]),
            (0x0001u16, [0x01, 0x00]),
            (0x0100u16, [0x00, 0x01]),
        ];

        for (value, expected_bytes) in test_cases {
            let mut buf = [0u8; 2];
            write_u16_le(&mut buf, value);
            assert_eq!(
                buf, expected_bytes,
                "write_u16_le produced wrong bytes for {:#x}",
                value
            );

            let read_value = read_u16_le(&expected_bytes);
            assert_eq!(
                read_value, value,
                "read_u16_le read wrong value from bytes"
            );
        }
    }

    #[test]
    #[should_panic(expected = "index")]
    fn test_read_u64_le_short_buffer() {
        let buf = [0u8; 7];
        read_u64_le(&buf);
    }

    #[test]
    #[should_panic(expected = "index")]
    fn test_write_u64_le_short_buffer() {
        let mut buf = [0u8; 7];
        write_u64_le(&mut buf, 42);
    }
}
