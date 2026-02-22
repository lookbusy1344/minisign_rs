use minisign::formats::*;

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
        assert_eq!(data, decoded, "roundtrip failed for {} bytes", data.len());
    }
}

#[test]
fn test_base64_invalid() {
    let invalid_inputs = vec!["!@#$%^&*()", "invalid base64", "===="];

    for input in invalid_inputs {
        let result = decode_base64(input);
        assert!(result.is_err(), "should fail for input: {input}");
    }
}

#[test]
fn test_read_u64_le_known_values() {
    // Test specific byte patterns to ensure correct endianness
    let test_cases = vec![
        (
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            0x0102_0304_0506_0708_u64,
        ),
        (
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x0000_0000_0000_0001_u64,
        ),
        (
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x0100_0000_0000_0000_u64,
        ),
    ];

    for (bytes, expected_value) in test_cases {
        let read_value = read_u64_le(&bytes).unwrap();
        assert_eq!(read_value, expected_value, "read_u64_le read wrong value");
    }
}

#[test]
fn test_read_u64_le_short_buffer() {
    let buf = [0u8; 7];
    let result = read_u64_le(&buf);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("at least 8 bytes"));
}

// Property-based tests
use proptest::prelude::*;

proptest! {
    /// Property test: base64 encode/decode roundtrip should preserve data
    #[test]
    fn prop_base64_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
        let encoded = encode_base64(&data);
        let decoded = decode_base64(&encoded).unwrap();
        prop_assert_eq!(data, decoded);
    }

    /// Property test: u64 little-endian round-trip via to_le_bytes / read_u64_le
    #[test]
    fn prop_u64_le_roundtrip(value: u64) {
        let buf = value.to_le_bytes();
        let decoded = read_u64_le(&buf).unwrap();
        prop_assert_eq!(value, decoded);
    }

}
