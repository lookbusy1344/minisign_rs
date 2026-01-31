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
fn test_u64_le_roundtrip() {
    let test_values = vec![
        0u64,
        1,
        255,
        256,
        65535,
        65536,
        u64::MAX,
        0x0123_4567_89AB_CDEF,
    ];

    for value in test_values {
        let mut buf = [0u8; 8];
        write_u64_le(&mut buf, value);
        let read_value = read_u64_le(&buf);
        assert_eq!(value, read_value, "u64 roundtrip failed for {value:#x}");
    }
}

#[test]
fn test_u64_le_known_values() {
    // Test specific byte patterns to ensure correct endianness
    let test_cases = vec![
        (
            0x0102_0304_0506_0708_u64,
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        ),
        (
            0x0000_0000_0000_0001_u64,
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            0x0100_0000_0000_0000_u64,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        ),
    ];

    for (value, expected_bytes) in test_cases {
        let mut buf = [0u8; 8];
        write_u64_le(&mut buf, value);
        assert_eq!(
            buf, expected_bytes,
            "write_u64_le produced wrong bytes for {value:#x}"
        );

        let read_value = read_u64_le(&expected_bytes);
        assert_eq!(read_value, value, "read_u64_le read wrong value from bytes");
    }
}

#[test]
fn test_u16_le_roundtrip() {
    let test_values = vec![0u16, 1, 255, 256, u16::MAX];

    for value in test_values {
        let mut buf = [0u8; 2];
        write_u16_le(&mut buf, value);
        let read_value = read_u16_le(&buf);
        assert_eq!(value, read_value, "u16 roundtrip failed for {value:#x}");
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
            "write_u16_le produced wrong bytes for {value:#x}"
        );

        let read_value = read_u16_le(&expected_bytes);
        assert_eq!(read_value, value, "read_u16_le read wrong value from bytes");
    }
}

#[test]
#[should_panic(expected = "read_u64_le requires at least 8 bytes")]
fn test_read_u64_le_short_buffer() {
    let buf = [0u8; 7];
    let _ = read_u64_le(&buf);
}

#[test]
#[should_panic(expected = "write_u64_le requires at least 8 bytes")]
fn test_write_u64_le_short_buffer() {
    let mut buf = [0u8; 7];
    write_u64_le(&mut buf, 42);
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

    /// Property test: u64 little-endian roundtrip
    #[test]
    fn prop_u64_le_roundtrip(value: u64) {
        let mut buf = [0u8; 8];
        write_u64_le(&mut buf, value);
        let decoded = read_u64_le(&buf);
        prop_assert_eq!(value, decoded);
    }

    /// Property test: u16 little-endian roundtrip
    #[test]
    fn prop_u16_le_roundtrip(value: u16) {
        let mut buf = [0u8; 2];
        write_u16_le(&mut buf, value);
        let decoded = read_u16_le(&buf);
        prop_assert_eq!(value, decoded);
    }
}
