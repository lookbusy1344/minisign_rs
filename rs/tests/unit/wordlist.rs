use minisign::crypto::KeyNum;
use minisign::wordlist::*;

#[test]
fn test_bytes_to_words_single_byte_even_position() {
    // Byte 0x00 at position 0 (even) should be "aardvark"
    let bytes = [0x00];
    let result = bytes_to_words(&bytes);
    assert_eq!(result, "aardvark");
}

#[test]
fn test_bytes_to_words_single_byte_odd_position() {
    // Byte 0x00 at position 1 (odd) should be "adroitness"
    // Need two bytes to test odd position
    let bytes = [0xFF, 0x00]; // 0xFF at even position, 0x00 at odd position
    let result = bytes_to_words(&bytes);
    assert!(
        result.ends_with("adroitness"),
        "Expected to end with 'adroitness', got: {result}"
    );
}

#[test]
fn test_bytes_to_words_known_values() {
    // Test first few byte values at even positions
    let test_cases = vec![
        (&[0x00][..], "aardvark"),
        (&[0x01][..], "absurd"),
        (&[0x02][..], "accrue"),
        (&[0x03][..], "acme"),
    ];

    for (bytes, expected) in test_cases {
        let result = bytes_to_words(bytes);
        assert_eq!(result, expected, "Failed for byte value {:#04x}", bytes[0]);
    }
}

#[test]
fn test_bytes_to_words_two_bytes() {
    // Byte 0x00 at even position = "aardvark"
    // Byte 0x01 at odd position = "adviser"
    let bytes = [0x00, 0x01];
    let result = bytes_to_words(&bytes);
    assert_eq!(result, "aardvark adviser");
}

#[test]
fn test_bytes_to_words_eight_bytes() {
    // Test an 8-byte keynum (typical use case)
    let bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let result = bytes_to_words(&bytes);

    // Should produce 8 words separated by spaces
    let words: Vec<&str> = result.split_whitespace().collect();
    assert_eq!(words.len(), 8, "Expected 8 words, got {}", words.len());

    // First word (0x00 at even position)
    assert_eq!(words[0], "aardvark");
    // Second word (0x01 at odd position)
    assert_eq!(words[1], "adviser");
}

#[test]
fn test_bytes_to_words_empty() {
    let bytes = [];
    let result = bytes_to_words(&bytes);
    assert_eq!(result, "");
}

#[test]
fn test_bytes_to_words_max_byte_value() {
    // Test 0xFF at even and odd positions
    let bytes = [0xFF, 0xFF];
    let result = bytes_to_words(&bytes);

    // 0xFF at even position should be "Zulu"
    // 0xFF at odd position should be "Yucatan"
    assert_eq!(result, "Zulu Yucatan");
}

#[test]
fn test_keynum_to_words() {
    // Test KeyNum conversion (8 bytes)
    let keynum_bytes = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let keynum = KeyNum::from_bytes(keynum_bytes);

    let result = keynum_to_words(&keynum);

    // Should produce same result as bytes_to_words
    let expected = bytes_to_words(&keynum_bytes);
    assert_eq!(result, expected);
}

#[test]
fn test_word_list_parity() {
    // Verify that even/odd position logic works correctly
    // Same byte value should produce different words at different positions
    let bytes = [0x10, 0x10]; // Same byte at both positions
    let result = bytes_to_words(&bytes);

    let words: Vec<&str> = result.split_whitespace().collect();
    assert_eq!(words.len(), 2);
    // Words should be different (even vs odd word list)
    assert_ne!(
        words[0], words[1],
        "Even and odd position words should differ"
    );
}

#[test]
fn test_all_bytes_covered() {
    // Test that all 256 byte values can be encoded
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let result = bytes_to_words(&all_bytes);

    // Should produce 256 words
    let words: Vec<&str> = result.split_whitespace().collect();
    assert_eq!(words.len(), 256, "Should encode all 256 byte values");

    // All words should be non-empty
    for word in words {
        assert!(!word.is_empty(), "Found empty word in output");
    }
}
