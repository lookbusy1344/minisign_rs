// Phase 2: H5 only - KeyNum constant-time comparison

use minisign::crypto::{KEYNUM_BYTES, KeyNum};
use subtle::ConstantTimeEq;

#[test]
fn h5_keynum_comparison_security() {
    let keynum1 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let keynum2 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
    let keynum3 = KeyNum::from_bytes([1, 2, 3, 4, 5, 6, 7, 9]);

    let equal: bool = keynum1.ct_eq(&keynum2).into();
    let not_equal: bool = keynum1.ct_eq(&keynum3).into();

    assert!(equal);
    assert!(!not_equal);
}

#[test]
fn h5_keynum_constant_time_eq_implementation() {
    let keynum = KeyNum::from_bytes([0u8; KEYNUM_BYTES]);
    let same = KeyNum::from_bytes([0u8; KEYNUM_BYTES]);
    let different = KeyNum::from_bytes([1u8; KEYNUM_BYTES]);

    let result1: bool = keynum.ct_eq(&same).into();
    let result2: bool = keynum.ct_eq(&different).into();

    assert!(result1, "Identical keynums should be equal");
    assert!(!result2, "Different keynums should not be equal");
}
