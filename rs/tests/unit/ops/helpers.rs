//! Shared helpers for ops unit tests

use minisign::{
    crypto::{KeyNum, SecretKey},
    keys::SeckeyStruct,
};
use rand::Rng;

/// Fast KDF work factor used across ops tests (N = 2^14, ~50 ms).
///
/// Production keys use `log_n` = 20 (N = 2^20, ~1-5 s). Using 14 here keeps
/// tests that involve encryption/decryption fast enough to run in CI without
/// marking them `#[ignore]`.
pub const TEST_LOG_N: u8 = 14;

/// Create an encrypted [`SeckeyStruct`] using fast KDF parameters.
///
/// The salt is generated freshly from the OS RNG on each call. Using this
/// helper instead of inlining the key-creation boilerplate ensures all tests
/// exercise the same parameters and reduces the chance of an accidentally
/// incorrect constant (e.g. wrong opslimit formula).
pub fn make_fast_encrypted_seckey(
    keynum: KeyNum,
    secret_key: &SecretKey,
    password: &[u8],
) -> SeckeyStruct {
    let mut kdf_salt = [0u8; 32];
    rand::thread_rng().fill(&mut kdf_salt);
    let n = 1u64 << TEST_LOG_N;
    let r = 8u64;
    SeckeyStruct::new_encrypted(
        keynum,
        secret_key,
        password,
        kdf_salt,
        4 * n * r,   // kdf_opslimit
        128 * n * r, // kdf_memlimit
        false,       // allow_fallback — tests use strict mode
    )
    .expect("fast encrypted seckey creation should not fail")
}
