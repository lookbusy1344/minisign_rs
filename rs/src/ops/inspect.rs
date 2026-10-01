//! Key file inspection operations
//!
//! This module provides functionality to inspect minisign key files
//! and display their security parameters and KDF configuration.

use crate::constants::{PRODUCTION_MEMLIMIT, PRODUCTION_OPSLIMIT};
use crate::credential_store::CredentialStatus;
use crate::errors::{Error, Result};
use crate::formats::decode_base64_into;
use crate::keys::{PubkeyStruct, SeckeyStruct};
use crate::ops::file_utils::{
    MAX_KEY_FILE_BYTES, MAX_SIGNATURE_FILE_BYTES, read_file_bounded, read_secret_file_bounded,
    utf8_text,
};
use crate::signature::SignatureAlgorithm;
use std::path::Path;
use zeroize::Zeroizing;

/// Security level classification for encrypted keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Production-strength parameters (N=2^20, 1024 MB)
    High,
    /// Reduced parameters after 1-2 fallbacks (512-256 MB)
    Medium,
    /// Weak parameters after 3+ fallbacks or minimum (<=128 MB)
    Low,
    /// Unencrypted key (no KDF protection)
    None,
    /// KDF parameters exceed the decryption budget; the key cannot be used
    Unsupported,
}

impl SecurityLevel {
    /// Classify security level from KDF parameters
    ///
    /// # Arguments
    ///
    /// * `memlimit` - Memory limit for the KDF
    /// * `is_fallback` - Whether the parameters indicate a fallback from production strength
    ///
    /// # Returns
    ///
    /// The appropriate security level based on the parameters
    #[must_use]
    pub fn from_kdf_params(memlimit: u64, is_fallback: bool) -> Self {
        if crate::crypto::check_kdf_budget(memlimit).is_err() {
            Self::Unsupported
        } else if !is_fallback {
            Self::High
        } else if memlimit >= 256_000_000 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// Options for inspecting a key file
#[derive(Debug, Clone)]
pub struct InspectOptions<'a> {
    /// Path to the key file (can be secret or public key)
    key_file: &'a Path,
    /// Whether to check the OS credential store for a saved password.
    /// Set to `false` when `--no-decrypt` is active to avoid triggering
    /// a Keychain/credential-store authorization prompt.
    check_credential_store: bool,
}

impl<'a> InspectOptions<'a> {
    #[must_use]
    pub const fn new(key_file: &'a Path) -> Self {
        Self {
            key_file,
            check_credential_store: true,
        }
    }

    #[must_use]
    pub const fn key_file(&self) -> &Path {
        self.key_file
    }

    /// Disable the OS credential store lookup.
    ///
    /// When called, `inspect()` will set `password_saved` to `CredentialStatus::NotSaved` without
    /// touching the keychain, preventing any authorization prompt.
    #[must_use]
    pub fn skip_credential_store_check(mut self) -> Self {
        self.check_credential_store = false;
        self
    }
}

/// Result of inspecting a key file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectResult {
    key_id: String,
    key_id_words: String,
    key_type: KeyType,
    security_level: Option<SecurityLevel>,
    kdf_info: Option<KdfInfo>,
    password_saved: CredentialStatus,
    credential_id: Option<String>,
}

impl InspectResult {
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn key_id_words(&self) -> &str {
        &self.key_id_words
    }

    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        self.key_type
    }

    #[must_use]
    pub const fn security_level(&self) -> Option<SecurityLevel> {
        self.security_level
    }

    #[must_use]
    pub fn kdf_info(&self) -> Option<&KdfInfo> {
        self.kdf_info.as_ref()
    }

    #[must_use]
    pub fn password_saved(&self) -> &CredentialStatus {
        &self.password_saved
    }

    #[must_use]
    pub fn credential_id(&self) -> Option<&str> {
        self.credential_id.as_deref()
    }
}

/// Type of key being inspected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    SecretEncrypted,
    SecretUnencrypted,
    Public,
}

/// KDF parameter information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfInfo {
    opslimit: u64,
    memlimit: u64,
    log_n: u8,
    r: u32,
    p: u32,
    is_fallback: bool,
    weakness_multiplier: Option<u64>,
}

impl KdfInfo {
    #[must_use]
    pub const fn opslimit(&self) -> u64 {
        self.opslimit
    }

    #[must_use]
    pub const fn memlimit(&self) -> u64 {
        self.memlimit
    }

    #[must_use]
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    #[must_use]
    pub const fn r(&self) -> u32 {
        self.r
    }

    #[must_use]
    pub const fn p(&self) -> u32 {
        self.p
    }

    #[must_use]
    pub const fn is_fallback(&self) -> bool {
        self.is_fallback
    }

    #[must_use]
    pub const fn weakness_multiplier(&self) -> Option<u64> {
        self.weakness_multiplier
    }
}

/// Key file type inferred from the untrusted comment line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFileType {
    Secret,
    Public,
}

/// Sniff the key file type from the `untrusted comment:` line.
///
/// Returns `None` when the first line does not carry a recognised minisign
/// key-type marker ("secret key" / "public key"). Non-standard comments
/// produced by third-party tools or the test fixtures fall through to the
/// caller's fallback logic.
fn sniff_key_file_type(contents: &str) -> Option<KeyFileType> {
    let first_line = contents.lines().next()?;
    let comment = first_line.strip_prefix("untrusted comment: ")?;
    if comment.contains("secret key") {
        Some(KeyFileType::Secret)
    } else if comment.contains("public key") {
        Some(KeyFileType::Public)
    } else {
        None
    }
}

/// Read a key file into a guarded buffer: it may hold a secret key.
fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_secret_file_bounded(path, MAX_KEY_FILE_BYTES)
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))
}

// The untrusted comment can mislabel a secret key as public, and malformed
// secret keys can reach the public fallback. Guard decoding on both paths.
fn decode_inspection_public_key(contents: &str) -> Result<Zeroizing<Vec<u8>>> {
    let data_line = contents
        .lines()
        .nth(1)
        .ok_or_else(|| Error::InvalidPublicKey("missing comment or data line".to_string()))?;
    // Decoded base64 is never longer than its input. Allocate before filling and
    // never grow the buffer; the file reader already bounds the input size.
    let mut decoded = Zeroizing::new(vec![0u8; data_line.len()]);
    let len = decode_base64_into(data_line, &mut decoded)?;
    decoded.truncate(len);
    Ok(decoded)
}

fn inspect_public_key_file(contents: &str) -> Result<InspectResult> {
    let decoded = decode_inspection_public_key(contents)?;
    let pubkey = PubkeyStruct::from_bytes(&decoded)?;
    Ok(inspect_public_key(&pubkey))
}

/// Inspect a key file and return detailed information
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file format is invalid
/// - The key structure cannot be parsed
pub fn inspect(options: &InspectOptions<'_>) -> Result<InspectResult> {
    let bytes = read_key_file(options.key_file())?;
    let contents = utf8_text(&bytes, options.key_file())
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))?;

    match sniff_key_file_type(contents) {
        Some(KeyFileType::Secret) => {
            let seckey = SeckeyStruct::from_file_contents(contents)?;
            inspect_secret_key(&seckey, options.check_credential_store)
        }
        Some(KeyFileType::Public) => inspect_public_key_file(contents),
        None => {
            // Non-standard comment — try both parsers for backward compatibility.
            if let Ok(seckey) = SeckeyStruct::from_file_contents(contents) {
                return inspect_secret_key(&seckey, options.check_credential_store);
            }
            if let Ok(result) = inspect_public_key_file(contents) {
                return Ok(result);
            }
            Err(Error::InvalidKeyFormat(
                "File is not a valid minisign key".to_string(),
            ))
        }
    }
}

/// Inspect a pre-loaded secret key
///
/// This variant accepts a pre-loaded `SeckeyStruct` to avoid redundant file I/O
/// when the key is already loaded. For encrypted keys, shows the encrypted keynum
/// placeholder. Use `inspect_private_with_key` to decrypt and show the real keynum.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
///
/// # Returns
///
/// An `InspectResult` containing key information
///
/// # Errors
///
/// Returns an error if the KDF parameters cannot be parsed
pub fn inspect_with_key(seckey: &SeckeyStruct) -> Result<InspectResult> {
    inspect_secret_key(seckey, true)
}

/// Inspect a pre-loaded secret key by decrypting it first (if encrypted)
///
/// This variant accepts a pre-loaded `SeckeyStruct` and decrypts it to retrieve
/// the real key ID. For unencrypted keys, it behaves identically to `inspect_with_key`.
///
/// # Arguments
///
/// * `seckey` - Pre-loaded secret key structure
/// * `password` - Password to decrypt the key (if encrypted)
///
/// # Returns
///
/// An `InspectResult` containing key information with real keynum
///
/// # Errors
///
/// Returns an error if:
/// - For encrypted keys: password is incorrect or decryption fails
pub fn inspect_private_with_key(seckey: &SeckeyStruct, password: &[u8]) -> Result<InspectResult> {
    if !seckey.is_encrypted() {
        // Unencrypted secret key - behave like regular inspect
        return inspect_secret_key(seckey, true);
    }

    // Encrypted - decrypt to get the real keynum
    let (_secret_key, decrypted_keynum) = seckey.decrypt(password)?;

    // Get the base inspection result
    let mut result = inspect_secret_key(seckey, true)?;

    // Update with the real keynum
    result.key_id = decrypted_keynum.to_key_id();
    result.key_id_words = crate::wordlist::keynum_to_words(&decrypted_keynum);

    Ok(result)
}

/// Inspect a public key from base64 string
///
/// # Errors
///
/// Returns an error if:
/// - The base64 string cannot be decoded
/// - The decoded data is not a valid public key
pub fn inspect_base64(base64_str: &str) -> Result<InspectResult> {
    let pubkey = PubkeyStruct::from_base64(base64_str)?;
    Ok(inspect_public_key(&pubkey))
}

/// Inspect a private key by decrypting it first (if encrypted)
///
/// This function works like `inspect()` but decrypts encrypted private keys
/// to retrieve the real key ID. For unencrypted keys and public keys, it
/// behaves identically to `inspect()`.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file is not a valid key
/// - For encrypted keys: password is incorrect or decryption fails
pub fn inspect_private(key_file: &Path, password: &[u8]) -> Result<InspectResult> {
    let bytes = read_key_file(key_file)?;
    let contents = utf8_text(&bytes, key_file)
        .map_err(|e| Error::Io(format!("Failed to read key file: {e}")))?;

    match sniff_key_file_type(contents) {
        Some(KeyFileType::Secret) => {
            let seckey = SeckeyStruct::from_file_contents(contents)?;
            inspect_private_with_key(&seckey, password)
        }
        Some(KeyFileType::Public) => inspect_public_key_file(contents),
        None => {
            // Non-standard comment — try both parsers for backward compatibility.
            if let Ok(seckey) = SeckeyStruct::from_file_contents(contents) {
                return inspect_private_with_key(&seckey, password);
            }
            if let Ok(result) = inspect_public_key_file(contents) {
                return Ok(result);
            }
            Err(Error::InvalidKeyFormat(
                "File is not a valid minisign key".to_string(),
            ))
        }
    }
}

/// Inspect a secret key structure
fn inspect_secret_key(
    seckey: &SeckeyStruct,
    check_credential_store: bool,
) -> Result<InspectResult> {
    inspect_secret_key_with_credentials(
        seckey,
        check_credential_store,
        crate::credential_store::has_password,
    )
}

fn inspect_secret_key_with_credentials(
    seckey: &SeckeyStruct,
    check_credential_store: bool,
    credential_status: impl FnOnce(&str) -> CredentialStatus,
) -> Result<InspectResult> {
    let key_id = seckey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(seckey.keynum());
    let credential_id = seckey.credential_id();

    if !seckey.is_encrypted() {
        // Unencrypted key
        let password_saved = if check_credential_store {
            credential_status(&credential_id)
        } else {
            CredentialStatus::NotSaved
        };
        return Ok(InspectResult {
            key_id,
            key_id_words,
            key_type: KeyType::SecretUnencrypted,
            security_level: Some(SecurityLevel::None),
            kdf_info: None,
            password_saved,
            credential_id: Some(credential_id),
        });
    }

    // Encrypted key - analyze KDF parameters
    let opslimit = seckey.kdf_opslimit();
    let memlimit = seckey.kdf_memlimit();

    // Convert to scrypt parameters
    let (log_n, r, p) = opslimit_memlimit_to_params(opslimit, memlimit)?;

    // Determine if this is a fallback key

    let is_fallback = opslimit < PRODUCTION_OPSLIMIT || memlimit < PRODUCTION_MEMLIMIT;

    // Calculate weakness multiplier if fallback
    let weakness_multiplier = if is_fallback {
        Some(PRODUCTION_MEMLIMIT / memlimit)
    } else {
        None
    };

    // Classify security level
    let security_level = SecurityLevel::from_kdf_params(memlimit, is_fallback);

    // Unsupported keys cannot be decrypted, so inspecting them must not request
    // credential-store authorization even when the caller enables that lookup.
    let password_saved = if check_credential_store && security_level != SecurityLevel::Unsupported {
        credential_status(&credential_id)
    } else {
        CredentialStatus::NotSaved
    };

    Ok(InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::SecretEncrypted,
        security_level: Some(security_level),
        kdf_info: Some(KdfInfo {
            opslimit,
            memlimit,
            log_n,
            r,
            p,
            is_fallback,
            weakness_multiplier,
        }),
        password_saved,
        credential_id: Some(credential_id),
    })
}

/// Inspect a public key structure
fn inspect_public_key(pubkey: &PubkeyStruct) -> InspectResult {
    let key_id = pubkey.keynum().to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(pubkey.keynum());

    InspectResult {
        key_id,
        key_id_words,
        key_type: KeyType::Public,
        security_level: None,
        kdf_info: None,
        password_saved: CredentialStatus::NotSaved,
        credential_id: None,
    }
}

/// Result of inspecting a signature file
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInspectResult {
    key_id: String,
    key_id_words: String,
    algorithm: SignatureAlgorithm,
}

impl SignatureInspectResult {
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn key_id_words(&self) -> &str {
        &self.key_id_words
    }

    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

/// Inspect a signature file and return key ID information
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file format is invalid
pub fn inspect_signature(signature_file: &Path) -> Result<SignatureInspectResult> {
    use crate::signature::SignatureBox;

    let contents = read_file_bounded(signature_file, MAX_SIGNATURE_FILE_BYTES)
        .map_err(|e| Error::Io(format!("Failed to read signature file: {e}")))?;

    let sig_box = SignatureBox::from_file_contents(&contents)?;

    let keynum = sig_box.sig_struct().keynum();
    let key_id = keynum.to_key_id();
    let key_id_words = crate::wordlist::keynum_to_words(keynum);
    let algorithm = sig_box.sig_struct().algorithm();

    Ok(SignatureInspectResult {
        key_id,
        key_id_words,
        algorithm,
    })
}

/// Convert opslimit/memlimit to scrypt parameters (`log_n`, r, p)
///
/// Delegates to [`crate::crypto::decode_kdf_params`]: inspection describes
/// over-budget parameters instead of rejecting them.
fn opslimit_memlimit_to_params(opslimit: u64, memlimit: u64) -> Result<(u8, u32, u32)> {
    crate::crypto::decode_kdf_params(opslimit, memlimit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SECKEY_STRUCT_SIZE;
    use std::cell::Cell;

    const OPSLIMIT_OFFSET: usize = 38;
    const MEMLIMIT_OFFSET: usize = 46;
    const ALGORITHM_HEADER: &[u8] = b"EdScB2";

    fn encrypted_key(memlimit: u64) -> SeckeyStruct {
        let mut bytes = [0u8; SECKEY_STRUCT_SIZE];
        bytes[..ALGORITHM_HEADER.len()].copy_from_slice(ALGORITHM_HEADER);
        let opslimit = memlimit / crate::crypto::LIBSODIUM_MEMLIMIT_MULTIPLIER
            * crate::crypto::LIBSODIUM_OPSLIMIT_MULTIPLIER;
        bytes[OPSLIMIT_OFFSET..MEMLIMIT_OFFSET].copy_from_slice(&opslimit.to_le_bytes());
        bytes[MEMLIMIT_OFFSET..MEMLIMIT_OFFSET + size_of::<u64>()]
            .copy_from_slice(&memlimit.to_le_bytes());
        SeckeyStruct::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn unsupported_key_inspection_never_queries_credentials() {
        let key = encrypted_key(PRODUCTION_MEMLIMIT * 2);
        let queried = Cell::new(false);
        let result = inspect_secret_key_with_credentials(&key, true, |_| {
            queried.set(true);
            CredentialStatus::Saved
        })
        .unwrap();

        assert_eq!(result.security_level(), Some(SecurityLevel::Unsupported));
        assert!(
            !queried.get(),
            "unsupported keys must not access credentials"
        );
        assert_eq!(result.password_saved(), &CredentialStatus::NotSaved);
    }

    #[test]
    fn supported_key_inspection_preserves_requested_credential_lookup() {
        let key = encrypted_key(PRODUCTION_MEMLIMIT);
        for requested in [false, true] {
            let queried = Cell::new(false);
            let result = inspect_secret_key_with_credentials(&key, requested, |id| {
                assert_eq!(id, key.credential_id());
                queried.set(true);
                CredentialStatus::Saved
            })
            .unwrap();

            assert_eq!(queried.get(), requested);
            assert_eq!(
                result.password_saved(),
                &if requested {
                    CredentialStatus::Saved
                } else {
                    CredentialStatus::NotSaved
                }
            );
        }
    }

    #[test]
    fn inspection_public_decoder_guards_mislabelled_secret_material() {
        let (secret, _, keynum) = crate::crypto::generate_keypair().unwrap();
        let key = SeckeyStruct::new_unencrypted(keynum, &secret);
        let contents = key.to_file_contents("minisign public key").unwrap();
        let decoded: Zeroizing<Vec<u8>> = decode_inspection_public_key(&contents).unwrap();

        assert_eq!(&decoded[..], &key.to_bytes());
        assert!(matches!(
            PubkeyStruct::from_bytes(&decoded),
            Err(Error::InvalidPublicKey(_))
        ));
    }
}
