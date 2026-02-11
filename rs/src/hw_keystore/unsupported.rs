//! Unsupported platform stub for hardware key store
//!
//! This implementation is used on platforms that don't have a hardware key store
//! backend compiled in. All operations return `HardwareKeyStoreUnavailable`.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use zeroize::Zeroizing;

/// Stub implementation for unsupported platforms
///
/// Always returns `HardwareKeyStoreUnavailable` for all operations.
/// Used when no platform-specific backend is available.
pub struct UnsupportedKeyStore;

impl HardwareKeyStore for UnsupportedKeyStore {
    fn generate_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreUnavailable)
    }

    fn get_public_key(&self, _label: &str) -> Result<p256::PublicKey> {
        Err(Error::HardwareKeyStoreUnavailable)
    }

    fn ecdh(&self, _label: &str, _peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        Err(Error::HardwareKeyStoreUnavailable)
    }

    fn key_exists(&self, _label: &str) -> Result<bool> {
        Err(Error::HardwareKeyStoreUnavailable)
    }

    fn delete_key(&self, _label: &str) -> Result<()> {
        Err(Error::HardwareKeyStoreUnavailable)
    }

    fn is_available(&self) -> bool {
        false
    }

    fn display_name(&self) -> &'static str {
        "Unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;

    #[test]
    fn test_unsupported_not_available() {
        let keystore = UnsupportedKeyStore;
        assert!(!keystore.is_available());
        assert_eq!(keystore.display_name(), "Unsupported");
    }

    #[test]
    fn test_unsupported_generate_key() {
        let keystore = UnsupportedKeyStore;
        let result = keystore.generate_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    #[test]
    fn test_unsupported_ecdh() {
        let keystore = UnsupportedKeyStore;
        let public = PublicKey::from(&EphemeralSecret::random(&mut rand_core::OsRng));
        let result = keystore.ecdh("test", &public);
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    #[test]
    fn test_unsupported_key_exists() {
        let keystore = UnsupportedKeyStore;
        let result = keystore.key_exists("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    #[test]
    fn test_unsupported_delete_key() {
        let keystore = UnsupportedKeyStore;
        let result = keystore.delete_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }
}
