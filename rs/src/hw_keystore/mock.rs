//! Mock hardware key store for testing
//!
//! Provides an in-memory implementation of `HardwareKeyStore` with configurable
//! behavior for testing error conditions.

use super::HardwareKeyStore;
use crate::errors::{Error, Result};
use p256::{PublicKey, SecretKey};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Configuration for mock behavior
#[derive(Debug, Clone)]
pub struct MockConfig {
    /// Simulate hardware unavailability
    pub available: bool,
    /// Simulate authentication denial
    pub deny_auth: bool,
    /// Simulate hardware errors
    pub simulate_error: bool,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            available: true,
            deny_auth: false,
            simulate_error: false,
        }
    }
}

/// Mock hardware key store for testing
///
/// Stores keys in memory with configurable error simulation.
/// Thread-safe via internal `Mutex`.
#[derive(Clone)]
pub struct MockKeyStore {
    keys: Arc<Mutex<HashMap<String, (SecretKey, PublicKey)>>>,
    config: Arc<Mutex<MockConfig>>,
}

impl MockKeyStore {
    /// Create a new mock key store with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(MockConfig::default())),
        }
    }

    /// Create a mock key store with custom configuration
    #[must_use]
    pub fn with_config(config: MockConfig) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(config)),
        }
    }

    /// Update the mock configuration
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (extremely rare, only in tests).
    pub fn set_config(&self, config: MockConfig) {
        *self.config.lock().unwrap() = config;
    }

    /// Get the current configuration
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (extremely rare, only in tests).
    #[must_use]
    pub fn get_config(&self) -> MockConfig {
        self.config.lock().unwrap().clone()
    }

    /// Clear all stored keys
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (extremely rare, only in tests).
    pub fn clear(&self) {
        self.keys.lock().unwrap().clear();
    }

    /// Get the number of stored keys
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (extremely rare, only in tests).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

impl Default for MockKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareKeyStore for MockKeyStore {
    fn generate_key(&self, label: &str) -> Result<PublicKey> {
        let config = self.config.lock().unwrap().clone();

        if !config.available {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        if config.simulate_error {
            return Err(Error::HardwareKeyStoreError {
                detail: "Mock hardware error".to_string(),
            });
        }

        let mut keys = self.keys.lock().unwrap();

        // Check if key already exists
        if keys.contains_key(label) {
            return Err(Error::other(format!(
                "Key with label '{label}' already exists"
            )));
        }

        // Generate P-256 keypair
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let public = secret.public_key();

        keys.insert(label.to_string(), (secret, public));

        Ok(public)
    }

    fn get_public_key(&self, label: &str) -> Result<PublicKey> {
        let config = self.config.lock().unwrap().clone();

        if !config.available {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        if config.simulate_error {
            return Err(Error::HardwareKeyStoreError {
                detail: "Mock hardware error".to_string(),
            });
        }

        let keys = self.keys.lock().unwrap();

        keys.get(label)
            .map(|(_, public)| *public)
            .ok_or_else(|| Error::HardwareKeyNotFound {
                label: label.to_string(),
            })
    }

    fn ecdh(&self, label: &str, peer_public: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        let config = self.config.lock().unwrap().clone();

        if !config.available {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        if config.deny_auth {
            return Err(Error::HardwareKeyStoreAuthDenied);
        }

        if config.simulate_error {
            return Err(Error::HardwareKeyStoreError {
                detail: "Mock hardware error".to_string(),
            });
        }

        let keys = self.keys.lock().unwrap();

        let (secret, _public) = keys.get(label).ok_or_else(|| Error::HardwareKeyNotFound {
            label: label.to_string(),
        })?;

        // Perform ECDH
        let shared_secret =
            p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer_public.as_affine());
        Ok(Zeroizing::new(*shared_secret.raw_secret_bytes().as_ref()))
    }

    fn key_exists(&self, label: &str) -> Result<bool> {
        let config = self.config.lock().unwrap().clone();

        if !config.available {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        let keys = self.keys.lock().unwrap();
        Ok(keys.contains_key(label))
    }

    fn delete_key(&self, label: &str) -> Result<()> {
        let config = self.config.lock().unwrap().clone();

        if !config.available {
            return Err(Error::HardwareKeyStoreUnavailable);
        }

        if config.simulate_error {
            return Err(Error::HardwareKeyStoreError {
                detail: "Mock hardware error".to_string(),
            });
        }

        let mut keys = self.keys.lock().unwrap();

        if keys.remove(label).is_none() {
            return Err(Error::HardwareKeyNotFound {
                label: label.to_string(),
            });
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        self.config.lock().unwrap().available
    }

    fn display_name(&self) -> &'static str {
        "Mock Hardware Key Store"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdh::EphemeralSecret;

    #[test]
    fn test_mock_default_available() {
        let mock = MockKeyStore::new();
        assert!(mock.is_available());
        assert_eq!(mock.display_name(), "Mock Hardware Key Store");
    }

    #[test]
    fn test_mock_generate_key() {
        let mock = MockKeyStore::new();
        let label = "test-key";

        let _public_key = mock.generate_key(label).unwrap();
        assert_eq!(mock.key_count(), 1);

        // Verify key exists
        assert!(mock.key_exists(label).unwrap());

        // Try to generate same label again (should fail)
        let result = mock.generate_key(label);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_ecdh() {
        let mock = MockKeyStore::new();
        let label = "test-key";

        // Generate key in mock hardware
        let hw_public = mock.generate_key(label).unwrap();

        // Generate ephemeral keypair
        let ephemeral_secret = EphemeralSecret::random(&mut rand_core::OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform ECDH from mock side
        let mock_shared = mock.ecdh(label, &ephemeral_public).unwrap();

        // Perform ECDH from ephemeral side
        let ephemeral_shared = crate::ecies::ecdh(&ephemeral_secret, &hw_public);

        // Should match
        assert_eq!(&*mock_shared, &*ephemeral_shared);
    }

    #[test]
    fn test_mock_ecdh_missing_key() {
        let mock = MockKeyStore::new();
        let ephemeral_public = PublicKey::from(&EphemeralSecret::random(&mut rand_core::OsRng));

        let result = mock.ecdh("nonexistent", &ephemeral_public);
        assert!(matches!(result, Err(Error::HardwareKeyNotFound { .. })));
    }

    #[test]
    fn test_mock_delete_key() {
        let mock = MockKeyStore::new();
        let label = "test-key";

        mock.generate_key(label).unwrap();
        assert_eq!(mock.key_count(), 1);

        mock.delete_key(label).unwrap();
        assert_eq!(mock.key_count(), 0);
        assert!(!mock.key_exists(label).unwrap());
    }

    #[test]
    fn test_mock_delete_nonexistent() {
        let mock = MockKeyStore::new();
        let result = mock.delete_key("nonexistent");
        assert!(matches!(result, Err(Error::HardwareKeyNotFound { .. })));
    }

    #[test]
    fn test_mock_unavailable() {
        let mock = MockKeyStore::with_config(MockConfig {
            available: false,
            ..Default::default()
        });

        assert!(!mock.is_available());

        let result = mock.generate_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreUnavailable)));
    }

    #[test]
    fn test_mock_auth_denied() {
        let mock = MockKeyStore::new();
        let label = "test-key";

        // Generate key first
        let _hw_public = mock.generate_key(label).unwrap();

        // Configure auth denial
        mock.set_config(MockConfig {
            available: true,
            deny_auth: true,
            simulate_error: false,
        });

        let ephemeral_public = PublicKey::from(&EphemeralSecret::random(&mut rand_core::OsRng));
        let result = mock.ecdh(label, &ephemeral_public);
        assert!(matches!(result, Err(Error::HardwareKeyStoreAuthDenied)));
    }

    #[test]
    fn test_mock_hardware_error() {
        let mock = MockKeyStore::with_config(MockConfig {
            available: true,
            deny_auth: false,
            simulate_error: true,
        });

        let result = mock.generate_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreError { .. })));

        // Delete also fails with hardware error
        let result = mock.delete_key("test");
        assert!(matches!(result, Err(Error::HardwareKeyStoreError { .. })));
    }

    #[test]
    fn test_mock_clear() {
        let mock = MockKeyStore::new();

        mock.generate_key("key1").unwrap();
        mock.generate_key("key2").unwrap();
        assert_eq!(mock.key_count(), 2);

        mock.clear();
        assert_eq!(mock.key_count(), 0);
    }

    #[test]
    fn test_mock_config_update() {
        let mock = MockKeyStore::new();
        assert!(mock.is_available());

        mock.set_config(MockConfig {
            available: false,
            ..Default::default()
        });

        assert!(!mock.is_available());

        let config = mock.get_config();
        assert!(!config.available);
    }
}
