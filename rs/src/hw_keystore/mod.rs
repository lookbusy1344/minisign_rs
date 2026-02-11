//! Hardware key store abstraction for platform-specific secure storage
//!
//! This module provides a trait-based abstraction over platform-specific hardware
//! security modules (HSMs) like macOS Secure Enclave, Windows TPM, and Linux TPM.
//!
//! ## Design
//!
//! The `HardwareKeyStore` trait defines operations for:
//! - Generating P-256 keys protected by device authentication (biometric/PIN)
//! - Performing ECDH inside hardware (key never leaves secure boundary)
//! - Key lifecycle management (existence checks, deletion)
//!
//! ## Implementations
//!
//! - **Mock**: In-memory implementation for testing
//! - **macOS**: Secure Enclave via `security-framework`
//! - **Windows**: TPM 2.0 via Windows CNG (future)
//! - **Linux**: TPM 2.0 via `tss-esapi` (future)
//! - **Unsupported**: Stub for platforms without hardware backend

use crate::errors::Result;
use zeroize::Zeroizing;

// Platform-specific implementations
// Mock is always available for testing purposes (not compiled in release if unused)
pub mod mock;

#[cfg(all(target_os = "macos", feature = "hw-keystore-macos"))]
pub mod macos;

#[cfg(all(target_os = "windows", feature = "hw-keystore-windows"))]
pub mod windows;

#[cfg(all(target_os = "linux", feature = "hw-keystore-linux"))]
pub mod linux;

// Unsupported fallback for platforms without a backend
#[cfg(not(any(
    all(target_os = "macos", feature = "hw-keystore-macos"),
    all(target_os = "windows", feature = "hw-keystore-windows"),
    all(target_os = "linux", feature = "hw-keystore-linux")
)))]
pub mod unsupported;

/// Hardware key store trait for platform-specific secure key storage
///
/// Implementations provide access to hardware security modules that can:
/// - Generate P-256 keys that never leave the hardware
/// - Perform ECDH operations inside the hardware
/// - Require device authentication (biometric/PIN) for key use
///
/// ## Security Model
///
/// Keys are identified by labels (e.g., "minisign:a1b2c3d4e5f6g7h8") and are
/// bound to the device. The private key never leaves the hardware boundary.
///
/// ## Platform Availability
///
/// Not all platforms have hardware key store support. Use `is_available()`
/// to check before attempting operations.
pub trait HardwareKeyStore {
    /// Generate a new P-256 key pair in hardware, gated by device auth.
    ///
    /// The private key stays in hardware and is protected by device authentication
    /// (biometric, PIN, or device password). Only the public key is returned.
    ///
    /// # Arguments
    ///
    /// * `label` - Key label for identification (e.g., "minisign:a1b2c3d4e5f6g7h8")
    ///
    /// # Returns
    ///
    /// Returns the public key component. The private key remains in hardware.
    ///
    /// # Errors
    ///
    /// - `HardwareKeyStoreUnavailable` - Hardware not available on this platform
    /// - `HardwareKeyStoreError` - Key generation failed
    /// - `Other` - Label already exists or other hardware error
    fn generate_key(&self, label: &str) -> Result<p256::PublicKey>;

    /// Get the public key for a hardware key.
    ///
    /// Retrieves the public component of a hardware key. The private key
    /// remains in hardware and is never exported.
    ///
    /// # Arguments
    ///
    /// * `label` - Key label identifying the hardware key
    ///
    /// # Returns
    ///
    /// Returns the public key component.
    ///
    /// # Errors
    ///
    /// - `HardwareKeyNotFound` - Key with this label doesn't exist
    /// - `HardwareKeyStoreError` - Failed to retrieve public key
    fn get_public_key(&self, label: &str) -> Result<p256::PublicKey>;

    /// Perform ECDH inside hardware: `shared_secret = ECDH(hw_private, peer_public)`.
    ///
    /// Triggers device authentication prompt (biometric/PIN). The ECDH computation
    /// happens inside the hardware security boundary, and only the shared secret
    /// is returned (never the private key).
    ///
    /// # Arguments
    ///
    /// * `label` - Key label identifying the hardware private key
    /// * `peer_public` - The peer's public key (ephemeral public key during decryption)
    ///
    /// # Returns
    ///
    /// Returns the ECDH shared secret wrapped in `Zeroizing<>`.
    ///
    /// # Errors
    ///
    /// - `HardwareKeyNotFound` - Key with this label doesn't exist
    /// - `HardwareKeyStoreAuthDenied` - User denied authentication prompt
    /// - `HardwareKeyStoreError` - ECDH operation failed
    fn ecdh(&self, label: &str, peer_public: &p256::PublicKey) -> Result<Zeroizing<[u8; 32]>>;

    /// Check if a key with this label exists in hardware.
    ///
    /// # Arguments
    ///
    /// * `label` - Key label to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the key exists, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns error only if hardware access fails (not if key doesn't exist).
    fn key_exists(&self, label: &str) -> Result<bool>;

    /// Delete a key from hardware.
    ///
    /// # Arguments
    ///
    /// * `label` - Key label to delete
    ///
    /// # Errors
    ///
    /// - `HardwareKeyNotFound` - Key doesn't exist (may also return Ok depending on platform)
    /// - `HardwareKeyStoreError` - Deletion failed
    fn delete_key(&self, label: &str) -> Result<()>;

    /// Returns true if hardware key store is available on this platform.
    ///
    /// This checks for:
    /// - Platform support (macOS/Windows/Linux with hardware)
    /// - Hardware presence (Secure Enclave, TPM)
    /// - System configuration (drivers, permissions)
    #[must_use]
    fn is_available(&self) -> bool;

    /// Human-readable name for UI messages (e.g. "Secure Enclave", "TPM 2.0").
    ///
    /// Used in user-facing messages to indicate which hardware backend is being used.
    #[must_use]
    fn display_name(&self) -> &'static str;
}

/// Get the default hardware key store for the current platform
///
/// Returns the appropriate implementation based on compile-time platform detection:
/// - macOS: Secure Enclave (if feature enabled)
/// - Windows: TPM 2.0 (if feature enabled)
/// - Linux: TPM 2.0 (if feature enabled)
/// - Others: Unsupported stub
///
/// # Examples
///
/// ```no_run
/// use minisign::hw_keystore::{get_default_keystore, HardwareKeyStore};
///
/// let keystore = get_default_keystore();
/// if keystore.is_available() {
///     println!("Hardware key store available: {}", keystore.display_name());
/// } else {
///     println!("No hardware key store on this platform");
/// }
/// ```
#[must_use]
pub fn get_default_keystore() -> Box<dyn HardwareKeyStore> {
    #[cfg(all(target_os = "macos", feature = "hw-keystore-macos"))]
    {
        Box::new(macos::MacOSKeyStore::new())
    }

    #[cfg(all(target_os = "windows", feature = "hw-keystore-windows"))]
    {
        Box::new(windows::WindowsKeyStore::new())
    }

    #[cfg(all(target_os = "linux", feature = "hw-keystore-linux"))]
    {
        Box::new(linux::LinuxKeyStore::new())
    }

    #[cfg(not(any(
        all(target_os = "macos", feature = "hw-keystore-macos"),
        all(target_os = "windows", feature = "hw-keystore-windows"),
        all(target_os = "linux", feature = "hw-keystore-linux")
    )))]
    {
        Box::new(unsupported::UnsupportedKeyStore)
    }
}
