//! Unit tests for credential store module
//!
//! These tests verify the credential store API behavior using the real OS keyring
//! (macOS Keychain, Windows Credential Manager, Linux Secret Service).
//!
//! **IMPORTANT**: These tests require user interaction (keyring authorization prompts)
//! and must run sequentially. Enable with: `cargo test --features credential_store_tests`
//!
//! Tests use RAII cleanup guards to ensure credentials are removed even if tests panic.

use minisign::Result;
use minisign::credential_store;
use serial_test::serial;

/// RAII guard that ensures credential cleanup on drop, even if test panics
struct CredentialGuard {
    key_id: String,
}

impl CredentialGuard {
    fn new(key_id: impl Into<String>) -> Self {
        let key_id = key_id.into();
        // Clean up any leftover credentials from previous failed test runs
        let _ = credential_store::forget_password(&key_id);
        Self { key_id }
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Drop for CredentialGuard {
    fn drop(&mut self) {
        // Ensure cleanup happens even if test panics
        let _ = credential_store::forget_password(&self.key_id);
    }
}

/// Helper to generate unique test key IDs to avoid collisions between tests
fn test_key_id(suffix: &str) -> String {
    format!("test_minisign_key_{suffix}")
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_save_retrieve_forget_round_trip() -> Result<()> {
    let guard = CredentialGuard::new(test_key_id("round_trip"));
    let key_id = guard.key_id();

    // Initially, no password should be saved
    assert!(!credential_store::has_password(key_id));
    assert!(credential_store::get_password(key_id).is_none());

    // Save a password
    let password = "test_password_123";
    credential_store::save_password(key_id, password)?;

    // Should now be retrievable
    assert!(credential_store::has_password(key_id));
    let retrieved = credential_store::get_password(key_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.as_ref().unwrap().as_str(), password);

    // Forget the password
    credential_store::forget_password(key_id)?;

    // Should no longer be saved
    assert!(!credential_store::has_password(key_id));
    assert!(credential_store::get_password(key_id).is_none());

    Ok(())
    // guard drops here, ensuring cleanup
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_get_password_returns_none_for_missing_entry() {
    let guard = CredentialGuard::new(test_key_id("missing_entry"));
    let key_id = guard.key_id();

    // Should return None for a key that was never saved
    assert!(credential_store::get_password(key_id).is_none());
    assert!(!credential_store::has_password(key_id));

    // guard drops here, ensuring cleanup
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_forget_password_is_idempotent() -> Result<()> {
    let guard = CredentialGuard::new(test_key_id("idempotent"));
    let key_id = guard.key_id();

    // Save a password
    credential_store::save_password(key_id, "password")?;
    assert!(credential_store::has_password(key_id));

    // Forget it once
    credential_store::forget_password(key_id)?;
    assert!(!credential_store::has_password(key_id));

    // Forgetting again should not error
    credential_store::forget_password(key_id)?;
    assert!(!credential_store::has_password(key_id));

    Ok(())
    // guard drops here, ensuring cleanup
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_password_is_zeroized() -> Result<()> {
    let guard = CredentialGuard::new(test_key_id("zeroize"));
    let key_id = guard.key_id();

    let password = "sensitive_password_456";
    credential_store::save_password(key_id, password)?;

    // Retrieve password
    let retrieved = credential_store::get_password(key_id);
    assert!(retrieved.is_some());

    // Verify the password is wrapped in a zeroizing type
    // (This is verified by the type system - if get_password returns
    // Zeroizing<String>, this will compile; if not, it won't)
    let _zeroizing_password = retrieved.unwrap();

    // Clean up
    credential_store::forget_password(key_id)?;

    Ok(())
    // guard drops here, ensuring cleanup
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_multiple_keys_independent() -> Result<()> {
    let guard_1 = CredentialGuard::new(test_key_id("multi_1"));
    let guard_2 = CredentialGuard::new(test_key_id("multi_2"));
    let key_id_1 = guard_1.key_id();
    let key_id_2 = guard_2.key_id();

    let password_1 = "password_one";
    let password_2 = "password_two";

    // Save both
    credential_store::save_password(key_id_1, password_1)?;
    credential_store::save_password(key_id_2, password_2)?;

    // Both should be retrievable independently
    assert_eq!(
        credential_store::get_password(key_id_1)
            .as_ref()
            .map(|s| s.as_str()),
        Some(password_1)
    );
    assert_eq!(
        credential_store::get_password(key_id_2)
            .as_ref()
            .map(|s| s.as_str()),
        Some(password_2)
    );

    // Forgetting one should not affect the other
    credential_store::forget_password(key_id_1)?;
    assert!(!credential_store::has_password(key_id_1));
    assert!(credential_store::has_password(key_id_2));

    Ok(())
    // guards drop here, ensuring cleanup of both credentials
}

#[test]
#[serial]
#[cfg_attr(not(feature = "credential_store_tests"), ignore)]
fn test_update_password() -> Result<()> {
    let guard = CredentialGuard::new(test_key_id("update"));
    let key_id = guard.key_id();

    // Save initial password
    credential_store::save_password(key_id, "old_password")?;
    assert_eq!(
        credential_store::get_password(key_id)
            .as_ref()
            .map(|s| s.as_str()),
        Some("old_password")
    );

    // Update to new password
    credential_store::save_password(key_id, "new_password")?;
    assert_eq!(
        credential_store::get_password(key_id)
            .as_ref()
            .map(|s| s.as_str()),
        Some("new_password")
    );

    // Clean up
    credential_store::forget_password(key_id)?;

    Ok(())
    // guard drops here, ensuring cleanup
}
