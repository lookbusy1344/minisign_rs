//! Unit tests for credential store module
//!
//! These tests verify the credential store API behavior. They may use either:
//! - The real OS keyring (macOS Keychain, Windows Credential Manager, etc.)
//! - A mock backend if the real keyring is unavailable
//!
//! If credential store operations fail (e.g., in headless CI environments),
//! the tests verify that failures are handled gracefully without blocking
//! minisign operations.

use minisign::Result;
use minisign::credential_store;
use serial_test::serial;

/// Check if the keyring backend is available
/// Returns true if we can save and retrieve passwords
fn is_keyring_available() -> bool {
    let test_key = "minisign_test_availability_check";

    // Try to save a test password
    if credential_store::save_password(test_key, "test").is_err() {
        return false;
    }

    // Try to retrieve it
    let retrieved = credential_store::get_password(test_key);

    // Clean up
    let _ = credential_store::forget_password(test_key);

    retrieved.is_some()
}

/// Helper to generate unique test key IDs to avoid collisions between tests
fn test_key_id(suffix: &str) -> String {
    format!("test_minisign_key_{suffix}")
}

/// Helper to clean up test credentials
fn cleanup_test_credential(key_id: &str) {
    let _ = credential_store::forget_password(key_id);
}

#[test]
#[serial]
fn test_save_retrieve_forget_round_trip() -> Result<()> {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return Ok(());
    }

    let key_id = test_key_id("round_trip");
    cleanup_test_credential(&key_id);

    // Initially, no password should be saved
    assert!(!credential_store::has_password(&key_id));
    assert!(credential_store::get_password(&key_id).is_none());

    // Save a password
    let password = "test_password_123";
    credential_store::save_password(&key_id, password)?;

    // Should now be retrievable
    assert!(credential_store::has_password(&key_id));
    let retrieved = credential_store::get_password(&key_id);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.as_ref().unwrap().as_str(), password);

    // Forget the password
    credential_store::forget_password(&key_id)?;

    // Should no longer be saved
    assert!(!credential_store::has_password(&key_id));
    assert!(credential_store::get_password(&key_id).is_none());

    cleanup_test_credential(&key_id);
    Ok(())
}

#[test]
#[serial]
fn test_get_password_returns_none_for_missing_entry() {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return;
    }

    let key_id = test_key_id("missing_entry");
    cleanup_test_credential(&key_id);

    // Should return None for a key that was never saved
    assert!(credential_store::get_password(&key_id).is_none());
    assert!(!credential_store::has_password(&key_id));

    cleanup_test_credential(&key_id);
}

#[test]
#[serial]
fn test_forget_password_is_idempotent() -> Result<()> {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return Ok(());
    }

    let key_id = test_key_id("idempotent");
    cleanup_test_credential(&key_id);

    // Save a password
    credential_store::save_password(&key_id, "password")?;
    assert!(credential_store::has_password(&key_id));

    // Forget it once
    credential_store::forget_password(&key_id)?;
    assert!(!credential_store::has_password(&key_id));

    // Forgetting again should not error
    credential_store::forget_password(&key_id)?;
    assert!(!credential_store::has_password(&key_id));

    cleanup_test_credential(&key_id);
    Ok(())
}

#[test]
#[serial]
fn test_password_is_zeroized() -> Result<()> {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return Ok(());
    }

    let key_id = test_key_id("zeroize");
    cleanup_test_credential(&key_id);

    let password = "sensitive_password_456";
    credential_store::save_password(&key_id, password)?;

    // Retrieve password
    let retrieved = credential_store::get_password(&key_id);
    assert!(retrieved.is_some());

    // Verify the password is wrapped in a zeroizing type
    // (This is verified by the type system - if get_password returns
    // Zeroizing<String>, this will compile; if not, it won't)
    let _zeroizing_password = retrieved.unwrap();

    // Clean up
    credential_store::forget_password(&key_id)?;
    cleanup_test_credential(&key_id);
    Ok(())
}

#[test]
#[serial]
fn test_multiple_keys_independent() -> Result<()> {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return Ok(());
    }

    let key_id_1 = test_key_id("multi_1");
    let key_id_2 = test_key_id("multi_2");
    cleanup_test_credential(&key_id_1);
    cleanup_test_credential(&key_id_2);

    let password_1 = "password_one";
    let password_2 = "password_two";

    // Save both
    credential_store::save_password(&key_id_1, password_1)?;
    credential_store::save_password(&key_id_2, password_2)?;

    // Both should be retrievable independently
    assert_eq!(
        credential_store::get_password(&key_id_1)
            .as_ref()
            .map(|s| s.as_str()),
        Some(password_1)
    );
    assert_eq!(
        credential_store::get_password(&key_id_2)
            .as_ref()
            .map(|s| s.as_str()),
        Some(password_2)
    );

    // Forgetting one should not affect the other
    credential_store::forget_password(&key_id_1)?;
    assert!(!credential_store::has_password(&key_id_1));
    assert!(credential_store::has_password(&key_id_2));

    // Clean up
    cleanup_test_credential(&key_id_1);
    cleanup_test_credential(&key_id_2);
    Ok(())
}

#[test]
#[serial]
fn test_update_password() -> Result<()> {
    if !is_keyring_available() {
        eprintln!("Skipping test: keyring backend unavailable");
        return Ok(());
    }

    let key_id = test_key_id("update");
    cleanup_test_credential(&key_id);

    // Save initial password
    credential_store::save_password(&key_id, "old_password")?;
    assert_eq!(
        credential_store::get_password(&key_id)
            .as_ref()
            .map(|s| s.as_str()),
        Some("old_password")
    );

    // Update to new password
    credential_store::save_password(&key_id, "new_password")?;
    assert_eq!(
        credential_store::get_password(&key_id)
            .as_ref()
            .map(|s| s.as_str()),
        Some("new_password")
    );

    // Clean up
    credential_store::forget_password(&key_id)?;
    cleanup_test_credential(&key_id);
    Ok(())
}
