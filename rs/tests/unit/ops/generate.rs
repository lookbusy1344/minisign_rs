use minisign::hw_keystore::mock::{MockConfig, MockKeyStore};
use minisign::ops::{GenerateOptions, generate};
use tempfile::TempDir;

#[test]
fn test_generate_with_hardware_key_shows_feedback() {
    let temp_dir = TempDir::new().unwrap();
    let secret_key_path = temp_dir.path().join("test.key");
    let public_key_path = temp_dir.path().join("test.pub");

    let password = b"test_password";
    let mock_hw = MockKeyStore::new();

    // Build options with hardware key enabled and quiet disabled (default)
    let options = GenerateOptions::builder(&secret_key_path, &public_key_path)
        .hardware_key(true)
        .build();

    // Generate with hardware key
    let result = generate(&options, Some(password), Some(&mock_hw));

    // Should succeed with mock hardware key store
    if let Err(ref e) = result {
        eprintln!("Generation failed: {e}");
    }
    assert!(result.is_ok());

    // Verify files were created
    assert!(secret_key_path.exists());
    assert!(public_key_path.exists());
}

#[test]
fn test_generate_with_hardware_key_quiet_mode() {
    let temp_dir = TempDir::new().unwrap();
    let secret_key_path = temp_dir.path().join("test_quiet.key");
    let public_key_path = temp_dir.path().join("test_quiet.pub");

    let password = b"test_password";
    let mock_hw = MockKeyStore::new();

    // Build options with hardware key enabled and quiet mode
    let options = GenerateOptions::builder(&secret_key_path, &public_key_path)
        .hardware_key(true)
        .quiet(true)
        .build();

    // Generate with hardware key in quiet mode
    let result = generate(&options, Some(password), Some(&mock_hw));

    // Should succeed
    if let Err(ref e) = result {
        eprintln!("Generation failed: {e}");
    }
    assert!(result.is_ok());

    // Verify files were created
    assert!(secret_key_path.exists());
    assert!(public_key_path.exists());
}

#[test]
fn test_generate_hardware_key_requires_password() {
    let temp_dir = TempDir::new().unwrap();
    let secret_key_path = temp_dir.path().join("test_nopwd.key");
    let public_key_path = temp_dir.path().join("test_nopwd.pub");

    let mock_hw = MockKeyStore::new();

    // Try to generate with hardware key but no password
    let options = GenerateOptions::builder(&secret_key_path, &public_key_path)
        .hardware_key(true)
        .no_password(true)
        .build();

    let result = generate(&options, None, Some(&mock_hw));

    // Should fail - hardware key protection requires password
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("password"));
}

#[test]
fn test_generate_hardware_key_unavailable() {
    let temp_dir = TempDir::new().unwrap();
    let secret_key_path = temp_dir.path().join("test_unavail.key");
    let public_key_path = temp_dir.path().join("test_unavail.pub");

    let password = b"test_password";

    // Create mock with hardware unavailable
    let config = MockConfig {
        available: false,
        deny_auth: false,
        simulate_error: false,
    };
    let mock_hw = MockKeyStore::with_config(config);

    let options = GenerateOptions::builder(&secret_key_path, &public_key_path)
        .hardware_key(true)
        .build();

    let result = generate(&options, Some(password), Some(&mock_hw));

    // Should fail - hardware not available
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unavailable"));
}

#[test]
fn test_generate_without_hardware_key() {
    let temp_dir = TempDir::new().unwrap();
    let secret_key_path = temp_dir.path().join("test_no_hw.key");
    let public_key_path = temp_dir.path().join("test_no_hw.pub");

    let password = b"test_password";

    // Generate without hardware key (mock can be None)
    let options = GenerateOptions::builder(&secret_key_path, &public_key_path).build();

    let result = generate(&options, Some(password), None);

    // Should succeed without hardware key
    assert!(result.is_ok());

    // Verify files were created
    assert!(secret_key_path.exists());
    assert!(public_key_path.exists());
}
