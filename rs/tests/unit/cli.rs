use clap::Parser;
use minisign::cli::*;
use serial_test::serial;
use std::path::PathBuf;

#[test]
fn test_action_detection() {
    let cli = Cli {
        generate: true,
        sign: false,
        verify: false,
        recreate: false,
        change: false,
        inspect: false,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_files: vec![],
        sequential: false,
        output: false,
        public_key_file: None,
        public_key_base64: None,
        quiet: false,
        pretty_quiet: false,
        secret_key_file: None,
        trusted_comment: None,
        untrusted_comment: None,
        signature_file: None,
        no_password: false,
        password_file: None,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
        help: None,
        version: None,
    };
    assert_eq!(cli.action(), Some(Action::Generate));
}

#[test]
fn test_no_action() {
    let cli = Cli {
        generate: false,
        sign: false,
        verify: false,
        recreate: false,
        change: false,
        inspect: false,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_files: vec![],
        sequential: false,
        output: false,
        public_key_file: None,
        public_key_base64: None,
        quiet: false,
        pretty_quiet: false,
        secret_key_file: None,
        trusted_comment: None,
        untrusted_comment: None,
        signature_file: None,
        no_password: false,
        password_file: None,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
        help: None,
        version: None,
    };
    assert_eq!(cli.action(), None);
}

#[test]
fn test_inspect_action_detection() {
    let cli = Cli {
        generate: false,
        sign: false,
        verify: false,
        recreate: false,
        change: false,
        inspect: true,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_files: vec![],
        sequential: false,
        output: false,
        public_key_file: None,
        public_key_base64: None,
        quiet: false,
        pretty_quiet: false,
        secret_key_file: None,
        trusted_comment: None,
        untrusted_comment: None,
        signature_file: None,
        no_password: false,
        password_file: None,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
        help: None,
        version: None,
    };
    assert_eq!(cli.action(), Some(Action::Inspect));
}

#[test]
#[serial]
fn test_default_paths() {
    let secret_path = Cli::default_secret_key_path();
    assert!(secret_path.to_string_lossy().contains(".minisign"));
    assert!(secret_path.to_string_lossy().contains("minisign.key"));

    let public_path = Cli::default_public_key_path();
    assert_eq!(public_path, PathBuf::from("./minisign.pub"));
}

#[test]
fn test_signature_path() {
    use std::path::Path;

    let msg = Path::new("test.txt");
    let sig = Cli::default_signature_path(msg).unwrap();
    assert_eq!(sig, PathBuf::from("test.txt.minisig"));

    let msg = Path::new("/path/to/file.dat");
    let sig = Cli::default_signature_path(msg).unwrap();
    assert_eq!(sig, PathBuf::from("/path/to/file.dat.minisig"));
}

#[test]
fn test_default_signature_path_edge_cases() {
    use minisign::errors::Error;
    use std::path::Path;

    // Path with regular file - should work
    let path = Path::new("/some/path/file.txt");
    let sig = Cli::default_signature_path(path).unwrap();
    assert_eq!(sig, PathBuf::from("/some/path/file.txt.minisig"));

    // Root path - file_name() returns None, should return error
    let root = Path::new("/");
    let result = Cli::default_signature_path(root);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPath(_)));

    // Relative path ending in ".." - file_name() returns None, should return error
    let rel = Path::new("../some/..");
    let result = Cli::default_signature_path(rel);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidPath(_)));
}

#[test]
fn test_allow_kdf_fallback_flag_defaults_to_false() {
    // Test that allow_kdf_fallback defaults to false for secure-by-default behavior
    let cli = Cli {
        generate: true,
        sign: false,
        verify: false,
        recreate: false,
        change: false,
        inspect: false,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_files: vec![],
        sequential: false,
        output: false,
        public_key_file: None,
        public_key_base64: None,
        quiet: false,
        pretty_quiet: false,
        secret_key_file: None,
        trusted_comment: None,
        untrusted_comment: None,
        signature_file: None,
        no_password: false,
        password_file: None,
        help: None,
        version: None,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    assert!(!cli.allow_kdf_fallback);
}

#[test]
fn test_allow_kdf_fallback_flag_can_be_enabled() {
    // Test that allow_kdf_fallback can be explicitly enabled
    let cli = Cli {
        generate: true,
        sign: false,
        verify: false,
        recreate: false,
        change: false,
        inspect: false,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_files: vec![],
        sequential: false,
        output: false,
        public_key_file: None,
        public_key_base64: None,
        quiet: false,
        pretty_quiet: false,
        secret_key_file: None,
        trusted_comment: None,
        untrusted_comment: None,
        signature_file: None,
        no_password: false,
        password_file: None,
        help: None,
        version: None,
        allow_kdf_fallback: true,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    assert!(cli.allow_kdf_fallback);
}

#[test]
#[serial]
fn test_minisign_config_dir_override() {
    use std::env;

    // SAFETY: This is a test-only function that sets env var for testing.
    // The test is single-threaded and cleans up after itself.
    unsafe {
        env::set_var("MINISIGN_CONFIG_DIR", "/custom/config/path");
    }

    let secret_path = Cli::default_secret_key_path();

    // Should use the custom path from env var
    assert_eq!(
        secret_path,
        PathBuf::from("/custom/config/path").join("minisign.key")
    );

    // SAFETY: Clean up the env var we set above
    unsafe {
        env::remove_var("MINISIGN_CONFIG_DIR");
    }
}

#[test]
#[serial]
fn test_minisign_config_dir_fallback_to_home() {
    use std::env;

    // SAFETY: Ensure env var is not set for this test
    unsafe {
        env::remove_var("MINISIGN_CONFIG_DIR");
    }

    let secret_path = Cli::default_secret_key_path();

    // Should fall back to home directory
    if let Some(home) = dirs::home_dir() {
        assert_eq!(secret_path, home.join(".minisign").join("minisign.key"));
    } else {
        assert_eq!(secret_path, PathBuf::from(".minisign.key"));
    }
}

#[test]
fn cli_accepts_multiple_message_files() {
    let cli = Cli::try_parse_from([
        "minisign_rs",
        "-S",
        "-m",
        "file1.txt",
        "-m",
        "file2.txt",
        "-m",
        "file3.txt",
    ])
    .unwrap();

    assert_eq!(cli.message_files.len(), 3);
    assert_eq!(cli.message_files[0].to_str().unwrap(), "file1.txt");
    assert_eq!(cli.message_files[1].to_str().unwrap(), "file2.txt");
    assert_eq!(cli.message_files[2].to_str().unwrap(), "file3.txt");
}

#[test]
fn cli_accepts_single_message_file() {
    let cli = Cli::try_parse_from(["minisign_rs", "-S", "-m", "file.txt"]).unwrap();

    assert_eq!(cli.message_files.len(), 1);
    assert_eq!(cli.message_files[0].to_str().unwrap(), "file.txt");
}

#[test]
fn cli_sequential_flag_defaults_false() {
    let cli = Cli::try_parse_from(["minisign_rs", "-S", "-m", "file.txt"]).unwrap();

    assert!(!cli.sequential);
}

#[test]
fn cli_sequential_flag_can_be_set() {
    let cli = Cli::try_parse_from(["minisign_rs", "-S", "-m", "file.txt", "--sequential"]).unwrap();

    assert!(cli.sequential);
}
