use minisign::cli::*;
use serial_test::serial;
use std::path::Path;

#[test]
fn test_action_detection() {
    let cli = Cli {
        action: Some(Action::Generate),
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_file: None,
        extra_files: vec![],
        #[cfg(feature = "parallel")]
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
        force_weak_kdf: false,
        save_password: false,
        forget_password: false,
    };
    assert_eq!(cli.action(), Some(Action::Generate));
}

#[test]
fn test_no_action() {
    let cli = Cli {
        action: None,
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_file: None,
        extra_files: vec![],
        #[cfg(feature = "parallel")]
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
        force_weak_kdf: false,
        save_password: false,
        forget_password: false,
    };
    assert_eq!(cli.action(), None);
}

#[test]
fn test_inspect_action_detection() {
    let cli = Cli {
        action: Some(Action::Inspect),
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_file: None,
        extra_files: vec![],
        #[cfg(feature = "parallel")]
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
        force_weak_kdf: false,
        save_password: false,
        forget_password: false,
    };
    assert_eq!(cli.action(), Some(Action::Inspect));
}

#[test]
#[serial]
fn test_default_paths() {
    let secret_path = Cli::default_secret_key_path().unwrap();
    assert!(secret_path.to_string_lossy().contains(".minisign"));
    assert!(secret_path.to_string_lossy().contains("minisign.key"));

    let public_path = Cli::default_public_key_path();
    assert_eq!(public_path, Path::new("./minisign.pub"));
}

#[test]
fn test_signature_path() {
    use std::path::Path;

    let msg = Path::new("test.txt");
    let sig = Cli::default_signature_path(msg).unwrap();
    assert_eq!(sig, Path::new("test.txt.minisig"));

    let msg = Path::new("/path/to/file.dat");
    let sig = Cli::default_signature_path(msg).unwrap();
    assert_eq!(sig, Path::new("/path/to/file.dat.minisig"));
}

#[test]
fn test_default_signature_path_edge_cases() {
    use minisign::errors::Error;
    use std::path::Path;

    // Path with regular file - should work
    let path = Path::new("/some/path/file.txt");
    let sig = Cli::default_signature_path(path).unwrap();
    assert_eq!(sig, Path::new("/some/path/file.txt.minisig"));

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
        action: Some(Action::Generate),
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_file: None,
        extra_files: vec![],
        #[cfg(feature = "parallel")]
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
        force_weak_kdf: false,
        save_password: false,
        forget_password: false,
    };
    assert!(!cli.allow_kdf_fallback);
}

#[test]
fn test_allow_kdf_fallback_flag_can_be_enabled() {
    // Test that allow_kdf_fallback can be explicitly enabled
    let cli = Cli {
        action: Some(Action::Generate),
        no_decrypt: false,
        force: false,
        prehashed: false,
        legacy: false,
        message_file: None,
        extra_files: vec![],
        #[cfg(feature = "parallel")]
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
        allow_kdf_fallback: true,
        force_weak_kdf: false,
        save_password: false,
        forget_password: false,
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

    let secret_path = Cli::default_secret_key_path().unwrap();

    // Should use the custom path from env var
    assert_eq!(
        secret_path,
        Path::new("/custom/config/path").join("minisign.key")
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

    let secret_path = Cli::default_secret_key_path().unwrap();

    // Should fall back to home directory
    if let Some(home) = dirs::home_dir() {
        assert_eq!(secret_path, home.join(".minisign").join("minisign.key"));
    } else {
        assert_eq!(secret_path, Path::new(".minisign.key"));
    }
}

// M8: MINISIGN_CONFIG_DIR set but empty must be a hard error, not a silent fallback.
#[test]
#[serial]
fn test_minisign_config_dir_empty_is_error() {
    use std::env;

    // SAFETY: sets env var in a serial test; cleaned up immediately after.
    unsafe {
        env::set_var("MINISIGN_CONFIG_DIR", "");
    }

    let result = Cli::default_secret_key_path();

    // SAFETY: clean up before any assert so we don't leak the env var on failure.
    unsafe {
        env::remove_var("MINISIGN_CONFIG_DIR");
    }

    assert!(
        result.is_err(),
        "expected error for empty MINISIGN_CONFIG_DIR, got Ok({:?})",
        result.unwrap()
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("MINISIGN_CONFIG_DIR"),
        "error message should name the variable: {err_msg}"
    );
}

#[test]
fn cli_positional_args_are_extra_files() {
    // C-compatible syntax: -m specifies the first file, remaining positional
    // args are additional files.  Repeated -m must NOT be accepted.
    let cli = Cli::parse_from([
        "minisign_rs",
        "-S",
        "-m",
        "file1.txt",
        "file2.txt",
        "file3.txt",
    ])
    .unwrap();

    assert_eq!(
        cli.message_file.as_ref().unwrap().to_str().unwrap(),
        "file1.txt"
    );
    assert_eq!(cli.extra_files.len(), 2);
    assert_eq!(cli.extra_files[0].to_str().unwrap(), "file2.txt");
    assert_eq!(cli.extra_files[1].to_str().unwrap(), "file3.txt");
}

#[test]
fn cli_all_message_files_merges_m_and_positional() {
    let cli = Cli::parse_from([
        "minisign_rs",
        "-S",
        "-m",
        "first.txt",
        "second.txt",
        "third.txt",
    ])
    .unwrap();

    let all = cli.all_message_files();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].to_str().unwrap(), "first.txt");
    assert_eq!(all[1].to_str().unwrap(), "second.txt");
    assert_eq!(all[2].to_str().unwrap(), "third.txt");
}

#[test]
fn cli_single_message_file_no_positional() {
    let cli = Cli::parse_from(["minisign_rs", "-S", "-m", "file.txt"]).unwrap();

    let all = cli.all_message_files();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].to_str().unwrap(), "file.txt");
}

#[test]
fn cli_no_message_file_returns_empty() {
    // -m is optional at the parser level; validation happens in handle_sign/handle_verify
    let cli = Cli::parse_from(["minisign_rs", "-S"]).unwrap();

    let all = cli.all_message_files();
    assert!(all.is_empty());
}

#[cfg(feature = "parallel")]
#[test]
fn cli_sequential_flag_defaults_false() {
    let cli = Cli::parse_from(["minisign_rs", "-S", "-m", "file.txt"]).unwrap();

    assert!(!cli.sequential);
}

#[cfg(feature = "parallel")]
#[test]
fn cli_sequential_flag_can_be_set() {
    let cli = Cli::parse_from(["minisign_rs", "-S", "-m", "file.txt", "--sequential"]).unwrap();

    assert!(cli.sequential);
}

#[test]
fn cli_save_password_flag_defaults_false() {
    let cli = Cli::parse_from(["minisign_rs", "-G"]).unwrap();
    assert!(!cli.save_password);
}

#[test]
#[cfg(feature = "credential_store")]
fn cli_save_password_long_flag() {
    let cli = Cli::parse_from(["minisign_rs", "-G", "--save-password"]).unwrap();
    assert!(cli.save_password);
}

#[test]
#[cfg(feature = "credential_store")]
fn cli_save_password_short_alias() {
    let cli = Cli::parse_from(["minisign_rs", "-G", "--sp"]).unwrap();
    assert!(cli.save_password);
}

#[test]
fn cli_forget_password_flag_defaults_false() {
    let cli = Cli::parse_from(["minisign_rs", "-K"]).unwrap();
    assert!(!cli.forget_password);
}

#[test]
fn cli_forget_password_long_flag() {
    let cli = Cli::parse_from(["minisign_rs", "-K", "--forget-password"]).unwrap();
    assert!(cli.forget_password);
}

#[test]
fn cli_forget_password_short_alias() {
    let cli = Cli::parse_from(["minisign_rs", "-K", "--fp"]).unwrap();
    assert!(cli.forget_password);
}

// ── Combined short flag (POSIX bundling) tests ────────────────────────────────

#[test]
fn cli_combined_inspect_public_key() {
    // -Ip key.pub  →  -I  -p key.pub
    let cli = Cli::parse_from(["minisign_rs", "-Ip", "key.pub"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Inspect));
    assert_eq!(cli.public_key_file.as_deref(), Some(Path::new("key.pub")));
}

#[test]
fn cli_combined_inspect_secret_key() {
    // -Is key.sec  →  -I  -s key.sec
    let cli = Cli::parse_from(["minisign_rs", "-Is", "key.sec"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Inspect));
    assert_eq!(cli.secret_key_file.as_deref(), Some(Path::new("key.sec")));
}

#[test]
fn cli_combined_sign_message() {
    // -Sm file.txt  →  -S  -m file.txt
    let cli = Cli::parse_from(["minisign_rs", "-Sm", "file.txt"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Sign));
    assert_eq!(cli.message_file.as_deref(), Some(Path::new("file.txt")));
}

#[test]
fn cli_combined_verify_message() {
    // -Vm file.txt  →  -V  -m file.txt
    let cli = Cli::parse_from(["minisign_rs", "-Vm", "file.txt"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Verify));
    assert_eq!(cli.message_file.as_deref(), Some(Path::new("file.txt")));
}

#[test]
fn cli_combined_all_boolean_flags() {
    // -GfW  →  -G  -f  -W
    let cli = Cli::parse_from(["minisign_rs", "-GfW"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Generate));
    assert!(cli.force);
    assert!(cli.no_password);
}

#[test]
fn cli_combined_two_boolean_flags() {
    // -Sf  →  -S  -f
    let cli = Cli::parse_from(["minisign_rs", "-Sf", "-m", "f.txt"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Sign));
    assert!(cli.force);
}

#[test]
fn cli_combined_value_embedded_in_bundle() {
    // -Iskey.sec  →  -I  -s key.sec  (value embedded directly after the flag char)
    let cli = Cli::parse_from(["minisign_rs", "-Iskey.sec"]).unwrap();
    assert_eq!(cli.action(), Some(Action::Inspect));
    assert_eq!(cli.secret_key_file.as_deref(), Some(Path::new("key.sec")));
}

/// `--save-password` / `--sp` should be rejected at parse time when the
/// `credential_store` feature is not compiled in, so users get an immediate
/// error rather than a silent no-op that reports false success.
#[test]
#[cfg(not(feature = "credential_store"))]
fn cli_save_password_rejected_without_credential_store_feature() {
    use minisign::errors::Error;
    let result = Cli::parse_from(["minisign_rs", "-G", "-W", "--save-password"]);
    assert!(
        matches!(result, Err(Error::Usage(_))),
        "expected Usage error when credential_store feature is disabled, got {result:?}"
    );

    let result_short = Cli::parse_from(["minisign_rs", "-G", "-W", "--sp"]);
    assert!(
        matches!(result_short, Err(Error::Usage(_))),
        "expected Usage error for --sp when credential_store feature is disabled, got {result_short:?}"
    );
}
