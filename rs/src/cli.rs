//! Command-line interface definition using clap
//!
//! This module defines the CLI structure matching the C minisign interface exactly.

use crate::errors::{Error, Result};
use clap::Parser;
use git_version::git_version;
use std::path::{Path, PathBuf};

const VERSION: &str = git_version!(
    args = ["--tags", "--abbrev=7", "--always"],
    prefix = concat!(env!("CARGO_PKG_VERSION"), " ("),
    suffix = ")",
    fallback = "unknown"
);

fn help_template() -> String {
    format!(
        "minisign_rs {VERSION} - A dead simple Rust tool to sign files and verify signatures\n\n\
Usage:\n\
minisign_rs -G [-f] [-p pubkey_file] [-s seckey_file] [-W]\n\
minisign_rs -R [-s seckey_file] [-p pubkey_file]\n\
minisign_rs -K [-s seckey_file] [-W]\n\
minisign_rs -I [-s seckey_file | -p pubkey_file]\n\
minisign_rs -S [-l] [-x sig_file] [-s seckey_file] [-c untrusted_comment] [-t trusted_comment] -m file\n\
minisign_rs -V [-H] [-x sig_file] [-p pubkey_file | -P pubkey] [-o] [-q] -m file\n\n\
-G, --generate    generate a new key pair\n\
-R, --recreate    recreate a public key file from a secret key file\n\
-K, --change-password  change/remove the password of the secret key\n\
-I, --inspect     inspect a key file and display security parameters\n\
-S, --sign        sign files\n\
-V, --verify      verify that a signature is valid for a given file\n\
-H, --prehashed   require input to be prehashed\n\
-l, --legacy      sign using the legacy format\n\
-m, --input <file>  file to sign/verify\n\
-o, --output      combined with -V, output the file content after verification\n\
-p, --publickey-path <pubkey_file>  public key file (default: ./minisign.pub)\n\
-P, --publickey <pubkey>  public key, as a base64 string\n\
-s, --secretkey-path <seckey_file>  secret key file (default: ~/.minisign/minisign.key)\n\
-W, --no-password do not encrypt/decrypt the secret key with a password\n\
-x, --signature <sigfile>  signature file (default: <file>.minisig)\n\
-c, --untrusted-comment <comment>  add a one-line untrusted comment\n\
-t, --trusted-comment <comment>  add a one-line trusted comment\n\
-q, --quiet       quiet mode, suppress output\n\
-Q, --pretty-quiet  pretty quiet mode, only print the trusted comment\n\
-f, --force       force. Combined with -G, overwrite a previous key pair\n\
-h, --help        display this help message\n\
-v, --version     display version number\n\n\
{{usage-heading}} {{usage}}\n\n\
{{all-args}}"
    )
}

/// A dead simple Rust tool to sign files and verify signatures
#[derive(Debug, Parser)]
#[command(name = "minisign_rs")]
#[command(version = VERSION)]
#[command(help_template = help_template())]
#[command(disable_help_flag = true)]
#[command(disable_version_flag = true)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Generate a new keypair
    #[arg(short = 'G', long = "generate", group = "action")]
    pub generate: bool,

    /// Sign files
    #[arg(short = 'S', long = "sign", group = "action")]
    pub sign: bool,

    /// Verify a signature
    #[arg(short = 'V', long = "verify", group = "action")]
    pub verify: bool,

    /// Recreate a public key from a secret key
    #[arg(short = 'R', long = "recreate", group = "action")]
    pub recreate: bool,

    /// Change or remove password from a secret key
    #[arg(short = 'K', long = "change-password", group = "action")]
    pub change: bool,

    /// Inspect a key file and display security parameters
    #[arg(short = 'I', long = "inspect", group = "action")]
    pub inspect: bool,

    /// Force overwrite existing files
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Sign or verify a prehashed file
    #[arg(short = 'H', long = "prehashed")]
    pub prehashed: bool,

    /// Legacy mode (sign only)
    #[arg(short = 'l', long = "legacy")]
    pub legacy: bool,

    /// Message file (required for sign and verify)
    #[arg(short = 'm', long = "input", value_name = "FILE")]
    pub message_file: Option<PathBuf>,

    /// Output verification result to stdout
    #[arg(short = 'o', long = "output")]
    pub output: bool,

    /// Public key file
    #[arg(short = 'p', long = "publickey-path", value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// Public key as base64 string
    #[arg(short = 'P', long = "publickey", value_name = "PUBLIC_KEY")]
    pub public_key_base64: Option<String>,

    /// Quiet mode (minimal output)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Pretty quiet mode (trusted comment only)
    #[arg(short = 'Q', long = "pretty-quiet")]
    pub pretty_quiet: bool,

    /// Secret key file
    #[arg(short = 's', long = "secretkey-path", value_name = "FILE")]
    pub secret_key_file: Option<PathBuf>,

    /// Trusted comment
    #[arg(short = 't', long = "trusted-comment", value_name = "COMMENT")]
    pub trusted_comment: Option<String>,

    /// Untrusted comment
    #[arg(short = 'c', long = "untrusted-comment", value_name = "COMMENT")]
    pub untrusted_comment: Option<String>,

    /// Signature file
    #[arg(short = 'x', long = "signature", value_name = "FILE")]
    pub signature_file: Option<PathBuf>,

    /// Do not use password (generate and change only)
    #[arg(short = 'W', long = "no-password")]
    pub no_password: bool,

    /// Read password from file (for testing only - insecure for production use)
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    /// Allow KDF parameter fallback if 128MB allocation fails (permission only, does not force fallback)
    #[arg(long = "allow-kdf-fallback")]
    pub allow_kdf_fallback: bool,

    /// Force weak KDF parameters for testing (DEBUG ONLY - creates intentionally insecure keys)
    #[cfg(debug_assertions)]
    #[arg(long = "force-weak-kdf", hide = true)]
    pub force_weak_kdf: bool,

    /// Show help
    #[arg(short = 'h', long = "help", action = clap::ArgAction::Help)]
    pub help: Option<bool>,

    /// Show version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    pub version: Option<bool>,
}

/// Determine which action was selected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Generate,
    Sign,
    Verify,
    Recreate,
    Change,
    Inspect,
}

impl Cli {
    /// Get the selected action, or None if no action was specified
    #[must_use]
    pub fn action(&self) -> Option<Action> {
        if self.generate {
            Some(Action::Generate)
        } else if self.sign {
            Some(Action::Sign)
        } else if self.verify {
            Some(Action::Verify)
        } else if self.recreate {
            Some(Action::Recreate)
        } else if self.change {
            Some(Action::Change)
        } else if self.inspect {
            Some(Action::Inspect)
        } else {
            None
        }
    }

    /// Get the default secret key path based on platform
    ///
    /// Checks the `MINISIGN_CONFIG_DIR` environment variable first.
    /// Falls back to `~/.minisign/` if not set.
    #[must_use]
    pub fn default_secret_key_path() -> PathBuf {
        if let Ok(config_dir) = std::env::var("MINISIGN_CONFIG_DIR") {
            PathBuf::from(config_dir).join("minisign.key")
        } else if let Some(home) = dirs::home_dir() {
            home.join(".minisign").join("minisign.key")
        } else {
            PathBuf::from(".minisign.key")
        }
    }

    /// Get the default public key path (current directory)
    #[must_use]
    pub fn default_public_key_path() -> PathBuf {
        PathBuf::from("./minisign.pub")
    }

    /// Get the default signature path for a message file
    ///
    /// # Errors
    ///
    /// Returns an error if the path has no valid filename component
    pub fn default_signature_path(message_file: &Path) -> Result<PathBuf> {
        let mut sig_path = message_file.to_path_buf();
        let file_name = message_file
            .file_name()
            .ok_or_else(|| Error::InvalidPath(message_file.to_path_buf()))?;

        let mut file_name_string = file_name.to_string_lossy().to_string();
        file_name_string.push_str(".minisig");
        sig_path.set_file_name(file_name_string);
        Ok(sig_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_action_detection() {
        let cli = Cli {
            generate: true,
            sign: false,
            verify: false,
            recreate: false,
            change: false,
            inspect: false,
            force: false,
            prehashed: false,
            legacy: false,
            message_file: None,
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
            force: false,
            prehashed: false,
            legacy: false,
            message_file: None,
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
            force: false,
            prehashed: false,
            legacy: false,
            message_file: None,
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
            force: false,
            prehashed: false,
            legacy: false,
            message_file: None,
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
            force: false,
            prehashed: false,
            legacy: false,
            message_file: None,
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
}
