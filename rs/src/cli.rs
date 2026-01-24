//! Command-line interface definition using clap
//!
//! This module defines the CLI structure matching the C minisign interface exactly.

use clap::Parser;
use std::path::{Path, PathBuf};

/// A dead simple tool to sign files and verify signatures
#[derive(Debug, Parser)]
#[command(name = "minisign")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), " (Rust)"))]
#[command(about = "A dead simple tool to sign files and verify signatures", long_about = None)]
#[command(disable_help_flag = true)]
#[command(disable_version_flag = true)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Generate a new keypair
    #[arg(short = 'G', group = "action")]
    pub generate: bool,

    /// Sign files
    #[arg(short = 'S', group = "action")]
    pub sign: bool,

    /// Verify a signature
    #[arg(short = 'V', group = "action")]
    pub verify: bool,

    /// Recreate a public key from a secret key
    #[arg(short = 'R', group = "action")]
    pub recreate: bool,

    /// Change or remove password from a secret key
    #[arg(short = 'C', group = "action")]
    pub change: bool,

    /// Force overwrite existing files
    #[arg(short = 'f')]
    pub force: bool,

    /// Sign or verify a prehashed file
    #[arg(short = 'H')]
    pub prehashed: bool,

    /// Legacy mode (sign only)
    #[arg(short = 'l')]
    pub legacy: bool,

    /// Message file (required for sign and verify)
    #[arg(short = 'm', value_name = "FILE")]
    pub message_file: Option<PathBuf>,

    /// Output verification result to stdout
    #[arg(short = 'o')]
    pub output: bool,

    /// Public key file
    #[arg(short = 'p', value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// Public key as base64 string
    #[arg(short = 'P', value_name = "PUBLIC_KEY")]
    pub public_key_base64: Option<String>,

    /// Quiet mode (minimal output)
    #[arg(short = 'q')]
    pub quiet: bool,

    /// Pretty quiet mode (trusted comment only)
    #[arg(short = 'Q')]
    pub pretty_quiet: bool,

    /// Secret key file
    #[arg(short = 's', value_name = "FILE")]
    pub secret_key_file: Option<PathBuf>,

    /// Trusted comment
    #[arg(short = 't', value_name = "COMMENT")]
    pub trusted_comment: Option<String>,

    /// Untrusted comment
    #[arg(short = 'c', value_name = "COMMENT")]
    pub untrusted_comment: Option<String>,

    /// Signature file
    #[arg(short = 'x', value_name = "FILE")]
    pub signature_file: Option<PathBuf>,

    /// Do not use password (generate and change only)
    #[arg(short = 'W')]
    pub no_password: bool,

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
        } else {
            None
        }
    }

    /// Get the default secret key path based on platform
    #[must_use]
    pub fn default_secret_key_path() -> PathBuf {
        if let Some(home) = dirs::home_dir() {
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
    #[must_use]
    pub fn default_signature_path(message_file: &Path) -> PathBuf {
        let mut sig_path = message_file.to_path_buf();
        let mut file_name = message_file
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        file_name.push_str(".minisig");
        sig_path.set_file_name(file_name);
        sig_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_detection() {
        let cli = Cli {
            generate: true,
            sign: false,
            verify: false,
            recreate: false,
            change: false,
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
            help: None,
            version: None,
        };
        assert_eq!(cli.action(), None);
    }

    #[test]
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
        let sig = Cli::default_signature_path(msg);
        assert_eq!(sig, PathBuf::from("test.txt.minisig"));

        let msg = Path::new("/path/to/file.dat");
        let sig = Cli::default_signature_path(msg);
        assert_eq!(sig, PathBuf::from("/path/to/file.dat.minisig"));
    }
}
