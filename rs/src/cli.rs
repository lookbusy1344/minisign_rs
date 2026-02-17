//! Command-line interface definition using clap
//!
//! This module defines the CLI structure matching the C minisign interface exactly.

use crate::errors::{Error, Result};
use clap::Parser;
use git_version::git_version;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

const VERSION: &str = git_version!(
    args = ["--tags", "--abbrev=7", "--always"],
    prefix = concat!(env!("CARGO_PKG_VERSION"), " ("),
    suffix = ")",
    fallback = "unknown"
);

/// A dead simple Rust tool to sign files and verify signatures
#[derive(Debug, Parser)]
#[command(name = "minisign_rs")]
#[command(version = VERSION)]
#[command(disable_help_flag = true)]
#[command(disable_version_flag = true)]
// clap derive requires boolean fields for CLI flags - builder pattern is not applicable here
// This is an intentional exception to CLAUDE.md policy against excessive booleans
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

    /// Inspect a key file and display security parameters (prompts for password if encrypted)
    #[arg(short = 'I', long = "inspect", group = "action")]
    pub inspect: bool,

    /// Force overwrite existing files
    #[arg(short = 'f', long = "force")]
    pub force: bool,

    /// Skip decryption of encrypted keys (show [encrypted] instead of prompting)
    #[arg(long = "no-decrypt")]
    pub no_decrypt: bool,

    /// Sign or verify a prehashed file
    #[arg(short = 'H', long = "prehashed")]
    pub prehashed: bool,

    /// Legacy mode (sign only)
    #[arg(short = 'l', long = "legacy")]
    pub legacy: bool,

    /// Message file (required for sign and verify)
    #[arg(short = 'm', long = "input", value_name = "FILE")]
    pub message_file: Option<PathBuf>,

    /// Additional files to sign (positional, C-compatible: -m file1 file2 file3)
    #[arg(value_name = "FILE")]
    pub extra_files: Vec<PathBuf>,

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

    /// Process files sequentially instead of in parallel
    #[arg(long)]
    pub sequential: bool,

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
    /// In release builds, this field exists but the CLI arg is not available (always false)
    #[cfg_attr(not(debug_assertions), arg(skip))]
    #[cfg_attr(debug_assertions, arg(long = "force-weak-kdf", hide = true))]
    pub force_weak_kdf: bool,

    /// Save password to OS credential store after successful use
    #[arg(long = "save-password", visible_alias = "sp")]
    pub save_password: bool,

    /// Remove saved password from OS credential store
    #[arg(long = "forget-password", visible_alias = "fp")]
    pub forget_password: bool,

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
    pub const fn action(&self) -> Option<Action> {
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

    /// Merge `-m` file and positional extra files into a single list.
    ///
    /// Matches C minisign semantics: `-m` specifies the first file, any
    /// remaining positional arguments are additional files to sign.
    ///
    /// Returns a `Cow` to avoid cloning when only `extra_files` are present.
    #[must_use]
    pub fn all_message_files(&self) -> Cow<'_, [PathBuf]> {
        match &self.message_file {
            Some(first) => {
                let mut files = Vec::with_capacity(1 + self.extra_files.len());
                files.push(first.clone());
                files.extend_from_slice(&self.extra_files);
                Cow::Owned(files)
            }
            None => Cow::Borrowed(&self.extra_files),
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

        let mut file_name_string = file_name.to_string_lossy().into_owned();
        file_name_string.push_str(".minisig");
        sig_path.set_file_name(file_name_string);
        Ok(sig_path)
    }
}
