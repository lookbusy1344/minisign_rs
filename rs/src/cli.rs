//! Command-line interface definition using pico-args
//!
//! This module defines the CLI structure matching the C minisign interface exactly.

use crate::errors::{Error, Result};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_DESCRIBE: &str = env!("GIT_DESCRIBE");

const HELP: &str = "\
minisign_rs - A dead simple Rust tool to sign files and verify signatures

Usage: minisign_rs -G [-f] [-p pubkey] [-s seckey] [-W] [-c comment]
       minisign_rs -S [-H | -l] [-x sigfile] [-s seckey] [-c comment] [-t comment] -m file [files...]
       minisign_rs -V [-x sigfile] [-p pubkey | -P key] [-o] [-q|-Q] -m file [files...]
       minisign_rs -R [-s seckey] [-p pubkey]
       minisign_rs -K [-s seckey] [-W]
       minisign_rs -I [-s seckey | -p pubkey | -P key | -x sigfile]

ACTIONS:
    -G, --generate          Generate a new keypair
    -S, --sign              Sign files
    -V, --verify            Verify a signature
    -R, --recreate          Recreate a public key from a secret key
    -K, --change-password   Change or remove password from a secret key
    -I, --inspect           Inspect a key file

OPTIONS:
    -c, --untrusted-comment <COMMENT>   Untrusted comment
    -f, --force                         Force overwrite existing files
    -h, --help                          Show this help
    -H, --prehashed                     Sign or verify a prehashed file
    -l, --legacy                        Legacy mode (sign only); forces sequential execution
                                        to bound memory (non-prehashed buffers up to 1 GB per file)
    -m, --input <FILE>                  Message file
    -o, --output                        Output verification result to stdout
    -p, --publickey-path <FILE>         Public key file
    -P, --publickey <KEY>               Public key as base64 string
    -q, --quiet                         Quiet mode (minimal output)
    -Q, --pretty-quiet                  Pretty quiet mode (trusted comment only)
    -s, --secretkey-path <FILE>         Secret key file
    -t, --trusted-comment <COMMENT>     Trusted comment
    -v, --version                       Show version
    -W, --no-password                   Do not use password (generate and change only)
    -x, --signature <FILE>              Signature file
        --allow-kdf-fallback            Allow KDF parameter fallback if 128MB allocation fails
        --forget-password, --fp         Remove saved password from credential store
        --no-decrypt                    Skip decryption of encrypted keys
        --password-file <FILE>          Read password from file (testing only - insecure)
        --save-password, --sp           Save password to OS credential store
";

// clippy: struct_excessive_bools — these are genuinely independent CLI flag booleans.
// The mutually-exclusive action flags have been extracted into Option<Action>.
// The remaining booleans represent orthogonal feature flags with no valid enum grouping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct Cli {
    /// The selected action (exactly one of -G/-S/-V/-R/-K/-I), or None if omitted.
    pub action: Option<Action>,

    pub force: bool,
    pub no_decrypt: bool,
    pub prehashed: bool,
    pub legacy: bool,
    pub output: bool,
    pub quiet: bool,
    pub pretty_quiet: bool,
    pub no_password: bool,
    pub allow_kdf_fallback: bool,
    pub save_password: bool,
    pub forget_password: bool,

    pub message_file: Option<PathBuf>,
    pub extra_files: Vec<PathBuf>,
    pub public_key_file: Option<PathBuf>,
    pub public_key_base64: Option<String>,
    pub secret_key_file: Option<PathBuf>,
    pub trusted_comment: Option<String>,
    pub untrusted_comment: Option<String>,
    pub signature_file: Option<PathBuf>,
    pub password_file: Option<PathBuf>,

    #[cfg(feature = "parallel")]
    pub sequential: bool,

    pub force_weak_kdf: bool,
}

/// Short flags that consume the next token as their value.
///
/// All other single-character flags are boolean. This list must stay in sync
/// with the `opt_value_from_str` calls in [`Cli::parse_args`].
const VALUE_FLAGS: &[char] = &['m', 'p', 'P', 's', 't', 'c', 'x'];

/// Expand POSIX-style combined short flags into individual arguments.
///
/// Converts bundles like `-Ip key.pub` or `-GfW` into the equivalent
/// separate tokens that pico-args can handle.  Stops expanding at the first
/// value-taking flag and treats any remaining characters in the bundle as
/// an embedded value (e.g. `-Iskey.sec` → `-I`, `-s`, `key.sec`).
///
/// Only single-dash arguments with more than one character are affected;
/// long options (`--flag`) and already-separated flags (`-I`) pass through
/// unchanged.
fn expand_combined_flags(args: Vec<std::ffi::OsString>) -> Vec<std::ffi::OsString> {
    let mut expanded = Vec::with_capacity(args.len());
    for arg in args {
        let Some(s) = arg.to_str() else {
            expanded.push(arg);
            continue;
        };

        let is_combined = s.starts_with('-') && !s.starts_with("--") && s.len() > 2;
        if !is_combined {
            expanded.push(arg);
            continue;
        }

        let chars: Vec<char> = s[1..].chars().collect();
        for (i, &ch) in chars.iter().enumerate() {
            expanded.push(std::ffi::OsString::from(format!("-{ch}")));
            if VALUE_FLAGS.contains(&ch) {
                // Remaining chars in the bundle are the embedded value (may be empty).
                if i + 1 < chars.len() {
                    let embedded: String = chars[i + 1..].iter().collect();
                    expanded.push(std::ffi::OsString::from(embedded));
                }
                break;
            }
        }
    }
    expanded
}

impl Cli {
    /// Parse arguments from the process environment.
    ///
    /// Exits the process (code 0) for `--help` and `--version`.
    ///
    /// # Errors
    ///
    /// Returns an error if an unknown flag is encountered or a required value
    /// is missing from a flag that takes an argument.
    pub fn parse() -> Result<Self> {
        let raw: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        let raw = expand_combined_flags(raw);
        let mut args = pico_args::Arguments::from_vec(raw);

        // Handle --help / --version before anything else
        if args.contains(["-h", "--help"]) {
            print!("{HELP}");
            std::process::exit(0);
        }
        if args.contains(["-v", "--version"]) {
            println!("minisign_rs {VERSION} ({GIT_DESCRIBE})");
            std::process::exit(0);
        }

        Self::parse_args(args)
    }

    /// Parse from an explicit list of arguments, skipping the first element
    /// (program name). Intended for use in tests.
    pub fn parse_from<I, S>(iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<std::ffi::OsString>,
    {
        let raw: Vec<std::ffi::OsString> = iter.into_iter().skip(1).map(Into::into).collect();
        let raw = expand_combined_flags(raw);
        let args = pico_args::Arguments::from_vec(raw);
        Self::parse_args(args)
    }

    /// Parse and validate the action flag from `args`, returning the selected
    /// `Action` or `None` if no action flag was given. Returns an error if
    /// more than one action flag is present.
    fn parse_action(args: &mut pico_args::Arguments) -> Result<Option<Action>> {
        let flags = [
            (args.contains(["-G", "--generate"]), Action::Generate),
            (args.contains(["-S", "--sign"]), Action::Sign),
            (args.contains(["-V", "--verify"]), Action::Verify),
            (args.contains(["-R", "--recreate"]), Action::Recreate),
            (args.contains(["-K", "--change-password"]), Action::Change),
            (args.contains(["-I", "--inspect"]), Action::Inspect),
        ];
        let mut found = flags.into_iter().filter(|(present, _)| *present);
        let action = found.next().map(|(_, a)| a);
        if found.next().is_some() {
            return Err(Error::Usage(
                "only one action flag (-G, -S, -V, -R, -K, -I) may be specified".to_string(),
            ));
        }
        Ok(action)
    }

    /// Core parsing logic shared by `parse()` and `parse_from()`.
    fn parse_args(mut args: pico_args::Arguments) -> Result<Self> {
        let action = Self::parse_action(&mut args)?;

        let mut cli = Self {
            action,

            force: args.contains(["-f", "--force"]),
            no_decrypt: args.contains("--no-decrypt"),
            prehashed: args.contains(["-H", "--prehashed"]),
            legacy: args.contains(["-l", "--legacy"]),
            output: args.contains(["-o", "--output"]),
            quiet: args.contains(["-q", "--quiet"]),
            pretty_quiet: args.contains(["-Q", "--pretty-quiet"]),
            no_password: args.contains(["-W", "--no-password"]),
            allow_kdf_fallback: args.contains("--allow-kdf-fallback"),
            save_password: args.contains("--save-password") || args.contains("--sp"),
            forget_password: args.contains("--forget-password") || args.contains("--fp"),

            message_file: args
                .opt_value_from_str(["-m", "--input"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            public_key_file: args
                .opt_value_from_str(["-p", "--publickey-path"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            public_key_base64: args
                .opt_value_from_str(["-P", "--publickey"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            secret_key_file: args
                .opt_value_from_str(["-s", "--secretkey-path"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            trusted_comment: args
                .opt_value_from_str(["-t", "--trusted-comment"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            untrusted_comment: args
                .opt_value_from_str(["-c", "--untrusted-comment"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            signature_file: args
                .opt_value_from_str(["-x", "--signature"])
                .map_err(|e| Error::Usage(e.to_string()))?,
            password_file: args
                .opt_value_from_str("--password-file")
                .map_err(|e| Error::Usage(e.to_string()))?,

            #[cfg(feature = "parallel")]
            sequential: args.contains("--sequential"),

            // Debug-only flag: present in debug builds, always false in release.
            force_weak_kdf: cfg_select! {
                debug_assertions => args.contains("--force-weak-kdf"),
                _ => false,
            },

            extra_files: Vec::new(),
        };

        // Reject conflicting quiet-mode flags.
        if cli.quiet && cli.pretty_quiet {
            return Err(Error::Usage("-q and -Q are mutually exclusive".to_string()));
        }

        // --save-password / --sp requires the credential_store feature to be compiled in.
        // Without it the flag would silently succeed while saving nothing.
        #[cfg(not(feature = "credential_store"))]
        if cli.save_password {
            return Err(Error::Usage(
                "--save-password requires the credential_store feature \
                 (recompile with default features)"
                    .to_string(),
            ));
        }

        // Collect remaining positional arguments as extra files.
        // Reject anything that looks like an unknown flag.
        let remaining = args.finish();
        let unknown: Vec<_> = remaining
            .iter()
            .filter(|a| a.to_string_lossy().starts_with('-'))
            .collect();
        if !unknown.is_empty() {
            let arg = unknown[0].to_string_lossy();
            return Err(Error::Usage(format!("Unknown argument: {arg}")));
        }
        if !remaining.is_empty() {
            cli.extra_files = remaining.into_iter().map(PathBuf::from).collect();
        }

        Ok(cli)
    }

    /// Get the selected action, or None if no action was specified.
    #[must_use]
    pub const fn action(&self) -> Option<Action> {
        self.action
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

    /// Get the default secret key path based on platform.
    ///
    /// Checks `MINISIGN_CONFIG_DIR` first, then falls back to `~/.minisign/`.
    ///
    /// # Errors
    ///
    /// Returns an error if `MINISIGN_CONFIG_DIR` is set but empty, or (on
    /// Windows) set to a value that is not valid Unicode.  A set-but-unreadable
    /// variable is always a misconfiguration; silently falling back to the home
    /// directory would sign or generate keys in the wrong location.
    ///
    /// # Security
    ///
    /// `MINISIGN_CONFIG_DIR` is treated as trusted input — it determines the default
    /// secret key path. Users are responsible for ensuring this variable is not
    /// controlled by untrusted processes (e.g. SUID wrappers, CI pipeline injection).
    pub fn default_secret_key_path() -> Result<PathBuf> {
        match std::env::var_os("MINISIGN_CONFIG_DIR") {
            Some(val) if val.is_empty() => Err(Error::Other(
                "MINISIGN_CONFIG_DIR is set but empty; unset it or provide a directory path"
                    .to_string(),
            )),
            Some(val) => Ok(PathBuf::from(val).join("minisign.key")),
            None => {
                if let Some(home) = dirs::home_dir() {
                    Ok(home.join(".minisign").join("minisign.key"))
                } else {
                    Ok(PathBuf::from(".minisign.key"))
                }
            }
        }
    }

    /// Get the default public key path (current directory).
    #[must_use]
    pub fn default_public_key_path() -> PathBuf {
        PathBuf::from("./minisign.pub")
    }

    /// Get the default signature path for a message file.
    ///
    /// # Errors
    ///
    /// Returns an error if the path has no valid filename component.
    pub fn default_signature_path(message_file: &Path) -> Result<PathBuf> {
        let mut sig_path = message_file.to_path_buf();
        let file_name = message_file
            .file_name()
            .ok_or_else(|| Error::InvalidPath(message_file.to_path_buf()))?;

        let mut sig_name = file_name.to_os_string();
        sig_name.push(".minisig");
        sig_path.set_file_name(sig_name);
        Ok(sig_path)
    }
}

/// Determine which action was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Generate,
    Sign,
    Verify,
    Recreate,
    Change,
    Inspect,
}
