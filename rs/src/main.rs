use clap::Parser;
use is_terminal::IsTerminal;
use minisign::{
    Error, Result,
    cli::{Action, Cli},
    ops::{
        ChangeOptions, GenerateOptions, InspectOptions, PublicKeySource, RecreateOptions,
        SignOptions, VerifyOptions, change, generate, inspect, recreate, sign, verify,
    },
};
use std::io::{self, Write};
use std::process;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn main() {
    let result = run();
    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            eprintln!("{e}");
            // Exit code 2 for usage errors, 1 for other errors
            let exit_code = match e {
                Error::Usage(_) | Error::MissingArgument(_) => 2,
                _ => 1,
            };
            process::exit(exit_code);
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Determine which action to perform
    let action = cli
        .action()
        .ok_or_else(|| Error::Usage("No action specified. Use -G, -S, -V, -R, -K, or -I".into()))?;

    match action {
        Action::Generate => handle_generate(&cli),
        Action::Sign => handle_sign(&cli),
        Action::Verify => handle_verify(&cli),
        Action::Recreate => handle_recreate(&cli),
        Action::Change => handle_change(&cli),
        Action::Inspect => handle_inspect(&cli),
    }
}

fn handle_generate(cli: &Cli) -> Result<()> {
    // Get secret key path (use default if not specified)
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Get public key path (use default if not specified)
    let public_key_file = cli
        .public_key_file
        .clone()
        .unwrap_or_else(Cli::default_public_key_path);

    // Get comment
    let comment = cli.untrusted_comment.clone();

    // Get password with confirmation (unless -W was specified)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password_with_confirmation(
            cli.password_file.as_deref(),
        )?)
    };

    let options = GenerateOptions {
        secret_key_file,
        public_key_file,
        comment,
        force: cli.force,
        no_password: cli.no_password,
        allow_kdf_fallback: cli.allow_kdf_fallback,
        #[cfg(debug_assertions)]
        force_weak_kdf: cli.force_weak_kdf,
    };

    let result = generate(&options, password.as_ref().map(|p| p.as_bytes()))?;

    if !cli.quiet {
        println!(
            "The secret key was saved as {} - Keep it secret!",
            result.secret_key_file.display()
        );
        println!(
            "The public key was saved as {} - That one can be public.",
            result.public_key_file.display()
        );
        println!();
        println!("Files signed using this key pair can be verified with the following command:");
        println!();
        // codeql[rust/cleartext-logging] - Public key is meant to be shared, not sensitive
        println!("minisign_rs -Vm <file> -P {}", result.public_key_base64);
    }

    Ok(())
}

fn handle_sign(cli: &Cli) -> Result<()> {
    // Validate required arguments
    let message_file = cli
        .message_file
        .as_ref()
        .ok_or_else(|| Error::Usage("Message file (-m) is required for signing".into()))?;

    // Get secret key path
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Get signature file path
    let signature_file = match &cli.signature_file {
        Some(path) => path.clone(),
        None => Cli::default_signature_path(message_file)?,
    };

    // Prompt for password (we'll check if the key needs it later)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password("Password: ", cli.password_file.as_deref())?)
    };

    let options = SignOptions {
        secret_key_file: secret_key_file.to_string_lossy().to_string(),
        message_file: message_file.to_string_lossy().to_string(),
        signature_file: Some(signature_file.to_string_lossy().to_string()),
        trusted_comment: cli.trusted_comment.clone(),
        untrusted_comment: cli.untrusted_comment.clone(),
        // Default behavior matches C minisign: prehashed=true (SIGALG_HASHED="ED")
        // Only use legacy mode (prehashed=false, SIGALG="Ed") when explicitly requested with -l
        prehashed: !cli.legacy,
        force: cli.force,
    };

    let result = sign(&options, password.as_ref().map(|p| p.as_bytes()))?;

    if !cli.quiet {
        // codeql[rust/cleartext-logging] - Key ID is public identifier, not sensitive
        println!(
            "Signing with key: {} ({})",
            result.key_id, result.key_id_words
        );
        // codeql[rust/cleartext-logging] - Logging file path, not sensitive data
        println!("Signature written to {}", result.signature_file);
    }

    Ok(())
}

fn handle_verify(cli: &Cli) -> Result<()> {
    // Validate required arguments
    let message_file = cli
        .message_file
        .as_ref()
        .ok_or_else(|| Error::Usage("Message file (-m) is required for verification".into()))?;

    // Get public key source (either -p or -P, one is required)
    let public_key = if let Some(ref pk_file) = cli.public_key_file {
        PublicKeySource::File(pk_file.to_string_lossy().to_string())
    } else if let Some(ref pk_base64) = cli.public_key_base64 {
        PublicKeySource::Base64(pk_base64.clone())
    } else {
        // Try default public key file
        let default_pk = Cli::default_public_key_path();
        if default_pk.exists() {
            PublicKeySource::File(default_pk.to_string_lossy().to_string())
        } else {
            return Err(Error::Usage(
                "Public key is required for verification. Use -p <file> or -P <key>".into(),
            ));
        }
    };

    // Get signature file path
    let signature_file = match &cli.signature_file {
        Some(path) => path.clone(),
        None => Cli::default_signature_path(message_file)?,
    };

    let options = VerifyOptions {
        public_key,
        signature_file: signature_file.to_string_lossy().to_string(),
        message_file: message_file.to_string_lossy().to_string(),
        output: cli.output,
        quiet: cli.quiet,
    };

    let result = verify(&options)?;

    // Handle output modes
    if cli.pretty_quiet {
        // -Q: Only show trusted comment
        println!("{}", result.trusted_comment);
    } else if !cli.quiet {
        // Normal output
        // codeql[rust/cleartext-logging] - Key ID is public identifier, not sensitive
        println!(
            "Verified with key: {} ({})",
            result.key_id, result.key_id_words
        );
        println!("Signature and comment signature verified");
        println!("Trusted comment: {}", result.trusted_comment);
    }

    Ok(())
}

fn handle_recreate(cli: &Cli) -> Result<()> {
    // Get secret key path
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Get public key path
    let public_key_file = cli
        .public_key_file
        .clone()
        .unwrap_or_else(Cli::default_public_key_path);

    // Prompt for password
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password("Password: ", cli.password_file.as_deref())?)
    };

    let options = RecreateOptions {
        secret_key_file,
        public_key_file,
        comment: cli.untrusted_comment.clone(),
        force: cli.force,
    };

    let result = recreate(&options, password.as_ref().map(|p| p.as_bytes()))?;

    if !cli.quiet {
        println!(
            "Public key recreated as {}",
            result.public_key_file.display()
        );
    }

    Ok(())
}

fn handle_change(cli: &Cli) -> Result<()> {
    // Get secret key path
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Prompt for current password (if the key is encrypted)
    let current_password = if cli.no_password {
        None
    } else {
        Some(prompt_password(
            "Current password: ",
            cli.password_file.as_deref(),
        )?)
    };

    // Prompt for new password (if we want one)
    let new_password = if cli.no_password {
        None
    } else {
        Some(prompt_password(
            "New password: ",
            cli.password_file.as_deref(),
        )?)
    };

    let options = ChangeOptions {
        secret_key_file,
        remove_password: cli.no_password && new_password.is_none(),
        allow_kdf_fallback: cli.allow_kdf_fallback,
        #[cfg(debug_assertions)]
        force_weak_kdf: cli.force_weak_kdf,
    };

    let result = change(
        &options,
        current_password.as_ref().map(|p| p.as_bytes()),
        new_password.as_ref().map(|p| p.as_bytes()),
    )?;

    if !cli.quiet {
        println!("Password changed for {}", result.secret_key_file.display());
    }

    Ok(())
}

fn handle_inspect(cli: &Cli) -> Result<()> {
    use minisign::ops::inspect::{KeyType, SecurityLevel, inspect_base64};

    // Determine the source and get the inspection result
    // Priority: -s (secret key), -p (public key file), -P (public key base64), then default secret key
    let (result, source_description) = if let Some(ref sk_file) = cli.secret_key_file {
        let path = sk_file.to_string_lossy().to_string();
        let options = InspectOptions {
            key_file: path.clone(),
        };
        (inspect(&options)?, format!("Inspecting: {path}"))
    } else if let Some(ref pk_file) = cli.public_key_file {
        let path = pk_file.to_string_lossy().to_string();
        let options = InspectOptions {
            key_file: path.clone(),
        };
        (inspect(&options)?, format!("Inspecting: {path}"))
    } else if let Some(ref pk_base64) = cli.public_key_base64 {
        // Inspect public key from base64 string
        (
            inspect_base64(pk_base64)?,
            "Inspecting: public key from command line (-P)".to_string(),
        )
    } else {
        // Default to secret key path
        let path = Cli::default_secret_key_path().to_string_lossy().to_string();
        let options = InspectOptions {
            key_file: path.clone(),
        };
        (inspect(&options)?, format!("Inspecting: {path} (default)"))
    };

    // Display the source
    println!("{source_description}\n");

    // Display security level prominently first (for secret keys)
    if let Some(security_level) = result.security_level {
        match security_level {
            SecurityLevel::High => println!("Security Level: HIGH [OK]\n"),
            SecurityLevel::Medium => println!("Security Level: MEDIUM [WARNING]\n"),
            SecurityLevel::Low => println!("Security Level: LOW [CRITICAL]\n"),
            SecurityLevel::None => println!("Security Level: NONE (UNENCRYPTED) [WARNING]\n"),
        }
    }

    // Display key information
    // codeql[rust/cleartext-logging] - Logging non-sensitive key metadata only
    println!("Key Information:");
    // codeql[rust/cleartext-logging] - Key ID is public identifier, not sensitive
    println!("├─ Key ID: {}", result.key_id);
    // codeql[rust/cleartext-logging] - Human-readable key ID (PGP Word List)
    println!("├─ Key ID (words): {}", result.key_id_words);

    match result.key_type {
        KeyType::SecretEncrypted => {
            println!("├─ Encrypted: Yes");
            // codeql[rust/cleartext-logging] - Logging algorithm name, not sensitive data
            println!("├─ KDF Algorithm: Scrypt");

            if let Some(kdf) = result.kdf_info {
                println!("└─ KDF Parameters:");
                // codeql[rust/cleartext-logging] - KDF parameters are public metadata, not sensitive
                println!(
                    "   ├─ opslimit: {} (N=2^{}, r={}, p={})",
                    kdf.opslimit, kdf.log_n, kdf.r, kdf.p
                );
                println!(
                    "   ├─ memlimit: {} ({} MB)",
                    kdf.memlimit,
                    kdf.memlimit / 1_048_576
                );

                if kdf.is_fallback {
                    println!("   ├─ Creation: Fallback (reduced parameters)");
                    if let Some(multiplier) = kdf.weakness_multiplier {
                        // codeql[rust/cleartext-logging] - Logging security strength metadata, not sensitive data
                        println!(
                            "   └─ Brute-force resistance: {multiplier}x weaker than production strength"
                        );
                    }
                } else {
                    println!("   └─ Creation: Normal (production parameters)");
                }

                // Add recommendation for weak keys
                if result.security_level == Some(SecurityLevel::Low) {
                    println!();
                    println!(
                        "*** RECOMMENDATION: Regenerate this key on a system with >=2GB RAM for full security."
                    );
                }
            }
        }
        KeyType::SecretUnencrypted => {
            println!("└─ Encrypted: No");
            println!();
            println!("*** WARNING: This key is stored in plaintext.");
            println!("   Anyone with file access can use it without a password.");
        }
        KeyType::Public => {
            println!("└─ Type: Ed25519 Public Key");
        }
    }

    Ok(())
}

/// Check if stdin is a terminal (interactive mode)
fn is_interactive() -> bool {
    io::stdin().is_terminal()
}

/// Prompt for password using rpassword or read from file
///
/// Returns a `Zeroizing<String>` that automatically clears the password from memory when dropped.
fn prompt_password(
    prompt: &str,
    password_file: Option<&std::path::Path>,
) -> Result<Zeroizing<String>> {
    // If password file is provided, read from it
    if let Some(path) = password_file {
        eprintln!(
            "Warning: --password-file is insecure and should only be used for testing purposes."
        );
        let password = std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("Failed to read password file: {e}")))?;
        // Trim trailing newline if present and wrap in Zeroizing
        return Ok(Zeroizing::new(password.trim_end().to_string()));
    }

    // Check if we're in an interactive environment
    if !is_interactive() {
        return Err(Error::Usage(
            "Cannot prompt for password in non-interactive mode. Use -W flag to skip password or --password-file."
                .into(),
        ));
    }

    print!("{prompt}");
    io::stdout()
        .flush()
        .map_err(|e| Error::Io(format!("Failed to flush stdout: {e}")))?;

    rpassword::read_password()
        .map(Zeroizing::new)
        .map_err(|e| Error::Io(format!("Failed to read password: {e}")))
}

/// Prompt for password with confirmation (for key generation)
///
/// Prompts twice and validates that both entries match.
/// If reading from a password file, only prompts once (confirmation not needed for automation).
///
/// Returns a `Zeroizing<String>` that automatically clears the password from memory when dropped.
fn prompt_password_with_confirmation(
    password_file: Option<&std::path::Path>,
) -> Result<Zeroizing<String>> {
    // If reading from file, no confirmation needed
    if password_file.is_some() {
        return prompt_password("Password: ", password_file);
    }

    // Prompt twice for interactive input
    let password1 = prompt_password("Password: ", None)?;
    let password2 = prompt_password("Password (one more time): ", None)?;

    // Compare passwords (constant-time comparison to prevent timing attacks)
    let passwords_match: bool = password1.as_bytes().ct_eq(password2.as_bytes()).into();
    if !passwords_match {
        return Err(Error::PasswordMismatch);
    }

    Ok(password1)
}
