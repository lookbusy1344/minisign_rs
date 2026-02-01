use clap::Parser;
use minisign::ops::sign::sign_multiple_files;
use minisign::ops::verify::verify_multiple_files;
use minisign::{
    Error, Result,
    cli::{Action, Cli},
    ops::{
        ChangeOptions, GenerateOptions, InspectOptions, PublicKeySource, RecreateOptions,
        SignOptions, VerifyOptions, change, generate, inspect, recreate, sign, verify,
    },
};
use std::io::IsTerminal;
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
        secret_key_file: &secret_key_file,
        public_key_file: &public_key_file,
        comment,
        force: cli.force,
        no_password: cli.no_password,
        allow_kdf_fallback: cli.allow_kdf_fallback,
        #[cfg(debug_assertions)]
        force_weak_kdf: cli.force_weak_kdf,
    };

    // Display working message for slow key generation
    if !cli.quiet {
        eprint!("Working...");
        io::stderr()
            .flush()
            .map_err(|e| Error::Io(format!("Failed to flush stderr: {e}")))?;
    }

    let result = generate(&options, password.as_ref().map(|p| p.as_bytes()))?;

    // Clear working message
    if !cli.quiet {
        eprint!("\r\x1b[K");
        io::stderr()
            .flush()
            .map_err(|e| Error::Io(format!("Failed to flush stderr: {e}")))?;
    }

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
        println!("minisign_rs -Vm <file> -P {}", result.public_key_base64);
    }

    Ok(())
}

fn handle_sign(cli: &Cli) -> Result<()> {
    let message_files = cli.all_message_files();

    // Validate required arguments
    if message_files.is_empty() {
        return Err(Error::Usage(
            "Message file (-m) is required for signing".into(),
        ));
    }

    // Get secret key path
    let secret_key_file = cli
        .secret_key_file
        .clone()
        .unwrap_or_else(Cli::default_secret_key_path);

    // Prompt for password (we'll check if the key needs it later)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password("Password: ", cli.password_file.as_deref())?)
    };

    // Display working message for signing operation
    if !cli.quiet {
        eprintln!("Working...");
        io::stderr()
            .flush()
            .map_err(|e| Error::Io(format!("Failed to flush stderr: {e}")))?;
    }

    if message_files.len() == 1 {
        // Single file path - preserve original behavior and output format
        let message_file = &message_files[0];

        let signature_file = match &cli.signature_file {
            Some(path) => path.clone(),
            None => Cli::default_signature_path(message_file)?,
        };

        let options = SignOptions {
            secret_key_file: &secret_key_file,
            message_file,
            signature_file: Some(&signature_file),
            trusted_comment: cli.trusted_comment.clone(),
            untrusted_comment: cli.untrusted_comment.clone(),
            // Default behavior matches C minisign: prehashed=true (SIGALG_HASHED="ED")
            // Only use legacy mode (prehashed=false, SIGALG="Ed") when explicitly requested with -l
            prehashed: !cli.legacy,
            force: cli.force,
        };

        let result = sign(&options, password.as_ref().map(|p| p.as_bytes()))?;

        if !cli.quiet {
            println!(
                "Signing with key: {} ({})",
                result.key_id, result.key_id_words
            );
            println!("Signature written to {}", result.signature_file.display());
        }
    } else {
        // Multiple files path - use multi-file API
        if cli.signature_file.is_some() {
            return Err(Error::Usage(
                "Custom signature file (-x) not supported with multiple message files".into(),
            ));
        }

        let options = SignOptions {
            secret_key_file: &secret_key_file,
            message_file: std::path::Path::new(""),
            signature_file: None,
            trusted_comment: cli.trusted_comment.clone(),
            untrusted_comment: cli.untrusted_comment.clone(),
            prehashed: !cli.legacy,
            force: cli.force,
        };

        sign_multiple_files(
            message_files,
            &options,
            password.as_ref().map(|p| p.as_bytes()),
            cli.sequential,
        )?;
    }

    Ok(())
}

fn handle_verify(cli: &Cli) -> Result<()> {
    let message_files = cli.all_message_files();

    // Validate required arguments
    if message_files.is_empty() {
        return Err(Error::Usage(
            "Message file (-m) is required for verification".into(),
        ));
    }

    // Get public key source (either -p or -P, one is required)
    let default_pk;
    let public_key = if let Some(ref pk_file) = cli.public_key_file {
        PublicKeySource::File(pk_file.as_path())
    } else if let Some(ref pk_base64) = cli.public_key_base64 {
        PublicKeySource::Base64(pk_base64.clone())
    } else {
        // Try default public key file
        default_pk = Cli::default_public_key_path();
        if default_pk.exists() {
            PublicKeySource::File(&default_pk)
        } else {
            return Err(Error::Usage(
                "Public key is required for verification. Use -p <file> or -P <key>".into(),
            ));
        }
    };

    if message_files.len() == 1 {
        // Single file path - preserve original behavior and output format
        let message_file = &message_files[0];

        // Get signature file path
        let signature_file = match &cli.signature_file {
            Some(path) => path.clone(),
            None => Cli::default_signature_path(message_file)?,
        };

        let options = VerifyOptions {
            public_key,
            signature_file: &signature_file,
            message_file,
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
            println!(
                "Verified with key: {} ({})",
                result.key_id, result.key_id_words
            );
            println!("Signature and comment signature verified");
            println!("Trusted comment: {}", result.trusted_comment);
        }
    } else {
        // Multiple files path - use multi-file API
        if cli.signature_file.is_some() {
            return Err(Error::Usage(
                "Custom signature file (-x) not supported with multiple message files".into(),
            ));
        }

        let options = VerifyOptions {
            public_key,
            signature_file: std::path::Path::new(""),
            message_file: std::path::Path::new(""),
            output: cli.output,
            quiet: cli.quiet,
        };

        verify_multiple_files(message_files, &options, cli.sequential)?;
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
        secret_key_file: &secret_key_file,
        public_key_file: &public_key_file,
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
        secret_key_file: &secret_key_file,
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

/// Display the signature inspection result
fn display_signature_inspect_result(result: &minisign::ops::inspect::SignatureInspectResult) {
    use minisign::signature::SignatureAlgorithm;

    println!("Signature Information:");
    println!("├─ Key ID: {}", result.key_id);
    println!("├─ Key ID (words): {}", result.key_id_words);

    let algorithm_desc = match result.algorithm {
        SignatureAlgorithm::Normal => "Normal (Ed25519)",
        SignatureAlgorithm::Prehashed => "Prehashed (Blake2b-512)",
    };
    println!("└─ Algorithm: {algorithm_desc}");
}

/// Display the inspection result
fn display_inspect_result(result: &minisign::ops::inspect::InspectResult) {
    use minisign::ops::inspect::{KeyType, SecurityLevel};

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
    println!("Key Information:");

    // For encrypted secret keys, key ID is not available without decryption
    if result.key_type == KeyType::SecretEncrypted && result.key_id == "0000000000000000" {
        println!("├─ Key ID: [encrypted - password required to view]");
        println!("├─ Key ID (words): [decrypt key to view]");
    } else {
        println!("├─ Key ID: {}", result.key_id);
        println!("├─ Key ID (words): {}", result.key_id_words);
    }

    match result.key_type {
        KeyType::SecretEncrypted => {
            println!("├─ Encrypted: Yes");
            println!("├─ KDF Algorithm: Scrypt");

            if let Some(kdf) = &result.kdf_info {
                println!("└─ KDF Parameters:");
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
}

fn handle_inspect(cli: &Cli) -> Result<()> {
    use minisign::ops::inspect::{
        InspectPrivateOptions, KeyType, inspect_base64, inspect_private, inspect_signature,
    };

    // Check if we're inspecting a signature file
    if let Some(ref sig_file) = cli.signature_file {
        let result = inspect_signature(sig_file)?;

        println!("Inspecting: {}\n", sig_file.display());
        display_signature_inspect_result(&result);
        return Ok(());
    }

    // Determine the source and get the inspection result
    // Priority: -s (secret key), -p (public key file), -P (public key base64), then default secret key
    let (mut result, source_description, key_file_path) =
        if let Some(ref sk_file) = cli.secret_key_file {
            let options = InspectOptions {
                key_file: sk_file.as_path(),
            };
            (
                inspect(&options)?,
                format!("Inspecting: {}", sk_file.display()),
                Some(sk_file.clone()),
            )
        } else if let Some(ref pk_file) = cli.public_key_file {
            let options = InspectOptions {
                key_file: pk_file.as_path(),
            };
            (
                inspect(&options)?,
                format!("Inspecting: {}", pk_file.display()),
                Some(pk_file.clone()),
            )
        } else if let Some(ref pk_base64) = cli.public_key_base64 {
            // Inspect public key from base64 string
            (
                inspect_base64(pk_base64)?,
                "Inspecting: public key from command line (-P)".to_string(),
                None,
            )
        } else {
            // Default to secret key path
            let path = Cli::default_secret_key_path();
            let options = InspectOptions { key_file: &path };
            (
                inspect(&options)?,
                format!("Inspecting: {} (default)", path.display()),
                Some(path),
            )
        };

    // Smart decryption: If key is encrypted and --no-decrypt is not set, prompt for password
    let mut decrypted = false;
    if result.key_type == KeyType::SecretEncrypted
        && result.key_id == "0000000000000000"
        && !cli.no_decrypt
        && let Some(ref path) = key_file_path
    {
        // Prompt for password and decrypt
        let password = prompt_password("Password: ", cli.password_file.as_deref())?;
        let options = InspectPrivateOptions {
            key_file: path.as_path(),
        };
        result = inspect_private(&options, password.as_bytes())?;
        decrypted = true;
    }

    // Display the source
    if decrypted {
        println!("{source_description} (decrypted)\n");
    } else {
        println!("{source_description}\n");
    }

    display_inspect_result(&result);

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
