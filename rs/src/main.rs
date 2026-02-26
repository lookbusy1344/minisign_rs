use minisign::constants::ENCRYPTED_KEYNUM_PLACEHOLDER;
use minisign::ops::file_utils::load_secret_key;
use minisign::ops::sign::sign_multiple_files;
use minisign::ops::verify::verify_multiple_files;
use minisign::{
    Error, Result,
    cli::{Action, Cli},
    ops::{
        ChangeOptions, GenerateOptions, InspectOptions, InspectResult, KeyType, PublicKeySource,
        RecreateOptions, SecurityLevel, SignOptions, SignatureInspectResult, VerifyOptions, change,
        generate, inspect, inspect_base64, inspect_private_with_key, inspect_signature,
        recreate_with_key, sign_with_key, verify,
    },
};
use std::io::IsTerminal;
use std::io::{self, Write};
use std::process;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Minimum number of characters recommended for a new password.
///
/// Passwords shorter than this generate a warning during interactive key
/// generation and password-change operations. The scrypt parameters are strong,
/// but a very short password drastically reduces the effective security.
const MIN_RECOMMENDED_PASSWORD_LEN: usize = 8;

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
    let cli = Cli::parse()?;

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
    let default_secret_key = Cli::default_secret_key_path();
    let secret_key_file = cli.secret_key_file.as_ref().unwrap_or(&default_secret_key);

    // Get public key path (use default if not specified)
    let default_public_key = Cli::default_public_key_path();
    let public_key_file = cli.public_key_file.as_ref().unwrap_or(&default_public_key);

    // Get comment
    let comment = cli.untrusted_comment.as_deref();

    // Fail fast if output files exist (before expensive password prompt + scrypt)
    if !cli.force {
        if secret_key_file.exists() {
            return Err(Error::FileExists(secret_key_file.into()));
        }
        if public_key_file.exists() {
            return Err(Error::FileExists(public_key_file.into()));
        }
    }

    // Get password with confirmation (unless -W was specified)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password_with_confirmation(
            cli.password_file.as_deref(),
        )?)
    };

    let mut builder = GenerateOptions::builder(secret_key_file, public_key_file)
        .force(cli.force)
        .no_password(cli.no_password)
        .allow_kdf_fallback(cli.allow_kdf_fallback)
        .force_weak_kdf(resolve_force_weak_kdf(cli));

    if let Some(comment) = comment {
        builder = builder.comment(comment);
    }

    let options = builder.build();

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

    // Save password to credential store if requested
    save_password_to_credential_store(
        result.credential_id(),
        password.as_ref(),
        cli.save_password,
        cli.quiet,
        Some("The key was still created successfully."),
    );

    if !cli.quiet {
        println!(
            "Key ID: {} ({})",
            result.keynum_hex(),
            result.keynum_words()
        );
        println!(
            "The secret key was saved as {} - Keep it secret!",
            result.secret_key_file().display()
        );
        println!(
            "The public key was saved as {} - That one can be public.",
            result.public_key_file().display()
        );
        println!();
        println!("Files signed using this key pair can be verified with the following command:");
        println!();
        println!("minisign_rs -Vm <file> -P {}", result.public_key_base64());
    }

    Ok(())
}

/// Get password for a key: check credential store first, then prompt
fn get_password_with_credential_store(
    key_id: &str,
    prompt: &str,
    quiet: bool,
    password_file: Option<&std::path::Path>,
) -> Result<Zeroizing<String>> {
    if let Some(saved_pwd) = minisign::credential_store::get_password(key_id) {
        if !quiet {
            eprintln!("Using saved password from credential store");
        }
        Ok(saved_pwd)
    } else {
        prompt_password(prompt, password_file)
    }
}

/// Save password to credential store if requested
///
/// # Arguments
///
/// * `extra_context_on_error` - Optional message to print after credential store save failure
fn save_password_to_credential_store(
    key_id: &str,
    password: Option<&Zeroizing<String>>,
    save_password: bool,
    quiet: bool,
    extra_context_on_error: Option<&str>,
) {
    if save_password {
        if let Some(pwd) = password {
            match minisign::credential_store::save_password(key_id, pwd) {
                Ok(()) => {
                    if !quiet {
                        eprintln!("Password saved to OS credential store");
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Failed to save password to credential store: {e}");
                    if let Some(msg) = extra_context_on_error {
                        eprintln!("{msg}");
                    }
                }
            }
        } else {
            eprintln!("Warning: --save-password ignored (key has no password)");
        }
    }
}

/// Remove a saved credential and print feedback, unless `quiet` is set.
fn forget_password_with_feedback(credential_id: &str, quiet: bool) -> Result<()> {
    minisign::credential_store::forget_password(credential_id)
        .map_err(|e| Error::CredentialStoreError(format!("Failed to remove password: {e}")))?;
    if !quiet {
        println!("Password removed from credential store");
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

    // Check for conflicting flags: -H (prehashed) and -l (legacy) are mutually exclusive
    if cli.prehashed && cli.legacy {
        return Err(Error::Usage(
            "Cannot use both --prehashed (-H) and --legacy (-l) flags together".into(),
        ));
    }

    // Determine prehashed mode:
    // - Default: true (prehashed mode, matches C minisign)
    // - With -H: true (explicit prehashed)
    // - With -l: false (legacy mode)
    let prehashed = cli.prehashed || !cli.legacy;

    // Get secret key path
    let default_secret_key = Cli::default_secret_key_path();
    let secret_key_file = cli.secret_key_file.as_ref().unwrap_or(&default_secret_key);

    // Load secret key to get credential ID for credential store lookup
    let seckey = load_secret_key(secret_key_file)?;
    let credential_id = seckey.credential_id();

    // Try to get password from credential store first, then prompt if needed
    let password = if cli.no_password {
        None
    } else {
        Some(get_password_with_credential_store(
            &credential_id,
            "Password: ",
            cli.quiet,
            cli.password_file.as_deref(),
        )?)
    };

    // Display working message for signing operation
    if !cli.quiet {
        eprint!("Working...");
        io::stderr()
            .flush()
            .map_err(|e| Error::Io(format!("Failed to flush stderr: {e}")))?;
    }

    if message_files.len() == 1 {
        handle_sign_single(
            cli,
            &message_files[0],
            secret_key_file,
            prehashed,
            &seckey,
            &credential_id,
            password.as_ref(),
        )?;
    } else {
        handle_sign_multiple(
            cli,
            message_files.into_owned(),
            secret_key_file,
            prehashed,
            &credential_id,
            password.as_ref(),
        )?;
    }

    // Clear working message (matches handle_generate pattern)
    if !cli.quiet {
        eprint!("\r\x1b[K");
        io::stderr()
            .flush()
            .map_err(|e| Error::Io(format!("Failed to flush stderr: {e}")))?;
    }

    if cli.forget_password {
        forget_password_with_feedback(&credential_id, cli.quiet)?;
    }

    Ok(())
}

/// Apply common CLI flags to a `SignOptions` builder chain
fn apply_sign_options<'a>(mut builder: SignOptions<'a>, cli: &'a Cli) -> SignOptions<'a> {
    if let Some(comment) = cli.trusted_comment.as_deref() {
        builder = builder.trusted_comment(comment);
    }
    if let Some(comment) = cli.untrusted_comment.as_deref() {
        builder = builder.untrusted_comment(comment);
    }
    builder.force(cli.force).quiet(cli.quiet)
}

/// Handle signing a single file
fn handle_sign_single(
    cli: &Cli,
    message_file: &std::path::Path,
    secret_key_file: &std::path::Path,
    prehashed: bool,
    seckey: &minisign::keys::SeckeyStruct,
    credential_id: &str,
    password: Option<&Zeroizing<String>>,
) -> Result<()> {
    let default_signature = Cli::default_signature_path(message_file)?;
    let signature_file = cli.signature_file.as_ref().unwrap_or(&default_signature);

    let options = apply_sign_options(
        SignOptions::builder(secret_key_file, message_file)
            .signature_file(signature_file)
            .prehashed(prehashed),
        cli,
    )
    .build();

    // Use sign_with_key to avoid redundant file load
    let result = sign_with_key(
        message_file,
        seckey,
        &options,
        password.map(|p| p.as_bytes()),
    )?;

    save_password_to_credential_store(credential_id, password, cli.save_password, cli.quiet, None);

    if !cli.quiet {
        println!(
            "Signing with key: {} ({})",
            result.key_id(),
            result.key_id_words()
        );
        println!("Signature written to {}", result.signature_file().display());
    }

    Ok(())
}

/// Handle signing multiple files
fn handle_sign_multiple(
    cli: &Cli,
    message_files: Vec<std::path::PathBuf>,
    secret_key_file: &std::path::Path,
    prehashed: bool,
    credential_id: &str,
    password: Option<&Zeroizing<String>>,
) -> Result<()> {
    if cli.signature_file.is_some() {
        return Err(Error::Usage(
            "Custom signature file (-x) not supported with multiple message files".into(),
        ));
    }

    let options = apply_sign_options(
        SignOptions::builder(secret_key_file, std::path::Path::new("")).prehashed(prehashed),
        cli,
    )
    .build();

    sign_multiple_files(
        message_files,
        &options,
        password.map(|p| p.as_bytes()),
        #[cfg(feature = "parallel")]
        cli.sequential,
        #[cfg(not(feature = "parallel"))]
        true,
    )?;

    save_password_to_credential_store(credential_id, password, cli.save_password, cli.quiet, None);

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
        PublicKeySource::Base64(pk_base64)
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
        let default_signature = Cli::default_signature_path(message_file)?;
        let signature_file = cli.signature_file.as_ref().unwrap_or(&default_signature);

        let options = VerifyOptions::builder(public_key, signature_file, message_file)
            .output(cli.output)
            .quiet(cli.quiet)
            .force_prehashed(cli.prehashed)
            .build();

        let result = verify(&options)?;

        // Handle output modes
        if cli.output {
            // -o: Output file content to stdout after verification
            let content =
                std::fs::read(message_file).map_err(|e| Error::file_read(message_file, e))?;
            io::stdout()
                .write_all(&content)
                .map_err(|e| Error::Io(format!("failed to write to stdout: {e}")))?;
        } else if cli.pretty_quiet {
            // -Q: Only show trusted comment
            println!("{}", result.trusted_comment());
        } else if !cli.quiet {
            // Normal output
            println!(
                "Verified with key: {} ({})",
                result.key_id(),
                result.key_id_words()
            );
            println!("Signature and comment signature verified");
            println!("Trusted comment: {}", result.trusted_comment());
        }
    } else {
        // Multiple files path - use multi-file API
        if cli.signature_file.is_some() {
            return Err(Error::Usage(
                "Custom signature file (-x) not supported with multiple message files".into(),
            ));
        }

        if cli.output {
            return Err(Error::Usage(
                "Output flag (-o) not supported with multiple message files".into(),
            ));
        }

        let options = VerifyOptions::builder(
            public_key,
            std::path::Path::new(""),
            std::path::Path::new(""),
        )
        .output(cli.output)
        .quiet(cli.quiet)
        .force_prehashed(cli.prehashed)
        .build();

        verify_multiple_files(
            message_files.into_owned(),
            &options,
            #[cfg(feature = "parallel")]
            cli.sequential,
            #[cfg(not(feature = "parallel"))]
            true,
        )?;
    }

    Ok(())
}

fn handle_recreate(cli: &Cli) -> Result<()> {
    // Reject -W flag for recreate operation
    // -W is documented as "generate and change only" in cli.rs
    if cli.no_password {
        return Err(Error::Usage(
            "-W (--no-password) is not supported for recreate operation. \
             Use -K (--change-password) with -W to remove password first."
                .into(),
        ));
    }

    // Get secret key path
    let default_secret_key = Cli::default_secret_key_path();
    let secret_key_file = cli.secret_key_file.as_ref().unwrap_or(&default_secret_key);

    // Get public key path
    let default_public_key = Cli::default_public_key_path();
    let public_key_file = cli.public_key_file.as_ref().unwrap_or(&default_public_key);

    // Load the key to check if it's encrypted
    let seckey = load_secret_key(secret_key_file)?;
    let credential_id = seckey.credential_id();

    // Get password: check credential store first, then prompt if needed
    let password = if seckey.is_encrypted() {
        Some(get_password_with_credential_store(
            &credential_id,
            "Password: ",
            cli.quiet,
            cli.password_file.as_deref(),
        )?)
    } else {
        None
    };

    let options = RecreateOptions::new(
        secret_key_file,
        public_key_file,
        cli.untrusted_comment.as_deref(),
        cli.force,
    );

    let result = recreate_with_key(&seckey, &options, password.as_ref().map(|p| p.as_bytes()))?;

    if !cli.quiet {
        println!(
            "Public key recreated as {}",
            result.public_key_file().display()
        );
    }

    if cli.forget_password {
        forget_password_with_feedback(&credential_id, cli.quiet)?;
    }

    Ok(())
}

fn handle_change(cli: &Cli) -> Result<()> {
    // Get secret key path
    let default_secret_key = Cli::default_secret_key_path();
    let secret_key_file = cli.secret_key_file.as_ref().unwrap_or(&default_secret_key);

    // Load the key to get credential ID and check if it's encrypted
    let seckey = load_secret_key(secret_key_file)?;
    let old_credential_id = seckey.credential_id();

    // Handle --forget-password (standalone usage)
    if cli.forget_password {
        return forget_password_with_feedback(&old_credential_id, cli.quiet);
    }

    // Get current password: check credential store first, then prompt if needed
    let current_password = if seckey.is_encrypted() {
        Some(get_password_with_credential_store(
            &old_credential_id,
            "Current password: ",
            cli.quiet,
            cli.password_file.as_deref(),
        )?)
    } else {
        None
    };

    // Prompt for new password with confirmation based on -W flag
    // -W means "don't use a new password" (remove encryption)
    let new_password = if cli.no_password {
        None
    } else {
        Some(prompt_password_with_confirmation(
            cli.password_file.as_deref(),
        )?)
    };

    let options = ChangeOptions::builder(secret_key_file)
        .remove_password(cli.no_password && new_password.is_none())
        .allow_kdf_fallback(cli.allow_kdf_fallback)
        .force_weak_kdf(resolve_force_weak_kdf(cli))
        .build();

    let result = change(
        &options,
        current_password.as_ref().map(|p| p.as_bytes()),
        new_password.as_ref().map(|p| p.as_bytes()),
    )?;

    // Delete old credential entry if password changed (credential_id changes with new password)
    if seckey.is_encrypted() && old_credential_id != result.credential_id() {
        let _ = minisign::credential_store::forget_password(&old_credential_id);
    }

    save_password_to_credential_store(
        result.credential_id(),
        new_password.as_ref(),
        cli.save_password,
        cli.quiet,
        None,
    );

    if !cli.quiet {
        println!(
            "Password changed for {}",
            result.secret_key_file().display()
        );
    }

    Ok(())
}

/// Display the signature inspection result
fn display_signature_inspect_result(result: &SignatureInspectResult) {
    use minisign::signature::SignatureAlgorithm;

    println!("Signature Information:");
    println!("├─ Key ID: {}", result.key_id());
    println!("├─ Key ID (words): {}", result.key_id_words());

    let algorithm_desc = match result.algorithm() {
        SignatureAlgorithm::Normal => "Normal (Ed25519)",
        SignatureAlgorithm::Prehashed => "Prehashed (Blake2b-512)",
    };
    println!("└─ Algorithm: {algorithm_desc}");
}

/// Display the inspection result
fn display_inspect_result(result: &InspectResult) {
    // Display security level prominently first (for secret keys)
    if let Some(security_level) = result.security_level() {
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
    if result.key_type() == KeyType::SecretEncrypted
        && result.key_id() == ENCRYPTED_KEYNUM_PLACEHOLDER
    {
        println!("├─ Key ID: [encrypted - password required]");
        println!("├─ Key ID (words): [encrypted]");
    } else {
        println!("├─ Key ID: {}", result.key_id());
        println!("├─ Key ID (words): {}", result.key_id_words());
    }

    // Display credential ID for secret keys
    if let Some(credential_id) = result.credential_id() {
        println!("├─ Credential ID: {credential_id}");
    }

    match result.key_type() {
        KeyType::SecretEncrypted => {
            println!("├─ Encrypted: Yes");
            println!("├─ KDF Algorithm: Scrypt");
            println!(
                "├─ Password saved: {}",
                if result.password_saved() { "Yes" } else { "No" }
            );

            if let Some(kdf) = result.kdf_info() {
                println!("└─ KDF Parameters:");
                println!(
                    "   ├─ opslimit: {} (N=2^{}, r={}, p={})",
                    kdf.opslimit(),
                    kdf.log_n(),
                    kdf.r(),
                    kdf.p()
                );
                println!(
                    "   ├─ memlimit: {} ({} MB)",
                    kdf.memlimit(),
                    kdf.memlimit() / 1_048_576
                );

                if kdf.is_fallback() {
                    println!("   ├─ Creation: Fallback (reduced parameters)");
                    if let Some(multiplier) = kdf.weakness_multiplier() {
                        println!(
                            "   └─ Brute-force resistance: {multiplier}x weaker than production strength"
                        );
                    }
                } else {
                    println!("   └─ Creation: Normal (production parameters)");
                }

                // Add recommendation for weak keys
                if result.security_level() == Some(SecurityLevel::Low) {
                    println!();
                    println!(
                        "*** RECOMMENDATION: Regenerate this key on a system with >=2GB RAM for full security."
                    );
                }
            }
        }
        KeyType::SecretUnencrypted => {
            println!("├─ Encrypted: No");
            println!(
                "└─ Password saved: {}",
                if result.password_saved() { "Yes" } else { "No" }
            );
            println!();
            println!("*** WARNING: This key is stored in plaintext.");
            println!("   Anyone with file access can use it without a password.");
        }
        KeyType::Public => {
            println!("└─ Type: Ed25519 Public Key");
        }
    }
}

fn build_inspect_options(path: &std::path::Path, no_decrypt: bool) -> InspectOptions<'_> {
    let opts = InspectOptions::new(path);
    if no_decrypt {
        opts.skip_credential_store_check()
    } else {
        opts
    }
}

fn handle_inspect(cli: &Cli) -> Result<()> {
    // Check if we're inspecting a signature file
    if let Some(ref sig_file) = cli.signature_file {
        let result = inspect_signature(sig_file)?;

        println!("Inspecting: {}\n", sig_file.display());
        display_signature_inspect_result(&result);
        return Ok(());
    }

    // Determine the source key file path first (before any credential store access)
    // Priority: -s (secret key), -p (public key file), -P (public key base64), then default secret key
    let default_secret_key = Cli::default_secret_key_path();
    let key_file_path: Option<&std::path::Path> = if cli.secret_key_file.is_some() {
        cli.secret_key_file.as_deref()
    } else if cli.public_key_file.is_some() {
        cli.public_key_file.as_deref()
    } else if cli.public_key_base64.is_none() {
        Some(default_secret_key.as_path())
    } else {
        None
    };

    // Handle --forget-password before calling inspect() to avoid a spurious
    // credential store read (which triggers a macOS Keychain prompt on its own).
    if cli.forget_password
        && let Some(path) = key_file_path
    {
        let seckey = load_secret_key(path)?;
        let credential_id = seckey.credential_id();
        return forget_password_with_feedback(&credential_id, cli.quiet);
    }

    let (mut result, source_description, key_file_path) =
        if let Some(ref sk_file) = cli.secret_key_file {
            let options = build_inspect_options(sk_file.as_path(), cli.no_decrypt);
            (
                inspect(&options)?,
                format!("Inspecting: {}", sk_file.display()),
                Some(sk_file.as_path()),
            )
        } else if let Some(ref pk_file) = cli.public_key_file {
            let options = build_inspect_options(pk_file.as_path(), cli.no_decrypt);
            (
                inspect(&options)?,
                format!("Inspecting: {}", pk_file.display()),
                Some(pk_file.as_path()),
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
            let options = build_inspect_options(&default_secret_key, cli.no_decrypt);
            (
                inspect(&options)?,
                format!("Inspecting: {} (default)", default_secret_key.display()),
                Some(default_secret_key.as_path()),
            )
        };

    // Smart decryption: If key is encrypted and --no-decrypt is not set, get password and decrypt
    let mut decrypted = false;
    if result.key_type() == KeyType::SecretEncrypted
        && result.key_id() == ENCRYPTED_KEYNUM_PLACEHOLDER
        && !cli.no_decrypt
        && let Some(path) = key_file_path
    {
        // Load secret key to get credential ID for credential store lookup
        let seckey = load_secret_key(path)?;
        let credential_id = seckey.credential_id();

        // Try credential store first, then prompt if needed
        let password = get_password_with_credential_store(
            &credential_id,
            "Password: ",
            cli.quiet,
            cli.password_file.as_deref(),
        )?;

        result = inspect_private_with_key(&seckey, password.as_bytes())?;
        decrypted = true;

        // Save password to credential store if requested
        save_password_to_credential_store(
            &credential_id,
            Some(&password),
            cli.save_password,
            cli.quiet,
            None,
        );
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

/// Resolve `--force-weak-kdf` flag, gated to debug builds only.
///
/// In release builds this always returns `false`, preventing accidental use
/// of weak KDF parameters in production.
fn resolve_force_weak_kdf(cli: &Cli) -> bool {
    cfg!(debug_assertions) && cli.force_weak_kdf
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
        // Wrap password in Zeroizing immediately to prevent leakage
        let mut password = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| Error::Io(format!("Failed to read password file: {e}")))?,
        );
        // Trim trailing newline in place
        let trimmed_len = password.trim_end().len();
        password.truncate(trimmed_len);
        return Ok(password);
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

    if password1.len() < MIN_RECOMMENDED_PASSWORD_LEN {
        eprintln!(
            "Warning: short password. Consider using at least {MIN_RECOMMENDED_PASSWORD_LEN} characters."
        );
    }

    Ok(password1)
}
