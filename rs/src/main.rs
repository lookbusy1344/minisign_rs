use clap::Parser;
use is_terminal::IsTerminal;
use minisign::{
    Error, Result,
    cli::{Action, Cli},
    ops::{
        ChangeOptions, GenerateOptions, PublicKeySource, RecreateOptions, SignOptions,
        VerifyOptions, change, generate, recreate, sign, verify,
    },
};
use std::io::{self, Write};
use std::process;

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
        .ok_or_else(|| Error::Usage("No action specified. Use -G, -S, -V, -R, or -C".into()))?;

    match action {
        Action::Generate => handle_generate(&cli),
        Action::Sign => handle_sign(&cli),
        Action::Verify => handle_verify(&cli),
        Action::Recreate => handle_recreate(&cli),
        Action::Change => handle_change(&cli),
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

    // Get password (unless -W was specified)
    let password = if cli.no_password {
        None
    } else {
        Some(prompt_password("Password: ", cli.password_file.as_deref())?)
    };

    let options = GenerateOptions {
        secret_key_file,
        public_key_file,
        comment,
        force: cli.force,
        no_password: cli.no_password,
    };

    let result = generate(&options, password.as_deref().map(str::as_bytes))?;

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
        println!("minisign -Vm <file> -P {}", result.keynum_hex);
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
    let signature_file = cli
        .signature_file
        .clone()
        .unwrap_or_else(|| Cli::default_signature_path(message_file));

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
        prehashed: !cli.legacy, // Legacy mode means non-prehashed
        force: cli.force,
    };

    let result = sign(&options, password.as_deref().map(str::as_bytes))?;

    if !cli.quiet {
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
    let signature_file = cli
        .signature_file
        .clone()
        .unwrap_or_else(|| Cli::default_signature_path(message_file));

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

    let result = recreate(&options, password.as_deref().map(str::as_bytes))?;

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
    };

    let result = change(
        &options,
        current_password.as_deref().map(str::as_bytes),
        new_password.as_deref().map(str::as_bytes),
    )?;

    if !cli.quiet {
        println!("Password changed for {}", result.secret_key_file.display());
    }

    Ok(())
}

/// Check if stdin is a terminal (interactive mode)
fn is_interactive() -> bool {
    io::stdin().is_terminal()
}

/// Prompt for password using rpassword or read from file
fn prompt_password(prompt: &str, password_file: Option<&std::path::Path>) -> Result<String> {
    // If password file is provided, read from it
    if let Some(path) = password_file {
        let password = std::fs::read_to_string(path)
            .map_err(|e| Error::Io(format!("Failed to read password file: {e}")))?;
        // Trim trailing newline if present
        return Ok(password.trim_end().to_string());
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

    rpassword::read_password().map_err(|e| Error::Io(format!("Failed to read password: {e}")))
}
