//! Public key recreation from secret key
//!
//! This module implements recreating a public key file from a secret key file.

use crate::{
    Result,
    crypto::PublicKey,
    errors::Error,
    keys::{PubkeyStruct, SeckeyStruct},
};
use std::path::PathBuf;

/// Options for recreating a public key
#[derive(Debug, Clone)]
pub struct RecreateOptions {
    /// Path to the secret key file
    pub secret_key_file: PathBuf,
    /// Path to write the public key file
    pub public_key_file: PathBuf,
    /// Comment for the public key file
    pub comment: Option<String>,
    /// Force overwrite existing public key file
    pub force: bool,
}

/// Result of public key recreation
#[derive(Debug, Clone)]
pub struct RecreateResult {
    /// Path where the public key was written
    pub public_key_file: PathBuf,
    /// The keynum in hexadecimal format
    pub keynum_hex: String,
}

/// Recreate a public key file from a secret key file
///
/// # Arguments
///
/// * `options` - Recreation options including file paths
/// * `password` - Password to decrypt the secret key (if encrypted)
///
/// # Returns
///
/// A `RecreateResult` containing the public key file path and keynum
///
/// # Errors
///
/// Returns an error if:
/// - The secret key file cannot be loaded
/// - The secret key cannot be decrypted (wrong password or corrupted)
/// - The public key file already exists (unless force is true)
/// - File I/O operations fail
pub fn recreate(options: &RecreateOptions, password: Option<&[u8]>) -> Result<RecreateResult> {
    // Check if public key file exists (unless force is set)
    if !options.force && options.public_key_file.exists() {
        return Err(Error::FileExists(options.public_key_file.clone()));
    }

    // Load the secret key
    let seckey = load_secret_key(&options.secret_key_file)?;

    // Decrypt if necessary
    let secret_key = if seckey.is_encrypted() {
        let pwd = password.ok_or(Error::PasswordRequired)?;
        seckey.decrypt(pwd)?
    } else {
        seckey.get_unencrypted_secret_key()?
    };

    // Extract public key from secret key
    // Ed25519 secret keys contain the public key in the second half (bytes 32-64)
    let public_key = extract_public_key_from_secret(&secret_key);

    // Create public key structure
    let pubkey = PubkeyStruct::new(*seckey.keynum(), public_key);

    // Generate comment
    let keynum_hex = seckey.keynum().to_hex();
    let comment = options
        .comment
        .clone()
        .unwrap_or_else(|| format!("minisign public key {keynum_hex}"));

    // Write the public key file
    let pubkey_contents = pubkey.to_file_contents(&comment);
    std::fs::write(&options.public_key_file, pubkey_contents)
        .map_err(|e| Error::file_write(&options.public_key_file, e))?;

    Ok(RecreateResult {
        public_key_file: options.public_key_file.clone(),
        keynum_hex,
    })
}

/// Load a secret key from a file
fn load_secret_key(path: &PathBuf) -> Result<SeckeyStruct> {
    let contents = std::fs::read_to_string(path).map_err(|e| Error::file_read(path, e))?;
    SeckeyStruct::from_file_contents(&contents)
}

/// Extract the public key from an Ed25519 secret key
///
/// Ed25519 secret keys are 64 bytes: [32-byte scalar || 32-byte public key]
fn extract_public_key_from_secret(secret_key: &crate::crypto::SecretKey) -> PublicKey {
    let secret_bytes = secret_key.as_bytes();

    // Ed25519 secret key format: [secret_scalar (32 bytes) || public_key (32 bytes)]
    let mut public_key_bytes = [0u8; 32];
    public_key_bytes.copy_from_slice(&secret_bytes[32..64]);

    PublicKey::from_bytes(public_key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::generate_keypair, keys::SeckeyStruct};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_recreate_from_unencrypted_key() {
        let temp_dir = TempDir::new().unwrap();

        // Generate a test keypair and write secret key
        let (secret_key, _public_key, keynum) = generate_keypair();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        let sk_contents = seckey.to_file_contents("test secret key");
        fs::write(&sk_path, sk_contents).unwrap();

        // Recreate public key
        let pk_path = temp_dir.path().join("test.pub");
        let options = RecreateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: Some("Recreated key".to_string()),
            force: false,
        };

        let result = recreate(&options, None).expect("recreation should succeed");

        // Verify public key file was created
        assert!(pk_path.exists());
        assert_eq!(result.public_key_file, pk_path);
        assert_eq!(result.keynum_hex, keynum.to_hex());

        // Verify the public key contents
        let pk_contents = fs::read_to_string(&pk_path).unwrap();
        // We provided a custom comment
        assert!(pk_contents.contains("Recreated key"));

        // Verify the public key can be parsed and has correct keynum
        let pubkey_recreated = PubkeyStruct::from_file_contents(&pk_contents).unwrap();
        assert_eq!(pubkey_recreated.keynum().to_hex(), keynum.to_hex());
    }

    #[test]
    fn test_recreate_from_encrypted_key_fast() {
        use rand::RngCore;

        let temp_dir = TempDir::new().unwrap();

        // Generate a test keypair with fast encryption (N=2^14)
        let (secret_key, _public_key, keynum) = generate_keypair();
        let password = b"testpassword";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kdf_salt);

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .unwrap();

        let sk_path = temp_dir.path().join("encrypted.key");
        let sk_contents = seckey.to_file_contents("encrypted secret key");
        fs::write(&sk_path, sk_contents).unwrap();

        // Recreate public key
        let pk_path = temp_dir.path().join("recreated.pub");
        let options = RecreateOptions {
            secret_key_file: sk_path.clone(),
            public_key_file: pk_path.clone(),
            comment: None,
            force: false,
        };

        let result = recreate(&options, Some(password)).expect("recreation should succeed");

        // Verify public key file was created
        assert!(pk_path.exists());
        assert_eq!(result.keynum_hex, keynum.to_hex());
    }

    #[test]
    fn test_recreate_without_password_fails() {
        use rand::RngCore;

        let temp_dir = TempDir::new().unwrap();

        // Create an encrypted secret key
        let (secret_key, _public_key, keynum) = generate_keypair();
        let password = b"testpassword";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kdf_salt);

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .unwrap();

        let sk_path = temp_dir.path().join("encrypted.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Try to recreate without password
        let pk_path = temp_dir.path().join("test.pub");
        let options = RecreateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
        };

        let result = recreate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::PasswordRequired));
    }

    #[test]
    fn test_recreate_wrong_password_fails() {
        use rand::RngCore;

        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair();
        let password = b"correctpassword";
        let mut kdf_salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut kdf_salt);

        let n = 1u64 << 14;
        let r = 8u64;
        let kdf_opslimit = 4 * n * r;
        let kdf_memlimit = 128 * n * r;

        let seckey = SeckeyStruct::new_encrypted(
            keynum,
            &secret_key,
            password,
            kdf_salt,
            kdf_opslimit,
            kdf_memlimit,
        )
        .unwrap();

        let sk_path = temp_dir.path().join("encrypted.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Try with wrong password
        let pk_path = temp_dir.path().join("test.pub");
        let options = RecreateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
        };

        let result = recreate(&options, Some(b"wrongpassword"));
        assert!(result.is_err());
        // Wrong password results in checksum failure when decrypting
        assert!(matches!(
            result.unwrap_err(),
            Error::DecryptionFailed | Error::ChecksumFailed
        ));
    }

    #[test]
    fn test_recreate_file_exists_without_force() {
        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        let pk_path = temp_dir.path().join("test.pub");
        fs::write(&pk_path, "existing content").unwrap();

        let options = RecreateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path,
            comment: None,
            force: false,
        };

        let result = recreate(&options, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::FileExists(_)));
    }

    #[test]
    fn test_recreate_force_overwrite() {
        let temp_dir = TempDir::new().unwrap();

        let (secret_key, _public_key, keynum) = generate_keypair();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        let pk_path = temp_dir.path().join("test.pub");
        fs::write(&pk_path, "existing content").unwrap();

        let options = RecreateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path.clone(),
            comment: Some("Forced recreation".to_string()),
            force: true,
        };

        recreate(&options, None).expect("should overwrite with force=true");

        let pk_contents = fs::read_to_string(&pk_path).unwrap();
        assert!(pk_contents.contains("Forced recreation"));
    }

    #[test]
    fn test_extract_public_key_from_secret() {
        let (secret_key, expected_public_key, _keynum) = generate_keypair();

        let extracted_public = extract_public_key_from_secret(&secret_key);

        assert_eq!(extracted_public.as_bytes(), expected_public_key.as_bytes());
    }

    #[test]
    fn test_recreate_matches_original_public_key() {
        let temp_dir = TempDir::new().unwrap();

        // Generate keypair and save both keys
        let (secret_key, public_key, keynum) = generate_keypair();
        let seckey = SeckeyStruct::new_unencrypted(keynum, &secret_key);
        let pubkey_original = PubkeyStruct::new(keynum, public_key);

        let sk_path = temp_dir.path().join("test.key");
        fs::write(&sk_path, seckey.to_file_contents("test")).unwrap();

        // Recreate public key
        let pk_path = temp_dir.path().join("recreated.pub");
        let options = RecreateOptions {
            secret_key_file: sk_path,
            public_key_file: pk_path.clone(),
            comment: Some("test".to_string()),
            force: false,
        };

        recreate(&options, None).expect("recreation should succeed");

        // Load the recreated public key and compare
        let pk_contents = fs::read_to_string(&pk_path).unwrap();
        let pubkey_recreated = PubkeyStruct::from_file_contents(&pk_contents).unwrap();

        assert_eq!(pubkey_original.keynum(), pubkey_recreated.keynum());
        assert_eq!(
            pubkey_original.public_key().as_bytes(),
            pubkey_recreated.public_key().as_bytes()
        );
    }
}
