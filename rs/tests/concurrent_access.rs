//! Concurrent access tests for minisign
//!
//! Tests TOCTOU (Time-of-Check-Time-of-Use) prevention by spawning
//! multiple threads/processes attempting to create the same files.

use minisign::ops::{
    generate::{GenerateOptions, generate},
    sign::{SignOptions, sign},
};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

/// Test concurrent key generation attempts to the same file
///
/// This verifies that `create_new(true)` prevents race conditions
/// when multiple threads try to create key files simultaneously.
#[test]
fn test_concurrent_key_generation_same_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = Arc::new(temp_dir.path().join("concurrent.key"));
    let public_key = Arc::new(temp_dir.path().join("concurrent.pub"));

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];
    let success_count = Arc::new(std::sync::Mutex::new(0u32));
    let error_count = Arc::new(std::sync::Mutex::new(0u32));

    for _ in 0..num_threads {
        let secret_key = Arc::clone(&secret_key);
        let public_key = Arc::clone(&public_key);
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier.wait();

            // All threads attempt to create keys at the same time
            let opts = GenerateOptions {
                secret_key_file: secret_key.as_ref().clone(),
                public_key_file: public_key.as_ref().clone(),
                comment: None,
                force: false, // Important: no force, should fail if exists
                no_password: true,
                allow_kdf_fallback: false,
                #[cfg(debug_assertions)]
                force_weak_kdf: false,
            };

            match generate(&opts, None) {
                Ok(_) => {
                    *success.lock().unwrap() += 1;
                }
                Err(_) => {
                    *errors.lock().unwrap() += 1;
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let success = *success_count.lock().unwrap();
    let errors = *error_count.lock().unwrap();

    // Exactly one thread should succeed, the rest should fail
    assert_eq!(success, 1, "Expected exactly 1 successful key generation");
    assert_eq!(
        errors,
        u32::try_from(num_threads - 1).unwrap(),
        "Expected {} failed attempts",
        num_threads - 1
    );

    // Verify that the files exist and are valid
    assert!(secret_key.exists(), "Secret key file should exist");
    assert!(public_key.exists(), "Public key file should exist");
}

/// Test concurrent signature creation to the same file
///
/// Verifies that signature file creation is atomic and prevents
/// race conditions.
#[test]
fn test_concurrent_signature_creation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // First, generate a key pair
    let secret_key = temp_dir.path().join("sign.key");
    let public_key = temp_dir.path().join("sign.pub");

    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create a test message
    let message_file = temp_dir.path().join("message.txt");
    fs::write(&message_file, b"concurrent test message").expect("Failed to create message");

    // Shared signature file path
    let sig_file = Arc::new(temp_dir.path().join("message.txt.minisig"));
    let secret_key = Arc::new(secret_key);
    let message_file = Arc::new(message_file);

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];
    let success_count = Arc::new(std::sync::Mutex::new(0u32));
    let error_count = Arc::new(std::sync::Mutex::new(0u32));

    for _ in 0..num_threads {
        let sig_file = Arc::clone(&sig_file);
        let secret_key = Arc::clone(&secret_key);
        let message_file = Arc::clone(&message_file);
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);

        let handle = thread::spawn(move || {
            // Wait for all threads to be ready
            barrier.wait();

            // All threads attempt to sign at the same time
            let opts = SignOptions {
                secret_key_file: secret_key.to_str().unwrap().to_string(),
                message_file: message_file.to_str().unwrap().to_string(),
                signature_file: Some(sig_file.to_str().unwrap().to_string()),
                prehashed: true,
                trusted_comment: None,
                untrusted_comment: None,
                force: false, // No force - should fail if exists
            };

            match sign(&opts, None) {
                Ok(_) => {
                    *success.lock().unwrap() += 1;
                }
                Err(_) => {
                    *errors.lock().unwrap() += 1;
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let success = *success_count.lock().unwrap();
    let errors = *error_count.lock().unwrap();

    // Exactly one thread should succeed
    assert_eq!(
        success, 1,
        "Expected exactly 1 successful signature creation"
    );
    assert_eq!(
        errors,
        u32::try_from(num_threads - 1).unwrap(),
        "Expected {} failed attempts",
        num_threads - 1
    );

    // Verify signature file exists
    assert!(sig_file.exists(), "Signature file should exist");
}

/// Test that force mode allows overwrites even with concurrent access
///
/// This verifies that when force=true, concurrent writes don't fail
/// (though the result may be from any of the racing threads).
#[test]
fn test_concurrent_key_generation_with_force() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = Arc::new(temp_dir.path().join("force.key"));
    let public_key = Arc::new(temp_dir.path().join("force.pub"));

    let num_threads = 5;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];

    for _ in 0..num_threads {
        let secret_key = Arc::clone(&secret_key);
        let public_key = Arc::clone(&public_key);
        let barrier = Arc::clone(&barrier);

        let handle = thread::spawn(move || {
            barrier.wait();

            let opts = GenerateOptions {
                secret_key_file: secret_key.as_ref().clone(),
                public_key_file: public_key.as_ref().clone(),
                comment: None,
                force: true, // Force mode should allow overwrites
                no_password: true,
                allow_kdf_fallback: false,
                #[cfg(debug_assertions)]
                force_weak_kdf: false,
            };

            // All operations should succeed (or fail for other reasons, not file exists)
            generate(&opts, None).expect("Generate should succeed with force=true");
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Files should exist (created by one of the threads)
    assert!(secret_key.exists(), "Secret key should exist");
    assert!(public_key.exists(), "Public key should exist");
}

/// Test sequential file creation is reliable
///
/// This is a control test to verify that non-concurrent access works
/// as expected.
#[test]
fn test_sequential_key_generation() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // First generation should succeed
    let secret_key = temp_dir.path().join("seq1.key");
    let public_key = temp_dir.path().join("seq1.pub");

    let opts = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: false,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };

    generate(&opts, None).expect("First generation should succeed");
    assert!(secret_key.exists());
    assert!(public_key.exists());

    // Second generation to same path should fail without force
    let result = generate(&opts, None);
    assert!(
        result.is_err(),
        "Second generation should fail without force"
    );

    // With force, should succeed
    let opts_force = GenerateOptions {
        secret_key_file: secret_key.clone(),
        public_key_file: public_key.clone(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };

    generate(&opts_force, None).expect("Generation with force should succeed");
}

/// Test that `create_new` prevents TOCTOU even with a deliberate timing window
///
/// This test creates a scenario where threads check for file existence
/// before attempting to create, but the atomic `create_new` should still
/// prevent races.
#[test]
fn test_toctou_prevention_with_existence_check() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let test_file = Arc::new(temp_dir.path().join("toctou.key"));

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = vec![];
    let success_count = Arc::new(std::sync::Mutex::new(0u32));

    for i in 0..num_threads {
        let test_file = Arc::clone(&test_file);
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);

        let handle = thread::spawn(move || {
            barrier.wait();

            // Deliberately check if file exists (classic TOCTOU pattern)
            if !test_file.exists() {
                // Add tiny delay to increase chance of race
                std::thread::sleep(std::time::Duration::from_micros(10));

                // Now try to create the file
                let _secret_key = PathBuf::from(format!("{}.{}", test_file.display(), i));
                let public_key = PathBuf::from(format!("{}.{}.pub", test_file.display(), i));

                let opts = GenerateOptions {
                    secret_key_file: test_file.as_ref().clone(),
                    public_key_file: public_key.clone(),
                    comment: None,
                    force: false,
                    no_password: true,
                    allow_kdf_fallback: false,
                    #[cfg(debug_assertions)]
                    force_weak_kdf: false,
                };

                if generate(&opts, None).is_ok() {
                    *success.lock().unwrap() += 1;
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let success = *success_count.lock().unwrap();

    // Despite the TOCTOU pattern in our test code, atomic create_new
    // should ensure only one thread succeeds
    assert_eq!(success, 1, "Atomic create_new should prevent TOCTOU races");
}

/// Test concurrent access to different files (should all succeed)
///
/// This is a sanity check that our atomic file creation doesn't
/// prevent legitimate concurrent operations on different files.
#[test]
fn test_concurrent_different_files() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    let num_threads = 8;
    let mut handles = vec![];

    for i in 0..num_threads {
        let temp_dir = temp_dir.path().to_owned();

        let handle = thread::spawn(move || {
            let secret_key = temp_dir.join(format!("key_{i}.key"));
            let public_key = temp_dir.join(format!("key_{i}.pub"));

            let opts = GenerateOptions {
                secret_key_file: secret_key.clone(),
                public_key_file: public_key.clone(),
                comment: None,
                force: false,
                no_password: true,
                allow_kdf_fallback: false,
                #[cfg(debug_assertions)]
                force_weak_kdf: false,
            };

            generate(&opts, None).expect("Should succeed for different files");

            (secret_key, public_key)
        });

        handles.push(handle);
    }

    // All threads should succeed and create their files
    let mut results = vec![];
    for handle in handles {
        let (secret_key, public_key) = handle.join().expect("Thread panicked");
        results.push((secret_key, public_key));
    }

    // Verify all files were created
    assert_eq!(results.len(), num_threads);
    for (secret_key, public_key) in results {
        assert!(
            secret_key.exists(),
            "Secret key file should exist"
        );
        assert!(
            public_key.exists(),
            "Public key file should exist"
        );
    }
}
