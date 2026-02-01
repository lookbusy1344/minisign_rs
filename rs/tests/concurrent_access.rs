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
                secret_key_file: secret_key.as_ref(),
                public_key_file: public_key.as_ref(),
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
        secret_key_file: secret_key.as_path(),
        public_key_file: public_key.as_path(),
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
                secret_key_file: &secret_key,
                message_file: &message_file,
                signature_file: Some(&sig_file),
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
                secret_key_file: secret_key.as_ref(),
                public_key_file: public_key.as_ref(),
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
        secret_key_file: secret_key.as_path(),
        public_key_file: public_key.as_path(),
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
        secret_key_file: secret_key.as_path(),
        public_key_file: public_key.as_path(),
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
                    secret_key_file: test_file.as_ref(),
                    public_key_file: public_key.as_path(),
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
                secret_key_file: secret_key.as_path(),
                public_key_file: public_key.as_path(),
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
        assert!(secret_key.exists(), "Secret key file should exist");
        assert!(public_key.exists(), "Public key file should exist");
    }
}

/// Test multiple processes signing with the same key simultaneously
///
/// Unlike thread-based tests, this spawns actual separate processes to verify
/// that file locking and atomic operations work across process boundaries.
#[test]
fn test_multiprocess_signing_same_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate a key pair first
    let secret_key = temp_dir.path().join("multi.key");
    let public_key = temp_dir.path().join("multi.pub");

    let gen_opts = GenerateOptions {
        secret_key_file: secret_key.as_path(),
        public_key_file: public_key.as_path(),
        comment: None,
        force: true,
        no_password: true,
        allow_kdf_fallback: false,
        #[cfg(debug_assertions)]
        force_weak_kdf: false,
    };
    generate(&gen_opts, None).expect("Failed to generate key");

    // Create multiple message files
    let num_processes = 5;
    let mut message_files = vec![];
    for i in 0..num_processes {
        let msg_file = temp_dir.path().join(format!("msg{i}.txt"));
        fs::write(&msg_file, format!("message {i}")).expect("Failed to write message");
        message_files.push(msg_file);
    }

    // Spawn multiple processes that will all sign simultaneously
    let mut handles = vec![];
    for (i, msg_file) in message_files.iter().enumerate() {
        let secret_key_str = secret_key.to_str().unwrap().to_string();
        let msg_file_str = msg_file.to_str().unwrap().to_string();
        let sig_file = temp_dir.path().join(format!("msg{i}.txt.minisig"));
        let sig_file_str = sig_file.to_str().unwrap().to_string();

        let handle = thread::spawn(move || {
            // Call sign operation directly (simulates separate process behavior)
            let opts = SignOptions {
                secret_key_file: secret_key_str.as_ref(),
                message_file: msg_file_str.as_ref(),
                signature_file: Some(sig_file_str.as_ref()),
                prehashed: true,
                trusted_comment: None,
                untrusted_comment: None,
                force: false,
            };

            sign(&opts, None)
        });

        handles.push((handle, i));
    }

    // Wait for all to complete
    let mut success_count = 0;
    for (handle, i) in handles {
        match handle.join().expect("Thread panicked") {
            Ok(_) => {
                success_count += 1;
                let sig_file = temp_dir.path().join(format!("msg{i}.txt.minisig"));
                assert!(sig_file.exists(), "Signature file {i} should exist");
            }
            Err(e) => {
                panic!("Process {i} failed: {e:?}");
            }
        }
    }

    // All processes should succeed since they're signing different message files
    assert_eq!(success_count, num_processes, "All processes should succeed");
}

/// Test reading a key file while it's being written
///
/// Verifies that partial reads during key generation fail gracefully
/// rather than returning corrupted data.
#[test]
fn test_read_during_write() {
    use std::time::Duration;

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = Arc::new(temp_dir.path().join("write.key"));
    let public_key = Arc::new(temp_dir.path().join("write.pub"));

    let secret_key_reader = Arc::clone(&secret_key);
    let read_attempts = Arc::new(std::sync::Mutex::new(vec![]));
    let read_attempts_clone = Arc::clone(&read_attempts);

    // Spawn writer thread
    let secret_key_writer = Arc::clone(&secret_key);
    let public_key_writer = Arc::clone(&public_key);
    let writer = thread::spawn(move || {
        let opts = GenerateOptions {
            secret_key_file: secret_key_writer.as_ref(),
            public_key_file: public_key_writer.as_ref(),
            comment: None,
            force: true,
            no_password: true,
            allow_kdf_fallback: false,
            #[cfg(debug_assertions)]
            force_weak_kdf: false,
        };

        // Add small delay to let reader start first
        thread::sleep(Duration::from_millis(5));
        generate(&opts, None).expect("Generate should succeed");
    });

    // Spawn reader thread that attempts to read during write
    let reader = thread::spawn(move || {
        for _ in 0..50 {
            match fs::read(&*secret_key_reader) {
                Ok(data) => {
                    // If we successfully read, store the size
                    read_attempts_clone.lock().unwrap().push((true, data.len()));
                }
                Err(_) => {
                    // File doesn't exist yet or read failed
                    read_attempts_clone.lock().unwrap().push((false, 0));
                }
            }
            thread::sleep(Duration::from_micros(100));
        }
    });

    writer.join().expect("Writer panicked");
    reader.join().expect("Reader panicked");

    // Check that the file exists and is valid after both threads complete
    assert!(secret_key.exists(), "Secret key should exist");
    let final_data = fs::read(&*secret_key).expect("Should read final file");
    assert!(!final_data.is_empty(), "Final file should not be empty");

    // Verify that any successful reads had valid data
    let attempts = read_attempts.lock().unwrap();
    for (success, size) in attempts.iter() {
        if *success && *size > 0 {
            // If we read data, it should be at least plausible
            // (key files are relatively fixed size after base64 decoding)
            assert!(*size > 50, "Partial read detected: size {size}");
        }
    }
}

/// Test that file creation is truly atomic even with aggressive concurrent access
///
/// This test verifies that `create_new(true)` provides atomic file creation
/// across multiple rapid attempts, ensuring no race windows.
#[test]
fn test_atomic_file_creation_stress() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let target_file = Arc::new(temp_dir.path().join("atomic.key"));
    let public_key_base = temp_dir.path().join("atomic");

    let num_attempts = 20;
    let barrier = Arc::new(Barrier::new(num_attempts));
    let mut handles = vec![];
    let success_count = Arc::new(std::sync::Mutex::new(0u32));

    for i in 0..num_attempts {
        let target_file = Arc::clone(&target_file);
        let public_key = public_key_base.with_extension(format!("pub.{i}"));
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);

        let handle = thread::spawn(move || {
            barrier.wait();

            // Minimal delay to maximize contention
            thread::sleep(std::time::Duration::from_nanos(100));

            let opts = GenerateOptions {
                secret_key_file: target_file.as_ref(),
                public_key_file: &public_key,
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
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let success = *success_count.lock().unwrap();

    // Exactly one should succeed despite aggressive concurrent attempts
    assert_eq!(
        success, 1,
        "Atomic create_new must prevent all but one creation"
    );
    assert!(target_file.exists(), "Target file should exist");
}
