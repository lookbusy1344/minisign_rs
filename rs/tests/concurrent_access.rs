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
            let opts = GenerateOptions::builder(secret_key.as_ref(), public_key.as_ref())
                .no_password(true)
                .build();

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

    let gen_opts = GenerateOptions::builder(secret_key.as_path(), public_key.as_path())
        .force(true)
        .no_password(true)
        .build();
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
            let opts = SignOptions::builder(&secret_key, &message_file)
                .signature_file(&sig_file)
                .build();

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

            let opts = GenerateOptions::builder(secret_key.as_ref(), public_key.as_ref())
                .force(true)
                .no_password(true)
                .build();

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

    // The resulting key file must be a parseable, non-corrupt key — not just present.
    // A corrupt file from interleaved writes (without atomic rename) would fail here.
    let sk_contents =
        std::fs::read_to_string(secret_key.as_ref()).expect("Secret key file should be readable");
    minisign::keys::SeckeyStruct::from_file_contents(&sk_contents)
        .expect("Secret key file must parse as a valid SeckeyStruct after concurrent writes");

    let pk_contents =
        std::fs::read_to_string(public_key.as_ref()).expect("Public key file should be readable");
    minisign::keys::PubkeyStruct::from_file_contents(&pk_contents)
        .expect("Public key file must parse as a valid PubkeyStruct after concurrent writes");
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

    let opts = GenerateOptions::builder(secret_key.as_path(), public_key.as_path())
        .no_password(true)
        .build();

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
    let opts_force = GenerateOptions::builder(secret_key.as_path(), public_key.as_path())
        .force(true)
        .no_password(true)
        .build();

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

                let opts = GenerateOptions::builder(test_file.as_ref(), public_key.as_path())
                    .no_password(true)
                    .build();

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

            let opts = GenerateOptions::builder(secret_key.as_path(), public_key.as_path())
                .no_password(true)
                .build();

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

/// Test multiple threads signing with the same key simultaneously
///
/// Verifies that concurrent thread-level access to the same key file does not
/// corrupt signatures or panic.
#[test]
fn test_concurrent_signing_same_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Generate a key pair first
    let secret_key = temp_dir.path().join("multi.key");
    let public_key = temp_dir.path().join("multi.pub");

    let gen_opts = GenerateOptions::builder(secret_key.as_path(), public_key.as_path())
        .force(true)
        .no_password(true)
        .build();
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
            let opts = SignOptions::builder(secret_key_str.as_ref(), msg_file_str.as_ref())
                .signature_file(sig_file_str.as_ref())
                .build();

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
/// Verifies that atomic temp-file-then-rename writes ensure any concurrent
/// read observes either the complete file or nothing — never partial content.
#[test]
fn test_read_during_write() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let secret_key = Arc::new(temp_dir.path().join("write.key"));
    let public_key = Arc::new(temp_dir.path().join("write.pub"));

    let read_attempts = Arc::new(std::sync::Mutex::new(vec![]));
    let read_attempts_reader = Arc::clone(&read_attempts);

    // Reader loops until this flag is set, then does a few final reads to
    // guarantee the atomicity assertion has data points to check.
    let write_done = Arc::new(AtomicBool::new(false));
    let write_done_reader = Arc::clone(&write_done);

    let secret_key_reader = Arc::clone(&secret_key);

    // Barrier releases writer and reader simultaneously, ensuring the reader
    // is actively looping when generate() begins.
    let barrier = Arc::new(Barrier::new(2));
    let barrier_reader = Arc::clone(&barrier);

    let reader = thread::spawn(move || {
        barrier_reader.wait();
        while !write_done_reader.load(Ordering::Acquire) {
            match fs::read(&*secret_key_reader) {
                Ok(data) => read_attempts_reader.lock().unwrap().push((true, data.len())),
                Err(_) => read_attempts_reader.lock().unwrap().push((false, 0)),
            }
            thread::yield_now();
        }
        // Five post-write reads guarantee the atomicity assertion below fires
        // at least once, eliminating the vacuous-pass failure mode.
        for _ in 0..5 {
            if let Ok(data) = fs::read(&*secret_key_reader) {
                read_attempts_reader.lock().unwrap().push((true, data.len()));
            }
        }
    });

    barrier.wait();
    let opts = GenerateOptions::builder(secret_key.as_ref(), public_key.as_ref())
        .force(true)
        .no_password(true)
        .build();
    generate(&opts, None).expect("Generate should succeed");
    write_done.store(true, Ordering::Release);

    reader.join().expect("Reader panicked");

    assert!(secret_key.exists(), "Secret key should exist");
    let final_data = fs::read(&*secret_key).expect("Should read final file");
    assert!(!final_data.is_empty(), "Final file should not be empty");

    let complete_size = final_data.len();
    let attempts = read_attempts.lock().unwrap();

    // The 5 post-write reads mean this assertion always fires; if it doesn't,
    // the reader thread never ran at all — a test infrastructure failure.
    assert!(
        attempts.iter().any(|(ok, sz)| *ok && *sz > 0),
        "reader never observed a completed write — atomicity invariant untested"
    );

    // Atomicity check: generate() uses atomic temp-then-rename, so any
    // successful read must return exactly complete_size bytes, never partial.
    for (success, size) in attempts.iter() {
        if *success && *size > 0 {
            assert_eq!(
                *size, complete_size,
                "atomic write must not expose partial content: got {size} bytes, expected {complete_size}"
            );
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

            let opts = GenerateOptions::builder(target_file.as_ref(), &public_key)
                .no_password(true)
                .build();

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
