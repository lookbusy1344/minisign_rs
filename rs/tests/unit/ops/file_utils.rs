//! Unit tests for file utility operations

mod read_message {
    use minisign::ops::file_utils::read_message_file;
    use tempfile::TempDir;

    #[test]
    fn reads_small_file_correctly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("msg.txt");
        std::fs::write(&path, b"hello world").unwrap();
        let buf = read_message_file(&path).expect("should read small file");
        assert_eq!(buf, b"hello world");
    }

    #[test]
    fn rejects_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.txt");
        assert!(read_message_file(&path).is_err());
    }
}

mod bounded_key_read {
    use minisign::ops::file_utils::{MAX_KEY_FILE_BYTES, read_bounded_string_from_reader};
    use std::io::{self, Read};

    struct FixedReader {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl FixedReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, pos: 0 }
        }
    }

    impl Read for FixedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.bytes.len() {
                return Ok(0);
            }
            let remaining = self.bytes.len() - self.pos;
            let to_copy = remaining.min(buf.len());
            buf[..to_copy].copy_from_slice(&self.bytes[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            Ok(to_copy)
        }
    }

    #[test]
    fn rejects_payload_after_cap_is_reached_during_read() {
        let reader = FixedReader::new(vec![b'x'; usize::try_from(MAX_KEY_FILE_BYTES + 1).unwrap()]);
        let result = read_bounded_string_from_reader(reader, "reader", MAX_KEY_FILE_BYTES);
        assert!(result.is_err(), "reader over the cap should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large") || err.contains("exceeds"),
            "error should mention size enforcement: {err}"
        );
    }

    #[test]
    fn rejects_invalid_utf8_after_reading_with_cap() {
        let reader = FixedReader::new(vec![0xff, 0xfe, 0xfd]);
        let result = read_bounded_string_from_reader(reader, "reader", 16);
        assert!(result.is_err(), "invalid UTF-8 should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("UTF-8") || err.contains("utf"),
            "error should mention UTF-8 decoding: {err}"
        );
    }
}

mod size_limit {
    use minisign::ops::file_utils::check_file_size_limit;
    use tempfile::{NamedTempFile, TempDir};

    #[test]
    fn small_file_passes() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), vec![0u8; 1024]).unwrap();
        check_file_size_limit(temp_file.path()).expect("small file should pass");
    }

    #[test]
    fn file_well_under_limit_passes() {
        // Test with 1 MB — well below the 1 GB limit
        const ONE_MB: usize = 1024 * 1024;
        let temp_dir = TempDir::new().unwrap();
        let file = temp_dir.path().join("medium.bin");
        std::fs::write(&file, vec![0u8; ONE_MB]).unwrap();
        check_file_size_limit(&file).expect("1 MB file should pass");
    }
}

#[cfg(unix)]
mod symlink_protection {
    use minisign::ops::file_utils::write_public_key_file;
    use tempfile::TempDir;

    #[test]
    fn force_write_rejects_symlink_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.pub");
        let link = dir.path().join("link.pub");

        std::fs::write(&target, "original content").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_public_key_file(&link, "new content", true);

        assert!(result.is_err(), "force-write through a symlink must fail");
        // The symlink target must not be modified
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original content"
        );
    }
}

#[cfg(unix)]
mod permissions {
    use minisign::ops::file_utils::has_lax_permissions;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn detects_world_readable_permissions() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.key");
        fs::write(&file, "key content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(has_lax_permissions(&file));
    }

    #[test]
    fn detects_group_readable_permissions() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.key");
        fs::write(&file, "key content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(has_lax_permissions(&file));
    }

    #[test]
    fn accepts_owner_only_permissions() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.key");
        fs::write(&file, "key content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!has_lax_permissions(&file));
    }

    #[test]
    fn accepts_owner_read_only_permissions() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("test.key");
        fs::write(&file, "key content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(!has_lax_permissions(&file));
    }

    #[test]
    fn returns_false_for_nonexistent_file() {
        let temp = TempDir::new().unwrap();
        let file = temp.path().join("does_not_exist.key");
        assert!(!has_lax_permissions(&file));
    }

    #[test]
    fn force_write_secret_key_preserves_owner_only_permissions() {
        use minisign::ops::file_utils::write_secret_key_file;

        let temp = TempDir::new().unwrap();
        let file = temp.path().join("secret.key");

        fs::write(&file, "original content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        write_secret_key_file(&file, "overwritten content", true).unwrap();

        assert_eq!(fs::read_to_string(&file).unwrap(), "overwritten content");
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
