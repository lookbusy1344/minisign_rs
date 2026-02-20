//! Unit tests for file utility operations

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
}
