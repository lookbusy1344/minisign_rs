//! Unit tests for file utility operations

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
