//! File permission hardening utilities.
//!
//! This module provides platform-specific utilities for setting secure file permissions
//! on database directories and files. On Unix-like systems, this restricts access to
//! owner-only. On mobile platforms (iOS/Android), the application sandbox provides
//! the primary security boundary.

use std::path::Path;

use crate::error::Error;

/// Creates a directory with secure permissions (owner-only access).
///
/// On Unix-like systems (macOS, Linux), this creates the directory with mode 0700
/// (owner read/write/execute only). On other platforms, this creates the directory
/// with default permissions.
///
/// # Arguments
///
/// * `path` - Path to the directory to create
///
/// # Errors
///
/// Returns an error if the directory cannot be created or permissions cannot be set.
pub fn create_secure_directory<P>(path: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    // Create the directory (and parents if needed)
    std::fs::create_dir_all(path)?;

    // Apply platform-specific permissions
    #[cfg(unix)]
    set_unix_directory_permissions(path)?;

    Ok(())
}

/// Sets secure permissions on an existing file (owner-only access).
///
/// On Unix-like systems, this sets mode 0600 (owner read/write only).
/// On other platforms, this is a no-op as we rely on app sandboxing.
///
/// # Arguments
///
/// * `path` - Path to the file
///
/// # Errors
///
/// Returns an error if permissions cannot be set.
pub fn set_secure_file_permissions<P>(path: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    if !path.exists() {
        return Ok(());
    }

    #[cfg(unix)]
    set_unix_file_permissions(path)?;

    Ok(())
}

/// Pre-creates a database file with secure permissions before opening.
///
/// This avoids a short window where SQLite might create the file with default
/// (umask-dependent) permissions. We create an empty file with secure permissions
/// first, then SQLite will open the existing file.
///
/// # Arguments
///
/// * `path` - Path to the database file
///
/// # Errors
///
/// Returns an error if the file cannot be created or permissions cannot be set.
///
/// # Special Cases
///
/// - In-memory databases (":memory:") are skipped
/// - Empty paths are skipped
pub fn precreate_secure_database_file<P>(path: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    // Skip special SQLite paths (in-memory databases, empty paths)
    let path_str = path.to_string_lossy();
    if path_str.is_empty() || path_str == ":memory:" || path_str.starts_with(':') {
        return Ok(());
    }

    // Skip if file already exists
    if path.exists() {
        return Ok(());
    }

    // Ensure parent directory exists with secure permissions
    if let Some(parent) = path.parent() {
        // Skip if parent is empty (e.g., for paths like "file.db" with no directory)
        if !parent.as_os_str().is_empty() && !parent.exists() {
            create_secure_directory(parent)?;
        }
    }

    // Create empty file
    std::fs::File::create(path)?;

    // Set secure permissions
    set_secure_file_permissions(path)?;

    Ok(())
}

/// Sets Unix file permissions to 0600 (owner read/write only).
#[cfg(unix)]
fn set_unix_file_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| {
        Error::FilePermission(format!(
            "Failed to set file permissions on {:?}: {}",
            path, e
        ))
    })
}

/// Sets Unix directory permissions to 0700 (owner read/write/execute only).
#[cfg(unix)]
fn set_unix_directory_permissions(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;

    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms).map_err(|e| {
        Error::FilePermission(format!(
            "Failed to set directory permissions on {:?}: {}",
            path, e
        ))
    })
}

/// Verifies that a file or directory has appropriately restrictive permissions.
///
/// On Unix, this checks that the file/directory is not world-readable or group-readable.
/// Returns an error if permissions are too permissive.
///
/// # Arguments
///
/// * `path` - Path to check
///
/// # Errors
///
/// Returns an error if permissions are too permissive or if the check fails.
#[cfg(unix)]
#[allow(dead_code)] // Reserved for future use by callers who want to verify permissions at startup
pub fn verify_permissions<P>(path: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    use std::os::unix::fs::PermissionsExt;

    let path = path.as_ref();

    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    // Check that no group or world permissions are set
    // (mode & 0o077) should be 0 for secure permissions
    if mode & 0o077 != 0 {
        return Err(Error::FilePermission(format!(
            "File {:?} has insecure permissions: {:o}. Expected owner-only access.",
            path,
            mode & 0o777
        )));
    }

    Ok(())
}

/// Verifies permissions (no-op on non-Unix platforms).
#[cfg(not(unix))]
#[allow(dead_code)] // Reserved for future use by callers who want to verify permissions at startup
pub fn verify_permissions<P>(_path: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    // On non-Unix platforms, we rely on app sandboxing
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_secure_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_dir = temp_dir.path().join("secure_dir");

        create_secure_directory(&test_dir).unwrap();
        assert!(test_dir.exists());
        assert!(test_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&test_dir).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn test_set_secure_file_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("secure_file.db");

        // Create file
        std::fs::File::create(&test_file).unwrap();

        set_secure_file_permissions(&test_file).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&test_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_precreate_secure_database_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("subdir").join("database.db");

        precreate_secure_database_file(&db_path).unwrap();

        assert!(db_path.exists());
        assert!(db_path.parent().unwrap().exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_perms = std::fs::metadata(&db_path).unwrap().permissions();
            assert_eq!(file_perms.mode() & 0o777, 0o600);

            let dir_perms = std::fs::metadata(db_path.parent().unwrap())
                .unwrap()
                .permissions();
            assert_eq!(dir_perms.mode() & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_permissions_secure() {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("secure.db");

        std::fs::File::create(&test_file).unwrap();
        set_secure_file_permissions(&test_file).unwrap();

        // Should pass verification
        verify_permissions(&test_file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_permissions_insecure() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("insecure.db");

        std::fs::File::create(&test_file).unwrap();

        // Set world-readable permissions
        let perms = std::fs::Permissions::from_mode(0o644);
        std::fs::set_permissions(&test_file, perms).unwrap();

        // Should fail verification
        let result = verify_permissions(&test_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_precreate_skips_memory_database() {
        // In-memory databases should be skipped without error
        let result = precreate_secure_database_file(":memory:");
        assert!(result.is_ok());

        // Other special SQLite paths
        let result = precreate_secure_database_file(":temp:");
        assert!(result.is_ok());

        // Empty path
        let result = precreate_secure_database_file("");
        assert!(result.is_ok());
    }

    #[test]
    fn test_precreate_skips_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("existing.db");

        // Create a file first
        std::fs::write(&db_path, b"existing content").unwrap();

        // precreate should skip it (not overwrite)
        precreate_secure_database_file(&db_path).unwrap();

        // Verify content is unchanged
        let content = std::fs::read(&db_path).unwrap();
        assert_eq!(content, b"existing content");
    }

    #[test]
    fn test_set_secure_file_permissions_nonexistent() {
        // Setting permissions on a non-existent file should succeed (no-op)
        let result = set_secure_file_permissions("/nonexistent/path/file.db");
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_nested_secure_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_dir = temp_dir.path().join("a").join("b").join("c").join("d");

        create_secure_directory(&nested_dir).unwrap();
        assert!(nested_dir.exists());
        assert!(nested_dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // All directories in the chain should exist
            assert!(temp_dir.path().join("a").exists());
            assert!(temp_dir.path().join("a").join("b").exists());
            assert!(temp_dir.path().join("a").join("b").join("c").exists());

            // The deepest directory should have secure permissions
            let perms = std::fs::metadata(&nested_dir).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o700);
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_permissions_nonexistent() {
        // Verifying permissions on non-existent file should succeed
        let result = verify_permissions("/nonexistent/path/file.db");
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_permissions_group_readable() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("group_readable.db");

        std::fs::File::create(&test_file).unwrap();

        // Set group-readable permissions
        let perms = std::fs::Permissions::from_mode(0o640);
        std::fs::set_permissions(&test_file, perms).unwrap();

        // Should fail verification
        let result = verify_permissions(&test_file);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insecure"));
    }

    #[cfg(unix)]
    #[test]
    fn test_verify_permissions_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let test_file = temp_dir.path().join("world_writable.db");

        std::fs::File::create(&test_file).unwrap();

        // Set world-writable permissions
        let perms = std::fs::Permissions::from_mode(0o666);
        std::fs::set_permissions(&test_file, perms).unwrap();

        // Should fail verification
        let result = verify_permissions(&test_file);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_permissions_on_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let secure_dir = temp_dir.path().join("secure_test");

        create_secure_directory(&secure_dir).unwrap();

        // Verify permissions
        verify_permissions(&secure_dir).unwrap();
    }
}
