//! Exclusive ownership of a production Marmot root across processes.
//!
//! SQLite WAL locking protects individual transactions. This lease protects the
//! larger stateful-runtime boundary: two independently hydrated Marmot runtimes
//! must not process and persist the same account root concurrently.

use std::io;
use std::path::Path;

use crate::AppError;

/// Stable owner-only lock file kept at the Marmot root.
///
/// This file must never be unlinked or replaced while a runtime may hold it:
/// advisory locks attach to the inode, not the pathname.
pub const MARMOT_ROOT_RUNTIME_LOCK_FILE: &str = ".marmot-runtime.lock";

/// Exclusive, nonblocking ownership of one production Marmot root.
///
/// The kernel releases the underlying advisory lock when this value is dropped
/// or the process exits, including abrupt iOS termination. `MarmotApp` keeps the
/// lease in an `Arc`, so every app/runtime clone must be gone before ownership
/// is released.
#[derive(Debug)]
pub struct MarmotRootRuntimeLease {
    #[cfg(unix)]
    _lease: fs_private::PrivateExclusiveFileLease,
    #[cfg(not(unix))]
    _unsupported: (),
}

impl MarmotRootRuntimeLease {
    /// Try to acquire exclusive ownership of `root` without waiting.
    ///
    /// [`AppError::RuntimeBusy`] means another process/runtime owns the root and
    /// the caller should either retry later (foreground app) or take its
    /// bounded fallback path (notification extension). Other failures retain
    /// their I/O classification. A missing root is created owner-only; the mode
    /// of an existing externally managed root is preserved.
    pub fn try_acquire(root: impl AsRef<Path>) -> Result<Self, AppError> {
        let root = root.as_ref();
        #[cfg(unix)]
        let prepared_root = fs_private::prepare_directory_path(
            root,
            fs_private::PRIVATE_DIR_MODE,
            fs_private::ExistingDirectoryMode::Preserve,
        )?;
        #[cfg(not(unix))]
        fs_private::create_dir_all_private(root)?;

        #[cfg(unix)]
        {
            let path = root.join(MARMOT_ROOT_RUNTIME_LOCK_FILE);
            match prepared_root.try_acquire_private_exclusive_file_lease(std::ffi::OsStr::new(
                MARMOT_ROOT_RUNTIME_LOCK_FILE,
            )) {
                Ok(lease) => Ok(Self { _lease: lease }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    Err(AppError::RuntimeBusy)
                }
                Err(error) => Err(AppError::Io(io::Error::new(
                    error.kind(),
                    format!(
                        "acquire Marmot root runtime lease at {}: {error}",
                        path.display()
                    ),
                ))),
            }
        }

        #[cfg(not(unix))]
        {
            Err(AppError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "exclusive Marmot root ownership is unsupported on this platform",
            )))
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{MarmotApp, MarmotAppConfig};
    use marmot_account::AccountHome;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn root_lease_creates_a_private_root_and_lock_file() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("Marmot");

        let lease = MarmotRootRuntimeLease::try_acquire(&root).unwrap();

        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o7777,
            fs_private::PRIVATE_DIR_MODE
        );
        assert_eq!(
            std::fs::metadata(root.join(MARMOT_ROOT_RUNTIME_LOCK_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            fs_private::PRIVATE_FILE_MODE
        );
        drop(lease);
    }

    #[test]
    fn second_root_lease_is_busy_until_every_owner_drops() {
        let root = tempfile::tempdir().unwrap();
        let first = std::sync::Arc::new(MarmotRootRuntimeLease::try_acquire(root.path()).unwrap());
        let clone = first.clone();

        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(root.path()),
            Err(AppError::RuntimeBusy)
        ));
        drop(first);
        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(root.path()),
            Err(AppError::RuntimeBusy)
        ));

        drop(clone);
        drop(MarmotRootRuntimeLease::try_acquire(root.path()).unwrap());
    }

    #[test]
    fn root_lease_preserves_an_existing_shared_root_mode() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750)).unwrap();

        let lease = MarmotRootRuntimeLease::try_acquire(root.path()).unwrap();

        let root_mode = std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o7777;
        assert_eq!(root_mode, 0o750);
        let lock_mode = std::fs::metadata(root.path().join(MARMOT_ROOT_RUNTIME_LOCK_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(lock_mode, fs_private::PRIVATE_FILE_MODE);
        drop(lease);
    }

    #[test]
    fn root_lease_rejects_symlink_root_and_lock_file() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target_root = parent.path().join("target-root");
        let linked_root = parent.path().join("linked-root");
        std::fs::create_dir(&target_root).unwrap();
        symlink(&target_root, &linked_root).unwrap();
        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(&linked_root),
            Err(AppError::Io(_))
        ));
        assert!(!target_root.join(MARMOT_ROOT_RUNTIME_LOCK_FILE).exists());

        let root = parent.path().join("real-root");
        std::fs::create_dir(&root).unwrap();
        let target_file = parent.path().join("target-file");
        std::fs::write(&target_file, b"unchanged").unwrap();
        symlink(&target_file, root.join(MARMOT_ROOT_RUNTIME_LOCK_FILE)).unwrap();
        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(&root),
            Err(AppError::Io(_))
        ));
        assert_eq!(std::fs::read(target_file).unwrap(), b"unchanged");
    }

    #[test]
    fn exclusive_root_app_clones_retain_ownership() {
        let root = tempfile::tempdir().unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            root.path(),
            Vec::new(),
            AccountHome::open(root.path()),
            MarmotAppConfig::default(),
        )
        .unwrap();
        let clone = app.clone();

        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(root.path()),
            Err(AppError::RuntimeBusy)
        ));
        drop(app);
        assert!(matches!(
            MarmotRootRuntimeLease::try_acquire(root.path()),
            Err(AppError::RuntimeBusy)
        ));

        drop(clone);
        drop(MarmotRootRuntimeLease::try_acquire(root.path()).unwrap());
    }
}
