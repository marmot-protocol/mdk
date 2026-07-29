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
    /// their I/O classification.
    pub fn try_acquire(root: impl AsRef<Path>) -> Result<Self, AppError> {
        let root = root.as_ref();
        fs_private::create_dir_all_private(root)?;

        #[cfg(unix)]
        {
            let path = root.join(MARMOT_ROOT_RUNTIME_LOCK_FILE);
            match fs_private::try_acquire_private_exclusive_file_lease(&path) {
                Ok(lease) => Ok(Self { _lease: lease }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    Err(AppError::RuntimeBusy)
                }
                Err(error) => Err(AppError::Io(error)),
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
