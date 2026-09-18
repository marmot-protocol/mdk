//! Same-file initialization is exclusive within the process; the runtime root
//! lease supplies cross-process exclusion. Unrelated databases open in parallel.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, Weak};

static LOCKS: LazyLock<Mutex<HashMap<PathBuf, Weak<DatabaseOpenLock>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) struct DatabaseOpenLock {
    path: PathBuf,
    mutex: Mutex<()>,
}

pub(crate) struct DatabaseOpenGuard<'a> {
    pub(super) path: &'a Path,
    _guard: MutexGuard<'a, ()>,
}

impl DatabaseOpenLock {
    pub(crate) fn lock(&self) -> DatabaseOpenGuard<'_> {
        DatabaseOpenGuard {
            path: &self.path,
            _guard: self.mutex.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }
}

pub(crate) fn database_open_lock(path: &Path) -> Arc<DatabaseOpenLock> {
    // Canonicalize the parent, not the file: the identity must stay the same
    // before and after SQLite creates it, including /var vs /private/var.
    // Account creation establishes the directory before any database opener.
    // Callers must preserve that ordering: creating a missing parent between
    // lookups could change a raw fallback path into a different canonical key.
    let path = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .map(|parent| parent.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    };
    let mut locks = LOCKS.lock().unwrap_or_else(|e| e.into_inner());
    // Keep only active opens/waiters, rather than every identity ever opened.
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(DatabaseOpenLock {
        path: path.clone(),
        mutex: Mutex::new(()),
    });
    locks.insert(path, Arc::downgrade(&lock));
    lock
}
