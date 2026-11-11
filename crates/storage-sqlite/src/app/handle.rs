//! `SqliteAppStorage`: the app side's handle on the account database.

use crate::base::connection::{ConnectionGuard, SharedConnection};
use cgka_traits::storage::StorageResult;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// The app side's handle on an account database. It shares the account's
/// connection, so it opens nothing of its own, closes with the account
/// storage, and fails its calls the way the account storage does once closed.
/// Get one from [`crate::SqliteAccountStorage::app_storage`].
#[derive(Clone)]
pub struct SqliteAppStorage {
    pub(crate) connection: SharedConnection,
    pub(crate) notification_revision: Arc<AtomicU64>,
}

impl SqliteAppStorage {
    /// SQL-free, process-local invalidation token for notification policy and
    /// projected groups. File-backed handles share it by canonical database
    /// path; in-memory handles are independent. Rollbacks may also advance it.
    /// Pair it with [`Self::connection_serial`] when caching across opens.
    pub fn notification_revision(&self) -> u64 {
        self.notification_revision.load(Ordering::Acquire)
    }

    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.connection.lock()
    }

    /// Whether the shared account connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }

    /// Whether `other` is a clone of this same opened database handle, not
    /// merely another connection to the same file.
    pub fn shares_connection_with(&self, other: &SqliteAppStorage) -> bool {
        self.connection.same_as(&other.connection)
    }

    /// A process-unique number for this opened handle, never reused. State
    /// derived from the database's data keys on it, so a reopened, reset or
    /// replaced database derives it again (mdk#2923).
    pub fn connection_serial(&self) -> u64 {
        self.connection.serial()
    }
}
