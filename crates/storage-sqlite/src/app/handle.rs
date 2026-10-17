//! `SqliteAppStorage`: the app side's handle on the account database.

use crate::base::connection::{ConnectionGuard, SharedConnection};
use cgka_traits::storage::StorageResult;

/// The app side's handle on an account database. It shares the account's
/// connection, so it opens nothing of its own, closes with the account
/// storage, and fails its calls the way the account storage does once closed.
/// Get one from [`crate::SqliteAccountStorage::app_storage`].
#[derive(Clone)]
pub struct SqliteAppStorage {
    pub(crate) connection: SharedConnection,
}

impl SqliteAppStorage {
    pub(crate) fn lock(&self) -> StorageResult<ConnectionGuard<'_>> {
        self.connection.lock()
    }

    /// Whether the shared account connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.connection.is_closed()
    }
}
