//! The one place that turns the account handle into the app handle.

use crate::{SqliteAccountStorage, SqliteAppStorage};

impl SqliteAccountStorage {
    /// The app side's handle on this account database, over the same
    /// connection: it opens nothing and closes with this storage.
    pub fn app_storage(&self) -> SqliteAppStorage {
        SqliteAppStorage {
            connection: self.connection.clone(),
        }
    }
}
