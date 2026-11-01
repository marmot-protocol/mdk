//! The account's backup recovery key, as a device that trusts no device group
//! keeps it (mdk#2628 item 4.4a). See migration 0163 for what the row means.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

impl SqliteAppStorage {
    /// The public half of the recovery key this device keeps while it trusts
    /// no device group, if any.
    pub fn kept_recovery_key(&self) -> StorageResult<Option<Vec<u8>>> {
        self.lock()?
            .query_row_cached(
                "SELECT public_key FROM backup_recovery_key WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .storage()
    }

    /// Keep `public_key` as the account's recovery key, in place of any kept.
    pub fn keep_recovery_key(&self, public_key: &[u8]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO backup_recovery_key (id, public_key) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET public_key = excluded.public_key",
                params![public_key],
            )
            .storage()?;
        Ok(())
    }

    /// Forget the kept recovery key, if any.
    pub fn forget_kept_recovery_key(&self) -> StorageResult<()> {
        let conn = self.lock()?;
        forget_kept_recovery_key(&conn)
    }
}

/// Forget the kept recovery key on `conn`. Trusting a device group does this
/// in its transaction: a roster this device founds holds the key, and a
/// joined group's account entry stands.
pub(crate) fn forget_kept_recovery_key(conn: &rusqlite::Connection) -> StorageResult<()> {
    conn.execute_cached("DELETE FROM backup_recovery_key WHERE id = 1", [])
        .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;

    #[test]
    fn the_kept_key_is_replaced_and_forgotten() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        assert_eq!(store.kept_recovery_key().unwrap(), None);
        for key in [vec![1; 32], vec![2; 32]] {
            store.keep_recovery_key(&key).unwrap();
            assert_eq!(store.kept_recovery_key().unwrap(), Some(key));
        }
        store.forget_kept_recovery_key().unwrap();
        assert_eq!(store.kept_recovery_key().unwrap(), None);
        store.forget_kept_recovery_key().unwrap();
    }

    #[test]
    fn keys_outside_the_rosters_bounds_are_refused() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        for key in [vec![], vec![1; 256]] {
            assert!(store.keep_recovery_key(&key).is_err());
        }
        assert_eq!(store.kept_recovery_key().unwrap(), None);
    }
}
