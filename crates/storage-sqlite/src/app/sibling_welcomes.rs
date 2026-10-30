//! The sibling Welcomes this device admitted from its trusted device group and
//! has not joined from yet (mdk#2628 item 3.5b). See migration 0160.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// The most admitted sibling Welcomes kept at once. One more is dropped; its
/// sender's resend (mdk#2628 3.5e) is the repair.
pub const MAX_STASHED_SIBLING_WELCOMES: usize = 64;

/// A sibling Welcome waiting for this device to join from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StashedSiblingWelcome {
    /// The device-group message that carried it, lowercase hex.
    pub message_id_hex: String,
    /// Its `SiblingWelcomeV1` bytes.
    pub content: Vec<u8>,
    /// When its sender wrote the message, in Unix seconds.
    pub created_at: u64,
    pub received_at: u64,
}

impl SqliteAppStorage {
    /// Keep an admitted sibling Welcome until it is joined. `false` when it
    /// is already kept or [`MAX_STASHED_SIBLING_WELCOMES`] are.
    pub fn stash_sibling_welcome(&self, welcome: &StashedSiblingWelcome) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let kept: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM sibling_welcomes_received",
                [],
                |row| row.get(0),
            )
            .storage()?;
        if i64_to_u64(kept)? >= MAX_STASHED_SIBLING_WELCOMES as u64 {
            return Ok(false);
        }
        let inserted = tx
            .execute_cached(
                "INSERT OR IGNORE INTO sibling_welcomes_received
                     (message_id_hex, content, created_at, received_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    welcome.message_id_hex,
                    welcome.content,
                    u64_to_i64(welcome.created_at)?,
                    u64_to_i64(welcome.received_at)?
                ],
            )
            .storage()?;
        tx.commit().storage()?;
        Ok(inserted == 1)
    }

    /// Every stashed sibling Welcome, oldest first.
    pub fn stashed_sibling_welcomes(&self) -> StorageResult<Vec<StashedSiblingWelcome>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT message_id_hex, content, created_at, received_at
                 FROM sibling_welcomes_received
                 ORDER BY received_at, message_id_hex",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(message_id_hex, content, created_at, received_at)| {
                Ok(StashedSiblingWelcome {
                    message_id_hex,
                    content,
                    created_at: i64_to_u64(created_at)?,
                    received_at: i64_to_u64(received_at)?,
                })
            })
            .collect()
    }

    /// Forget a stashed sibling Welcome once its join settled it.
    pub fn delete_stashed_sibling_welcome(&self, message_id_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM sibling_welcomes_received WHERE message_id_hex = ?1",
                params![message_id_hex],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlCipherKey, SqliteAccountStorage};

    fn stashed(id: usize) -> StashedSiblingWelcome {
        StashedSiblingWelcome {
            message_id_hex: format!("{id:064x}"),
            content: vec![1, 2, 3],
            created_at: 5,
            received_at: id as u64,
        }
    }

    #[test]
    fn a_stashed_sibling_welcome_survives_reopen_until_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("local identity key").unwrap();
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key)
                .unwrap()
                .app_storage();
            assert!(store.stash_sibling_welcome(&stashed(2)).unwrap());
            assert!(store.stash_sibling_welcome(&stashed(1)).unwrap());
            assert!(!store.stash_sibling_welcome(&stashed(1)).unwrap());
        }
        let store = SqliteAccountStorage::open_encrypted(&path, &key)
            .unwrap()
            .app_storage();
        assert_eq!(
            store.stashed_sibling_welcomes().unwrap(),
            vec![stashed(1), stashed(2)]
        );
        store
            .delete_stashed_sibling_welcome(&stashed(1).message_id_hex)
            .unwrap();
        assert_eq!(store.stashed_sibling_welcomes().unwrap(), vec![stashed(2)]);
    }

    #[test]
    fn the_stash_keeps_at_most_its_cap() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        for id in 0..MAX_STASHED_SIBLING_WELCOMES {
            assert!(store.stash_sibling_welcome(&stashed(id)).unwrap());
        }
        assert!(
            !store
                .stash_sibling_welcome(&stashed(MAX_STASHED_SIBLING_WELCOMES))
                .unwrap()
        );
        store
            .delete_stashed_sibling_welcome(&stashed(0).message_id_hex)
            .unwrap();
        assert!(
            store
                .stash_sibling_welcome(&stashed(MAX_STASHED_SIBLING_WELCOMES))
                .unwrap()
        );
    }
}
