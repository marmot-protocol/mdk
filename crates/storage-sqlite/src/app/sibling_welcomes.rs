//! The sibling Welcomes this device admitted from its trusted device group and
//! has not joined from yet (mdk#2628 item 3.5b). See migration 0160.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// The most admitted sibling Welcomes kept at once. One more takes the place
/// of the oldest held one; with none held, it is dropped, and its sender's
/// resend (mdk#2628 3.5e) is the repair.
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
    /// The chat it adds this device to, lowercase hex, once the engine held
    /// it because this device still held an active copy of that chat.
    pub held_group_id_hex: Option<String>,
}

impl SqliteAppStorage {
    /// Keep an admitted sibling Welcome until it is joined, in place of the
    /// oldest held one when [`MAX_STASHED_SIBLING_WELCOMES`] are kept. `false`
    /// when it is already kept, or the stash is full and holds none.
    pub fn stash_sibling_welcome(&self, welcome: &StashedSiblingWelcome) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let (kept, already): (i64, bool) = tx
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(message_id_hex = ?1), 0) > 0
                 FROM sibling_welcomes_received",
                params![welcome.message_id_hex],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .storage()?;
        if already {
            return Ok(false);
        }
        if i64_to_u64(kept)? >= MAX_STASHED_SIBLING_WELCOMES as u64 {
            let evicted = tx
                .execute_cached(
                    "DELETE FROM sibling_welcomes_received WHERE message_id_hex = (
                         SELECT message_id_hex FROM sibling_welcomes_received
                         WHERE held_group_id_hex IS NOT NULL
                         ORDER BY received_at, message_id_hex LIMIT 1
                     )",
                    [],
                )
                .storage()?;
            if evicted == 0 {
                return Ok(false);
            }
        }
        let inserted = tx
            .execute_cached(
                "INSERT INTO sibling_welcomes_received
                     (message_id_hex, content, created_at, received_at, held_group_id_hex)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    welcome.message_id_hex,
                    welcome.content,
                    u64_to_i64(welcome.created_at)?,
                    u64_to_i64(welcome.received_at)?,
                    welcome.held_group_id_hex
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
                "SELECT message_id_hex, content, created_at, received_at, held_group_id_hex
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
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(message_id_hex, content, created_at, received_at, held_group_id_hex)| {
                    Ok(StashedSiblingWelcome {
                        message_id_hex,
                        content,
                        created_at: i64_to_u64(created_at)?,
                        received_at: i64_to_u64(received_at)?,
                        held_group_id_hex,
                    })
                },
            )
            .collect()
    }

    /// Mark a stashed sibling Welcome held, into the chat `group_id_hex`.
    pub fn hold_stashed_sibling_welcome(
        &self,
        message_id_hex: &str,
        group_id_hex: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE sibling_welcomes_received SET held_group_id_hex = ?2
                 WHERE message_id_hex = ?1",
                params![message_id_hex, group_id_hex],
            )
            .storage()?;
        Ok(())
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
            held_group_id_hex: None,
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
    fn a_full_stash_drops_its_oldest_held_welcome_for_a_new_one() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        for id in 0..MAX_STASHED_SIBLING_WELCOMES {
            assert!(store.stash_sibling_welcome(&stashed(id)).unwrap());
        }
        let chat = "ab".repeat(16);
        for id in [5, 3] {
            store
                .hold_stashed_sibling_welcome(&stashed(id).message_id_hex, &chat)
                .unwrap();
        }
        let new = stashed(MAX_STASHED_SIBLING_WELCOMES);
        assert!(!store.stash_sibling_welcome(&stashed(7)).unwrap());
        assert!(store.stash_sibling_welcome(&new).unwrap());
        let kept = store.stashed_sibling_welcomes().unwrap();
        assert_eq!(kept.len(), MAX_STASHED_SIBLING_WELCOMES);
        assert!(!kept.contains(&stashed(3)));
        let five = kept
            .iter()
            .find(|welcome| welcome.message_id_hex == stashed(5).message_id_hex);
        assert_eq!(
            five.unwrap().held_group_id_hex.as_deref(),
            Some(chat.as_str())
        );
        assert!(kept.contains(&new));

        store
            .delete_stashed_sibling_welcome(&stashed(5).message_id_hex)
            .unwrap();
        assert!(store.stash_sibling_welcome(&stashed(1000)).unwrap());
        assert!(!store.stash_sibling_welcome(&stashed(1001)).unwrap());
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
