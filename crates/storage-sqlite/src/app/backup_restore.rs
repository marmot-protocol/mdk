//! Nonsecret backup-index availability, never membership or restored content.
//! Keys here are PUBLIC recovery halves, not words, entropy or archive keys.

use crate::base::connection::CachedSql;
use crate::{BackupHistorySource, SqliteAppStorage, SqliteResultExt};
use crate::{i64_to_u64, u64_to_i64};
use cgka_traits::{
    GroupId,
    storage::{StorageError, StorageResult},
};
use rusqlite::params;

/// One verified-format archive head's public availability metadata. Its source
/// identifies fetched bytes, not an authenticated writer or historical author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRestoreArchive {
    pub source: BackupHistorySource,
    pub head_server: String,
    pub head_size: u64,
}

impl SqliteAppStorage {
    /// Replace one archive's chat index atomically. A chat id here is only
    /// metadata under the archive format's 1..=256-byte limit, never a group,
    /// route, transcript or membership row.
    pub fn put_backup_restore_archive(
        &self,
        archive: &BackupRestoreArchive,
        chats: &[GroupId],
    ) -> StorageResult<()> {
        if !(1..=8_388_608).contains(&archive.head_size)
            || chats
                .iter()
                .any(|chat| !(1..=256).contains(&chat.as_slice().len()))
        {
            return Err(StorageError::Backend(
                "invalid backup catalog metadata".into(),
            ));
        }
        let written_at = u64_to_i64(archive.source.written_at)?;
        let size = u64_to_i64(archive.head_size)?;
        self.connection.with_transaction(|| {
            let conn=self.lock()?;
            conn.execute_cached(
                "INSERT INTO backup_restore_catalog
                    (recovery_key,backup_id,head_sha256,head_server,head_size,written_at)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(recovery_key,backup_id) DO UPDATE SET
                    head_sha256=excluded.head_sha256,head_server=excluded.head_server,
                    head_size=excluded.head_size,written_at=excluded.written_at",
                params![archive.source.recovery_public_key.as_slice(),archive.source.backup_id.as_slice(),
                    archive.source.head_sha256.as_slice(),archive.head_server,size,written_at],
            ).storage()?;
            conn.execute_cached("DELETE FROM backup_restore_catalog_chats WHERE recovery_key=?1 AND backup_id=?2",
                params![archive.source.recovery_public_key.as_slice(),archive.source.backup_id.as_slice()]).storage()?;
            for chat in chats {
                conn.execute_cached("INSERT OR IGNORE INTO backup_restore_catalog_chats (recovery_key,backup_id,chat_id)
                    VALUES (?1,?2,?3)",params![archive.source.recovery_public_key.as_slice(),archive.source.backup_id.as_slice(),chat.as_slice()]).storage()?;
            }
            Ok(())
        })
    }

    /// Forget only this key's catalog entries no longer listed by a completed,
    /// valid pointer. Other old words' catalogs and imported provenance remain.
    pub fn retain_backup_restore_archives(
        &self,
        key: &[u8; 32],
        listed: &[[u8; 16]],
    ) -> StorageResult<()> {
        if listed.len() > 16 {
            return Err(StorageError::Backend(
                "invalid backup catalog pointer".into(),
            ));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let ids = conn
                .prepare_cached(
                    "SELECT backup_id FROM backup_restore_catalog WHERE recovery_key=?1",
                )
                .storage()?
                .query_map([key.as_slice()], |row| row.get::<_, Vec<u8>>(0))
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            for id in ids {
                if !listed
                    .iter()
                    .any(|listed| listed.as_slice() == id.as_slice())
                {
                    conn.execute_cached(
                        "DELETE FROM backup_restore_catalog WHERE recovery_key=?1 AND backup_id=?2",
                        params![key.as_slice(), id],
                    )
                    .storage()?;
                }
            }
            Ok(())
        })
    }

    /// Availability metadata for one exact raw MLS group id. This lookup
    /// grants no right to import; the app rechecks its own current leaf.
    pub fn backup_restore_archives_for_chat(
        &self,
        chat: &GroupId,
    ) -> StorageResult<Vec<BackupRestoreArchive>> {
        let conn = self.lock()?;
        let mut query=conn.prepare_cached(
            "SELECT a.recovery_key,a.backup_id,a.head_sha256,a.head_server,a.head_size,a.written_at
             FROM backup_restore_catalog_chats c JOIN backup_restore_catalog a
               ON a.recovery_key=c.recovery_key AND a.backup_id=c.backup_id
             WHERE c.chat_id=?1 ORDER BY a.written_at DESC,a.recovery_key,a.backup_id"
        ).storage()?;
        let rows = query
            .query_map([chat.as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let invalid = || StorageError::Backend("invalid backup catalog identity".into());
        rows.into_iter()
            .map(|(key, id, head, server, size, at)| {
                Ok(BackupRestoreArchive {
                    source: BackupHistorySource {
                        recovery_public_key: key.try_into().map_err(|_| invalid())?,
                        backup_id: id.try_into().map_err(|_| invalid())?,
                        head_sha256: head.try_into().map_err(|_| invalid())?,
                        written_at: i64_to_u64(at)?,
                    },
                    head_server: server,
                    head_size: i64_to_u64(size)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    /// A new index is all-or-nothing, and an old key's catalog is independent
    /// of the current key even when both pointers happen to name the same id.
    #[test]
    fn catalog_updates_are_atomic_and_old_recovery_keys_remain_independent() {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let s = storage.app_storage();
        let archive = |key, head| BackupRestoreArchive {
            source: BackupHistorySource {
                recovery_public_key: [key; 32],
                backup_id: [3; 16],
                head_sha256: [head; 32],
                written_at: 50,
            },
            head_server: "https://blossom.example".into(),
            head_size: 100,
        };
        let first = GroupId::new(vec![1]);
        let other = GroupId::new(vec![2; 16]);
        let replacement = GroupId::new(vec![3; 16]);
        s.put_backup_restore_archive(&archive(1, 4), std::slice::from_ref(&first))
            .unwrap();
        s.put_backup_restore_archive(&archive(2, 5), std::slice::from_ref(&other))
            .unwrap();
        s.lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER abort_catalog AFTER INSERT ON backup_restore_catalog_chats
             BEGIN SELECT RAISE(ABORT,'catalog_atomic_abort'); END;",
            )
            .unwrap();
        let error = s
            .put_backup_restore_archive(&archive(1, 6), std::slice::from_ref(&replacement))
            .unwrap_err();
        assert!(
            matches!(error, StorageError::Backend(ref text) if text.contains("catalog_atomic_abort"))
        );
        assert_eq!(
            s.backup_restore_archives_for_chat(&first).unwrap(),
            vec![archive(1, 4)]
        );
        assert!(
            s.backup_restore_archives_for_chat(&replacement)
                .unwrap()
                .is_empty()
        );
        s.retain_backup_restore_archives(&[1; 32], &[]).unwrap();
        assert!(
            s.backup_restore_archives_for_chat(&first)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.backup_restore_archives_for_chat(&other).unwrap(),
            vec![archive(2, 5)]
        );
    }
}
