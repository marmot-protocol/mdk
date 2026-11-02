//! The sibling devices this device's own confirmed Commits added to groups
//! (mdk#2628 D76). See migration 0149. The table is outside every snapshot,
//! so rolling a group back keeps its rows.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{
    SIBLING_ADD_RETENTION_SECS, SiblingAdd, SiblingAddStorage, StorageResult,
};
use cgka_traits::types::GroupId;
use rusqlite::params;

impl SiblingAddStorage for SqliteAccountStorage {
    fn record_sibling_adds(
        &self,
        group_id: &GroupId,
        slots: &[[u8; 32]],
        added_at: u64,
    ) -> StorageResult<()> {
        let conn = self.lock()?;
        for slot in slots {
            conn.execute_cached(
                "INSERT INTO cgka_sibling_adds (group_id, slot, added_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id, slot) DO UPDATE
                     SET added_at = max(added_at, excluded.added_at)",
                params![group_id.as_slice(), slot.as_slice(), u64_to_i64(added_at)?],
            )
            .storage()?;
        }
        conn.execute_cached(
            "DELETE FROM cgka_sibling_adds WHERE added_at < ?1",
            params![u64_to_i64(
                added_at.saturating_sub(SIBLING_ADD_RETENTION_SECS)
            )?],
        )
        .storage()?;
        Ok(())
    }

    fn sibling_adds(&self) -> StorageResult<Vec<SiblingAdd>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id, slot, added_at FROM cgka_sibling_adds
                 ORDER BY added_at, group_id, slot",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(rows
            .into_iter()
            .filter_map(|(group_id, slot, added_at)| {
                Some(SiblingAdd {
                    group_id: GroupId::new(group_id),
                    slot: slot.try_into().ok()?,
                    added_at: u64::try_from(added_at).ok()?,
                })
            })
            .collect())
    }

    fn forget_sibling_add(&self, add: &SiblingAdd) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM cgka_sibling_adds
                 WHERE group_id = ?1 AND slot = ?2 AND added_at = ?3",
                params![
                    add.group_id.as_slice(),
                    add.slot.as_slice(),
                    u64_to_i64(add.added_at)?
                ],
            )
            .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::{GroupStorage as _, MessageStorage as _, StorageProvider as _};

    fn add(group: u8, slot: u8, added_at: u64) -> SiblingAdd {
        SiblingAdd {
            group_id: gid(group),
            slot: [slot; 32],
            added_at,
        }
    }

    /// An add recorded again takes the later time, and forgetting the earlier
    /// sighting keeps it. Forgetting the current one drops it.
    #[test]
    fn a_sibling_add_recorded_again_outlives_forgetting_the_earlier_one() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 1)).unwrap();
        store
            .record_sibling_adds(&gid(1), &[[1; 32], [2; 32]], 100)
            .unwrap();
        store.record_sibling_adds(&gid(2), &[[1; 32]], 150).unwrap();
        let first = store.sibling_adds().unwrap();
        assert_eq!(first, vec![add(1, 1, 100), add(1, 2, 100), add(2, 1, 150)]);

        store.record_sibling_adds(&gid(1), &[[1; 32]], 200).unwrap();
        store.forget_sibling_add(&first[0]).unwrap();
        store.forget_sibling_add(&first[1]).unwrap();
        assert_eq!(
            store.sibling_adds().unwrap(),
            vec![add(2, 1, 150), add(1, 1, 200)]
        );
        store.forget_sibling_add(&add(1, 1, 200)).unwrap();
        assert_eq!(store.sibling_adds().unwrap(), vec![add(2, 1, 150)]);
    }

    /// Recording drops adds older than a week; a rewind keeps adds and a
    /// deleted group's adds go with it.
    #[test]
    fn sibling_adds_expire_survive_a_rewind_and_go_with_their_group() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 1)).unwrap();
        store.record_sibling_adds(&gid(1), &[[1; 32]], 100).unwrap();
        store
            .record_sibling_adds(&gid(2), &[[1; 32]], 101 + SIBLING_ADD_RETENTION_SECS)
            .unwrap();
        assert_eq!(
            store.sibling_adds().unwrap(),
            vec![add(2, 1, 101 + SIBLING_ADD_RETENTION_SECS)]
        );

        store
            .create_group_state_snapshot(&gid(2), "anchor")
            .unwrap();
        store
            .record_sibling_adds(&gid(2), &[[2; 32]], 200 + SIBLING_ADD_RETENTION_SECS)
            .unwrap();
        store
            .rollback_group_state_keeping_live_records(&gid(2), "anchor")
            .unwrap();
        assert_eq!(store.sibling_adds().unwrap().len(), 2);
        store.delete_group(&gid(2)).unwrap();
        assert!(store.sibling_adds().unwrap().is_empty());
    }
}
