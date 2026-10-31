//! The KeyPackages device-group rosters this device held announced (mdk#2628
//! D31 item 7). See migration 0144. The table is outside every snapshot, so
//! rolling a group back keeps its rows.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{AnnouncedKeyPackage, AnnouncedKeyPackageStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::params;

impl AnnouncedKeyPackageStorage for SqliteAccountStorage {
    fn record_announced_key_packages(
        &self,
        group_id: &GroupId,
        announced: &[AnnouncedKeyPackage],
        seen_at: u64,
    ) -> StorageResult<()> {
        let seen_at = u64_to_i64(seen_at)?;
        let conn = self.lock()?;
        for announcement in announced {
            conn.execute_cached(
                "INSERT INTO cgka_announced_key_packages
                     (group_id, slot, key_package_ref, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (group_id, slot, key_package_ref) DO UPDATE
                     SET last_seen_at = max(last_seen_at, excluded.last_seen_at)",
                params![
                    group_id.as_slice(),
                    announcement.slot.as_slice(),
                    announcement.key_package_ref,
                    seen_at
                ],
            )
            .storage()?;
        }
        Ok(())
    }

    fn prune_announced_key_packages(&self, before: u64) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM cgka_announced_key_packages WHERE last_seen_at < ?1",
                params![u64_to_i64(before)?],
            )
            .storage()?;
        Ok(())
    }

    fn announced_key_packages(
        &self,
        group_id: &GroupId,
        since: u64,
    ) -> StorageResult<Vec<AnnouncedKeyPackage>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT slot, key_package_ref FROM cgka_announced_key_packages
                 WHERE group_id = ?1 AND last_seen_at >= ?2
                 ORDER BY slot, key_package_ref",
            )
            .storage()?;
        let rows = stmt
            .query_map(params![group_id.as_slice(), u64_to_i64(since)?], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(rows
            .into_iter()
            .filter_map(|(slot, key_package_ref)| {
                Some(AnnouncedKeyPackage {
                    slot: slot.try_into().ok()?,
                    key_package_ref,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::test_support::{gid, sample_group};
    use crate::{SqlCipherKey, SqliteAccountStorage};
    use cgka_traits::storage::{GroupStorage as _, MessageStorage as _, StorageProvider as _};

    fn announced(slot: u8, reference: u8) -> AnnouncedKeyPackage {
        AnnouncedKeyPackage {
            slot: [slot; 32],
            key_package_ref: vec![reference; 32],
        }
    }

    #[test]
    fn announcements_keep_their_latest_sighting_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("local identity key").unwrap();
        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
            store.put_group(&sample_group(gid(2), 0, 1)).unwrap();
            store
                .record_announced_key_packages(&gid(1), &[announced(1, 1)], 100)
                .unwrap();
            store
                .record_announced_key_packages(&gid(1), &[announced(1, 1), announced(1, 2)], 200)
                .unwrap();
            store
                .record_announced_key_packages(&gid(2), &[announced(1, 3)], 200)
                .unwrap();
        }
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            store.announced_key_packages(&gid(1), 0).unwrap(),
            vec![announced(1, 1), announced(1, 2)]
        );
        // The latest sighting counts: the repeat at 200 renewed (1, 1), and
        // an earlier one never takes it back.
        store
            .record_announced_key_packages(&gid(1), &[announced(1, 1)], 50)
            .unwrap();
        assert_eq!(
            store.announced_key_packages(&gid(1), 150).unwrap(),
            vec![announced(1, 1), announced(1, 2)]
        );
        assert!(
            store
                .announced_key_packages(&gid(1), 201)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.announced_key_packages(&gid(2), 0).unwrap(),
            vec![announced(1, 3)]
        );
    }

    /// Pruning goes by time alone: however many a slot announced, each stays
    /// until it was last seen before the bound.
    #[test]
    fn pruning_drops_only_old_announcements() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        for reference in 1..=40 {
            store
                .record_announced_key_packages(
                    &gid(1),
                    &[announced(1, reference)],
                    u64::from(reference) * 100,
                )
                .unwrap();
        }
        store.prune_announced_key_packages(200).unwrap();
        assert_eq!(
            store.announced_key_packages(&gid(1), 0).unwrap(),
            (2..=40)
                .map(|reference| announced(1, reference))
                .collect::<Vec<_>>()
        );
    }

    /// A branch-selection rewind keeps what the dropped branch announced; a
    /// deleted group's announcements go with it.
    #[test]
    fn a_rewind_keeps_announcements_and_deleting_the_group_drops_them() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        store
            .create_group_state_snapshot(&gid(1), "anchor")
            .unwrap();
        store.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        store
            .record_announced_key_packages(&gid(1), &[announced(1, 1)], 100)
            .unwrap();
        store
            .rollback_group_state_keeping_live_records(&gid(1), "anchor")
            .unwrap();
        assert_eq!(store.get_group(&gid(1)).unwrap().epoch.0, 0);
        assert_eq!(
            store.announced_key_packages(&gid(1), 0).unwrap(),
            vec![announced(1, 1)]
        );
        store.delete_group(&gid(1)).unwrap();
        assert!(store.announced_key_packages(&gid(1), 0).unwrap().is_empty());
    }
}
