//! The tag signature keys device-group rosters this device held listed
//! (mdk#2761). See migration 0145. The table is outside every snapshot, so
//! rolling a group back keeps its rows.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, u64_to_i64};
use cgka_traits::storage::{RosterTagKey, RosterTagKeyStorage, StorageResult};
use cgka_traits::types::GroupId;
use rusqlite::params;

impl RosterTagKeyStorage for SqliteAccountStorage {
    fn record_roster_tag_keys(
        &self,
        group_id: &GroupId,
        keys: &[RosterTagKey],
        seen_at: u64,
    ) -> StorageResult<()> {
        let seen_at = u64_to_i64(seen_at)?;
        let conn = self.lock()?;
        for key in keys {
            conn.execute_cached(
                "INSERT INTO cgka_roster_tag_keys
                     (group_id, slot, tag_signature_key, last_seen_at, seen_seq, held_as_removed)
                 VALUES (?1, ?2, ?3, ?4,
                         (SELECT coalesce(max(seen_seq), 0) + 1 FROM cgka_roster_tag_keys), ?5)
                 ON CONFLICT (group_id, slot, tag_signature_key) DO UPDATE
                     SET last_seen_at = max(last_seen_at, excluded.last_seen_at),
                         seen_seq = excluded.seen_seq,
                         held_as_removed = max(held_as_removed, excluded.held_as_removed)",
                params![
                    group_id.as_slice(),
                    key.slot.as_slice(),
                    key.tag_signature_key,
                    seen_at,
                    key.held_as_removed
                ],
            )
            .storage()?;
        }
        Ok(())
    }

    fn prune_roster_tag_keys(&self, before: u64, per_slot: usize) -> StorageResult<()> {
        let conn = self.lock()?;
        conn.execute_cached(
            "DELETE FROM cgka_roster_tag_keys WHERE last_seen_at < ?1",
            params![u64_to_i64(before)?],
        )
        .storage()?;
        conn.execute_cached(
            "DELETE FROM cgka_roster_tag_keys WHERE rowid IN (
                 SELECT rowid FROM (
                     SELECT rowid, ROW_NUMBER() OVER (
                         PARTITION BY group_id, slot
                         ORDER BY seen_seq DESC
                     ) AS newest
                     FROM cgka_roster_tag_keys
                 ) WHERE newest > ?1
             )",
            params![u64_to_i64(per_slot as u64)?],
        )
        .storage()?;
        Ok(())
    }

    fn roster_tag_keys(&self, group_id: &GroupId, since: u64) -> StorageResult<Vec<RosterTagKey>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT slot, tag_signature_key, held_as_removed FROM cgka_roster_tag_keys
                 WHERE group_id = ?1 AND last_seen_at >= ?2
                 ORDER BY slot, seen_seq DESC",
            )
            .storage()?;
        let rows = stmt
            .query_map(params![group_id.as_slice(), u64_to_i64(since)?], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(rows
            .into_iter()
            .filter_map(|(slot, tag_signature_key, held_as_removed)| {
                Some(RosterTagKey {
                    slot: slot.try_into().ok()?,
                    tag_signature_key,
                    held_as_removed,
                })
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use crate::base::test_support::{gid, sample_group};
    use cgka_traits::storage::{GroupStorage as _, MessageStorage as _, StorageProvider as _};

    fn key(slot: u8, key: u8) -> RosterTagKey {
        RosterTagKey {
            slot: [slot; 32],
            tag_signature_key: vec![key; 32],
            held_as_removed: false,
        }
    }

    /// A key keeps its latest sighting time, and a slot's keys read in the
    /// order they were last seen: the order of the keys in a call and of the
    /// calls, not the clock, which can give one second to several.
    #[test]
    fn keys_keep_their_latest_sighting_and_read_newest_first() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        store.put_group(&sample_group(gid(2), 0, 1)).unwrap();
        store
            .record_roster_tag_keys(&gid(1), &[key(2, 1), key(1, 2)], 100)
            .unwrap();
        store
            .record_roster_tag_keys(&gid(1), &[key(1, 1)], 200)
            .unwrap();
        store
            .record_roster_tag_keys(&gid(2), &[key(1, 3)], 200)
            .unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 0).unwrap(),
            vec![key(1, 1), key(1, 2), key(2, 1)]
        );
        // One pass lists slot 1's key 3 and then its key 2 again, in the
        // second key 1 was last seen in.
        store
            .record_roster_tag_keys(&gid(1), &[key(1, 3), key(1, 2)], 200)
            .unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 0).unwrap(),
            vec![key(1, 2), key(1, 3), key(1, 1), key(2, 1)]
        );
        // A sighting at an earlier time is the latest seen, but never takes
        // the later time back.
        store
            .record_roster_tag_keys(&gid(1), &[key(1, 1)], 50)
            .unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 150).unwrap(),
            vec![key(1, 1), key(1, 2), key(1, 3)]
        );
        assert_eq!(store.roster_tag_keys(&gid(2), 0).unwrap(), vec![key(1, 3)]);
        // A key once listed in a `removed` record stays held as removed when
        // a later state lists it in a device entry.
        let held = RosterTagKey {
            held_as_removed: true,
            ..key(2, 1)
        };
        store
            .record_roster_tag_keys(&gid(1), std::slice::from_ref(&held), 300)
            .unwrap();
        store
            .record_roster_tag_keys(&gid(1), &[key(2, 1)], 300)
            .unwrap();
        assert_eq!(store.roster_tag_keys(&gid(1), 250).unwrap(), vec![held]);
    }

    #[test]
    fn pruning_drops_old_keys_and_keeps_each_slots_newest() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        for n in 1..=4 {
            store
                .record_roster_tag_keys(&gid(1), &[key(1, n), key(2, 10 + n)], u64::from(n) * 100)
                .unwrap();
        }
        store.prune_roster_tag_keys(200, 2).unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 0).unwrap(),
            vec![key(1, 4), key(1, 3), key(2, 14), key(2, 13)]
        );
        store.prune_roster_tag_keys(400, 2).unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 0).unwrap(),
            vec![key(1, 4), key(2, 14)]
        );
        // Within one second, the key seen again outranks the ones recorded
        // after it first.
        store
            .record_roster_tag_keys(&gid(1), &[key(3, 1), key(3, 2), key(3, 3)], 500)
            .unwrap();
        store
            .record_roster_tag_keys(&gid(1), &[key(3, 1)], 500)
            .unwrap();
        store.prune_roster_tag_keys(400, 2).unwrap();
        assert_eq!(
            store.roster_tag_keys(&gid(1), 0).unwrap(),
            vec![key(1, 4), key(2, 14), key(3, 1), key(3, 3)]
        );
    }

    /// A branch-selection rewind keeps the keys the dropped branch listed; a
    /// deleted group's keys go with it.
    #[test]
    fn a_rewind_keeps_keys_and_deleting_the_group_drops_them() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 1)).unwrap();
        store
            .create_group_state_snapshot(&gid(1), "anchor")
            .unwrap();
        store.put_group(&sample_group(gid(1), 1, 2)).unwrap();
        store
            .record_roster_tag_keys(&gid(1), &[key(1, 1)], 100)
            .unwrap();
        store
            .rollback_group_state_keeping_live_records(&gid(1), "anchor")
            .unwrap();
        assert_eq!(store.get_group(&gid(1)).unwrap().epoch.0, 0);
        assert_eq!(store.roster_tag_keys(&gid(1), 0).unwrap(), vec![key(1, 1)]);
        store.delete_group(&gid(1)).unwrap();
        assert!(store.roster_tag_keys(&gid(1), 0).unwrap().is_empty());
    }
}
