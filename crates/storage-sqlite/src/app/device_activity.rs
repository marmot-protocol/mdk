//! Heartbeats in the device group (mdk#2628 item 3.6, D35). See migration
//! 0143.
//!
//! For each sibling the trusted roster lists, this device keeps when it first
//! found that sibling's entry there and the newest time one of its heartbeats
//! counted for, so the Devices screen can show when it was last active and
//! judge it inactive. A row belongs to one entry, named by its `linked_at`:
//! a slot removed and linked again is a new entry, and every write for it
//! starts the row afresh, whether or not this device saw the slot leave. It
//! also keeps when it last sent its own heartbeat, and in which device
//! group, across restarts.

use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};

/// What this device knows of one sibling's activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceActivityRecord {
    pub slot_id_hex: String,
    /// The `linked_at` of the roster entry this row describes.
    pub linked_at: u64,
    /// When this device first found that entry in its roster, in Unix
    /// seconds.
    pub first_seen_at: u64,
    /// The newest time one of its heartbeats counted for, in Unix seconds;
    /// `None` until one has.
    pub last_active_at: Option<u64>,
}

/// The heartbeat this device last sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceHeartbeatSent {
    /// The device group it went to.
    pub group_id_hex: String,
    /// When, in Unix seconds.
    pub sent_at: u64,
}

impl SqliteAppStorage {
    /// Every sibling this device tracks, by slot.
    pub fn device_activity(&self) -> StorageResult<Vec<DeviceActivityRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT slot_id_hex, linked_at, first_seen_at, last_active_at
                 FROM device_activity ORDER BY slot_id_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(slot_id_hex, linked_at, first_seen_at, last_active_at)| {
                Ok(DeviceActivityRecord {
                    slot_id_hex,
                    linked_at: i64_to_u64(linked_at)?,
                    first_seen_at: i64_to_u64(first_seen_at)?,
                    last_active_at: last_active_at.map(i64_to_u64).transpose()?,
                })
            })
            .collect()
    }

    /// Track exactly `siblings`, the roster's sibling entries as slot and
    /// `linked_at`: an entry not tracked yet, a slot's first or one linked
    /// again, is first seen `now` with no activity, and every other row is
    /// dropped. Returns whether any row was added, started afresh or dropped.
    pub fn track_device_activity(
        &self,
        siblings: &[(String, u64)],
        now: u64,
    ) -> StorageResult<bool> {
        let now = u64_to_i64(now)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let tracked: Vec<String> = {
            let mut stmt = tx
                .prepare_cached("SELECT slot_id_hex FROM device_activity")
                .storage()?;
            stmt.query_map([], |row| row.get(0))
                .storage()?
                .collect::<Result<_, _>>()
                .storage()?
        };
        let mut changed = false;
        for slot in tracked
            .iter()
            .filter(|slot| !siblings.iter().any(|(sibling, _)| sibling == *slot))
        {
            tx.execute_cached(
                "DELETE FROM device_activity WHERE slot_id_hex = ?1",
                params![slot],
            )
            .storage()?;
            changed = true;
        }
        for (slot, linked_at) in siblings {
            changed |= tx
                .execute_cached(
                    "INSERT INTO device_activity (slot_id_hex, linked_at, first_seen_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(slot_id_hex) DO UPDATE SET
                        linked_at = excluded.linked_at,
                        first_seen_at = excluded.first_seen_at,
                        last_active_at = NULL
                     WHERE linked_at != excluded.linked_at",
                    params![slot, u64_to_i64(*linked_at)?, now],
                )
                .storage()?
                != 0;
        }
        tx.commit().storage()?;
        Ok(changed)
    }

    /// Count a heartbeat dated `active_at` of the sibling whose entry is
    /// `slot_id_hex` linked at `linked_at`. Last activity only moves forward.
    /// An entry not tracked yet, a slot's first or one linked again, is first
    /// seen `now`.
    pub fn note_device_active(
        &self,
        slot_id_hex: &str,
        linked_at: u64,
        active_at: u64,
        now: u64,
    ) -> StorageResult<()> {
        // Every right-hand side reads the row as it was before this update.
        self.lock()?
            .execute_cached(
                "INSERT INTO device_activity (slot_id_hex, linked_at, first_seen_at, last_active_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(slot_id_hex) DO UPDATE SET
                    linked_at = excluded.linked_at,
                    first_seen_at = CASE WHEN linked_at = excluded.linked_at
                        THEN first_seen_at ELSE excluded.first_seen_at END,
                    last_active_at = CASE WHEN linked_at = excluded.linked_at
                        THEN MAX(COALESCE(last_active_at, excluded.last_active_at),
                                 excluded.last_active_at)
                        ELSE excluded.last_active_at END",
                params![
                    slot_id_hex,
                    u64_to_i64(linked_at)?,
                    u64_to_i64(now)?,
                    u64_to_i64(active_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// The heartbeat this device last sent, if it has sent one.
    pub fn device_heartbeat_sent(&self) -> StorageResult<Option<DeviceHeartbeatSent>> {
        self.lock()?
            .query_row_cached(
                "SELECT group_id_hex, sent_at FROM device_heartbeat_sent WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .storage()?
            .map(|(group_id_hex, sent_at)| {
                Ok(DeviceHeartbeatSent {
                    group_id_hex,
                    sent_at: i64_to_u64(sent_at)?,
                })
            })
            .transpose()
    }

    /// Keep `sent` as the heartbeat this device last sent; `None` forgets it.
    pub fn put_device_heartbeat_sent(
        &self,
        sent: Option<&DeviceHeartbeatSent>,
    ) -> StorageResult<()> {
        let conn = self.lock()?;
        match sent {
            Some(sent) => conn.execute_cached(
                "INSERT INTO device_heartbeat_sent (singleton, group_id_hex, sent_at)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(singleton) DO UPDATE SET
                    group_id_hex = excluded.group_id_hex,
                    sent_at = excluded.sent_at",
                params![sent.group_id_hex, u64_to_i64(sent.sent_at)?],
            ),
            None => conn.execute_cached("DELETE FROM device_heartbeat_sent", []),
        }
        .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn activity(
        slot: &str,
        first_seen_at: u64,
        last_active_at: Option<u64>,
    ) -> DeviceActivityRecord {
        DeviceActivityRecord {
            slot_id_hex: slot.into(),
            linked_at: 1,
            first_seen_at,
            last_active_at,
        }
    }

    fn siblings(slots: &[&str]) -> Vec<(String, u64)> {
        slots.iter().map(|slot| ((*slot).to_owned(), 1)).collect()
    }

    #[test]
    fn device_activity_tracks_the_roster_and_only_moves_forward() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(
            store
                .track_device_activity(&siblings(&["aa", "bb"]), 100)
                .unwrap()
        );
        assert!(
            !store
                .track_device_activity(&siblings(&["aa", "bb"]), 200)
                .unwrap()
        );
        store.note_device_active("aa", 1, 150, 300).unwrap();
        store.note_device_active("aa", 1, 120, 300).unwrap();
        // A heartbeat of a sibling not tracked yet starts tracking it.
        store.note_device_active("cc", 1, 250, 300).unwrap();
        assert_eq!(
            store.device_activity().unwrap(),
            vec![
                activity("aa", 100, Some(150)),
                activity("bb", 100, None),
                activity("cc", 300, Some(250)),
            ]
        );

        // A sibling the roster no longer lists is forgotten, so one linked
        // again is first seen afresh.
        assert!(
            store
                .track_device_activity(&siblings(&["aa", "cc"]), 400)
                .unwrap()
        );
        assert!(
            store
                .track_device_activity(&siblings(&["aa", "bb", "cc"]), 500)
                .unwrap()
        );
        assert_eq!(
            store.device_activity().unwrap(),
            vec![
                activity("aa", 100, Some(150)),
                activity("bb", 500, None),
                activity("cc", 300, Some(250)),
            ]
        );
    }

    /// A slot removed and linked again before this device saw it leave is a
    /// new entry with a new `linked_at`: tracking it, or counting its
    /// heartbeat, starts its row afresh instead of carrying the earlier
    /// entry's activity over.
    #[test]
    fn an_entry_linked_again_starts_its_activity_afresh() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store
            .track_device_activity(&siblings(&["aa", "bb"]), 100)
            .unwrap();
        store.note_device_active("aa", 1, 150, 200).unwrap();
        store.note_device_active("bb", 1, 160, 200).unwrap();

        assert!(
            store
                .track_device_activity(&[("aa".into(), 7), ("bb".into(), 1)], 300)
                .unwrap()
        );
        store.note_device_active("bb", 9, 350, 400).unwrap();
        assert_eq!(
            store.device_activity().unwrap(),
            vec![
                DeviceActivityRecord {
                    slot_id_hex: "aa".into(),
                    linked_at: 7,
                    first_seen_at: 300,
                    last_active_at: None,
                },
                DeviceActivityRecord {
                    slot_id_hex: "bb".into(),
                    linked_at: 9,
                    first_seen_at: 400,
                    last_active_at: Some(350),
                },
            ]
        );
    }

    #[test]
    fn a_device_keeps_its_last_heartbeat() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert_eq!(store.device_heartbeat_sent().unwrap(), None);
        let first = DeviceHeartbeatSent {
            group_id_hex: "11".into(),
            sent_at: 100,
        };
        store.put_device_heartbeat_sent(Some(&first)).unwrap();
        assert_eq!(store.device_heartbeat_sent().unwrap(), Some(first));
        let second = DeviceHeartbeatSent {
            group_id_hex: "22".into(),
            sent_at: 200,
        };
        store.put_device_heartbeat_sent(Some(&second)).unwrap();
        assert_eq!(store.device_heartbeat_sent().unwrap(), Some(second));
        store.put_device_heartbeat_sent(None).unwrap();
        assert_eq!(store.device_heartbeat_sent().unwrap(), None);
    }
}
