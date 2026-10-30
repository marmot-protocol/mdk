//! The removals of other devices this device's user decided (mdk#2628 item
//! 3.6b). See migration 0146 for what a row owes.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::params;

/// A device this device's user removed from the account's device group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRemovalRecord {
    pub group_id_hex: String,
    /// The removed device's KeyPackage slot.
    pub slot_hex: String,
    /// When the user decided, and the `rejected_at` of the slot's `removed`
    /// record.
    pub requested_at: u64,
    /// When a relay accepted the deletion of the removed device's slot;
    /// `None` while it is owed.
    pub slot_withdrawn_at: Option<u64>,
}

impl SqliteAppStorage {
    /// Record the user's decision to remove the device in `slot_hex` from the
    /// device group `group_id_hex`. A decision already recorded for the slot
    /// is kept. Returns whether this one is new.
    pub fn record_device_removal(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        requested_at: u64,
    ) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "INSERT INTO device_removals (group_id_hex, slot_hex, requested_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id_hex, slot_hex) DO NOTHING",
                params![group_id_hex, slot_hex, u64_to_i64(requested_at)?],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// Every removal this device decided, oldest decision first.
    pub fn device_removals(&self) -> StorageResult<Vec<DeviceRemovalRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, slot_hex, requested_at, slot_withdrawn_at FROM device_removals
                 ORDER BY requested_at ASC, group_id_hex ASC, slot_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(group_id_hex, slot_hex, requested_at, slot_withdrawn_at)| {
                    Ok(DeviceRemovalRecord {
                        group_id_hex,
                        slot_hex,
                        requested_at: i64_to_u64(requested_at)?,
                        slot_withdrawn_at: slot_withdrawn_at.map(i64_to_u64).transpose()?,
                    })
                },
            )
            .collect()
    }

    /// Record when a relay accepted the deletion of the removed device's
    /// slot, or with `None`, that the deletion is owed again: the removal was
    /// dropped and the device may publish before it is committed again.
    /// Returns whether a removal was recorded for the slot.
    pub fn set_device_removal_slot_withdrawn(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        slot_withdrawn_at: Option<u64>,
    ) -> StorageResult<bool> {
        let slot_withdrawn_at = slot_withdrawn_at.map(u64_to_i64).transpose()?;
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE device_removals SET slot_withdrawn_at = ?3
                 WHERE group_id_hex = ?1 AND slot_hex = ?2",
                params![group_id_hex, slot_hex, slot_withdrawn_at],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::SqliteAccountStorage;
    use cgka_traits::Timestamp;

    #[test]
    fn a_removal_keeps_its_first_decision_until_its_group_is_forgotten() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        assert!(store.record_device_removal("bb", "01", 20).unwrap());
        assert!(store.record_device_removal("aa", "02", 9).unwrap());
        assert!(store.record_device_removal("aa", "01", 5).unwrap());
        assert!(!store.record_device_removal("aa", "01", 7).unwrap());
        let removals = store.device_removals().unwrap();
        assert_eq!(
            removals
                .iter()
                .map(|removal| (removal.slot_hex.as_str(), removal.requested_at))
                .collect::<Vec<_>>(),
            [("01", 5), ("02", 9), ("01", 20)]
        );

        assert_eq!(removals[0].slot_withdrawn_at, None);
        assert!(
            store
                .set_device_removal_slot_withdrawn("aa", "01", Some(6))
                .unwrap()
        );
        assert_eq!(
            store.device_removals().unwrap()[0].slot_withdrawn_at,
            Some(6)
        );
        assert!(
            store
                .set_device_removal_slot_withdrawn("aa", "01", None)
                .unwrap()
        );
        assert_eq!(store.device_removals().unwrap()[0].slot_withdrawn_at, None);
        assert!(
            !store
                .set_device_removal_slot_withdrawn("aa", "09", Some(6))
                .unwrap()
        );

        // Forgetting a group deletes its decisions, and only its own.
        account.forget_group_local_data("aa", Timestamp(1)).unwrap();
        assert_eq!(
            store
                .device_removals()
                .unwrap()
                .iter()
                .map(|removal| removal.group_id_hex.as_str())
                .collect::<Vec<_>>(),
            ["bb"]
        );
        assert!(store.record_device_removal("aa", "01", 11).unwrap());
    }
}
