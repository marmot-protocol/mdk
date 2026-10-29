//! The links this device approved and how each ended, and the device groups
//! it joined through a link whose first commit has not landed yet (mdk#2628
//! item 3.3b, D40). See migration 0133 for the states.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// How a link this device approved ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLinkOutcome {
    /// The new device has not made its first commit in the device group yet.
    Pending,
    /// Its first commit there is on the selected branch.
    Linked,
    /// The approving commit never landed or lost, or the new device made no
    /// commit by the deadline.
    Failed,
}

impl DeviceLinkOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Linked => "linked",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> StorageResult<Self> {
        Ok(match value {
            "pending" => Self::Pending,
            "linked" => Self::Linked,
            "failed" => Self::Failed,
            _ => return Err(StorageError::Backend("unknown device link outcome".into())),
        })
    }
}

/// A device this device approved adding to the account's device group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLinkRecord {
    pub group_id_hex: String,
    /// The added device's KeyPackage slot.
    pub slot_hex: String,
    /// The `KeyPackageRef` both users confirmed.
    pub key_package_ref_hex: String,
    /// The signature key of that KeyPackage's leaf: the leaf the link adds,
    /// and the tag signature key the new device sets with its first commit.
    pub leaf_signature_key_hex: String,
    /// The link's Welcome, once the approving commit made it.
    pub welcome_id_hex: Option<String>,
    /// When this device approved the link, just before its commit.
    pub linked_at: u64,
    pub outcome: DeviceLinkOutcome,
    /// When the outcome was decided; `None` while pending.
    pub decided_at: Option<u64>,
}

impl SqliteAppStorage {
    /// Record a link as pending just before its approving commit, replacing
    /// an earlier link of the same slot.
    pub fn record_device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        key_package_ref_hex: &str,
        leaf_signature_key_hex: &str,
        linked_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO device_links
                     (group_id_hex, slot_hex, key_package_ref_hex, leaf_signature_key_hex,
                      welcome_id_hex, linked_at, outcome, decided_at)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5, 'pending', NULL)
                 ON CONFLICT (group_id_hex, slot_hex) DO UPDATE SET
                     key_package_ref_hex = excluded.key_package_ref_hex,
                     leaf_signature_key_hex = excluded.leaf_signature_key_hex,
                     welcome_id_hex = NULL,
                     linked_at = excluded.linked_at,
                     outcome = 'pending',
                     decided_at = NULL",
                params![
                    group_id_hex,
                    slot_hex,
                    key_package_ref_hex,
                    leaf_signature_key_hex,
                    u64_to_i64(linked_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Record the Welcome a pending link's approving commit made. Returns
    /// whether the link was pending.
    pub fn record_device_link_welcome(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        welcome_id_hex: &str,
    ) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE device_links SET welcome_id_hex = ?3
                 WHERE group_id_hex = ?1 AND slot_hex = ?2 AND outcome = 'pending'",
                params![group_id_hex, slot_hex, welcome_id_hex],
            )
            .storage()?;
        Ok(changed != 0)
    }

    pub fn device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
    ) -> StorageResult<Option<DeviceLinkRecord>> {
        self.lock()?
            .query_row_cached(
                &format!("{SELECT_LINK} WHERE group_id_hex = ?1 AND slot_hex = ?2"),
                params![group_id_hex, slot_hex],
                device_link_row,
            )
            .optional()
            .storage()?
            .map(device_link_record)
            .transpose()
    }

    /// Every link this device approved, oldest first.
    pub fn device_links(&self) -> StorageResult<Vec<DeviceLinkRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(&format!(
                "{SELECT_LINK} ORDER BY linked_at ASC, group_id_hex ASC, slot_hex ASC"
            ))
            .storage()?;
        let rows = stmt
            .query_map([], device_link_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(device_link_record).collect()
    }

    /// Decide a pending link's outcome. Returns whether it was pending.
    pub fn decide_device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        outcome: DeviceLinkOutcome,
        decided_at: u64,
    ) -> StorageResult<bool> {
        if outcome == DeviceLinkOutcome::Pending {
            return Err(StorageError::Backend(
                "a device link ends linked or failed".into(),
            ));
        }
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE device_links SET outcome = ?3, decided_at = ?4
                 WHERE group_id_hex = ?1 AND slot_hex = ?2 AND outcome = 'pending'",
                params![
                    group_id_hex,
                    slot_hex,
                    outcome.as_str(),
                    u64_to_i64(decided_at)?
                ],
            )
            .storage()?;
        Ok(changed != 0)
    }

    /// Record that this device joined `group_id_hex` through a link, at
    /// `joined_at`. An earlier join of the group is kept.
    pub fn record_device_group_join(
        &self,
        group_id_hex: &str,
        joined_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO device_group_joins (group_id_hex, joined_at) VALUES (?1, ?2)
                 ON CONFLICT (group_id_hex) DO NOTHING",
                params![group_id_hex, u64_to_i64(joined_at)?],
            )
            .storage()?;
        Ok(())
    }

    /// The device groups this device joined through a link whose first
    /// commit there has not landed yet, with when it joined.
    pub fn device_group_joins(&self) -> StorageResult<Vec<(String, u64)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, joined_at FROM device_group_joins ORDER BY group_id_hex",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(group_id_hex, joined_at)| Ok((group_id_hex, i64_to_u64(joined_at)?)))
            .collect()
    }

    /// Forget a join: its first commit landed, or the device left the
    /// group. Returns whether there was one.
    pub fn delete_device_group_join(&self, group_id_hex: &str) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "DELETE FROM device_group_joins WHERE group_id_hex = ?1",
                params![group_id_hex],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

const SELECT_LINK: &str = "SELECT group_id_hex, slot_hex, key_package_ref_hex,
         leaf_signature_key_hex, welcome_id_hex, linked_at, outcome, decided_at
     FROM device_links";

type DeviceLinkRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    String,
    Option<i64>,
);

fn device_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceLinkRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn device_link_record(
    (
        group_id_hex,
        slot_hex,
        key_package_ref_hex,
        leaf_signature_key_hex,
        welcome_id_hex,
        linked_at,
        outcome,
        decided_at,
    ): DeviceLinkRow,
) -> StorageResult<DeviceLinkRecord> {
    Ok(DeviceLinkRecord {
        group_id_hex,
        slot_hex,
        key_package_ref_hex,
        leaf_signature_key_hex,
        welcome_id_hex,
        linked_at: i64_to_u64(linked_at)?,
        outcome: DeviceLinkOutcome::parse(&outcome)?,
        decided_at: decided_at.map(i64_to_u64).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use DeviceLinkOutcome::*;

    #[test]
    fn a_link_is_decided_once_and_a_new_link_starts_pending_again() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.record_device_link("aa", "01", "ab", "11", 5).unwrap();
        assert!(store.record_device_link_welcome("aa", "01", "w1").unwrap());
        assert!(store.decide_device_link("aa", "01", Linked, 7).unwrap());
        assert!(!store.decide_device_link("aa", "01", Failed, 8).unwrap());
        assert!(!store.record_device_link_welcome("aa", "01", "w2").unwrap());
        assert!(store.decide_device_link("aa", "01", Pending, 8).is_err());
        assert_eq!(
            store.device_link("aa", "01").unwrap().unwrap(),
            DeviceLinkRecord {
                group_id_hex: "aa".into(),
                slot_hex: "01".into(),
                key_package_ref_hex: "ab".into(),
                leaf_signature_key_hex: "11".into(),
                welcome_id_hex: Some("w1".into()),
                linked_at: 5,
                outcome: Linked,
                decided_at: Some(7),
            }
        );

        store.record_device_link("aa", "01", "cd", "22", 9).unwrap();
        store.record_device_link("aa", "02", "ef", "33", 6).unwrap();
        let links = store.device_links().unwrap();
        assert_eq!(
            links
                .iter()
                .map(|link| (link.slot_hex.as_str(), link.outcome, link.decided_at))
                .collect::<Vec<_>>(),
            vec![("02", Pending, None), ("01", Pending, None)]
        );
        assert_eq!(links[1].key_package_ref_hex, "cd");
        assert_eq!(links[1].leaf_signature_key_hex, "22");
        assert_eq!(links[1].welcome_id_hex, None);
        assert!(store.device_link("bb", "01").unwrap().is_none());
    }

    #[test]
    fn a_join_is_kept_until_deleted() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.record_device_group_join("aa", 5).unwrap();
        store.record_device_group_join("aa", 9).unwrap();
        store.record_device_group_join("bb", 6).unwrap();
        assert_eq!(
            store.device_group_joins().unwrap(),
            vec![("aa".into(), 5), ("bb".into(), 6)]
        );
        assert!(store.delete_device_group_join("aa").unwrap());
        assert!(!store.delete_device_group_join("aa").unwrap());
        assert_eq!(store.device_group_joins().unwrap(), vec![("bb".into(), 6)]);
    }
}
