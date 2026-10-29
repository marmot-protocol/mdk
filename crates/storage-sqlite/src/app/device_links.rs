//! The links this device approved, and whether each approving commit has
//! settled (mdk#2628 item 3.3b). See migration 0130 for the states.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// Where an approving commit stands under the convergence rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceLinkSettlement {
    /// Approved, not settled yet.
    Pending,
    /// Settled with the device in the roster.
    Settled,
    /// Settled without it: a competing commit won, or the approving commit
    /// never landed.
    Reversed,
}

impl DeviceLinkSettlement {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Settled => "settled",
            Self::Reversed => "reversed",
        }
    }

    fn parse(value: &str) -> StorageResult<Self> {
        Ok(match value {
            "pending" => Self::Pending,
            "settled" => Self::Settled,
            "reversed" => Self::Reversed,
            _ => {
                return Err(StorageError::Backend(
                    "unknown device link settlement".into(),
                ));
            }
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
    /// When this device approved the link, just before its commit.
    pub linked_at: u64,
    pub settlement: DeviceLinkSettlement,
    /// When the settlement was decided; `None` while pending.
    pub settled_at: Option<u64>,
}

impl SqliteAppStorage {
    /// Record a link as pending just before its approving commit, replacing
    /// an earlier link of the same slot.
    pub fn record_device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        key_package_ref_hex: &str,
        linked_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO device_links
                     (group_id_hex, slot_hex, key_package_ref_hex, linked_at, settlement, settled_at)
                 VALUES (?1, ?2, ?3, ?4, 'pending', NULL)
                 ON CONFLICT (group_id_hex, slot_hex) DO UPDATE SET
                     key_package_ref_hex = excluded.key_package_ref_hex,
                     linked_at = excluded.linked_at,
                     settlement = 'pending',
                     settled_at = NULL",
                params![
                    group_id_hex,
                    slot_hex,
                    key_package_ref_hex,
                    u64_to_i64(linked_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
    ) -> StorageResult<Option<DeviceLinkRecord>> {
        self.lock()?
            .query_row_cached(
                "SELECT group_id_hex, slot_hex, key_package_ref_hex, linked_at, settlement, settled_at
                 FROM device_links WHERE group_id_hex = ?1 AND slot_hex = ?2",
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
            .prepare_cached(
                "SELECT group_id_hex, slot_hex, key_package_ref_hex, linked_at, settlement, settled_at
                 FROM device_links ORDER BY linked_at ASC, group_id_hex ASC, slot_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], device_link_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(device_link_record).collect()
    }

    /// Decide a pending link's settlement. Returns whether it was pending.
    pub fn settle_device_link(
        &self,
        group_id_hex: &str,
        slot_hex: &str,
        settlement: DeviceLinkSettlement,
        settled_at: u64,
    ) -> StorageResult<bool> {
        if settlement == DeviceLinkSettlement::Pending {
            return Err(StorageError::Backend(
                "a device link settles as settled or reversed".into(),
            ));
        }
        let changed = self
            .lock()?
            .execute_cached(
                "UPDATE device_links SET settlement = ?3, settled_at = ?4
                 WHERE group_id_hex = ?1 AND slot_hex = ?2 AND settlement = 'pending'",
                params![
                    group_id_hex,
                    slot_hex,
                    settlement.as_str(),
                    u64_to_i64(settled_at)?
                ],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

type DeviceLinkRow = (String, String, String, i64, String, Option<i64>);

fn device_link_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceLinkRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn device_link_record(
    (group_id_hex, slot_hex, key_package_ref_hex, linked_at, settlement, settled_at): DeviceLinkRow,
) -> StorageResult<DeviceLinkRecord> {
    Ok(DeviceLinkRecord {
        group_id_hex,
        slot_hex,
        key_package_ref_hex,
        linked_at: i64_to_u64(linked_at)?,
        settlement: DeviceLinkSettlement::parse(&settlement)?,
        settled_at: settled_at.map(i64_to_u64).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use DeviceLinkSettlement::*;

    #[test]
    fn a_link_settles_once_and_a_new_link_starts_pending_again() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        store.record_device_link("aa", "01", "ab", 5).unwrap();
        assert!(store.settle_device_link("aa", "01", Settled, 7).unwrap());
        assert!(!store.settle_device_link("aa", "01", Reversed, 8).unwrap());
        assert!(store.settle_device_link("aa", "01", Pending, 8).is_err());
        assert_eq!(
            store.device_link("aa", "01").unwrap().unwrap(),
            DeviceLinkRecord {
                group_id_hex: "aa".into(),
                slot_hex: "01".into(),
                key_package_ref_hex: "ab".into(),
                linked_at: 5,
                settlement: Settled,
                settled_at: Some(7),
            }
        );

        store.record_device_link("aa", "01", "cd", 9).unwrap();
        store.record_device_link("aa", "02", "ef", 6).unwrap();
        let links = store.device_links().unwrap();
        assert_eq!(
            links
                .iter()
                .map(|link| (link.slot_hex.as_str(), link.settlement, link.settled_at))
                .collect::<Vec<_>>(),
            vec![("02", Pending, None), ("01", Pending, None)]
        );
        assert_eq!(links[1].key_package_ref_hex, "cd");
        assert!(store.device_link("bb", "01").unwrap().is_none());
    }
}
