//! Renames this device made in its device group's roster, one row per device
//! renamed (mdk#2628 item 3.6, D37). See migration 0137.
//!
//! Every rename writes a fresh rename id next to the label. The row keeps the
//! ids this device's rename wrote and the ids the entry held where its renames
//! were built, so after a fork this device reads from the winning roster's id
//! alone whether its rename applied, was lost with nothing renaming the device
//! since, or lost to another rename that stands.

use cgka_traits::app_components::DeviceRenameId;
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};

/// A rename this device made of one device, and the ids it can tell it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRenameRecord {
    pub slot_id_hex: String,
    /// The label this device's latest rename of the device sets.
    pub label: String,
    /// The rename ids that rename wrote, oldest first: the first commit's,
    /// then one for each time it was made again. Never empty.
    pub written: Vec<DeviceRenameId>,
    /// The rename ids the device's entry held where this device's renames of
    /// it were built, oldest first; `None` for an entry never renamed. Never
    /// empty.
    pub replaced: Vec<Option<DeviceRenameId>>,
}

impl SqliteAppStorage {
    /// Every device this device keeps a rename of.
    pub fn device_renames(&self) -> StorageResult<Vec<DeviceRenameRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT slot_id_hex, label, written, replaced
                 FROM device_renames ORDER BY slot_id_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], device_rename_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(device_rename_record).collect()
    }

    /// This device's rename of `slot_id_hex`, if it keeps one.
    pub fn device_rename(&self, slot_id_hex: &str) -> StorageResult<Option<DeviceRenameRecord>> {
        self.lock()?
            .query_row_cached(
                "SELECT slot_id_hex, label, written, replaced
                 FROM device_renames WHERE slot_id_hex = ?1",
                params![slot_id_hex],
                device_rename_row,
            )
            .optional()
            .storage()?
            .map(device_rename_record)
            .transpose()
    }

    /// Keep `record` as this device's rename of its device, in place of any
    /// earlier one.
    pub fn put_device_rename(&self, record: &DeviceRenameRecord) -> StorageResult<()> {
        if record.written.is_empty() || record.replaced.is_empty() {
            return Err(StorageError::Backend(
                "a device rename names the ids it wrote and replaced".into(),
            ));
        }
        let written: Vec<u8> = record.written.iter().flatten().copied().collect();
        let mut replaced = Vec::with_capacity(record.replaced.len() * 17);
        for id in &record.replaced {
            replaced.push(u8::from(id.is_some()));
            replaced.extend_from_slice(&id.unwrap_or_default());
        }
        self.lock()?
            .execute_cached(
                "INSERT INTO device_renames (slot_id_hex, label, written, replaced)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(slot_id_hex) DO UPDATE SET
                    label = excluded.label,
                    written = excluded.written,
                    replaced = excluded.replaced",
                params![record.slot_id_hex, record.label, written, replaced],
            )
            .storage()?;
        Ok(())
    }

    /// Forget this device's rename of `slot_id_hex`.
    pub fn drop_device_rename(&self, slot_id_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM device_renames WHERE slot_id_hex = ?1",
                params![slot_id_hex],
            )
            .storage()?;
        Ok(())
    }
}

type DeviceRenameRow = (String, String, Vec<u8>, Vec<u8>);

fn device_rename_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRenameRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn device_rename_record(
    (slot_id_hex, label, written, replaced): DeviceRenameRow,
) -> StorageResult<DeviceRenameRecord> {
    let corrupt = || StorageError::Backend("device rename ids are malformed".into());
    let (written, []) = written.as_chunks::<16>() else {
        return Err(corrupt());
    };
    let (replaced, []) = replaced.as_chunks::<17>() else {
        return Err(corrupt());
    };
    let replaced = replaced
        .iter()
        .map(|cell| {
            let (presence, id) = cell.split_first_chunk::<1>().ok_or_else(corrupt)?;
            let id = DeviceRenameId::try_from(id).map_err(|_| corrupt())?;
            match presence {
                [0] if id == DeviceRenameId::default() => Ok(None),
                [1] => Ok(Some(id)),
                _ => Err(corrupt()),
            }
        })
        .collect::<StorageResult<Vec<_>>>()?;
    Ok(DeviceRenameRecord {
        slot_id_hex,
        label,
        written: written.to_vec(),
        replaced,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn rename(
        slot: &str,
        label: &str,
        written: &[u8],
        replaced: &[Option<u8>],
    ) -> DeviceRenameRecord {
        DeviceRenameRecord {
            slot_id_hex: slot.into(),
            label: label.into(),
            written: written.iter().map(|id| [*id; 16]).collect(),
            replaced: replaced.iter().map(|id| id.map(|id| [id; 16])).collect(),
        }
    }

    #[test]
    fn a_device_keeps_one_rename_per_device_renamed() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let laptop = rename("bb", "Laptop", &[1], &[None]);
        let phone = rename("aa", "Phone", &[2, 3], &[Some(9), None, Some(4)]);
        store.put_device_rename(&laptop).unwrap();
        store.put_device_rename(&phone).unwrap();
        assert_eq!(
            store.device_renames().unwrap(),
            vec![phone.clone(), laptop.clone()]
        );
        assert_eq!(store.device_rename("aa").unwrap(), Some(phone));

        let renamed_again = rename("bb", "Work", &[5], &[None, Some(1)]);
        store.put_device_rename(&renamed_again).unwrap();
        assert_eq!(store.device_rename("bb").unwrap(), Some(renamed_again));

        store.drop_device_rename("aa").unwrap();
        assert_eq!(store.device_rename("aa").unwrap(), None);
        assert_eq!(store.device_renames().unwrap().len(), 1);
        assert!(
            store
                .put_device_rename(&rename("cc", "", &[], &[None]))
                .is_err()
        );
        assert!(
            store
                .put_device_rename(&rename("cc", "", &[1], &[]))
                .is_err()
        );
    }
}
