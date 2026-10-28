//! The device groups this device knows of, and how it came to know each
//! (mdk#2628 item 3.1). See migration 0125 for the states.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// How this device came to know a device group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceGroupTrust {
    /// This device chose the id and is creating the group.
    Creating,
    /// This device created the group.
    Created,
    /// A confirmed link named the group; its Welcome has not arrived.
    AwaitingWelcome,
    /// This device joined through the Welcome a confirmed link named.
    Linked,
    /// This device holds a device group no confirmed link named.
    Untrusted,
}

impl DeviceGroupTrust {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::AwaitingWelcome => "awaiting_welcome",
            Self::Linked => "linked",
            Self::Untrusted => "untrusted",
        }
    }

    fn parse(value: &str) -> StorageResult<Self> {
        Ok(match value {
            "creating" => Self::Creating,
            "created" => Self::Created,
            "awaiting_welcome" => Self::AwaitingWelcome,
            "linked" => Self::Linked,
            "untrusted" => Self::Untrusted,
            _ => {
                return Err(StorageError::Backend(
                    "unknown device group trust state".into(),
                ));
            }
        })
    }

    /// Whether this device may act on the group's roster.
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::Created | Self::Linked)
    }

    /// Whether the row claims this account's device group: trusted, or on its
    /// way to being trusted.
    const fn claims_account(self) -> bool {
        !matches!(self, Self::Untrusted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGroupRecord {
    pub group_id_hex: String,
    pub trust: DeviceGroupTrust,
    /// The confirmed `KeyPackageRef`; `None` only for an untrusted group.
    pub key_package_ref_hex: Option<String>,
    pub recorded_at: u64,
}

const CLAIMING: &str = "trust IN ('creating', 'created', 'awaiting_welcome', 'linked')";

impl SqliteAppStorage {
    pub fn device_group(&self, group_id_hex: &str) -> StorageResult<Option<DeviceGroupRecord>> {
        self.lock()?
            .query_row_cached(
                "SELECT group_id_hex, trust, key_package_ref_hex, recorded_at
                 FROM device_groups WHERE group_id_hex = ?1",
                params![group_id_hex],
                device_group_row,
            )
            .optional()
            .storage()?
            .map(device_group_record)
            .transpose()
    }

    /// Every device group row, oldest first.
    pub fn device_groups(&self) -> StorageResult<Vec<DeviceGroupRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT group_id_hex, trust, key_package_ref_hex, recorded_at
                 FROM device_groups ORDER BY recorded_at ASC, group_id_hex ASC",
            )
            .storage()?;
        let rows = stmt
            .query_map([], device_group_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter().map(device_group_record).collect()
    }

    /// Insert `record` unless a row for its group exists, or, when it claims
    /// the account's device group, unless another row already does. An
    /// account has one device group. Returns whether the row was inserted.
    pub fn insert_device_group(&self, record: &DeviceGroupRecord) -> StorageResult<bool> {
        check_ref(record.trust, record.key_package_ref_hex.as_deref())?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let taken: bool = tx
            .query_row_cached(
                &format!(
                    "SELECT EXISTS(SELECT 1 FROM device_groups WHERE group_id_hex = ?1)
                         OR (?2 AND EXISTS(SELECT 1 FROM device_groups WHERE {CLAIMING}))"
                ),
                params![record.group_id_hex, record.trust.claims_account()],
                |row| row.get(0),
            )
            .storage()?;
        if taken {
            return Ok(false);
        }
        tx.execute_cached(
            "INSERT INTO device_groups (group_id_hex, trust, key_package_ref_hex, recorded_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.group_id_hex,
                record.trust.as_str(),
                record.key_package_ref_hex,
                u64_to_i64(record.recorded_at)?
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(true)
    }

    /// Move the group's row from `from` to `to`, keeping its
    /// `KeyPackageRef` unless `key_package_ref_hex` names one. Moving an
    /// untrusted row to a claiming state fails if another row claims the
    /// account. Returns whether the row moved.
    pub fn set_device_group_trust(
        &self,
        group_id_hex: &str,
        from: DeviceGroupTrust,
        to: DeviceGroupTrust,
        key_package_ref_hex: Option<&str>,
        recorded_at: u64,
    ) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let current: Option<Option<String>> = tx
            .query_row_cached(
                "SELECT key_package_ref_hex FROM device_groups
                 WHERE group_id_hex = ?1 AND trust = ?2",
                params![group_id_hex, from.as_str()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        let Some(current_ref) = current else {
            return Ok(false);
        };
        let next_ref = key_package_ref_hex.map(str::to_owned).or(current_ref);
        check_ref(to, next_ref.as_deref())?;
        if to.claims_account() && !from.claims_account() {
            let claimed: bool = tx
                .query_row_cached(
                    &format!("SELECT EXISTS(SELECT 1 FROM device_groups WHERE {CLAIMING})"),
                    [],
                    |row| row.get(0),
                )
                .storage()?;
            if claimed {
                return Ok(false);
            }
        }
        tx.execute_cached(
            "UPDATE device_groups
             SET trust = ?2, key_package_ref_hex = ?3, recorded_at = ?4
             WHERE group_id_hex = ?1",
            params![
                group_id_hex,
                to.as_str(),
                next_ref,
                u64_to_i64(recorded_at)?
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(true)
    }

    /// Delete the group's row if it is in `trust`. Returns whether it went.
    pub fn delete_device_group(
        &self,
        group_id_hex: &str,
        trust: DeviceGroupTrust,
    ) -> StorageResult<bool> {
        let changed = self
            .lock()?
            .execute_cached(
                "DELETE FROM device_groups WHERE group_id_hex = ?1 AND trust = ?2",
                params![group_id_hex, trust.as_str()],
            )
            .storage()?;
        Ok(changed != 0)
    }
}

type DeviceGroupRow = (String, String, Option<String>, i64);

fn device_group_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceGroupRow> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn device_group_record(
    (group_id_hex, trust, key_package_ref_hex, recorded_at): DeviceGroupRow,
) -> StorageResult<DeviceGroupRecord> {
    Ok(DeviceGroupRecord {
        group_id_hex,
        trust: DeviceGroupTrust::parse(&trust)?,
        key_package_ref_hex,
        recorded_at: i64_to_u64(recorded_at)?,
    })
}

fn check_ref(trust: DeviceGroupTrust, key_package_ref_hex: Option<&str>) -> StorageResult<()> {
    if (trust == DeviceGroupTrust::Untrusted) != key_package_ref_hex.is_none() {
        return Err(StorageError::Backend(
            "only an untrusted device group has no confirmed KeyPackageRef".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use DeviceGroupTrust::*;

    fn record(group: &str, trust: DeviceGroupTrust) -> DeviceGroupRecord {
        DeviceGroupRecord {
            group_id_hex: group.into(),
            trust,
            key_package_ref_hex: (trust != Untrusted).then(|| "ab".into()),
            recorded_at: 1,
        }
    }

    #[test]
    fn an_account_has_one_device_group() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(store.insert_device_group(&record("aa", Creating)).unwrap());
        assert!(!store.insert_device_group(&record("aa", Untrusted)).unwrap());
        assert!(
            !store
                .insert_device_group(&record("bb", AwaitingWelcome))
                .unwrap()
        );
        assert!(store.insert_device_group(&record("bb", Untrusted)).unwrap());
        // An untrusted group cannot become the account's while another
        // claims it.
        assert!(
            !store
                .set_device_group_trust("bb", Untrusted, Linked, Some("cd"), 2)
                .unwrap()
        );
        assert!(store.delete_device_group("aa", Creating).unwrap());
        assert!(
            store
                .set_device_group_trust("bb", Untrusted, Linked, Some("cd"), 2)
                .unwrap()
        );
        assert_eq!(
            store.device_group("bb").unwrap().unwrap(),
            DeviceGroupRecord {
                group_id_hex: "bb".into(),
                trust: Linked,
                key_package_ref_hex: Some("cd".into()),
                recorded_at: 2,
            }
        );
    }

    #[test]
    fn trust_moves_only_from_the_expected_state() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(store.insert_device_group(&record("aa", Creating)).unwrap());
        assert!(
            !store
                .set_device_group_trust("aa", AwaitingWelcome, Linked, None, 2)
                .unwrap()
        );
        assert!(
            store
                .set_device_group_trust("aa", Creating, Created, None, 2)
                .unwrap()
        );
        assert!(!store.delete_device_group("aa", Creating).unwrap());
        let held = store.device_group("aa").unwrap().unwrap();
        assert_eq!(held.trust, Created);
        assert!(held.trust.is_trusted());
        assert_eq!(held.key_package_ref_hex.as_deref(), Some("ab"));
        assert_eq!(store.device_groups().unwrap(), vec![held]);
    }

    #[test]
    fn only_an_untrusted_group_has_no_confirmed_key_package() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let mut missing = record("aa", Created);
        missing.key_package_ref_hex = None;
        assert!(store.insert_device_group(&missing).is_err());
        let mut named = record("aa", Untrusted);
        named.key_package_ref_hex = Some("ab".into());
        assert!(store.insert_device_group(&named).is_err());
        assert!(store.device_groups().unwrap().is_empty());
    }
}
