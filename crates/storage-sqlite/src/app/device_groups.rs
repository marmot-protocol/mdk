//! The device groups this device knows of, and how it came to know each
//! (mdk#2628 item 3.1). See migration 0125 for the states.

use crate::app::compromise_warning::{FirstTrustedRoster, record_first_trusted_roster};
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
        check_untrusted_target(record.trust)?;
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
    /// account. Returns whether the row moved. A move into a trusted state
    /// goes through [`Self::trust_device_group`].
    pub fn set_device_group_trust(
        &self,
        group_id_hex: &str,
        from: DeviceGroupTrust,
        to: DeviceGroupTrust,
        key_package_ref_hex: Option<&str>,
        recorded_at: u64,
    ) -> StorageResult<bool> {
        check_untrusted_target(to)?;
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let moved = move_trust(
            &tx,
            group_id_hex,
            from,
            to,
            key_package_ref_hex,
            recorded_at,
        )?;
        tx.commit().storage()?;
        Ok(moved)
    }

    /// Move the group's row from `from` into the trusted state `to`, as
    /// [`Self::set_device_group_trust`] does, and in the same transaction
    /// take `first` as the roster this device first trusts: the compromise
    /// warning counts its rejections as seen and this device's own as unseen
    /// (mdk#2628 3.7a, D68). Returns `None` if the row did not move, otherwise
    /// whether the open warning changed.
    pub fn trust_device_group(
        &self,
        group_id_hex: &str,
        from: DeviceGroupTrust,
        to: DeviceGroupTrust,
        key_package_ref_hex: Option<&str>,
        recorded_at: u64,
        first: &FirstTrustedRoster<'_>,
    ) -> StorageResult<Option<bool>> {
        if !to.is_trusted() {
            return Err(StorageError::Backend(
                "trust_device_group moves only into a trusted state".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        if !move_trust(
            &tx,
            group_id_hex,
            from,
            to,
            key_package_ref_hex,
            recorded_at,
        )? {
            return Ok(None);
        }
        let changed = record_first_trusted_roster(&tx, group_id_hex, first)?;
        tx.commit().storage()?;
        Ok(Some(changed))
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

/// Move the group's row from `from` to `to` in `tx`. Returns whether it
/// moved.
fn move_trust(
    tx: &rusqlite::Transaction<'_>,
    group_id_hex: &str,
    from: DeviceGroupTrust,
    to: DeviceGroupTrust,
    key_package_ref_hex: Option<&str>,
    recorded_at: u64,
) -> StorageResult<bool> {
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
    Ok(true)
}

/// Refuse a trusted state: only [`SqliteAppStorage::trust_device_group`]
/// moves a row there, with the roster the compromise warning takes as this
/// device's first.
fn check_untrusted_target(trust: DeviceGroupTrust) -> StorageResult<()> {
    if trust.is_trusted() {
        return Err(StorageError::Backend(
            "a device group becomes trusted only through trust_device_group".into(),
        ));
    }
    Ok(())
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

    const NO_ROSTER: FirstTrustedRoster<'static> = FirstTrustedRoster {
        own: &[],
        roster: &[],
        now: 2,
    };

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
        assert_eq!(
            store
                .trust_device_group("bb", Untrusted, Linked, Some("cd"), 2, &NO_ROSTER)
                .unwrap(),
            None
        );
        assert!(store.delete_device_group("aa", Creating).unwrap());
        assert_eq!(
            store
                .trust_device_group("bb", Untrusted, Linked, Some("cd"), 2, &NO_ROSTER)
                .unwrap(),
            Some(false)
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
        assert_eq!(
            store
                .trust_device_group("aa", AwaitingWelcome, Linked, None, 2, &NO_ROSTER)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .trust_device_group("aa", Creating, Created, None, 2, &NO_ROSTER)
                .unwrap(),
            Some(false)
        );
        assert!(!store.delete_device_group("aa", Creating).unwrap());
        let held = store.device_group("aa").unwrap().unwrap();
        assert_eq!(held.trust, Created);
        assert!(held.trust.is_trusted());
        assert_eq!(held.key_package_ref_hex.as_deref(), Some("ab"));
        assert_eq!(store.device_groups().unwrap(), vec![held]);
    }

    /// Only `trust_device_group` makes a row trusted, so the compromise
    /// warning's first roster is always written with it; it moves into
    /// nothing else.
    #[test]
    fn a_group_becomes_trusted_only_through_the_trust_write() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        assert!(store.insert_device_group(&record("aa", Created)).is_err());
        assert!(store.insert_device_group(&record("aa", Linked)).is_err());
        assert!(store.insert_device_group(&record("aa", Creating)).unwrap());
        assert!(
            store
                .set_device_group_trust("aa", Creating, Created, None, 2)
                .is_err()
        );
        assert!(
            store
                .trust_device_group("aa", Creating, Untrusted, None, 2, &NO_ROSTER)
                .is_err()
        );
        assert_eq!(store.device_group("aa").unwrap().unwrap().trust, Creating);
        // The way back is a plain move.
        assert_eq!(
            store
                .trust_device_group("aa", Creating, Created, None, 2, &NO_ROSTER)
                .unwrap(),
            Some(false)
        );
        assert!(
            store
                .set_device_group_trust("aa", Created, Creating, None, 3)
                .unwrap()
        );
        assert_eq!(store.device_group("aa").unwrap().unwrap().trust, Creating);
    }

    #[test]
    fn only_an_untrusted_group_has_no_confirmed_key_package() {
        let store = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let mut missing = record("aa", Creating);
        missing.key_package_ref_hex = None;
        assert!(store.insert_device_group(&missing).is_err());
        let mut named = record("aa", Untrusted);
        named.key_package_ref_hex = Some("ab".into());
        assert!(store.insert_device_group(&named).is_err());
        assert!(store.device_groups().unwrap().is_empty());
    }
}
