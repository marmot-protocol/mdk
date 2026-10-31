//! What this device keeps about the account's backup recovery key (mdk#2628
//! item 4.4a). See migration 0163 for what the row means.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// What this device keeps about the account's recovery key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum BackupRecoveryKeyRecord {
    #[default]
    Empty,
    /// The public half of the recovery key words confirmed while this
    /// device had no device group derive; the roster it founds carries it.
    Kept { public_key: Vec<u8> },
    /// The public half of the recovery key the words last confirmed on this
    /// device derive, and the key the roster held when they replaced it:
    /// `None` when they turned backups on, or were kept before this device
    /// trusted a device group.
    Confirmed {
        public_key: Vec<u8>,
        replaces: Option<Vec<u8>>,
    },
    /// Backups turned off on this device while the roster held `replaces`.
    TurningOff { replaces: Vec<u8> },
}

impl SqliteAppStorage {
    /// What this device keeps about the account's recovery key.
    pub fn backup_recovery_key(&self) -> StorageResult<BackupRecoveryKeyRecord> {
        let row = self
            .lock()?
            .query_row_cached(
                "SELECT state, public_key, replaces FROM backup_recovery_key WHERE id = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()
            .storage()?;
        let Some((state, public_key, replaces)) = row else {
            return Ok(BackupRecoveryKeyRecord::Empty);
        };
        Ok(match (state.as_str(), public_key, replaces) {
            ("kept", Some(public_key), None) => BackupRecoveryKeyRecord::Kept { public_key },
            ("confirmed", Some(public_key), replaces) => BackupRecoveryKeyRecord::Confirmed {
                public_key,
                replaces,
            },
            ("turning_off", None, Some(replaces)) => {
                BackupRecoveryKeyRecord::TurningOff { replaces }
            }
            _ => {
                return Err(StorageError::Backend(
                    "backup recovery key row is malformed".into(),
                ));
            }
        })
    }

    /// Keep `record` in place of whatever this device kept.
    pub fn put_backup_recovery_key(&self, record: &BackupRecoveryKeyRecord) -> StorageResult<()> {
        let conn = self.lock()?;
        let (state, public_key, replaces) = match record {
            BackupRecoveryKeyRecord::Empty => {
                conn.execute_cached("DELETE FROM backup_recovery_key WHERE id = 1", [])
                    .storage()?;
                return Ok(());
            }
            BackupRecoveryKeyRecord::Kept { public_key } => {
                ("kept", Some(public_key.as_slice()), None)
            }
            BackupRecoveryKeyRecord::Confirmed {
                public_key,
                replaces,
            } => (
                "confirmed",
                Some(public_key.as_slice()),
                replaces.as_deref(),
            ),
            BackupRecoveryKeyRecord::TurningOff { replaces } => {
                ("turning_off", None, Some(replaces.as_slice()))
            }
        };
        conn.execute_cached(
            "INSERT INTO backup_recovery_key (id, state, public_key, replaces)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                state = excluded.state,
                public_key = excluded.public_key,
                replaces = excluded.replaces",
            params![state, public_key, replaces],
        )
        .storage()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BackupRecoveryKeyRecord;
    use crate::SqliteAccountStorage;

    fn confirmed(public_key: u8, replaces: Option<u8>) -> BackupRecoveryKeyRecord {
        BackupRecoveryKeyRecord::Confirmed {
            public_key: vec![public_key; 32],
            replaces: replaces.map(|key| vec![key; 32]),
        }
    }

    #[test]
    fn any_record_is_put_back_exactly() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        assert_eq!(
            store.backup_recovery_key().unwrap(),
            BackupRecoveryKeyRecord::Empty
        );
        for record in [
            BackupRecoveryKeyRecord::Kept {
                public_key: vec![1; 32],
            },
            confirmed(1, None),
            confirmed(2, Some(1)),
            BackupRecoveryKeyRecord::TurningOff {
                replaces: vec![2; 32],
            },
            confirmed(3, None),
            BackupRecoveryKeyRecord::Empty,
            BackupRecoveryKeyRecord::Kept {
                public_key: vec![4; 32],
            },
            BackupRecoveryKeyRecord::Empty,
        ] {
            store.put_backup_recovery_key(&record).unwrap();
            assert_eq!(store.backup_recovery_key().unwrap(), record);
        }
    }

    #[test]
    fn keys_outside_the_rosters_bounds_are_refused() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        for record in [
            BackupRecoveryKeyRecord::Kept { public_key: vec![] },
            BackupRecoveryKeyRecord::Kept {
                public_key: vec![1; 256],
            },
            BackupRecoveryKeyRecord::Confirmed {
                public_key: vec![],
                replaces: None,
            },
            BackupRecoveryKeyRecord::Confirmed {
                public_key: vec![1; 256],
                replaces: None,
            },
            BackupRecoveryKeyRecord::Confirmed {
                public_key: vec![1; 32],
                replaces: Some(vec![]),
            },
            BackupRecoveryKeyRecord::Confirmed {
                public_key: vec![1; 32],
                replaces: Some(vec![2; 256]),
            },
            BackupRecoveryKeyRecord::TurningOff { replaces: vec![] },
            BackupRecoveryKeyRecord::TurningOff {
                replaces: vec![1; 256],
            },
        ] {
            assert!(store.put_backup_recovery_key(&record).is_err());
        }
        assert_eq!(
            store.backup_recovery_key().unwrap(),
            BackupRecoveryKeyRecord::Empty
        );
    }
}
