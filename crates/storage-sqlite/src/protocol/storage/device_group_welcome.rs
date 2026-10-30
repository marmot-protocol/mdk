use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::storage::{
    DeviceGroupWelcomeExpectation, DeviceGroupWelcomeStorage, StorageResult,
};
use cgka_traits::types::GroupId;
use rusqlite::{OptionalExtension, params};

impl DeviceGroupWelcomeStorage for SqliteAccountStorage {
    fn put_device_group_welcome_expectation(
        &self,
        expectation: &DeviceGroupWelcomeExpectation,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR REPLACE INTO cgka_device_group_welcome_expectations (group_id, record)
                 VALUES (?1, ?2)",
                params![expectation.group_id.as_slice(), serialize(expectation)?],
            )
            .storage()?;
        Ok(())
    }

    fn device_group_welcome_expectation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<DeviceGroupWelcomeExpectation>> {
        let record: Option<Vec<u8>> = self
            .lock()?
            .query_row_cached(
                "SELECT record FROM cgka_device_group_welcome_expectations WHERE group_id = ?1",
                params![group_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        record.as_deref().map(deserialize).transpose()
    }

    fn device_group_welcome_expectations(
        &self,
    ) -> StorageResult<Vec<DeviceGroupWelcomeExpectation>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT record FROM cgka_device_group_welcome_expectations ORDER BY group_id",
            )
            .storage()?;
        let records = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<rusqlite::Result<Vec<_>>>()
            .storage()?;
        records.iter().map(|record| deserialize(record)).collect()
    }

    fn delete_device_group_welcome_expectation(&self, group_id: &GroupId) -> StorageResult<bool> {
        let deleted = self
            .lock()?
            .execute_cached(
                "DELETE FROM cgka_device_group_welcome_expectations WHERE group_id = ?1",
                params![group_id.as_slice()],
            )
            .storage()?;
        Ok(deleted > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlCipherKey, SqliteAccountStorage};

    #[test]
    fn device_group_welcome_expectation_survives_reopen_and_deletes_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marmot.sqlite");
        let key = SqlCipherKey::new("local identity key").unwrap();
        let group_id = GroupId::new(vec![7; 16]);
        let expectation = DeviceGroupWelcomeExpectation {
            group_id: group_id.clone(),
            sender_signature_key: vec![9; 32],
            key_package_ref: vec![5; 32],
            expires_at: 1_800_000_600,
        };

        {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store
                .put_device_group_welcome_expectation(&DeviceGroupWelcomeExpectation {
                    sender_signature_key: vec![1; 32],
                    ..expectation.clone()
                })
                .unwrap();
            store
                .put_device_group_welcome_expectation(&expectation)
                .unwrap();
        }

        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(
            reopened
                .device_group_welcome_expectation(&group_id)
                .unwrap(),
            Some(expectation.clone())
        );
        assert_eq!(
            reopened
                .device_group_welcome_expectation(&GroupId::new(vec![8; 16]))
                .unwrap(),
            None
        );
        assert_eq!(
            reopened.device_group_welcome_expectations().unwrap(),
            vec![expectation.clone()]
        );
        assert!(
            reopened
                .delete_device_group_welcome_expectation(&group_id)
                .unwrap()
        );
        assert!(
            !reopened
                .delete_device_group_welcome_expectation(&group_id)
                .unwrap()
        );
        assert_eq!(
            reopened
                .device_group_welcome_expectation(&group_id)
                .unwrap(),
            None
        );
        assert!(
            reopened
                .device_group_welcome_expectations()
                .unwrap()
                .is_empty()
        );
    }

    /// A record stored before expectations named their KeyPackage reads with
    /// an empty `KeyPackageRef`, which matches no Welcome.
    #[test]
    fn an_expectation_stored_without_its_key_package_reads_with_an_empty_ref() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group_id = GroupId::new(vec![7; 16]);
        let record = serde_json::json!({
            "group_id": group_id,
            "sender_signature_key": vec![9u8; 32],
            "expires_at": 1_800_000_600u64,
        });
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_device_group_welcome_expectations (group_id, record)
                 VALUES (?1, ?2)",
                params![group_id.as_slice(), serde_json::to_vec(&record).unwrap()],
            )
            .unwrap();
        let read = store
            .device_group_welcome_expectation(&group_id)
            .unwrap()
            .unwrap();
        assert!(read.key_package_ref.is_empty());
        assert_eq!(
            store.device_group_welcome_expectations().unwrap(),
            vec![read]
        );
    }
}
