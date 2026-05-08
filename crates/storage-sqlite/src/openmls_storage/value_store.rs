use super::labels::build_key;
use super::{SqliteOpenMlsStorage, SqliteOpenMlsStorageError};
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use rusqlite::{OptionalExtension, params};
use serde::de::DeserializeOwned;

impl SqliteOpenMlsStorage {
    pub(in crate::openmls_storage) fn write_value(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key);
        self.lock()?.execute(
            "INSERT OR REPLACE INTO openmls_values
                (provider_version, label, storage_key, group_key, value)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                CURRENT_VERSION,
                label,
                storage_key,
                group_key.as_deref(),
                value
            ],
        )?;
        Ok(())
    }

    pub(in crate::openmls_storage) fn write_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        self.write_value(label, key, group_key, serde_json::to_vec(value)?)
    }

    pub(in crate::openmls_storage) fn write_group_entity<
        GroupId: Key<CURRENT_VERSION>,
        T: Entity<CURRENT_VERSION>,
    >(
        &self,
        label: &[u8],
        group_id: &GroupId,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let group_key = Self::group_key(group_id)?;
        self.write_entity(label, group_key.clone(), Some(group_key), value)
    }

    pub(in crate::openmls_storage) fn append_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let mut list: Vec<Vec<u8>> = self.read_raw_list(label, &key)?.unwrap_or_default();
        list.push(serde_json::to_vec(value)?);
        self.write_value(label, key, group_key, serde_json::to_vec(&list)?)
    }

    pub(in crate::openmls_storage) fn remove_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = serde_json::to_vec(value)?;
        let mut list: Vec<Vec<u8>> = self.read_raw_list(label, &key)?.unwrap_or_default();
        if let Some(pos) = list.iter().position(|stored| stored == &encoded) {
            list.remove(pos);
        }
        self.write_value(label, key, group_key, serde_json::to_vec(&list)?)
    }

    fn read_raw_list(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>, SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key.to_vec());
        let value: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT value FROM openmls_values
                 WHERE provider_version = ?1 AND storage_key = ?2",
                params![CURRENT_VERSION, storage_key],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_slice(&value).map_err(Into::into))
            .transpose()
    }

    pub(in crate::openmls_storage) fn read_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        self.read_json(label, key)
    }

    pub(in crate::openmls_storage) fn read_json<T: DeserializeOwned>(
        &self,
        label: &[u8],
        key: Vec<u8>,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key);
        let value: Option<Vec<u8>> = self
            .lock()?
            .query_row(
                "SELECT value FROM openmls_values
                 WHERE provider_version = ?1 AND storage_key = ?2",
                params![CURRENT_VERSION, storage_key],
                |row| row.get(0),
            )
            .optional()?;
        value
            .map(|value| serde_json::from_slice(&value).map_err(Into::into))
            .transpose()
    }

    pub(in crate::openmls_storage) fn read_group_entity<
        GroupId: Key<CURRENT_VERSION>,
        T: Entity<CURRENT_VERSION>,
    >(
        &self,
        label: &[u8],
        group_id: &GroupId,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        self.read_entity(label, Self::group_key(group_id)?)
    }

    pub(in crate::openmls_storage) fn read_list<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
    ) -> Result<Vec<T>, SqliteOpenMlsStorageError> {
        self.read_raw_list(label, &key)?
            .unwrap_or_default()
            .into_iter()
            .map(|value| serde_json::from_slice(&value).map_err(Into::into))
            .collect()
    }

    pub(in crate::openmls_storage) fn delete_value(
        &self,
        label: &[u8],
        key: Vec<u8>,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key);
        self.lock()?.execute(
            "DELETE FROM openmls_values
             WHERE provider_version = ?1 AND storage_key = ?2",
            params![CURRENT_VERSION, storage_key],
        )?;
        Ok(())
    }

    pub(in crate::openmls_storage) fn delete_group_value<GroupId: Key<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        group_id: &GroupId,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        self.delete_value(label, Self::group_key(group_id)?)
    }

    pub(in crate::openmls_storage) fn delete_group_labels<GroupId: Key<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        labels: &[&[u8]],
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let group_key = Self::group_key(group_id)?;
        let conn = self.lock()?;
        for label in labels {
            conn.execute(
                "DELETE FROM openmls_values
                 WHERE provider_version = ?1 AND group_key = ?2 AND label = ?3",
                params![CURRENT_VERSION, group_key, *label],
            )?;
        }
        Ok(())
    }
}
