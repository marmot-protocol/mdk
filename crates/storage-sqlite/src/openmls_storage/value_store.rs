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
        let storage_key = build_key(label, key);
        let mut conn = self.lock()?;
        if self.connection.is_current_thread_transaction_owner() {
            append_entity_on_connection(&conn, label, storage_key, group_key.as_deref(), value)?;
        } else {
            let tx = conn.transaction()?;
            append_entity_on_connection(&tx, label, storage_key, group_key.as_deref(), value)?;
            tx.commit()?;
        }
        Ok(())
    }

    pub(in crate::openmls_storage) fn remove_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = serde_json::to_vec(value)?;
        let storage_key = build_key(label, key);
        let mut conn = self.lock()?;
        if self.connection.is_current_thread_transaction_owner() {
            remove_entity_on_connection(
                &conn,
                label,
                storage_key,
                group_key.as_deref(),
                encoded.as_slice(),
            )?;
        } else {
            let tx = conn.transaction()?;
            remove_entity_on_connection(
                &tx,
                label,
                storage_key,
                group_key.as_deref(),
                encoded.as_slice(),
            )?;
            tx.commit()?;
        }
        Ok(())
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
        let mut conn = self.lock()?;
        // Wrap every label delete in a single transaction so the operation is
        // atomic. clear_proposal_queue deletes QUEUED_PROPOSAL_LABEL and
        // PROPOSAL_QUEUE_REFS_LABEL together; a crash (SIGKILL/OOM/power loss)
        // between two separate autocommit deletes could otherwise leave queue
        // refs whose entities are gone, which bricks MlsGroup::load for that
        // group with no self-healing path (issue #148). If the engine already
        // owns a broader OpenMLS transaction, execute directly inside it instead
        // of starting a nested SQLite transaction.
        if self.connection.is_current_thread_transaction_owner() {
            delete_group_labels_on_connection(&conn, group_key.as_slice(), labels)?;
        } else {
            let tx = conn.transaction()?;
            delete_group_labels_on_connection(&tx, group_key.as_slice(), labels)?;
            tx.commit()?;
        }
        Ok(())
    }
}

fn list_values_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
) -> Result<Vec<Vec<u8>>, SqliteOpenMlsStorageError> {
    conn.query_row(
        "SELECT value FROM openmls_values
         WHERE provider_version = ?1 AND storage_key = ?2",
        params![CURRENT_VERSION, storage_key],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|value| serde_json::from_slice(&value))
    .transpose()
    .map(|value| value.unwrap_or_default())
    .map_err(Into::into)
}

fn write_list_on_connection(
    conn: &rusqlite::Connection,
    label: &[u8],
    storage_key: &[u8],
    group_key: Option<&[u8]>,
    list: &[Vec<u8>],
) -> Result<(), SqliteOpenMlsStorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO openmls_values
            (provider_version, label, storage_key, group_key, value)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            CURRENT_VERSION,
            label,
            storage_key,
            group_key,
            serde_json::to_vec(list)?
        ],
    )?;
    Ok(())
}

fn append_entity_on_connection<T: Entity<CURRENT_VERSION>>(
    conn: &rusqlite::Connection,
    label: &[u8],
    storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    value: &T,
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_on_connection(conn, storage_key.as_slice())?;
    list.push(serde_json::to_vec(value)?);
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)
}

fn remove_entity_on_connection(
    conn: &rusqlite::Connection,
    label: &[u8],
    storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    encoded: &[u8],
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_on_connection(conn, storage_key.as_slice())?;
    if let Some(pos) = list.iter().position(|stored| stored == encoded) {
        list.remove(pos);
    }
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)
}

fn delete_group_labels_on_connection(
    conn: &rusqlite::Connection,
    group_key: &[u8],
    labels: &[&[u8]],
) -> Result<(), SqliteOpenMlsStorageError> {
    for label in labels {
        conn.execute(
            "DELETE FROM openmls_values
             WHERE provider_version = ?1 AND group_key = ?2 AND label = ?3",
            params![CURRENT_VERSION, group_key, *label],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn list_mutations_keep_read_modify_write_under_one_transaction() {
        let source = include_str!("value_store.rs");
        for function in ["append_entity", "remove_entity"] {
            let body = source
                .split(&format!("fn {function}"))
                .nth(1)
                .expect("function body");
            let body = body
                .split("pub(in crate::openmls_storage) fn")
                .next()
                .unwrap_or(body);
            let body = body.split("\n    fn ").next().unwrap_or(body);

            assert!(body.contains("transaction()"), "{function}");
            assert!(!body.contains("read_raw_list"), "{function}");
            assert!(!body.contains("self.write_value"), "{function}");
        }
    }

    #[test]
    fn delete_group_labels_deletes_all_labels_under_one_transaction() {
        // clear_proposal_queue deletes multiple labels (QueuedProposal entities
        // and ProposalQueueRefs) in one call. Those deletes must be atomic: a
        // crash between separate autocommit deletes could leave refs whose
        // entities are gone, which bricks MlsGroup::load for that group with no
        // self-healing path (issue #148). Enforce the single-transaction wrap
        // by source inspection, mirroring the list-mutation guard above.
        let source = include_str!("value_store.rs");
        let body = source
            .split("fn delete_group_labels")
            .nth(1)
            .expect("delete_group_labels body");
        let body = body
            .split("\n    fn ")
            .next()
            .unwrap_or(body)
            .split("\nfn ")
            .next()
            .unwrap_or(body)
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or(body);

        assert!(
            body.contains("transaction()"),
            "delete_group_labels must wrap its deletes in a single transaction"
        );
        assert!(
            body.contains("tx.commit()"),
            "delete_group_labels must commit its transaction"
        );
        assert!(
            !body.contains("conn.execute"),
            "delete_group_labels must execute through the transaction, not the bare connection"
        );
    }
}
