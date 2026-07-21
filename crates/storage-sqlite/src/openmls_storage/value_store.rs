use super::labels::{build_key, build_key_legacy};
use super::{SqliteOpenMlsStorage, SqliteOpenMlsStorageError};
use crate::connection::retry_on_busy;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;

impl SqliteOpenMlsStorage {
    pub(in crate::openmls_storage) fn write_value(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key.clone());
        let legacy_storage_key = build_key_legacy(label, key);
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            write_value_on_connection(
                &conn,
                label,
                storage_key.as_slice(),
                legacy_storage_key.as_slice(),
                group_key.as_deref(),
                value.as_slice(),
            )?;
            Ok(())
        } else {
            // Own a fresh transaction so the new row and legacy cleanup commit
            // together; retry the whole idempotent write on transient lock
            // contention (issue #484).
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                write_value_on_connection(
                    &tx,
                    label,
                    storage_key.as_slice(),
                    legacy_storage_key.as_slice(),
                    group_key.as_deref(),
                    value.as_slice(),
                )?;
                tx.commit()?;
                Ok(())
            })
        }
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
        let storage_key = build_key(label, key.clone());
        let legacy_storage_key = build_key_legacy(label, key);
        if self.connection.is_current_thread_transaction_owner() {
            // Inside a broader engine-owned OpenMLS transaction: execute directly
            // and let the owning transaction handle retry/rollback. Retrying a
            // single statement inside someone else's transaction would corrupt it.
            let conn = self.lock()?;
            append_entity_on_connection(
                &conn,
                label,
                storage_key,
                legacy_storage_key,
                group_key.as_deref(),
                value,
            )?;
            Ok(())
        } else {
            // Own a fresh transaction: the whole read-modify-write is idempotent,
            // so retry it on transient lock contention (issue #484).
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                append_entity_on_connection(
                    &tx,
                    label,
                    storage_key.clone(),
                    legacy_storage_key.clone(),
                    group_key.as_deref(),
                    value,
                )?;
                tx.commit()?;
                Ok(())
            })
        }
    }

    pub(in crate::openmls_storage) fn remove_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: &[u8],
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = serde_json::to_vec(value)?;
        let storage_key = build_key(label, key.clone());
        let legacy_storage_key = build_key_legacy(label, key);
        if self.connection.is_current_thread_transaction_owner() {
            // Inside a broader engine-owned OpenMLS transaction: see append_entity.
            let conn = self.lock()?;
            remove_entity_on_connection(
                &conn,
                label,
                storage_key,
                legacy_storage_key,
                group_key.as_deref(),
                encoded.as_slice(),
            )?;
            Ok(())
        } else {
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                remove_entity_on_connection(
                    &tx,
                    label,
                    storage_key.clone(),
                    legacy_storage_key.clone(),
                    group_key.as_deref(),
                    encoded.as_slice(),
                )?;
                tx.commit()?;
                Ok(())
            })
        }
    }

    fn read_raw_list(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<Vec<Vec<u8>>>, SqliteOpenMlsStorageError> {
        let storage_key = build_key(label, key.to_vec());
        let legacy_storage_key = build_key_legacy(label, key.to_vec());
        let conn = self.lock()?;
        let value = match read_value_on_connection(&conn, &storage_key)? {
            Some(value) => Some(value),
            None => read_value_on_connection(&conn, &legacy_storage_key)?,
        };
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
        let storage_key = build_key(label, key.clone());
        let legacy_storage_key = build_key_legacy(label, key);
        let conn = self.lock()?;
        let value = match read_value_on_connection(&conn, &storage_key)? {
            Some(value) => Some(value),
            None => read_value_on_connection(&conn, &legacy_storage_key)?,
        };
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
        let storage_key = build_key(label, key.clone());
        let legacy_storage_key = build_key_legacy(label, key);
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            delete_value_on_connection(&conn, storage_key.as_slice())?;
            delete_value_on_connection(&conn, legacy_storage_key.as_slice())?;
            Ok(())
        } else {
            // Own a fresh transaction so the new-format row and legacy row are
            // removed atomically; retry the whole idempotent delete on transient
            // lock contention (issue #484).
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                delete_value_on_connection(&tx, storage_key.as_slice())?;
                delete_value_on_connection(&tx, legacy_storage_key.as_slice())?;
                tx.commit()?;
                Ok(())
            })
        }
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
        // Wrap every label delete in a single transaction so the operation is
        // atomic. clear_proposal_queue deletes QUEUED_PROPOSAL_LABEL and
        // PROPOSAL_QUEUE_REFS_LABEL together; a crash (SIGKILL/OOM/power loss)
        // between two separate autocommit deletes could otherwise leave queue
        // refs whose entities are gone, which bricks MlsGroup::load for that
        // group with no self-healing path (issue #148). If the engine already
        // owns a broader OpenMLS transaction, execute directly inside it instead
        // of starting a nested SQLite transaction.
        if self.connection.is_current_thread_transaction_owner() {
            let conn = self.lock()?;
            delete_group_labels_on_connection(&conn, group_key.as_slice(), labels)?;
            Ok(())
        } else {
            // Own a fresh transaction: the whole atomic delete is idempotent, so
            // retry it on transient lock contention (issue #484).
            retry_on_busy(|| {
                let mut conn = self.lock()?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                delete_group_labels_on_connection(&tx, group_key.as_slice(), labels)?;
                tx.commit()?;
                Ok(())
            })
        }
    }
}

fn read_value_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
) -> Result<Option<Vec<u8>>, SqliteOpenMlsStorageError> {
    Ok(conn
        .query_row(
            "SELECT value FROM openmls_values
             WHERE provider_version = ?1 AND storage_key = ?2",
            params![CURRENT_VERSION, storage_key],
            |row| row.get(0),
        )
        .optional()?)
}

fn write_value_on_connection(
    conn: &rusqlite::Connection,
    label: &[u8],
    storage_key: &[u8],
    legacy_storage_key: &[u8],
    group_key: Option<&[u8]>,
    value: &[u8],
) -> Result<(), SqliteOpenMlsStorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO openmls_values
            (provider_version, label, storage_key, group_key, value)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![CURRENT_VERSION, label, storage_key, group_key, value],
    )?;
    delete_value_on_connection(conn, legacy_storage_key)
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

fn list_values_with_legacy_fallback_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
    legacy_storage_key: &[u8],
) -> Result<Vec<Vec<u8>>, SqliteOpenMlsStorageError> {
    if read_value_on_connection(conn, storage_key)?.is_some() {
        list_values_on_connection(conn, storage_key)
    } else {
        list_values_on_connection(conn, legacy_storage_key)
    }
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
    legacy_storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    value: &T,
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_with_legacy_fallback_on_connection(
        conn,
        storage_key.as_slice(),
        legacy_storage_key.as_slice(),
    )?;
    list.push(serde_json::to_vec(value)?);
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)?;
    delete_value_on_connection(conn, legacy_storage_key.as_slice())
}

fn remove_entity_on_connection(
    conn: &rusqlite::Connection,
    label: &[u8],
    storage_key: Vec<u8>,
    legacy_storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    encoded: &[u8],
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_with_legacy_fallback_on_connection(
        conn,
        storage_key.as_slice(),
        legacy_storage_key.as_slice(),
    )?;
    if let Some(pos) = list.iter().position(|stored| stored == encoded) {
        list.remove(pos);
    }
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)?;
    delete_value_on_connection(conn, legacy_storage_key.as_slice())
}

fn delete_value_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
) -> Result<(), SqliteOpenMlsStorageError> {
    conn.execute(
        "DELETE FROM openmls_values
         WHERE provider_version = ?1 AND storage_key = ?2",
        params![CURRENT_VERSION, storage_key],
    )?;
    Ok(())
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
    use super::*;
    use crate::SqliteAccountStorage;
    use openmls_traits::storage::Entity;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestEntity(u8);

    impl Entity<CURRENT_VERSION> for TestEntity {}

    #[test]
    fn value_storage_key_length_delimits_label_and_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;

        // These two rows collide under the legacy concatenation:
        // label("A") + key("BC") == label("AB") + key("C").
        mls.write_value(
            b"A",
            b"BC".to_vec(),
            None,
            serde_json::to_vec(&1u8).unwrap(),
        )
        .unwrap();
        mls.write_value(
            b"AB",
            b"C".to_vec(),
            None,
            serde_json::to_vec(&2u8).unwrap(),
        )
        .unwrap();

        assert_eq!(mls.read_json::<u8>(b"A", b"BC".to_vec()).unwrap(), Some(1));
        assert_eq!(mls.read_json::<u8>(b"AB", b"C".to_vec()).unwrap(), Some(2));
    }

    #[test]
    fn value_storage_reads_and_deletes_legacy_concatenated_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label = b"LegacyValue";
        let key = b"row".to_vec();
        let legacy_key = build_key_legacy(label, key.clone());

        mls.lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO openmls_values
                    (provider_version, label, storage_key, group_key, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    CURRENT_VERSION,
                    label,
                    legacy_key.clone(),
                    Option::<&[u8]>::None,
                    serde_json::to_vec(&7u8).unwrap()
                ],
            )
            .unwrap();

        assert_eq!(mls.read_json::<u8>(label, key.clone()).unwrap(), Some(7));

        mls.write_value(label, key.clone(), None, serde_json::to_vec(&8u8).unwrap())
            .unwrap();
        let legacy_count: u64 = mls
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM openmls_values
                 WHERE provider_version = ?1 AND storage_key = ?2",
                params![CURRENT_VERSION, legacy_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 0, "new write should migrate legacy row away");
        assert_eq!(
            mls.read_json::<u8>(label, key.clone()).unwrap(),
            Some(8),
            "new length-delimited row must shadow the legacy row"
        );

        mls.delete_value(label, key.clone()).unwrap();
        assert_eq!(mls.read_json::<u8>(label, key).unwrap(), None);
    }

    #[test]
    fn list_storage_migrates_legacy_concatenated_key_on_mutation() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label = b"LegacyList";
        let key = b"list".to_vec();
        let legacy_key = build_key_legacy(label, key.clone());
        let legacy_list = vec![serde_json::to_vec(&TestEntity(1)).unwrap()];

        mls.lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO openmls_values
                    (provider_version, label, storage_key, group_key, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    CURRENT_VERSION,
                    label,
                    legacy_key.clone(),
                    Option::<&[u8]>::None,
                    serde_json::to_vec(&legacy_list).unwrap()
                ],
            )
            .unwrap();

        mls.append_entity(label, key.clone(), None, &TestEntity(2))
            .unwrap();
        assert_eq!(
            mls.read_list::<TestEntity>(label, key.clone()).unwrap(),
            vec![TestEntity(1), TestEntity(2)]
        );
        let legacy_count: u64 = mls
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM openmls_values
                 WHERE provider_version = ?1 AND storage_key = ?2",
                params![CURRENT_VERSION, legacy_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 0, "legacy row should be migrated away");

        mls.remove_entity(label, key.clone(), None, &TestEntity(1))
            .unwrap();
        assert_eq!(
            mls.read_list::<TestEntity>(label, key).unwrap(),
            vec![TestEntity(2)]
        );
    }

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

            assert!(
                body.contains("transaction_with_behavior(TransactionBehavior::Immediate)"),
                "{function}"
            );
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
            body.contains("transaction_with_behavior(TransactionBehavior::Immediate)"),
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
