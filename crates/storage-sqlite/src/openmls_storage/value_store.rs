use super::labels::{OpenMlsValueLabel, ValueSensitivity, build_key, build_key_legacy};
use super::{SqliteOpenMlsStorage, SqliteOpenMlsStorageError};
use crate::connection::retry_on_busy;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretBytesVisitor;

        impl<'de> Visitor<'de> for SecretBytesVisitor {
            type Value = SecretBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON byte array")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new(Vec::with_capacity(seq.size_hint().unwrap_or(0)));
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                Ok(SecretBytes(bytes))
            }
        }

        deserializer.deserialize_seq(SecretBytesVisitor)
    }
}

enum SerializedBuffer {
    Public(Vec<u8>),
    Secret(SecretBytes),
}

impl SerializedBuffer {
    fn from_database(label: OpenMlsValueLabel, bytes: Vec<u8>) -> Self {
        match label.sensitivity() {
            ValueSensitivity::Public => Self::Public(bytes),
            ValueSensitivity::Secret => Self::Secret(SecretBytes::new(bytes)),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Public(bytes) => bytes,
            Self::Secret(bytes) => bytes.as_slice(),
        }
    }
}

fn serialize_buffer<T: Serialize + ?Sized>(
    label: OpenMlsValueLabel,
    value: &T,
) -> Result<SerializedBuffer, SqliteOpenMlsStorageError> {
    match label.sensitivity() {
        ValueSensitivity::Public => Ok(SerializedBuffer::Public(serde_json::to_vec(value)?)),
        ValueSensitivity::Secret => {
            // Serialize directly into zeroizing ownership. `to_writer` may leave
            // a partial JSON document when serialization fails; the guard wipes
            // that partial buffer as this error unwinds.
            let mut bytes = Zeroizing::new(Vec::new());
            serde_json::to_writer(&mut *bytes, value)?;
            Ok(SerializedBuffer::Secret(SecretBytes(bytes)))
        }
    }
}

enum SerializedList {
    Public(Vec<Vec<u8>>),
    Secret(Vec<SecretBytes>),
}

impl SerializedList {
    fn deserialize(
        label: OpenMlsValueLabel,
        bytes: &[u8],
    ) -> Result<Self, SqliteOpenMlsStorageError> {
        match label.sensitivity() {
            ValueSensitivity::Public => Ok(Self::Public(serde_json::from_slice(bytes)?)),
            ValueSensitivity::Secret => Ok(Self::Secret(serde_json::from_slice(bytes)?)),
        }
    }

    fn push(&mut self, value: SerializedBuffer) {
        match (self, value) {
            (Self::Public(values), SerializedBuffer::Public(value)) => values.push(value),
            (Self::Secret(values), SerializedBuffer::Secret(value)) => values.push(value),
            _ => unreachable!("label sensitivity must be stable within one list operation"),
        }
    }

    fn remove_matching(&mut self, encoded: &SerializedBuffer) {
        match self {
            Self::Public(values) => {
                if let Some(pos) = values
                    .iter()
                    .position(|stored| stored.as_slice() == encoded.as_slice())
                {
                    values.remove(pos);
                }
            }
            Self::Secret(values) => {
                if let Some(pos) = values
                    .iter()
                    .position(|stored| stored.as_slice() == encoded.as_slice())
                {
                    // Removing the SecretBytes drops its Zeroizing<Vec<u8>> here.
                    values.remove(pos);
                }
            }
        }
    }
}

impl Serialize for SerializedList {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Public(values) => values.serialize(serializer),
            Self::Secret(values) => values.serialize(serializer),
        }
    }
}

impl SqliteOpenMlsStorage {
    fn write_serialized_value(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &SerializedBuffer,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label.as_bytes(), key.clone());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key);
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

    pub(in crate::openmls_storage) fn write_json<T: Serialize + ?Sized>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = serialize_buffer(label, value)?;
        self.write_serialized_value(label, key, group_key, &encoded)
    }

    #[cfg(test)]
    pub(in crate::openmls_storage) fn write_value(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: Vec<u8>,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = SerializedBuffer::from_database(label, value);
        self.write_serialized_value(label, key, group_key, &encoded)
    }

    pub(in crate::openmls_storage) fn write_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        self.write_json(label, key, group_key, value)
    }

    pub(in crate::openmls_storage) fn write_group_entity<
        GroupId: Key<CURRENT_VERSION>,
        T: Entity<CURRENT_VERSION>,
    >(
        &self,
        label: OpenMlsValueLabel,
        group_id: &GroupId,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let group_key = Self::group_key(group_id)?;
        self.write_entity(label, group_key.clone(), Some(group_key), value)
    }

    pub(in crate::openmls_storage) fn append_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label.as_bytes(), key.clone());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key);
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
        label: OpenMlsValueLabel,
        key: Vec<u8>,
        group_key: Option<Vec<u8>>,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let encoded = serialize_buffer(label, value)?;
        let storage_key = build_key(label.as_bytes(), key.clone());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key);
        if self.connection.is_current_thread_transaction_owner() {
            // Inside a broader engine-owned OpenMLS transaction: see append_entity.
            let conn = self.lock()?;
            remove_entity_on_connection(
                &conn,
                label,
                storage_key,
                legacy_storage_key,
                group_key.as_deref(),
                &encoded,
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
                    &encoded,
                )?;
                tx.commit()?;
                Ok(())
            })
        }
    }

    fn read_raw_list(
        &self,
        label: OpenMlsValueLabel,
        key: &[u8],
    ) -> Result<Option<SerializedList>, SqliteOpenMlsStorageError> {
        let storage_key = build_key(label.as_bytes(), key.to_vec());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key.to_vec());
        let conn = self.lock()?;
        let value = match read_value_on_connection(&conn, &storage_key, label)? {
            Some(value) => Some(value),
            None => read_value_on_connection(&conn, &legacy_storage_key, label)?,
        };
        value
            .map(|value| SerializedList::deserialize(label, value.as_slice()))
            .transpose()
    }

    pub(in crate::openmls_storage) fn read_entity<T: Entity<CURRENT_VERSION>>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        self.read_json(label, key)
    }

    pub(in crate::openmls_storage) fn read_json<T: DeserializeOwned>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        let storage_key = build_key(label.as_bytes(), key.clone());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key);
        let conn = self.lock()?;
        let value = match read_value_on_connection(&conn, &storage_key, label)? {
            Some(value) => Some(value),
            None => read_value_on_connection(&conn, &legacy_storage_key, label)?,
        };
        value
            .map(|value| serde_json::from_slice(value.as_slice()).map_err(Into::into))
            .transpose()
    }

    pub(in crate::openmls_storage) fn read_group_entity<
        GroupId: Key<CURRENT_VERSION>,
        T: Entity<CURRENT_VERSION>,
    >(
        &self,
        label: OpenMlsValueLabel,
        group_id: &GroupId,
    ) -> Result<Option<T>, SqliteOpenMlsStorageError> {
        self.read_entity(label, Self::group_key(group_id)?)
    }

    pub(in crate::openmls_storage) fn read_list<T: Entity<CURRENT_VERSION>>(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
    ) -> Result<Vec<T>, SqliteOpenMlsStorageError> {
        match self.read_raw_list(label, &key)? {
            Some(SerializedList::Public(values)) => values
                .into_iter()
                .map(|value| serde_json::from_slice(&value).map_err(Into::into))
                .collect(),
            Some(SerializedList::Secret(values)) => values
                .into_iter()
                .map(|value| serde_json::from_slice(value.as_slice()).map_err(Into::into))
                .collect(),
            None => Ok(Vec::new()),
        }
    }

    pub(in crate::openmls_storage) fn delete_value(
        &self,
        label: OpenMlsValueLabel,
        key: Vec<u8>,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        let storage_key = build_key(label.as_bytes(), key.clone());
        let legacy_storage_key = build_key_legacy(label.as_bytes(), key);
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
        label: OpenMlsValueLabel,
        group_id: &GroupId,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        self.delete_value(label, Self::group_key(group_id)?)
    }

    pub(in crate::openmls_storage) fn delete_group_labels<GroupId: Key<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        labels: &[OpenMlsValueLabel],
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
    label: OpenMlsValueLabel,
) -> Result<Option<SerializedBuffer>, SqliteOpenMlsStorageError> {
    Ok(conn
        .query_row(
            "SELECT value FROM openmls_values
             WHERE provider_version = ?1 AND storage_key = ?2",
            params![CURRENT_VERSION, storage_key],
            |row| row.get(0),
        )
        .optional()?
        .map(|bytes| SerializedBuffer::from_database(label, bytes)))
}

fn write_value_on_connection(
    conn: &rusqlite::Connection,
    label: OpenMlsValueLabel,
    storage_key: &[u8],
    legacy_storage_key: &[u8],
    group_key: Option<&[u8]>,
    value: &[u8],
) -> Result<(), SqliteOpenMlsStorageError> {
    conn.execute(
        "INSERT OR REPLACE INTO openmls_values
            (provider_version, label, storage_key, group_key, value)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            CURRENT_VERSION,
            label.as_bytes(),
            storage_key,
            group_key,
            value
        ],
    )?;
    delete_value_on_connection(conn, legacy_storage_key)
}

fn list_values_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
    label: OpenMlsValueLabel,
) -> Result<Option<SerializedList>, SqliteOpenMlsStorageError> {
    read_value_on_connection(conn, storage_key, label)?
        .map(|value| SerializedList::deserialize(label, value.as_slice()))
        .transpose()
}

fn list_values_with_legacy_fallback_on_connection(
    conn: &rusqlite::Connection,
    storage_key: &[u8],
    legacy_storage_key: &[u8],
    label: OpenMlsValueLabel,
) -> Result<SerializedList, SqliteOpenMlsStorageError> {
    if let Some(values) = list_values_on_connection(conn, storage_key, label)? {
        Ok(values)
    } else if let Some(values) = list_values_on_connection(conn, legacy_storage_key, label)? {
        Ok(values)
    } else {
        Ok(match label.sensitivity() {
            ValueSensitivity::Public => SerializedList::Public(Vec::new()),
            ValueSensitivity::Secret => SerializedList::Secret(Vec::new()),
        })
    }
}

fn write_list_on_connection(
    conn: &rusqlite::Connection,
    label: OpenMlsValueLabel,
    storage_key: &[u8],
    group_key: Option<&[u8]>,
    list: &SerializedList,
) -> Result<(), SqliteOpenMlsStorageError> {
    let encoded = serialize_buffer(label, list)?;
    conn.execute(
        "INSERT OR REPLACE INTO openmls_values
            (provider_version, label, storage_key, group_key, value)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            CURRENT_VERSION,
            label.as_bytes(),
            storage_key,
            group_key,
            encoded.as_slice()
        ],
    )?;
    Ok(())
}

fn append_entity_on_connection<T: Entity<CURRENT_VERSION>>(
    conn: &rusqlite::Connection,
    label: OpenMlsValueLabel,
    storage_key: Vec<u8>,
    legacy_storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    value: &T,
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_with_legacy_fallback_on_connection(
        conn,
        storage_key.as_slice(),
        legacy_storage_key.as_slice(),
        label,
    )?;
    list.push(serialize_buffer(label, value)?);
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)?;
    delete_value_on_connection(conn, legacy_storage_key.as_slice())
}

fn remove_entity_on_connection(
    conn: &rusqlite::Connection,
    label: OpenMlsValueLabel,
    storage_key: Vec<u8>,
    legacy_storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    encoded: &SerializedBuffer,
) -> Result<(), SqliteOpenMlsStorageError> {
    let mut list = list_values_with_legacy_fallback_on_connection(
        conn,
        storage_key.as_slice(),
        legacy_storage_key.as_slice(),
        label,
    )?;
    list.remove_matching(encoded);
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
    labels: &[OpenMlsValueLabel],
) -> Result<(), SqliteOpenMlsStorageError> {
    for label in labels {
        conn.execute(
            "DELETE FROM openmls_values
             WHERE provider_version = ?1 AND group_key = ?2 AND label = ?3",
            params![CURRENT_VERSION, group_key, label.as_bytes()],
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
    fn secret_value_paths_select_zeroizing_buffers() {
        let label = OpenMlsValueLabel::secret(b"TestSecret");

        assert!(matches!(
            serialize_buffer(label, &TestEntity(7)).unwrap(),
            SerializedBuffer::Secret(_)
        ));
        assert!(matches!(
            SerializedBuffer::from_database(label, b"7".to_vec()),
            SerializedBuffer::Secret(_)
        ));

        let mut list = SerializedList::deserialize(label, b"[[55],[56]]").unwrap();
        let encoded = serialize_buffer(label, &TestEntity(7)).unwrap();
        list.remove_matching(&encoded);
        match list {
            SerializedList::Secret(values) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0].as_slice(), b"8");
            }
            SerializedList::Public(_) => panic!("secret list used ordinary buffers"),
        }

        assert!(SerializedList::deserialize(label, b"[[55],").is_err());
    }

    #[test]
    fn value_storage_key_length_delimits_label_and_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label_a = OpenMlsValueLabel::public(b"A");
        let label_ab = OpenMlsValueLabel::public(b"AB");

        // These two rows collide under the legacy concatenation:
        // label("A") + key("BC") == label("AB") + key("C").
        mls.write_value(
            label_a,
            b"BC".to_vec(),
            None,
            serde_json::to_vec(&1u8).unwrap(),
        )
        .unwrap();
        mls.write_value(
            label_ab,
            b"C".to_vec(),
            None,
            serde_json::to_vec(&2u8).unwrap(),
        )
        .unwrap();

        assert_eq!(
            mls.read_json::<u8>(label_a, b"BC".to_vec()).unwrap(),
            Some(1)
        );
        assert_eq!(
            mls.read_json::<u8>(label_ab, b"C".to_vec()).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn value_storage_reads_and_deletes_legacy_concatenated_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label = OpenMlsValueLabel::public(b"LegacyValue");
        let key = b"row".to_vec();
        let legacy_key = build_key_legacy(label.as_bytes(), key.clone());

        mls.lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO openmls_values
                    (provider_version, label, storage_key, group_key, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    CURRENT_VERSION,
                    label.as_bytes(),
                    legacy_key.clone(),
                    Option::<&[u8]>::None,
                    serde_json::to_vec(&7u8).unwrap()
                ],
            )
            .unwrap();

        assert_eq!(mls.read_json::<u8>(label, key.clone()).unwrap(), Some(7));

        mls.write_value(label, key.clone(), None, serde_json::to_vec(&8u8).unwrap())
            .unwrap();
        let legacy_count: i64 = mls
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
        let label = OpenMlsValueLabel::public(b"LegacyList");
        let key = b"list".to_vec();
        let legacy_key = build_key_legacy(label.as_bytes(), key.clone());
        let legacy_list = vec![serde_json::to_vec(&TestEntity(1)).unwrap()];

        mls.lock()
            .unwrap()
            .execute(
                "INSERT OR REPLACE INTO openmls_values
                    (provider_version, label, storage_key, group_key, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    CURRENT_VERSION,
                    label.as_bytes(),
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
        let legacy_count: i64 = mls
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
