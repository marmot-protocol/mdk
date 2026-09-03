use super::labels::{OpenMlsValueLabel, ValueSensitivity, build_key, build_key_legacy};
use super::{SqliteOpenMlsStorage, SqliteOpenMlsStorageError};
use crate::codec::{SensitiveBytes, serialize_sensitive_json};
use crate::connection::CachedSql;
use crate::connection::retry_on_busy;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Serialize, Serializer};

/// Leading bytes of a MessagePack-encoded value. Rows written before this
/// encoding are serde_json documents, which never begin with NUL, so a read
/// tells the two apart by this prefix and older rows keep decoding until
/// their next write replaces them.
///
/// serde_json spelled every `Vec<u8>` as an array of decimal integers: four
/// times the bytes on disk and a text integer parse per byte on every read.
/// A 64-member ratchet tree was 111 KB of JSON, parsed twice per app-message
/// send. MessagePack is self-describing, which OpenMLS's hand-written
/// `Deserialize` impls require, so a positional format such as postcard
/// cannot serve here.
const VALUE_ENCODING_V2_PREFIX: [u8; 2] = [0x00, 0x02];

/// Labels whose raw row bytes leave this crate and are parsed by the engine
/// as serde_json (`cgka_engine::key_package` reads stored bundles through
/// `StoredKeyPackageBundle::value`). Those stay JSON until that seam carries
/// decoded values.
const fn label_stays_json(label: OpenMlsValueLabel) -> bool {
    label.is_key_package()
}

fn encode_public<T: Serialize + ?Sized>(
    label: OpenMlsValueLabel,
    value: &T,
) -> Result<Vec<u8>, SqliteOpenMlsStorageError> {
    if label_stays_json(label) {
        return Ok(serde_json::to_vec(value)?);
    }
    let mut out = VALUE_ENCODING_V2_PREFIX.to_vec();
    rmp_serde::encode::write(&mut out, value)?;
    Ok(out)
}

fn encode_secret<T: Serialize + ?Sized>(
    label: OpenMlsValueLabel,
    value: &T,
) -> Result<SensitiveBytes, SqliteOpenMlsStorageError> {
    if label_stays_json(label) {
        return Ok(serialize_sensitive_json(value)?);
    }
    let mut out = SensitiveBytes::with_capacity(256);
    std::io::Write::write_all(&mut out, &VALUE_ENCODING_V2_PREFIX)
        .expect("in-memory sensitive buffer write cannot fail");
    rmp_serde::encode::write(&mut out, value)?;
    Ok(out)
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SqliteOpenMlsStorageError> {
    match bytes.strip_prefix(&VALUE_ENCODING_V2_PREFIX) {
        Some(body) => Ok(rmp_serde::from_slice(body)?),
        None => Ok(serde_json::from_slice(bytes)?),
    }
}

/// The serde_json form of `value`, for matching list elements written before
/// [`VALUE_ENCODING_V2_PREFIX`].
fn encode_legacy_json<T: Serialize + ?Sized>(
    label: OpenMlsValueLabel,
    value: &T,
) -> Result<SerializedBuffer, SqliteOpenMlsStorageError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(SerializedBuffer::from_database(label, bytes))
}

enum SerializedBuffer {
    Public(Vec<u8>),
    Secret(SensitiveBytes),
}

impl SerializedBuffer {
    fn from_database(label: OpenMlsValueLabel, bytes: Vec<u8>) -> Self {
        match label.sensitivity() {
            ValueSensitivity::Public => Self::Public(bytes),
            ValueSensitivity::Secret => Self::Secret(SensitiveBytes::new(bytes)),
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
        ValueSensitivity::Public => Ok(SerializedBuffer::Public(encode_public(label, value)?)),
        ValueSensitivity::Secret => Ok(SerializedBuffer::Secret(encode_secret(label, value)?)),
    }
}

enum SerializedList {
    Public(Vec<Vec<u8>>),
    Secret(Vec<SensitiveBytes>),
}

impl SerializedList {
    fn deserialize(
        label: OpenMlsValueLabel,
        bytes: &[u8],
    ) -> Result<Self, SqliteOpenMlsStorageError> {
        match label.sensitivity() {
            ValueSensitivity::Public => Ok(Self::Public(decode(bytes)?)),
            ValueSensitivity::Secret => Ok(Self::Secret(decode(bytes)?)),
        }
    }

    fn push<T: Serialize + ?Sized>(
        &mut self,
        label: OpenMlsValueLabel,
        value: &T,
    ) -> Result<(), SqliteOpenMlsStorageError> {
        match self {
            Self::Public(values) => values.push(encode_public(label, value)?),
            Self::Secret(values) => values.push(encode_secret(label, value)?),
        }
        Ok(())
    }

    /// Remove the first element equal to any of `encodings`. A list written
    /// before the current encoding holds serde_json elements, so callers pass
    /// both the current and the legacy form of the value.
    fn remove_matching(&mut self, encodings: &[SerializedBuffer]) {
        fn remove<T: AsRef<[u8]>>(values: &mut Vec<T>, encodings: &[SerializedBuffer]) {
            if let Some(pos) = values.iter().position(|stored| {
                encodings
                    .iter()
                    .any(|encoded| stored.as_ref() == encoded.as_slice())
            }) {
                values.remove(pos);
            }
        }

        match self {
            Self::Public(values) => remove(values, encodings),
            Self::Secret(values) => remove(values, encodings),
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
        let encoded = [
            serialize_buffer(label, value)?,
            encode_legacy_json(label, value)?,
        ];
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
        value.map(|value| decode(value.as_slice())).transpose()
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
            Some(SerializedList::Public(values)) => {
                values.into_iter().map(|value| decode(&value)).collect()
            }
            Some(SerializedList::Secret(values)) => values
                .into_iter()
                .map(|value| decode(value.as_slice()))
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
        .query_row_cached(
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
    conn.execute_cached(
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
    conn.execute_cached(
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
    list.push(label, value)?;
    write_list_on_connection(conn, label, storage_key.as_slice(), group_key, &list)?;
    delete_value_on_connection(conn, legacy_storage_key.as_slice())
}

fn remove_entity_on_connection(
    conn: &rusqlite::Connection,
    label: OpenMlsValueLabel,
    storage_key: Vec<u8>,
    legacy_storage_key: Vec<u8>,
    group_key: Option<&[u8]>,
    encoded: &[SerializedBuffer],
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
    conn.execute_cached(
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
        conn.execute_cached(
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
        let label = OpenMlsValueLabel::test_secret(b"TestSecret");

        assert!(matches!(
            serialize_buffer(label, &TestEntity(7)).unwrap(),
            SerializedBuffer::Secret(_)
        ));
        assert!(matches!(
            SerializedBuffer::from_database(label, b"7".to_vec()),
            SerializedBuffer::Secret(_)
        ));

        // A list written by the serde_json era: elements are JSON documents.
        let mut list = SerializedList::deserialize(label, b"[[55],[56]]").unwrap();
        let encoded = [
            serialize_buffer(label, &TestEntity(7)).unwrap(),
            encode_legacy_json(label, &TestEntity(7)).unwrap(),
        ];
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
    fn list_push_derives_buffer_ownership_from_the_existing_list() {
        let mut public = SerializedList::Public(Vec::new());
        public
            .push(OpenMlsValueLabel::test_public(b"P"), &TestEntity(7))
            .unwrap();
        assert!(matches!(public, SerializedList::Public(values) if values == [[0, 2, 7]]));

        let mut secret = SerializedList::Secret(Vec::new());
        secret
            .push(OpenMlsValueLabel::test_secret(b"S"), &TestEntity(8))
            .unwrap();
        assert!(matches!(
            secret,
            SerializedList::Secret(values) if values.len() == 1 && values[0].as_slice() == [0, 2, 8]
        ));
    }

    #[test]
    fn values_decode_from_either_encoding_and_write_the_current_one() {
        #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
        struct Blob {
            bytes: Vec<u8>,
            epoch: u64,
        }
        let blob = Blob {
            bytes: (0..=255).collect(),
            epoch: 7,
        };

        let json = serde_json::to_vec(&blob).unwrap();
        assert_eq!(decode::<Blob>(&json).unwrap(), blob);

        let label = OpenMlsValueLabel::test_public(b"Blob");
        let current = encode_public(label, &blob).unwrap();
        assert!(current.starts_with(&VALUE_ENCODING_V2_PREFIX));
        assert_eq!(decode::<Blob>(&current).unwrap(), blob);
        assert!(current.len() < json.len());

        let secret = encode_secret(OpenMlsValueLabel::test_secret(b"Blob"), &blob).unwrap();
        assert_eq!(secret.as_slice(), current.as_slice());
        assert!(decode::<Blob>(b"\x00\x02\xff").is_err());
        assert!(decode::<Blob>(b"[[55],").is_err());
    }

    #[test]
    fn stored_json_row_reads_back_and_is_rewritten_in_the_current_encoding() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label = OpenMlsValueLabel::test_public(b"Legacy");

        mls.write_value(
            label,
            b"k".to_vec(),
            None,
            serde_json::to_vec(&TestEntity(9)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            mls.read_entity::<TestEntity>(label, b"k".to_vec()).unwrap(),
            Some(TestEntity(9))
        );

        mls.write_entity(label, b"k".to_vec(), None, &TestEntity(10))
            .unwrap();
        let raw = read_value_on_connection(
            &store.lock().unwrap(),
            &build_key(label.as_bytes(), b"k".to_vec()),
            label,
        )
        .unwrap()
        .unwrap();
        assert!(raw.as_slice().starts_with(&VALUE_ENCODING_V2_PREFIX));
        assert_eq!(
            mls.read_entity::<TestEntity>(label, b"k".to_vec()).unwrap(),
            Some(TestEntity(10))
        );
    }

    #[test]
    fn value_storage_key_length_delimits_label_and_key() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let mls = &store.openmls;
        let label_a = OpenMlsValueLabel::test_public(b"A");
        let label_ab = OpenMlsValueLabel::test_public(b"AB");

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
        let label = OpenMlsValueLabel::test_public(b"LegacyValue");
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
        let label = OpenMlsValueLabel::test_public(b"LegacyList");
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
