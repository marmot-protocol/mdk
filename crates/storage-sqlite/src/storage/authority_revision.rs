//! Indexed, group-local revision probes for the engine's scalar authority cache.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use cgka_traits::{GroupId, StorageError};
use rusqlite::params;

pub(crate) fn read(store: &SqliteAccountStorage, group: &GroupId) -> StorageResult<[u8; 32]> {
    let key = crate::openmls_storage::mls_group_key(group)?;
    let conn = store.lock()?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT source, revision FROM group_authority_revisions
         WHERE (source = 0 AND source_key = ?1) OR (source = 1 AND source_key = ?2)",
        )
        .storage()?;
    let mut rows = stmt.query(params![group.as_slice(), key]).storage()?;
    let mut token = [0; 32];
    while let Some(row) = rows.next().storage()? {
        let source: u8 = row.get(0).storage()?;
        let value: Vec<u8> = row.get(1).storage()?;
        if source > 1 || value.len() != 16 {
            return Err(StorageError::Serialization(
                "invalid authority revision".into(),
            ));
        }
        token[usize::from(source) * 16..(usize::from(source) + 1) * 16].copy_from_slice(&value);
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;
    use cgka_traits::storage::StorageProvider;

    fn group_write(store: &SqliteAccountStorage, id: &[u8], value: &[u8]) {
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_groups(id, epoch, record) VALUES(?1, 0, ?2)
             ON CONFLICT(id) DO UPDATE SET record = excluded.record",
                params![id, value],
            )
            .unwrap();
    }
    fn mls_write(store: &SqliteAccountStorage, group: &GroupId, label: &[u8], value: &[u8]) {
        let key = crate::openmls_storage::mls_group_key(group).unwrap();
        let mut storage_key = key.clone();
        storage_key.extend_from_slice(label);
        store.lock().unwrap().execute(
            "INSERT INTO openmls_values(provider_version,label,storage_key,group_key,value)
             VALUES(1,?1,?2,?3,?4) ON CONFLICT(provider_version,storage_key) DO UPDATE SET value=excluded.value",
            params![label,storage_key,key,value]
        ).unwrap();
    }
    #[test]
    fn authority_revision_tracks_exact_sources_and_rollback_without_aba() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![1, 2]);
        let other = GroupId::new(vec![3]);
        let revision = || read(&store, &group).unwrap();
        assert_eq!(revision(), [0; 32]);
        group_write(&store, group.as_slice(), b"first");
        let initial = revision();
        group_write(&store, group.as_slice(), b"first");
        group_write(&store, other.as_slice(), b"other");
        mls_write(&store, &other, b"Tree", b"other tree");
        mls_write(&store, &group, b"MessageSecrets", b"ratchet");
        assert_eq!(revision(), initial);
        for label in [
            b"Tree".as_slice(),
            b"GroupContext",
            b"GroupState",
            b"OwnLeafNodeIndex",
        ] {
            let before = revision();
            mls_write(&store, &group, label, b"one");
            let inserted = revision();
            assert_ne!(inserted, before);
            mls_write(&store, &group, label, b"one");
            assert_eq!(revision(), inserted);
            mls_write(&store, &group, label, b"two");
            assert_ne!(revision(), inserted);
        }
        let committed = revision();
        let mut aborted = [0; 32];
        store
            .with_transaction(|_| {
                group_write(&store, group.as_slice(), b"aborted");
                aborted = revision();
                Err::<(), StorageError>(StorageError::NotFound)
            })
            .unwrap_err();
        assert_eq!(revision(), committed);
        group_write(&store, group.as_slice(), b"new committed value");
        assert_ne!(revision(), aborted);
        let before_delete = revision();
        store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM cgka_groups WHERE id=?1",
                params![group.as_slice()],
            )
            .unwrap();
        assert_ne!(revision(), before_delete);
        group_write(&store, group.as_slice(), b"new committed value");
        assert_ne!(revision(), before_delete);
        let before_mls_delete = revision();
        store
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM openmls_values WHERE group_key=?1",
                params![crate::openmls_storage::mls_group_key(&group).unwrap()],
            )
            .unwrap();
        assert_ne!(revision(), before_mls_delete);
    }

    #[test]
    fn authority_read_snapshot_is_reentrant_and_sees_foreign_writes_after_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.db");
        let key = SqlCipherKey::new("42".repeat(32)).unwrap();
        let reader = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let writer = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let group = GroupId::new(vec![1, 2]);
        group_write(&reader, group.as_slice(), b"before");
        let before = read(&reader, &group).unwrap();
        reader
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        reader
            .with_read_snapshot(|store| -> StorageResult<()> {
                assert_eq!(read(store, &group)?, before);
                group_write(&writer, group.as_slice(), b"after");
                store.with_read_snapshot(|nested| -> StorageResult<()> {
                    assert_eq!(read(nested, &group)?, before);
                    Ok(())
                })
            })
            .unwrap();
        let after = read(&reader, &group).unwrap();
        assert_ne!(after, before);
        reader.close().unwrap();
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert_eq!(read(&reopened, &group).unwrap(), after);
        assert!(matches!(
            read(&reader, &group),
            Err(StorageError::Closed(_))
        ));
    }
    #[test]
    fn authority_revision_probe_work_is_independent_of_other_groups() {
        use crate::query_work_test_support::measure;
        for count in [20, 20_000] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            store.lock().unwrap().execute_batch(&format!(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < {count})
                 INSERT INTO group_authority_revisions SELECT 0, CAST(x AS BLOB), randomblob(16) FROM n;"
            )).unwrap();
            let group = GroupId::new(b"1".to_vec());
            let (_, steps) = measure(&store, || read(&store, &group).unwrap());
            assert!(steps < 100, "{count} groups required {steps} VM steps");
        }
    }
}
