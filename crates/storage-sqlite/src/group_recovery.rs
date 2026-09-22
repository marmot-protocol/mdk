//! Encrypted staging and transactional promotion for explicit group recovery.
//!
//! Protocol validation belongs to the session. This layer preserves the original
//! database and fences promotion against every intervening account write.

use std::path::{Path, PathBuf};

use cgka_traits::storage::{MessageStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::{GroupId, MessageId};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{
    SqlCipherHardening, SqlCipherKey, SqliteAccountStorage, SqliteResultExt,
    open_hardened_sqlcipher,
};

/// A private encrypted candidate and its original account connection.
///
/// Files are deliberately retained on failure/drop so a host can inspect or
/// remove them explicitly. Never log their contents or the connection fence.
pub struct GroupRecoveryStore {
    source: SqliteAccountStorage,
    candidate: SqliteAccountStorage,
    group: GroupId,
    key: SqlCipherKey,
    path: PathBuf,
    fence: (i64, i64),
}

fn write_fence(conn: &Connection) -> StorageResult<(i64, i64)> {
    Ok((
        conn.query_row("PRAGMA main.data_version", [], |r| r.get(0))
            .storage()?,
        conn.query_row("SELECT total_changes()", [], |r| r.get(0))
            .storage()?,
    ))
}

impl GroupRecoveryStore {
    /// Make `before.sqlite` and `candidate.sqlite` inside a private directory.
    /// Existing files are never overwritten. The host must quiesce account
    /// mutations; any intervening write makes promotion fail closed.
    pub fn prepare_group_recovery(
        source: SqliteAccountStorage,
        group: GroupId,
        directory: &Path,
        key: SqlCipherKey,
    ) -> StorageResult<Self> {
        fs_private::create_dir_all_private(directory)
            .map_err(|_| StorageError::Backend("create private recovery directory".into()))?;
        let before = directory.join("before.sqlite");
        let path = directory.join("candidate.sqlite");
        for file in [&before, &path] {
            fs_private::create_new_private(file)
                .map_err(|_| StorageError::Backend("create exclusive recovery file".into()))?;
        }
        let fence = source.with_read_snapshot(|source| {
            let conn = source.lock()?;
            // Force the read snapshot before copying either image.
            let _: i64 = conn
                .query_row("SELECT count(*) FROM cgka_groups", [], |r| r.get(0))
                .storage()?;
            let fence = write_fence(&conn)?;
            for file in [&before, &path] {
                let mut destination = Connection::open(file).storage()?;
                open_hardened_sqlcipher(&destination, &key, SqlCipherHardening::live_cache())?;
                rusqlite::backup::Backup::new(&conn, &mut destination)
                    .storage()?
                    .run_to_completion(128, std::time::Duration::from_millis(10), None)
                    .storage()?;
            }
            Ok::<_, StorageError>(fence)
        })?;
        let candidate = SqliteAccountStorage::open_encrypted(&path, &key)?;
        Ok(Self {
            source,
            candidate,
            group,
            key,
            path,
            fence,
        })
    }

    /// Candidate storage only. Never return the live connection to replay code.
    pub fn candidate(&self) -> &SqliteAccountStorage {
        &self.candidate
    }

    /// Rewind canonical state and reset only the scratch group's replay ledger.
    /// The session supplies already-consumed application IDs from the anchor.
    pub fn rewind_group(&self, anchor: &str, consumed: &[MessageId]) -> StorageResult<()> {
        let consumed: std::collections::HashSet<_> = consumed.iter().collect();
        self.candidate.with_transaction(|store| {
            store.rollback_group_state_to_snapshot(&self.group, anchor)?;
            for row in store.list_messages(&self.group, cgka_traits::EpochId(0))? {
                if !consumed.contains(&row.id) {
                    store.delete_message(&row.id)?;
                }
            }
            for name in store.list_group_snapshots(&self.group)? {
                if name != anchor {
                    store.release_group_snapshot(&self.group, &name)?;
                }
            }
            let conn = store.lock()?;
            for table in [
                "cgka_convergence_passes",
                "cgka_deferred_peel_generations",
                "cgka_processed_transport_ids",
                "cgka_released_transport_receipts",
            ] {
                conn.execute(
                    &format!("DELETE FROM {table} WHERE group_id=?1"),
                    [self.group.as_slice()],
                )
                .storage()?;
            }
            // This cache has no group column. Only the isolated account copy
            // loses it; live/global duplicate evidence is never promoted.
            conn.execute("DELETE FROM cgka_ingress_dedup", [])
                .storage()?;
            Ok(())
        })
    }

    /// Promote one validated group in a single transaction. Consume the handle
    /// so a second application cannot reuse the captured source fence.
    ///
    /// The caller must discard/reopen its old engine after success. Pending
    /// application outputs are replayed through the normal durable outbox.
    pub fn apply_group_recovery(self) -> StorageResult<()> {
        self.candidate.close()?;
        let mut conn = self.source.lock()?;
        conn.execute(
            "ATTACH DATABASE ?1 AS recovery_candidate KEY ?2",
            params![
                self.path
                    .to_str()
                    .ok_or_else(|| StorageError::Backend("invalid recovery path".into()))?,
                self.key.as_secret_str()
            ],
        )
        .storage()?;
        let result = (|| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .storage()?;
            if write_fence(&tx)? != self.fence {
                return Err(StorageError::Backend(
                    "recovery source changed; prepare again".into(),
                ));
            }
            let group = self.group.as_slice();
            let mls_key = crate::openmls_storage::mls_group_key(&self.group)?;
            tx.execute("UPDATE cgka_groups SET (epoch,record)=(SELECT epoch,record FROM recovery_candidate.cgka_groups WHERE id=?1) WHERE id=?1", [group]).storage()?;
            for table in [
                "cgka_member_capabilities",
                "cgka_group_snapshots",
                "cgka_member_validation_cache",
                "cgka_convergence_passes",
                "cgka_transport_group_routes",
                "cgka_deferred_peel_generations",
                "cgka_processed_transport_ids",
                "cgka_released_transport_receipts",
                "cgka_group_state_checkpoints",
                "pending_application_authority",
            ] {
                tx.execute(&format!("DELETE FROM {table} WHERE group_id=?1"), [group])
                    .storage()?;
                tx.execute(&format!("INSERT INTO {table} SELECT * FROM recovery_candidate.{table} WHERE group_id=?1"), [group]).storage()?;
            }
            tx.execute("DELETE FROM openmls_values WHERE group_key=?1", [&mls_key])
                .storage()?;
            tx.execute("INSERT INTO openmls_values SELECT * FROM recovery_candidate.openmls_values WHERE group_key=?1", [&mls_key]).storage()?;
            // Insertion order is account-global. Reassign it, preserving relative
            // candidate order, and point pending deliveries at the new values.
            // Keep historical rows absent from the recovered branch as invalidated
            // evidence. Existing app projections and pending deliveries may refer
            // to them even when this replay cannot authenticate them again.
            let missing = tx.prepare("SELECT id FROM cgka_messages WHERE group_id=?1 AND id NOT IN (SELECT id FROM recovery_candidate.cgka_messages WHERE group_id=?1)").storage()?
                .query_map([group], |row| row.get::<_, Vec<u8>>(0)).storage()?.collect::<Result<Vec<_>,_>>().storage()?;
            for id in missing {
                crate::storage::messages::update_message_state_on_connection(
                    &tx,
                    &MessageId::new(id),
                    cgka_traits::MessageState::EpochInvalidated,
                )?;
            }
            tx.execute("DELETE FROM cgka_messages WHERE group_id=?1 AND id IN (SELECT id FROM recovery_candidate.cgka_messages WHERE group_id=?1)", [group]).storage()?;
            tx.execute("INSERT INTO cgka_messages (id,group_id,epoch,state,storage_format,record,payload,deferred_peel) SELECT id,group_id,epoch,state,storage_format,record,payload,deferred_peel FROM recovery_candidate.cgka_messages WHERE group_id=?1 ORDER BY insert_order", [group]).storage()?;
            tx.execute(
                "DELETE FROM pending_application_events WHERE group_id=?1",
                [group],
            )
            .storage()?;
            tx.execute("INSERT INTO pending_application_events SELECT p.message_id,p.group_id,m.insert_order,p.record FROM recovery_candidate.pending_application_events p JOIN main.cgka_messages m ON m.id=p.message_id AND m.group_id=p.group_id WHERE p.group_id=?1", [group]).storage()?;
            if tx
                .prepare("PRAGMA foreign_key_check")
                .storage()?
                .query([])
                .storage()?
                .next()
                .storage()?
                .is_some()
            {
                return Err(StorageError::Backend(
                    "recovery foreign key check failed".into(),
                ));
            }
            tx.commit().storage()?;
            self.source.connection.note_openmls_write();
            Ok(())
        })();
        let detached = conn
            .execute_batch("DETACH DATABASE recovery_candidate")
            .storage();
        result?;
        detached
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::test_support::{gid, member_id, mid, sample_group, sample_message};
    use cgka_traits::storage::GroupStorage;
    use cgka_traits::{EpochId, GroupEvent};

    fn stage(path: &Path, directory: &Path) -> GroupRecoveryStore {
        let key = SqlCipherKey::new("recovery storage test").unwrap();
        let source = SqliteAccountStorage::open_encrypted(path, &key).unwrap();
        GroupRecoveryStore::prepare_group_recovery(source, gid(1), directory, key).unwrap()
    }

    fn seed(path: &Path) -> SqliteAccountStorage {
        let store = SqliteAccountStorage::open_encrypted(
            path,
            &SqlCipherKey::new("recovery storage test").unwrap(),
        )
        .unwrap();
        store.put_group(&sample_group(gid(1), 2, 2)).unwrap();
        store.put_group(&sample_group(gid(2), 9, 3)).unwrap();
        store
            .put_message(&sample_message(mid(1), gid(1), 2))
            .unwrap();
        store
            .put_message(&sample_message(mid(2), gid(2), 9))
            .unwrap();
        store
    }

    fn advance(candidate: &SqliteAccountStorage) {
        candidate.put_group(&sample_group(gid(1), 4, 4)).unwrap();
        candidate.delete_message(&mid(1)).unwrap();
        candidate
            .put_message(&sample_message(mid(3), gid(1), 4))
            .unwrap();
        candidate
            .put_pending_application_event(&GroupEvent::MessageReceived {
                group_id: gid(1),
                message_id: mid(3),
                sender: member_id(1),
                epoch: EpochId(4),
                payload: b"recovered".to_vec(),
                retention: None,
                authority: None,
            })
            .unwrap();
    }

    #[test]
    fn promotion_preserves_neighbors() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.sqlite");
        let live = seed(&path);
        let recovery = stage(&path, &root.path().join("repair"));
        advance(recovery.candidate());
        // Force a candidate-only order that collides with the other group's
        // existing row. Promotion must allocate a new global order.
        recovery
            .candidate()
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM cgka_messages WHERE group_id=?1",
                [gid(2).as_slice()],
            )
            .unwrap();
        let other_order: i64 = live
            .lock()
            .unwrap()
            .query_row(
                "SELECT insert_order FROM cgka_messages WHERE id=?1",
                [mid(2).as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        recovery
            .candidate()
            .lock()
            .unwrap()
            .execute(
                "UPDATE cgka_messages SET insert_order=?1 WHERE id=?2",
                params![other_order, mid(3).as_slice()],
            )
            .unwrap();
        recovery.apply_group_recovery().unwrap();
        assert_eq!(live.get_group(&gid(1)).unwrap().epoch, EpochId(4));
        assert_eq!(
            live.get_message(&mid(1)).unwrap().state,
            cgka_traits::MessageState::EpochInvalidated
        );
        assert_eq!(live.get_group(&gid(2)).unwrap(), sample_group(gid(2), 9, 3));
        assert_eq!(
            live.get_message(&mid(2)).unwrap(),
            sample_message(mid(2), gid(2), 9)
        );
        let conn = live.lock().unwrap();
        let matching:i64=conn.query_row("SELECT count(*) FROM pending_application_events p JOIN cgka_messages m ON m.id=p.message_id AND m.insert_order=p.message_insert_order",[],|r|r.get(0)).unwrap();
        assert_eq!(matching, 1);
        drop(conn);
        let before = SqliteAccountStorage::open_encrypted(
            root.path().join("repair/before.sqlite"),
            &SqlCipherKey::new("recovery storage test").unwrap(),
        )
        .unwrap();
        assert_eq!(before.get_group(&gid(1)).unwrap().epoch, EpochId(2));
        let prefix = std::fs::read(root.path().join("repair/before.sqlite")).unwrap();
        assert_ne!(&prefix[..16], b"SQLite format 3\0");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.path().join("repair"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(root.path().join("repair/before.sqlite"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn stale_source_refuses_promotion() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.sqlite");
        let live = seed(&path);
        let recovery = stage(&path, &root.path().join("repair"));
        advance(recovery.candidate());
        live.put_message(&sample_message(mid(4), gid(2), 9))
            .unwrap();
        assert!(recovery.apply_group_recovery().is_err());
        assert_eq!(live.get_group(&gid(1)).unwrap().epoch, EpochId(2));
        assert!(live.get_message(&mid(4)).is_ok());
        assert!(live.list_pending_application_events().unwrap().is_empty());
    }

    #[test]
    fn failed_promotion_is_atomic() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.sqlite");
        let live = seed(&path);
        live.lock().unwrap().execute_batch("CREATE TRIGGER fail_recovery BEFORE INSERT ON pending_application_events BEGIN SELECT RAISE(ABORT,'injected failure'); END;").unwrap();
        let recovery = stage(&path, &root.path().join("repair"));
        recovery
            .candidate()
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_recovery")
            .unwrap();
        advance(recovery.candidate());
        assert!(recovery.apply_group_recovery().is_err());
        drop(live);
        let reopened = SqliteAccountStorage::open_encrypted(
            &path,
            &SqlCipherKey::new("recovery storage test").unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.get_group(&gid(1)).unwrap().epoch, EpochId(2));
        assert!(reopened.get_message(&mid(1)).is_ok());
        assert!(reopened.get_message(&mid(3)).is_err());
        assert!(
            reopened
                .list_pending_application_events()
                .unwrap()
                .is_empty()
        );
    }
}
