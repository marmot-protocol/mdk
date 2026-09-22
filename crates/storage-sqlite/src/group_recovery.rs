//! Encrypted staging and transactional promotion for explicit group recovery.
//!
//! Protocol validation belongs to the session. This layer preserves the original
//! database and fences promotion against every intervening account write.

use std::path::{Path, PathBuf};

use cgka_traits::storage::{MessageStorage, StorageError, StorageProvider, StorageResult};
use cgka_traits::{GroupId, MessageId};
use rusqlite::{Connection, TransactionBehavior, params};

use crate::{SqlCipherKey, SqliteAccountStorage, SqliteResultExt, SqliteStorageOptions};

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

/// Capture writes through both this connection and other account connections.
fn write_fence(conn: &Connection) -> StorageResult<(i64, i64)> {
    Ok((
        conn.query_row("PRAGMA main.data_version", [], |r| r.get(0))
            .storage()?,
        conn.query_row("SELECT total_changes()", [], |r| r.get(0))
            .storage()?,
    ))
}

impl GroupRecoveryStore {
    /// Make a candidate at `path` in a private directory using the source options.
    /// Existing files are never overwritten. The host must quiesce account
    /// mutations; any intervening write makes promotion fail closed.
    pub fn prepare_group_recovery(
        source: SqliteAccountStorage,
        group: GroupId,
        path: &Path,
        key: SqlCipherKey,
        options: SqliteStorageOptions,
    ) -> StorageResult<Self> {
        let directory = path
            .parent()
            .ok_or_else(|| StorageError::Backend("invalid recovery path".into()))?;
        fs_private::create_dir_all_private(directory)
            .map_err(|_| StorageError::Backend("create private recovery directory".into()))?;
        fs_private::create_new_private(path)
            .map_err(|_| StorageError::Backend("create exclusive recovery file".into()))?;
        let candidate = SqliteAccountStorage::open_encrypted_with_options(path, &key, options)?;
        let fence = source.with_read_snapshot(|source| {
            let conn = source.lock()?;
            // Force the read snapshot before copying the account.
            let _: i64 = conn
                .query_row("SELECT count(*) FROM cgka_groups", [], |r| r.get(0))
                .storage()?;
            let fence = write_fence(&conn)?;
            let mut destination = candidate.lock()?;
            rusqlite::backup::Backup::new(&conn, &mut destination)
                .storage()?
                .run_to_completion(128, std::time::Duration::from_millis(10), None)
                .storage()?;
            Ok::<_, StorageError>(fence)
        })?;
        Ok(Self {
            source,
            candidate,
            group,
            key,
            path: path.to_owned(),
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
                return Err(StorageError::RecoverySourceChanged);
            }
            let group = self.group.as_slice();
            // Policies and local publication/terminal intent are host-owned.
            // Refuse candidate changes instead of silently dropping replay effects.
            for table in [
                "cgka_convergence_policies",
                "cgka_group_maintenance",
                "cgka_maintenance_obligations",
                "cgka_group_evolutions",
                "cgka_disband_requests",
                "cgka_disband_candidates",
                "cgka_disband_tombstones",
                "cgka_leave_requests",
            ] {
                let changed: bool = tx.query_row(
                    &format!("SELECT EXISTS(SELECT * FROM main.{table} WHERE group_id=?1 EXCEPT SELECT * FROM recovery_candidate.{table} WHERE group_id=?1) OR EXISTS(SELECT * FROM recovery_candidate.{table} WHERE group_id=?1 EXCEPT SELECT * FROM main.{table} WHERE group_id=?1)"),
                    [group], |row| row.get(0),
                ).storage()?;
                if changed {
                    return Err(StorageError::Backend(
                        "recovery changed host-owned group state".into(),
                    ));
                }
            }
            // Old stalled epochs no longer describe this group. App history,
            // acquisition state and account-global dedup evidence remain live.
            for table in ["app_epoch_backfill_intents", "app_epoch_stall_evidence"] {
                tx.execute(&format!("DELETE FROM {table} WHERE group_id=?1"), [group])
                    .storage()?;
            }
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
            tx.execute("INSERT INTO cgka_messages (insert_order,id,group_id,epoch,state,storage_format,record,payload,deferred_peel) SELECT (SELECT coalesce(max(seq),0) FROM main.sqlite_sequence WHERE name='cgka_messages') + row_number() OVER (ORDER BY insert_order),id,group_id,epoch,state,storage_format,record,payload,deferred_peel FROM recovery_candidate.cgka_messages WHERE group_id=?1", [group]).storage()?;
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

    /// Stage an independent encrypted copy of the seeded account.
    fn stage(path: &Path, directory: &Path) -> GroupRecoveryStore {
        let key = SqlCipherKey::new("recovery storage test").unwrap();
        let source = SqliteAccountStorage::open_encrypted(path, &key).unwrap();
        GroupRecoveryStore::prepare_group_recovery(
            source,
            gid(1),
            &directory.join("candidate.sqlite"),
            key,
            SqliteStorageOptions::default(),
        )
        .unwrap()
    }

    /// Seed two groups so promotion can prove isolation.
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

    /// Add deliveries whose insertion order differs from their message IDs.
    fn advance(candidate: &SqliteAccountStorage) {
        candidate.put_group(&sample_group(gid(1), 4, 4)).unwrap();
        candidate.delete_message(&mid(1)).unwrap();
        for id in [3, 5, 4] {
            candidate
                .put_message(&sample_message(mid(id), gid(1), 4))
                .unwrap();
            candidate
                .put_pending_application_event(&GroupEvent::MessageReceived {
                    group_id: gid(1),
                    message_id: mid(id),
                    sender: member_id(1),
                    epoch: EpochId(4),
                    payload: b"recovered".to_vec(),
                    retention: None,
                    authority: None,
                })
                .unwrap();
        }
    }

    #[test]
    fn promotion_preserves_neighbors() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.sqlite");
        let live = seed(&path);
        for group in [gid(1), gid(2)] {
            live.lock()
                .unwrap()
                .execute(
                    "INSERT INTO app_epoch_backfill_intents VALUES (?1,2,0)",
                    [group.as_slice()],
                )
                .unwrap();
            live.lock()
                .unwrap()
                .execute(
                    "INSERT INTO app_epoch_stall_evidence VALUES (?1,2,1,0,0,0)",
                    [group.as_slice()],
                )
                .unwrap();
        }
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
        assert_eq!(matching, 3);
        for table in ["app_epoch_backfill_intents", "app_epoch_stall_evidence"] {
            let remaining: Vec<Vec<u8>> = conn
                .prepare(&format!("SELECT group_id FROM {table}"))
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(remaining, vec![gid(2).as_slice().to_vec()]);
        }
        let ids = conn
            .prepare(
                "SELECT id FROM cgka_messages WHERE group_id=?1 AND id != ?2 ORDER BY insert_order",
            )
            .unwrap()
            .query_map(params![gid(1).as_slice(), mid(1).as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            ids,
            [mid(3), mid(5), mid(4)].map(|id| id.as_slice().to_vec())
        );
        drop(conn);
        assert!(!root.path().join("repair/before.sqlite").exists());
        let prefix = std::fs::read(root.path().join("repair/candidate.sqlite")).unwrap();
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
                std::fs::metadata(root.path().join("repair/candidate.sqlite"))
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
        assert!(matches!(
            recovery.apply_group_recovery(),
            Err(StorageError::RecoverySourceChanged)
        ));
        assert_eq!(live.get_group(&gid(1)).unwrap().epoch, EpochId(2));
        assert!(live.get_message(&mid(4)).is_ok());
        assert!(live.list_pending_application_events().unwrap().is_empty());
    }

    #[test]
    fn recovery_preserves_options() {
        let root = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("recovery options").unwrap();
        let options = SqliteStorageOptions {
            cipher_compatibility: 3,
            cipher_memory_security: false,
            journal_mode: crate::SqliteJournalMode::Delete,
            ..SqliteStorageOptions::default()
        };
        let live = SqliteAccountStorage::open_encrypted_with_options(
            root.path().join("source.sqlite"),
            &key,
            options.clone(),
        )
        .unwrap();
        live.put_group(&sample_group(gid(1), 2, 2)).unwrap();
        let recovery = GroupRecoveryStore::prepare_group_recovery(
            live.clone(),
            gid(1),
            &root.path().join("repair/candidate.sqlite"),
            key,
            options,
        )
        .unwrap();
        let journal: String = recovery
            .candidate()
            .lock()
            .unwrap()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(journal, "delete");
        advance(recovery.candidate());
        recovery.apply_group_recovery().unwrap();
        assert_eq!(live.get_group(&gid(1)).unwrap().epoch, EpochId(4));
    }

    #[test]
    fn changed_host_state_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source.sqlite");
        let live = seed(&path);
        let recovery = stage(&path, &root.path().join("repair"));
        advance(recovery.candidate());
        recovery
            .candidate()
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO cgka_leave_requests VALUES (?1,x'00')",
                [gid(1).as_slice()],
            )
            .unwrap();
        assert!(recovery.apply_group_recovery().is_err());
        assert_eq!(live.get_group(&gid(1)).unwrap().epoch, EpochId(2));
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
