//! Durable authenticated group-recovery jobs. The runtime owns expiry and retries;
//! storage never discards a pending job to admit another one.

use crate::base::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, deserialize, serialize};
use cgka_traits::group_recovery::GroupRecoveryMessage;
use cgka_traits::storage::{StorageError, StorageResult};
use cgka_traits::transport::TransportMessage;
use cgka_traits::types::{GroupId, MemberId, MessageId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// Maximum retained coordinator jobs in one account-device database.
pub const MAX_GROUP_RECOVERY_COORDINATOR_JOBS: usize = 256;
/// Maximum retained coordinator jobs for one group.
pub const MAX_GROUP_RECOVERY_COORDINATOR_JOBS_PER_GROUP: usize = 16;

/// The local account's role in an authenticated recovery handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRecoveryRole {
    /// The unusable group copy requesting a replacement Welcome.
    Recipient,
    /// The healthy administrator replacing one authenticated member leaf.
    Coordinator,
}

impl GroupRecoveryRole {
    fn as_sql(self) -> i64 {
        match self {
            Self::Recipient => 0,
            Self::Coordinator => 1,
        }
    }
}

/// Durable position in the recovery workflow, interpreted by the runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRecoveryPhase {
    /// A recipient request is pending.
    Request,
    /// A coordinator's source-bound challenge is pending.
    Challenge,
    /// A recipient's fresh KeyPackage grant is pending.
    Grant,
    /// The coordinator is publishing the replacement commit.
    Publishing,
    /// The recipient is waiting for its replacement Welcome.
    AwaitWelcome,
    /// The workflow has completed; the runtime may explicitly remove it.
    Complete,
}

/// Account-private recovery state, including the exact outbound signed artifact.
///
/// Timestamps are Unix seconds. All retained jobs count toward admission limits,
/// including expired and complete jobs, until the runtime explicitly deletes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecoveryRecord {
    pub group_id: GroupId,
    pub request_id: [u8; 32],
    pub role: GroupRecoveryRole,
    pub peer: MemberId,
    pub leaf_index: u32,
    /// The recipient's durable unusable-copy identity, not a wire value.
    pub local_state_token: Option<[u8; 32]>,
    pub expires_at: u64,
    pub retry_at: u64,
    pub attempts: u32,
    pub phase: GroupRecoveryPhase,
    /// The latest request, challenge, or source-bound grant for this job.
    pub message: GroupRecoveryMessage,
    /// Reuse these bytes until acknowledged; never regenerate a retry's wrap.
    pub outbound: Option<TransportMessage>,
    /// Links publication recovery to the existing durable evolution/fanout.
    pub commit_id: Option<MessageId>,
}

#[derive(Serialize)]
struct StoredRecoveryRef<'a> {
    version: u8,
    record: &'a GroupRecoveryRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecovery {
    version: u8,
    record: GroupRecoveryRecord,
}

fn decode(bytes: &[u8]) -> StorageResult<GroupRecoveryRecord> {
    let stored: StoredRecovery = deserialize(bytes)?;
    if stored.version != 1 {
        return Err(StorageError::Serialization(
            "unsupported group recovery record version".into(),
        ));
    }
    Ok(stored.record)
}

impl SqliteAccountStorage {
    /// Insert or replace one recovery job atomically with capacity admission.
    ///
    /// Same-key updates remain possible at capacity. A different recipient nonce
    /// for the same group returns [`StorageError::AlreadyExists`]; coordinator
    /// capacity exhaustion returns [`StorageError::Capacity`]. Neither refusal
    /// changes existing jobs. This joins the caller's transaction when present.
    pub fn put_group_recovery(&self, record: &GroupRecoveryRecord) -> StorageResult<()> {
        if record.message.group_id != record.group_id
            || record.message.request_id != record.request_id
            || record.message.expires_at != record.expires_at
        {
            return Err(StorageError::Serialization(
                "group recovery message does not match journal identity".into(),
            ));
        }
        let bytes = serialize(&StoredRecoveryRef { version: 1, record })?;
        self.connection.with_transaction(|| {
            let connection = self.lock()?;
            let exists: bool = connection
                .query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM cgka_group_recovery
                 WHERE group_id = ?1 AND role = ?2 AND request_id = ?3)",
                    params![
                        record.group_id.as_slice(),
                        record.role.as_sql(),
                        record.request_id.as_slice()
                    ],
                    |row| row.get(0),
                )
                .storage()?;
            if !exists {
                match record.role {
                    GroupRecoveryRole::Recipient => {
                        let occupied: bool = connection
                            .query_row_cached(
                                "SELECT EXISTS(SELECT 1 FROM cgka_group_recovery
                             WHERE group_id = ?1 AND role = 0)",
                                params![record.group_id.as_slice()],
                                |row| row.get(0),
                            )
                            .storage()?;
                        if occupied {
                            return Err(StorageError::AlreadyExists);
                        }
                    }
                    GroupRecoveryRole::Coordinator => {
                        let (account, group): (i64, i64) = connection
                            .query_row_cached(
                                "SELECT COUNT(*), COALESCE(SUM(group_id = ?1), 0)
                             FROM cgka_group_recovery WHERE role = 1",
                                params![record.group_id.as_slice()],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            )
                            .storage()?;
                        if crate::i64_to_usize(account)? >= MAX_GROUP_RECOVERY_COORDINATOR_JOBS
                            || crate::i64_to_usize(group)?
                                >= MAX_GROUP_RECOVERY_COORDINATOR_JOBS_PER_GROUP
                        {
                            return Err(StorageError::Capacity(
                                "group recovery coordinator journal is full".into(),
                            ));
                        }
                    }
                }
            }
            connection
                .execute_cached(
                    "INSERT INTO cgka_group_recovery (group_id, role, request_id, record)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(group_id, role, request_id) DO UPDATE SET record = excluded.record",
                    params![
                        record.group_id.as_slice(),
                        record.role.as_sql(),
                        record.request_id.as_slice(),
                        bytes
                    ],
                )
                .storage()?;
            Ok(())
        })
    }

    /// Read a job by its full group, role, and nonce identity.
    pub fn group_recovery(
        &self,
        group_id: &GroupId,
        role: GroupRecoveryRole,
        request_id: &[u8; 32],
    ) -> StorageResult<Option<GroupRecoveryRecord>> {
        self.lock()?
            .query_row_cached(
                "SELECT record FROM cgka_group_recovery
             WHERE group_id = ?1 AND role = ?2 AND request_id = ?3",
                params![group_id.as_slice(), role.as_sql(), request_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?
            .map(|bytes| decode(&bytes))
            .transpose()
    }

    /// List retained jobs deterministically, without expiring or rescheduling them.
    pub fn list_group_recoveries(&self) -> StorageResult<Vec<GroupRecoveryRecord>> {
        let connection = self.lock()?;
        let mut statement = connection
            .prepare_cached(
                "SELECT record FROM cgka_group_recovery ORDER BY group_id, role, request_id",
            )
            .storage()?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .storage()?;
        rows.map(|row| decode(&row.storage()?)).collect()
    }

    /// Explicitly remove a job. Group deletion also cascades to all its jobs.
    pub fn delete_group_recovery(
        &self,
        group_id: &GroupId,
        role: GroupRecoveryRole,
        request_id: &[u8; 32],
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            self.lock()?
                .execute_cached(
                    "DELETE FROM cgka_group_recovery
                 WHERE group_id = ?1 AND role = ?2 AND request_id = ?3",
                    params![group_id.as_slice(), role.as_sql(), request_id.as_slice()],
                )
                .storage()?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;
    use crate::base::test_support::{gid, member_id, mid, sample_group};
    use cgka_traits::engine::KeyPackage;
    use cgka_traits::group_recovery::{GroupRecoveryBody, GroupRecoverySource};
    use cgka_traits::storage::{GroupStorage, StorageProvider};
    use cgka_traits::transport::{Timestamp, TransportEnvelope, TransportSource};
    use cgka_traits::types::EpochId;

    fn record(group: u8, nonce: u8, role: GroupRecoveryRole) -> GroupRecoveryRecord {
        GroupRecoveryRecord {
            group_id: gid(group),
            request_id: [nonce; 32],
            role,
            peer: member_id(7),
            leaf_index: 9,
            local_state_token: Some([3; 32]),
            expires_at: u64::MAX,
            retry_at: 1_800_000_123,
            attempts: 4,
            phase: GroupRecoveryPhase::Request,
            message: GroupRecoveryMessage {
                group_id: gid(group),
                request_id: [nonce; 32],
                expires_at: u64::MAX,
                body: GroupRecoveryBody::Request {
                    device_key_hash: [23; 32],
                },
            },
            outbound: Some(TransportMessage {
                id: mid(11),
                payload: (0..=255).collect(),
                timestamp: Timestamp(1_800_000_000),
                causal_deps: vec![mid(10)],
                source: TransportSource("opaque-transport".into()),
                envelope: TransportEnvelope::GroupRecovery {
                    recipient: member_id(7),
                },
            }),
            commit_id: Some(mid(12)),
        }
    }

    #[test]
    fn group_recovery_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery.sqlite");
        let key = SqlCipherKey::new("group recovery persistence test key").unwrap();
        let mut expected = record(1, 1, GroupRecoveryRole::Recipient);
        let source = GroupRecoverySource {
            epoch: EpochId(23),
            epoch_authenticator_hash: [21; 32],
            leaf_index: 9,
            leaf_hash: [22; 32],
            device_key_hash: [23; 32],
        };
        let phases = [
            (
                GroupRecoveryPhase::Request,
                GroupRecoveryBody::Request {
                    device_key_hash: [23; 32],
                },
            ),
            (
                GroupRecoveryPhase::Challenge,
                GroupRecoveryBody::Challenge {
                    source: source.clone(),
                },
            ),
            (
                GroupRecoveryPhase::Grant,
                GroupRecoveryBody::Grant {
                    source,
                    key_package: KeyPackage::with_source_event_id(vec![31, 0, 255], mid(32)),
                    device_signature: vec![33; 64],
                },
            ),
        ];
        for (phase, body) in phases {
            let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
            expected.phase = phase;
            expected.message.body = body;
            expected.retry_at += 27;
            expected.attempts += 1;
            store.put_group_recovery(&expected).unwrap();
            store.close().unwrap();
            let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
            let stored = reopened
                .group_recovery(&gid(1), GroupRecoveryRole::Recipient, &[1; 32])
                .unwrap()
                .unwrap();
            assert_eq!(stored, expected);
            // KeyPackage equality intentionally ignores transport provenance;
            // persistence must retain it too, including the Welcome routing link.
            assert_eq!(serialize(&stored).unwrap(), serialize(&expected).unwrap());
            assert_eq!(
                stored.outbound.as_ref().unwrap().payload,
                (0..=255).collect::<Vec<u8>>()
            );
            assert_eq!(
                reopened.list_group_recoveries().unwrap(),
                vec![expected.clone()]
            );
            reopened.close().unwrap();
        }
    }

    #[test]
    fn group_recovery_isolation() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for group in 1..=2 {
            store.put_group(&sample_group(gid(group), 0, 0)).unwrap();
            for role in [GroupRecoveryRole::Recipient, GroupRecoveryRole::Coordinator] {
                let mut job = record(group, 1, role);
                store.put_group_recovery(&job).unwrap();
                job.attempts = 10;
                job.expires_at = 0;
                job.message.expires_at = 0;
                store.put_group_recovery(&job).unwrap();
                assert_eq!(
                    store.group_recovery(&gid(group), role, &[1; 32]).unwrap(),
                    Some(job)
                );
            }
        }
        assert_eq!(store.list_group_recoveries().unwrap().len(), 4);
        let before = store.list_group_recoveries().unwrap();
        assert!(matches!(
            store.put_group_recovery(&record(1, 2, GroupRecoveryRole::Recipient)),
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(store.list_group_recoveries().unwrap(), before);
        store
            .delete_group_recovery(&gid(1), GroupRecoveryRole::Recipient, &[1; 32])
            .unwrap();
        assert!(
            store
                .group_recovery(&gid(1), GroupRecoveryRole::Coordinator, &[1; 32])
                .unwrap()
                .is_some()
        );
        store.delete_group(&gid(1)).unwrap();
        assert_eq!(store.list_group_recoveries().unwrap().len(), 2);
        assert!(
            store
                .list_group_recoveries()
                .unwrap()
                .iter()
                .all(|job| job.group_id == gid(2))
        );
        assert!(
            store
                .put_group_recovery(&record(3, 1, GroupRecoveryRole::Recipient))
                .is_err()
        );
        assert_eq!(store.list_group_recoveries().unwrap().len(), 2);
    }

    #[test]
    fn group_recovery_capacity() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for group in 1..=17 {
            store.put_group(&sample_group(gid(group), 0, 0)).unwrap();
        }
        for group in 1..=16 {
            for nonce in 0..16 {
                store
                    .put_group_recovery(&record(group, nonce, GroupRecoveryRole::Coordinator))
                    .unwrap();
            }
            let before = store.list_group_recoveries().unwrap();
            assert!(matches!(
                store.put_group_recovery(&record(group, 16, GroupRecoveryRole::Coordinator)),
                Err(StorageError::Capacity(_))
            ));
            assert_eq!(store.list_group_recoveries().unwrap(), before);
        }
        let mut existing = record(1, 0, GroupRecoveryRole::Coordinator);
        existing.phase = GroupRecoveryPhase::Publishing;
        existing.retry_at += 55;
        store.put_group_recovery(&existing).unwrap();
        assert_eq!(
            store
                .group_recovery(&gid(1), existing.role, &existing.request_id)
                .unwrap(),
            Some(existing)
        );
        let before = store.list_group_recoveries().unwrap();
        assert!(matches!(
            store.put_group_recovery(&record(17, 1, GroupRecoveryRole::Coordinator)),
            Err(StorageError::Capacity(_))
        ));
        assert_eq!(store.list_group_recoveries().unwrap(), before);
        store
            .put_group_recovery(&record(17, 1, GroupRecoveryRole::Recipient))
            .unwrap();
        store
            .delete_group_recovery(&gid(1), GroupRecoveryRole::Coordinator, &[0; 32])
            .unwrap();
        store
            .put_group_recovery(&record(17, 1, GroupRecoveryRole::Coordinator))
            .unwrap();
        assert_eq!(store.list_group_recoveries().unwrap().len(), 257);
    }

    #[test]
    fn group_recovery_race_capacity() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("concurrent-recovery.sqlite");
        let key = SqlCipherKey::new("concurrent group recovery test key").unwrap();
        let first = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let second = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        first.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        for nonce in 0..12 {
            first
                .put_group_recovery(&record(1, nonce, GroupRecoveryRole::Coordinator))
                .unwrap();
        }
        let barrier = Arc::new(Barrier::new(8));
        let writers: Vec<_> = (12..20)
            .map(|nonce| {
                let store = if nonce % 2 == 0 {
                    first.clone()
                } else {
                    second.clone()
                };
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    match store.put_group_recovery(&record(
                        1,
                        nonce,
                        GroupRecoveryRole::Coordinator,
                    )) {
                        Ok(()) => true,
                        Err(StorageError::Capacity(_)) => false,
                        Err(error) => panic!("unexpected journal admission error: {error}"),
                    }
                })
            })
            .collect();
        let accepted = writers
            .into_iter()
            .map(|writer| usize::from(writer.join().unwrap()))
            .sum::<usize>();
        assert_eq!(accepted, 4);
        assert_eq!(first.list_group_recoveries().unwrap().len(), 16);
        assert_eq!(second.list_group_recoveries().unwrap().len(), 16);
        first.close().unwrap();
        second.close().unwrap();
    }

    #[test]
    fn group_recovery_rollback() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let initial = record(1, 1, GroupRecoveryRole::Recipient);
        store.put_group_recovery(&initial).unwrap();
        let result: StorageResult<()> = store.with_transaction(|storage| {
            let mut updated = initial.clone();
            updated.phase = GroupRecoveryPhase::AwaitWelcome;
            updated.outbound = None;
            storage.put_group_recovery(&updated)?;
            storage.put_group_recovery(&record(1, 1, GroupRecoveryRole::Coordinator))?;
            storage.delete_group(&gid(1))?;
            Err(StorageError::Backend(
                "intentional transaction abort".into(),
            ))
        });
        assert!(result.is_err());
        assert_eq!(store.get_group(&gid(1)).unwrap().epoch, EpochId(0));
        assert_eq!(store.list_group_recoveries().unwrap(), vec![initial]);
    }

    #[test]
    fn group_recovery_bad_row() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store.put_group(&sample_group(gid(1), 0, 0)).unwrap();
        let mut job = record(1, 1, GroupRecoveryRole::Recipient);
        job.message.request_id = [2; 32];
        assert!(matches!(
            store.put_group_recovery(&job),
            Err(StorageError::Serialization(_))
        ));
        assert!(store.list_group_recoveries().unwrap().is_empty());
        job.message.request_id = job.request_id;
        store.put_group_recovery(&job).unwrap();
        let unknown = serialize(&StoredRecoveryRef {
            version: 2,
            record: &job,
        })
        .unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE cgka_group_recovery SET record = ?1",
                params![unknown],
            )
            .unwrap();
        assert!(matches!(
            store.group_recovery(&gid(1), job.role, &job.request_id),
            Err(StorageError::Serialization(_))
        ));
        assert!(matches!(
            store.list_group_recoveries(),
            Err(StorageError::Serialization(_))
        ));
    }
}
