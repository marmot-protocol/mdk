//! The backup ledger (mdk#2628 item 4.4b): the backups this device is
//! writing until a relay accepts a pointer listing them, the blobs it
//! condemned, and when its next backup pass is due. See migration 0164 for
//! what each row means. Nothing secret is stored.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension as _, params};

/// A backup this device is writing, or wrote and has not yet seen a relay
/// accept a pointer listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRun {
    pub backup_id: [u8; 16],
    /// The public half of the recovery key it is sealed to.
    pub recovery_key: Vec<u8>,
    pub written_at: u64,
    /// Its head, once uploaded.
    pub head: Option<BackupRunHead>,
}

/// Where an uploaded run's head is, and until when its pointer is published
/// again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRunHead {
    pub sha256: String,
    pub size: u64,
    pub server: String,
    pub publish_until: u64,
}

/// A blob to delete from its Blossom server while no pointer lists its
/// backup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CondemnedBackupBlob {
    pub sha256: String,
    pub server: String,
    /// The backup it belongs to.
    pub backup_id: [u8; 16],
    pub condemned_at: u64,
    /// How many deletes of it failed.
    pub attempts: u64,
}

/// When this device's next backup pass is due, and how many in a row
/// failed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackupSchedule {
    pub next_pass_at: u64,
    pub failed_passes: u64,
}

impl SqliteAppStorage {
    /// When the next backup pass is due; at once when none was scheduled.
    pub fn backup_schedule(&self) -> StorageResult<BackupSchedule> {
        let row: Option<(i64, i64)> = self
            .lock()?
            .query_row_cached(
                "SELECT next_pass_at, failed_passes FROM backup_schedule WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .storage()?;
        let Some((next_pass_at, failed_passes)) = row else {
            return Ok(BackupSchedule::default());
        };
        Ok(BackupSchedule {
            next_pass_at: i64_to_u64(next_pass_at)?,
            failed_passes: i64_to_u64(failed_passes)?,
        })
    }

    /// Schedule the next backup pass.
    pub fn schedule_backup_pass(&self, schedule: BackupSchedule) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO backup_schedule (id, next_pass_at, failed_passes) VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET
                     next_pass_at = excluded.next_pass_at,
                     failed_passes = excluded.failed_passes",
                params![
                    u64_to_i64(schedule.next_pass_at)?,
                    u64_to_i64(schedule.failed_passes)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Note that the roster names `writer` the backup writer for `key` at
    /// `now`, and return since when this device has seen that pair: `now`
    /// when it last saw another, or none.
    pub fn note_backup_writer(
        &self,
        key: &[u8],
        writer: &[u8; 32],
        now: u64,
    ) -> StorageResult<u64> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let seen: Option<i64> = conn
                .query_row_cached(
                    "SELECT writer_seen_at FROM backup_schedule
                     WHERE id = 1 AND writer_key = ?1 AND writer_slot = ?2",
                    params![key, writer.as_slice()],
                    |row| row.get(0),
                )
                .optional()
                .storage()?;
            if let Some(seen) = seen {
                return i64_to_u64(seen);
            }
            conn.execute_cached(
                "INSERT INTO backup_schedule
                     (id, next_pass_at, failed_passes, writer_key, writer_slot, writer_seen_at)
                 VALUES (1, 0, 0, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                     writer_key = excluded.writer_key,
                     writer_slot = excluded.writer_slot,
                     writer_seen_at = excluded.writer_seen_at",
                params![key, writer.as_slice(), u64_to_i64(now)?],
            )
            .storage()?;
            Ok(now)
        })
    }

    /// Start a run of backup `backup_id`, sealed to `key`, written at
    /// `written_at`.
    pub fn begin_backup_run(
        &self,
        backup_id: &[u8; 16],
        key: &[u8],
        written_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT INTO backup_runs (backup_id, recovery_key, written_at) VALUES (?1, ?2, ?3)",
                params![backup_id.as_slice(), key, u64_to_i64(written_at)?],
            )
            .storage()?;
        Ok(())
    }

    /// Record a blob of run `backup_id`, before it is uploaded.
    pub fn record_backup_run_blob(
        &self,
        backup_id: &[u8; 16],
        sha256: &str,
        server: &str,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "INSERT OR IGNORE INTO backup_run_blobs (backup_id, sha256, server)
                 VALUES (?1, ?2, ?3)",
                params![backup_id.as_slice(), sha256, server],
            )
            .storage()?;
        Ok(())
    }

    /// Record that run `backup_id` uploaded its head.
    pub fn record_backup_run_head(
        &self,
        backup_id: &[u8; 16],
        head: &BackupRunHead,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE backup_runs
                 SET head_sha256 = ?2, head_size = ?3, head_server = ?4, publish_until = ?5
                 WHERE backup_id = ?1",
                params![
                    backup_id.as_slice(),
                    head.sha256,
                    u64_to_i64(head.size)?,
                    head.server,
                    u64_to_i64(head.publish_until)?
                ],
            )
            .storage()?;
        Ok(())
    }

    /// Every run, oldest first.
    pub fn backup_runs(&self) -> StorageResult<Vec<BackupRun>> {
        type Row = (
            Vec<u8>,
            Vec<u8>,
            i64,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<i64>,
        );
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT backup_id, recovery_key, written_at,
                        head_sha256, head_size, head_server, publish_until
                 FROM backup_runs ORDER BY written_at, backup_id",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<Row>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(id, key, written_at, sha256, size, server, publish_until)| {
                    let head = match (sha256, size, server, publish_until) {
                        (Some(sha256), Some(size), Some(server), Some(publish_until)) => {
                            Some(BackupRunHead {
                                sha256,
                                size: i64_to_u64(size)?,
                                server,
                                publish_until: i64_to_u64(publish_until)?,
                            })
                        }
                        _ => None,
                    };
                    Ok(BackupRun {
                        backup_id: backup_id_of(id)?,
                        recovery_key: key,
                        written_at: i64_to_u64(written_at)?,
                        head,
                    })
                },
            )
            .collect()
    }

    /// A relay accepted a pointer listing run `backup_id`: forget the run.
    /// Its blobs are the pointer's now.
    pub fn finish_backup_run(&self, backup_id: &[u8; 16]) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM backup_run_blobs WHERE backup_id = ?1",
                params![backup_id.as_slice()],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM backup_runs WHERE backup_id = ?1",
                params![backup_id.as_slice()],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Abandon run `backup_id` at `now`: condemn every blob it recorded
    /// under its key, first tried at `first_try_at`, and forget the run.
    pub fn abandon_backup_run(
        &self,
        backup_id: &[u8; 16],
        now: u64,
        first_try_at: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "INSERT OR IGNORE INTO backup_condemned_blobs
                     (sha256, server, recovery_key, backup_id, condemned_at, next_try_at)
                 SELECT blobs.sha256, blobs.server, runs.recovery_key, runs.backup_id, ?2, ?3
                 FROM backup_run_blobs AS blobs
                 JOIN backup_runs AS runs ON runs.backup_id = blobs.backup_id
                 WHERE blobs.backup_id = ?1",
                params![
                    backup_id.as_slice(),
                    u64_to_i64(now)?,
                    u64_to_i64(first_try_at)?
                ],
            )
            .storage()?;
            drop(conn);
            self.finish_backup_run(backup_id)
        })
    }

    /// Condemn `blobs` of backup `backup_id`, each a SHA-256 and the server
    /// that holds it, under `key` at `now`, first tried at `first_try_at`. A
    /// blob condemned already keeps its row.
    pub fn condemn_backup_blobs(
        &self,
        key: &[u8],
        backup_id: &[u8; 16],
        blobs: &[(String, String)],
        now: u64,
        first_try_at: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for (sha256, server) in blobs {
                conn.execute_cached(
                    "INSERT OR IGNORE INTO backup_condemned_blobs
                         (sha256, server, recovery_key, backup_id, condemned_at, next_try_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        sha256,
                        server,
                        key,
                        backup_id.as_slice(),
                        u64_to_i64(now)?,
                        u64_to_i64(first_try_at)?
                    ],
                )
                .storage()?;
            }
            Ok(())
        })
    }

    /// The blobs condemned under `key` whose delete is due at `now`, oldest
    /// first.
    pub fn due_condemned_backup_blobs(
        &self,
        key: &[u8],
        now: u64,
    ) -> StorageResult<Vec<CondemnedBackupBlob>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT sha256, server, backup_id, condemned_at, attempts
                 FROM backup_condemned_blobs
                 WHERE recovery_key = ?1 AND next_try_at <= ?2
                 ORDER BY condemned_at, sha256, server",
            )
            .storage()?;
        let rows = stmt
            .query_map(params![key, u64_to_i64(now)?], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<(String, String, Vec<u8>, i64, i64)>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(sha256, server, backup_id, condemned_at, attempts)| {
                Ok(CondemnedBackupBlob {
                    sha256,
                    server,
                    backup_id: backup_id_of(backup_id)?,
                    condemned_at: i64_to_u64(condemned_at)?,
                    attempts: i64_to_u64(attempts)?,
                })
            })
            .collect()
    }

    /// When the next delete of a blob condemned under `key` is due, if any.
    pub fn next_condemned_backup_try(&self, key: &[u8]) -> StorageResult<Option<u64>> {
        let next: Option<i64> = self
            .lock()?
            .query_row_cached(
                "SELECT min(next_try_at) FROM backup_condemned_blobs WHERE recovery_key = ?1",
                params![key],
                |row| row.get(0),
            )
            .storage()?;
        next.map(i64_to_u64).transpose()
    }

    /// A delete of a condemned blob failed: try again from `next_try_at`.
    pub fn defer_condemned_backup_blob(
        &self,
        sha256: &str,
        server: &str,
        next_try_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE backup_condemned_blobs SET attempts = attempts + 1, next_try_at = ?3
                 WHERE sha256 = ?1 AND server = ?2",
                params![sha256, server, u64_to_i64(next_try_at)?],
            )
            .storage()?;
        Ok(())
    }

    /// Forget a condemned blob: deleted, listed again, or given up on.
    pub fn forget_condemned_backup_blob(&self, sha256: &str, server: &str) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM backup_condemned_blobs WHERE sha256 = ?1 AND server = ?2",
                params![sha256, server],
            )
            .storage()?;
        Ok(())
    }

    /// Forget every run and condemned blob under any key but `key`, and
    /// with no key every one: backups under other words, or turned off,
    /// stay as they are.
    pub fn forget_backups_except(&self, key: Option<&[u8]>) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM backup_run_blobs WHERE backup_id IN (
                     SELECT backup_id FROM backup_runs WHERE recovery_key IS NOT ?1
                 )",
                params![key],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM backup_runs WHERE recovery_key IS NOT ?1",
                params![key],
            )
            .storage()?;
            conn.execute_cached(
                "DELETE FROM backup_condemned_blobs WHERE recovery_key IS NOT ?1",
                params![key],
            )
            .storage()?;
            Ok(())
        })
    }
}

fn backup_id_of(bytes: Vec<u8>) -> StorageResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| cgka_traits::storage::StorageError::Backend("backup id length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    const RUN: [u8; 16] = [1; 16];
    const KEY: &[u8] = &[7; 32];
    const OTHER_KEY: &[u8] = &[8; 32];

    fn hash(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn blob(byte: u8, server: &str) -> (String, String) {
        (hash(byte), server.to_owned())
    }

    fn condemned(store: &SqliteAppStorage, key: &[u8]) -> Vec<(String, String)> {
        store
            .due_condemned_backup_blobs(key, u64::MAX >> 1)
            .unwrap()
            .into_iter()
            .map(|blob| (blob.sha256, blob.server))
            .collect()
    }

    /// An abandoned run's blobs, head included, are condemned under the
    /// key it was sealed to and the run is gone; a finished run's are not.
    #[test]
    fn an_abandoned_run_condemns_what_it_uploaded_and_a_finished_one_nothing() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        store.begin_backup_run(&RUN, KEY, 10).unwrap();
        store
            .record_backup_run_blob(&RUN, &hash(1), "https://a/")
            .unwrap();
        store
            .record_backup_run_blob(&RUN, &hash(2), "https://b/")
            .unwrap();
        store
            .record_backup_run_blob(&RUN, &hash(3), "https://a/")
            .unwrap();
        let head = BackupRunHead {
            sha256: hash(3),
            size: 9,
            server: "https://a/".into(),
            publish_until: 20,
        };
        store.record_backup_run_head(&RUN, &head).unwrap();
        assert_eq!(
            store.backup_runs().unwrap(),
            vec![BackupRun {
                backup_id: RUN,
                recovery_key: KEY.to_vec(),
                written_at: 10,
                head: Some(head),
            }]
        );

        let finished = [2; 16];
        store.begin_backup_run(&finished, KEY, 11).unwrap();
        store
            .record_backup_run_blob(&finished, &hash(4), "https://a/")
            .unwrap();
        store.finish_backup_run(&finished).unwrap();

        store.abandon_backup_run(&RUN, 30, 40).unwrap();
        assert!(store.backup_runs().unwrap().is_empty());
        assert!(
            store
                .due_condemned_backup_blobs(KEY, 39)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            condemned(&store, KEY),
            vec![
                blob(1, "https://a/"),
                blob(2, "https://b/"),
                blob(3, "https://a/")
            ]
        );
        assert_eq!(store.next_condemned_backup_try(KEY).unwrap(), Some(40));
        assert!(condemned(&store, OTHER_KEY).is_empty());
    }

    /// A failed delete counts and waits; a forgotten blob is gone; and
    /// condemning a blob again keeps when it was first condemned.
    #[test]
    fn a_condemned_blob_waits_after_a_failed_delete_until_forgotten() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        store
            .condemn_backup_blobs(KEY, &RUN, &[blob(1, "https://a/")], 10, 10)
            .unwrap();
        store
            .condemn_backup_blobs(KEY, &RUN, &[blob(1, "https://a/")], 50, 50)
            .unwrap();
        store
            .defer_condemned_backup_blob(&hash(1), "https://a/", 100)
            .unwrap();
        assert!(
            store
                .due_condemned_backup_blobs(KEY, 99)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.due_condemned_backup_blobs(KEY, 100).unwrap(),
            vec![CondemnedBackupBlob {
                sha256: hash(1),
                server: "https://a/".into(),
                backup_id: RUN,
                condemned_at: 10,
                attempts: 1,
            }]
        );
        store
            .forget_condemned_backup_blob(&hash(1), "https://a/")
            .unwrap();
        assert_eq!(store.next_condemned_backup_try(KEY).unwrap(), None);
    }

    /// New words keep only what is under them, and backups turned off
    /// nothing.
    #[test]
    fn only_the_current_keys_runs_and_condemned_blobs_are_kept() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        for (run, key, byte) in [([1; 16], KEY, 1), ([2; 16], OTHER_KEY, 2)] {
            store.begin_backup_run(&run, key, 10).unwrap();
            store
                .record_backup_run_blob(&run, &hash(byte), "https://a/")
                .unwrap();
            store
                .condemn_backup_blobs(key, &run, &[blob(byte + 10, "https://a/")], 10, 10)
                .unwrap();
        }
        store.forget_backups_except(Some(KEY)).unwrap();
        let runs = store.backup_runs().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].recovery_key, KEY);
        assert_eq!(condemned(&store, KEY), vec![blob(11, "https://a/")]);
        assert!(condemned(&store, OTHER_KEY).is_empty());
        // The surviving run's blobs are still its own.
        store.abandon_backup_run(&[1; 16], 20, 20).unwrap();
        assert_eq!(
            condemned(&store, KEY),
            vec![blob(11, "https://a/"), blob(1, "https://a/")]
        );

        store.forget_backups_except(None).unwrap();
        assert!(condemned(&store, KEY).is_empty());
        assert!(store.backup_runs().unwrap().is_empty());
    }

    /// The first time this device saw a writer for a key stays while the
    /// roster names that pair, and restarts when either changes; the pass
    /// schedule is kept apart.
    #[test]
    fn a_writer_is_seen_since_the_roster_first_named_it_for_the_key() {
        let account = SqliteAccountStorage::in_memory().unwrap();
        let store = account.app_storage();
        assert_eq!(store.backup_schedule().unwrap(), BackupSchedule::default());
        let schedule = BackupSchedule {
            next_pass_at: 500,
            failed_passes: 2,
        };
        store.schedule_backup_pass(schedule).unwrap();
        assert_eq!(store.note_backup_writer(KEY, &[1; 32], 10).unwrap(), 10);
        assert_eq!(store.note_backup_writer(KEY, &[1; 32], 20).unwrap(), 10);
        assert_eq!(store.note_backup_writer(KEY, &[2; 32], 30).unwrap(), 30);
        assert_eq!(
            store.note_backup_writer(OTHER_KEY, &[2; 32], 40).unwrap(),
            40
        );
        assert_eq!(
            store.note_backup_writer(OTHER_KEY, &[2; 32], 50).unwrap(),
            40
        );
        assert_eq!(store.backup_schedule().unwrap(), schedule);
    }
}
