//! Migration 0164: the backup ledger (mdk#2628 item 4.4b).
//!
//! - `backup_runs`: each backup this device is writing, or wrote and has not
//!   yet seen a relay accept a pointer listing: its id, the recovery key it
//!   is sealed to and when it was written. Once its head is uploaded, the
//!   head's `head_sha256`, `head_size` and `head_server`, and until when its
//!   pointer is published again (`publish_until`), all four set together.
//! - `backup_run_blobs`: each blob of a run, recorded before it is uploaded,
//!   so a run that is abandoned or cut short has its blobs condemned.
//! - `backup_condemned_blobs`: blobs to delete from their Blossom server
//!   while the pointer under `recovery_key` lists no backup `backup_id`, the
//!   backup each belongs to, with when they were condemned, how many deletes
//!   failed and when the next is due.
//! - `backup_schedule`, at most one row: when the next backup pass is due
//!   and how many in a row failed; and the backup writer this device last
//!   saw the roster name for a key, with when it first saw that pair.
//!
//! Nothing secret is stored: no archive key and no words. No rows are seeded.
use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        "CREATE TABLE backup_runs (
            backup_id BLOB PRIMARY KEY NOT NULL CHECK (length(backup_id) = 16),
            recovery_key BLOB NOT NULL CHECK (length(recovery_key) BETWEEN 1 AND 255),
            written_at INTEGER NOT NULL CHECK (written_at >= 0),
            head_sha256 TEXT CHECK (head_sha256 IS NULL OR length(head_sha256) = 64),
            head_size INTEGER CHECK (head_size IS NULL OR head_size > 0),
            head_server TEXT,
            publish_until INTEGER CHECK (publish_until IS NULL OR publish_until >= 0),
            CHECK ((head_sha256 IS NULL) = (head_size IS NULL)
                AND (head_sha256 IS NULL) = (head_server IS NULL)
                AND (head_sha256 IS NULL) = (publish_until IS NULL))
        );
        CREATE TABLE backup_run_blobs (
            backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
            server TEXT NOT NULL,
            PRIMARY KEY (backup_id, sha256, server)
        );
        CREATE TABLE backup_condemned_blobs (
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
            server TEXT NOT NULL,
            recovery_key BLOB NOT NULL CHECK (length(recovery_key) BETWEEN 1 AND 255),
            backup_id BLOB NOT NULL CHECK (length(backup_id) = 16),
            condemned_at INTEGER NOT NULL CHECK (condemned_at >= 0),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            next_try_at INTEGER NOT NULL CHECK (next_try_at >= 0),
            PRIMARY KEY (sha256, server)
        );
        CREATE TABLE backup_schedule (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            next_pass_at INTEGER NOT NULL CHECK (next_pass_at >= 0),
            failed_passes INTEGER NOT NULL CHECK (failed_passes >= 0),
            writer_key BLOB CHECK (writer_key IS NULL OR length(writer_key) BETWEEN 1 AND 255),
            writer_slot BLOB CHECK (writer_slot IS NULL OR length(writer_slot) = 32),
            writer_seen_at INTEGER CHECK (writer_seen_at IS NULL OR writer_seen_at >= 0),
            CHECK ((writer_key IS NULL) = (writer_slot IS NULL)
                AND (writer_key IS NULL) = (writer_seen_at IS NULL))
        );",
    )
    .storage()
}

#[cfg(test)]
mod tests {
    use crate::base::migrations::run_through;
    use rusqlite::Connection;

    /// A run's head columns and the schedule's writer columns are set
    /// together or not at all.
    #[test]
    fn a_head_and_a_seen_writer_are_whole_or_absent() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_through(&mut conn, 164).unwrap();
        let hash = "a".repeat(64);
        for (sql, whole) in [
            (
                format!(
                    "INSERT INTO backup_runs VALUES (x'{}', x'07', 1, NULL, NULL, NULL, NULL)",
                    "01".repeat(16)
                ),
                true,
            ),
            (
                format!(
                    "INSERT INTO backup_runs VALUES (x'{}', x'07', 1, '{hash}', 9, 'https://a/', 5)",
                    "02".repeat(16)
                ),
                true,
            ),
            (
                format!(
                    "INSERT INTO backup_runs VALUES (x'{}', x'07', 1, '{hash}', 9, 'https://a/', NULL)",
                    "03".repeat(16)
                ),
                false,
            ),
            (
                format!(
                    "INSERT INTO backup_runs VALUES (x'{}', x'07', 1, NULL, NULL, 'https://a/', NULL)",
                    "04".repeat(16)
                ),
                false,
            ),
            (
                "INSERT INTO backup_schedule VALUES (1, 0, 0, x'07', NULL, 3)".to_owned(),
                false,
            ),
            (
                format!(
                    "INSERT INTO backup_schedule VALUES (1, 0, 0, x'07', x'{}', 3)",
                    "05".repeat(32)
                ),
                true,
            ),
        ] {
            let result = conn.execute_batch(&sql);
            if whole {
                result.unwrap();
            } else {
                let refused = result.unwrap_err();
                assert!(
                    refused.to_string().starts_with("CHECK constraint failed"),
                    "{sql}: {refused}"
                );
            }
        }
    }
}
