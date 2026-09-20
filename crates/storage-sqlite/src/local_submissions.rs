//! Device-local submission identity and durable admission before engine work.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

const MAX_PENDING_SUBMISSIONS: i64 = 256;
const MAX_PENDING_BYTES: i64 = 16 * 1024 * 1024;

/// Private source data, never a wire DTO or diagnostic record.
pub struct LocalSubmission {
    pub group_id_hex: String,
    pub client_token: String,
    pub message_id_hex: String,
    pub request_hash: Vec<u8>,
    pub payload_hash: Vec<u8>,
    pub payload: Option<Vec<u8>>,
    pub request_json: Option<String>,
    /// 0: app-owned queue; 1: engine-owned; 3: rejected before engine acceptance.
    /// Value 2 is reserved for the API's completed outcome (stored in outcome_json).
    pub state: u8,
    pub outcome_json: Option<String>,
}

impl std::fmt::Debug for LocalSubmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSubmission")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LocalSubmission> {
    Ok(LocalSubmission {
        group_id_hex: row.get(0)?,
        client_token: row.get(1)?,
        message_id_hex: row.get(2)?,
        request_hash: row.get(3)?,
        payload_hash: row.get(4)?,
        payload: row.get(5)?,
        state: row.get(6)?,
        outcome_json: row.get(7)?,
        request_json: row.get(8)?,
    })
}
const COLUMNS: &str = "group_id_hex, client_token, message_id_hex, request_hash, payload_hash, payload, state, outcome_json, request_json";

impl SqliteAccountStorage {
    pub fn local_submission(
        &self,
        group: &str,
        token: &str,
    ) -> StorageResult<Option<LocalSubmission>> {
        self.lock()?.query_row_cached(&format!("SELECT {COLUMNS} FROM local_message_submissions WHERE group_id_hex=?1 AND client_token=?2"), params![group, token], from_row).optional().storage()
    }

    /// Called inside the app transaction that also records the pending source row.
    pub fn insert_local_submission(&self, submission: &LocalSubmission) -> StorageResult<()> {
        let conn = self.lock()?;
        let (count, bytes): (i64, i64) = conn.query_row_cached(
            "SELECT count(*), COALESCE(sum(length(payload)+length(request_json)),0) FROM local_message_submissions WHERE state=0", [], |r| Ok((r.get(0)?, r.get(1)?)),
        ).storage()?;
        let incoming = submission.payload.as_ref().map_or(0, Vec::len)
            + submission.request_json.as_ref().map_or(0, String::len);
        if count >= MAX_PENDING_SUBMISSIONS
            || incoming > MAX_PENDING_BYTES as usize
            || bytes > MAX_PENDING_BYTES - incoming as i64
        {
            return Err(StorageError::Backend(
                "local submission queue is full".to_owned(),
            ));
        }
        conn.execute_cached(
            "INSERT INTO local_message_submissions(group_id_hex,client_token,message_id_hex,request_hash,payload_hash,payload,request_json) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![submission.group_id_hex, submission.client_token, submission.message_id_hex, submission.request_hash, submission.payload_hash, submission.payload, submission.request_json],
        ).storage()?;
        Ok(())
    }

    pub fn next_local_submission(&self) -> StorageResult<Option<LocalSubmission>> {
        self.lock()?.query_row_cached(&format!("SELECT {COLUMNS} FROM local_message_submissions WHERE state=0 ORDER BY sequence LIMIT 1"), [], from_row).optional().storage()
    }

    /// The engine's durable queue/fanout owns accepted sends. Never re-enqueue
    /// them after a crash between acceptance and the app's completion callback.
    pub(crate) fn accept_local_submission_tx(
        conn: &rusqlite::Connection,
        group: &str,
        field: &str,
        value: &rusqlite::types::Value,
    ) -> StorageResult<()> {
        let column = match field {
            "payload_hash" => "payload_hash",
            "app_event_id" => "message_id_hex",
            _ => return Err(StorageError::Backend("invalid acceptance field".to_owned())),
        };
        conn.execute_cached(&format!("UPDATE local_message_submissions SET state=1, payload=NULL, request_json=NULL WHERE group_id_hex=?1 AND {column}=?2 AND state=0"), params![group, value]).storage()?;
        Ok(())
    }

    pub fn finish_local_submission(
        &self,
        group: &str,
        token: &str,
        outcome: Option<&str>,
    ) -> StorageResult<()> {
        self.lock()?.execute_cached(
            "UPDATE local_message_submissions SET state=CASE WHEN state=0 THEN 3 ELSE state END, payload=NULL, request_json=NULL, outcome_json=?3 WHERE group_id_hex=?1 AND client_token=?2",
            params![group, token, outcome],
        ).storage()?;
        Ok(())
    }
}
