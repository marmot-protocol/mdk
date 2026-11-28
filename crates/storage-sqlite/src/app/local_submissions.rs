//! Device-local submission identity and durable admission before engine work.
use crate::base::connection::{CachedSql, canonical_group_id_hex};
use crate::{SqliteAppStorage, SqliteResultExt};
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
    pub media_upload_receipt_json: Option<String>,
    /// 0: app-owned queue; 1: engine-owned; 3: rejected before engine acceptance;
    /// 4: refused, never sent, because the group gained a member account the
    /// send's member list leaves out. Value 2 is reserved for the API's
    /// completed outcome (stored in outcome_json).
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
        media_upload_receipt_json: row.get(9)?,
    })
}
const COLUMNS: &str = "group_id_hex, client_token, message_id_hex, request_hash, payload_hash, payload, state, outcome_json, request_json, media_upload_receipt_json";

impl SqliteAppStorage {
    pub fn local_submission(
        &self,
        group: &str,
        token: &str,
    ) -> StorageResult<Option<LocalSubmission>> {
        let group = canonical_group_id_hex(group);
        self.lock()?.query_row_cached(&format!("SELECT {COLUMNS} FROM local_message_submissions WHERE group_id_hex=?1 AND client_token=?2"), params![group.as_ref(), token], from_row).optional().storage()
    }

    /// Check both retained admissions and source rows, including legacy sends.
    /// Call inside the transaction that inserts the admission and pending row.
    pub fn local_message_identity_exists(&self, group: &str, message: &str) -> StorageResult<bool> {
        let group = canonical_group_id_hex(group);
        self.lock()?.query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM local_message_submissions WHERE group_id_hex=?1 AND message_id_hex=?2) OR EXISTS(SELECT 1 FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2)",
            params![group.as_ref(), message], |row| row.get(0),
        ).storage()
    }

    /// Called inside the app transaction that also records the pending source row.
    pub fn insert_local_submission(&self, submission: &LocalSubmission) -> StorageResult<()> {
        let group_id_hex = canonical_group_id_hex(&submission.group_id_hex);
        let conn = self.lock()?;
        let (count, bytes): (i64, i64) = conn
            .query_row_cached(
                "SELECT count(*), COALESCE(sum(
                COALESCE(length(payload), 0)
                + COALESCE(length(CAST(request_json AS BLOB)), 0)
                + COALESCE(length(CAST(media_upload_receipt_json AS BLOB)), 0)
            ), 0) FROM local_message_submissions WHERE state=0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .storage()?;
        let incoming = submission.payload.as_ref().map_or(0, Vec::len)
            + submission.request_json.as_ref().map_or(0, String::len)
            + submission
                .media_upload_receipt_json
                .as_ref()
                .map_or(0, String::len);
        if count >= MAX_PENDING_SUBMISSIONS
            || incoming > MAX_PENDING_BYTES as usize
            || bytes > MAX_PENDING_BYTES - incoming as i64
        {
            return Err(StorageError::Backend(
                "local submission queue is full".to_owned(),
            ));
        }
        conn.execute_cached(
            "INSERT INTO local_message_submissions(group_id_hex,client_token,message_id_hex,request_hash,payload_hash,payload,request_json,media_upload_receipt_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![group_id_hex.as_ref(), submission.client_token, submission.message_id_hex, submission.request_hash, submission.payload_hash, submission.payload, submission.request_json, submission.media_upload_receipt_json],
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
        let group = canonical_group_id_hex(group);
        let column = match field {
            "payload_hash" => "payload_hash",
            "app_event_id" => "message_id_hex",
            _ => return Err(StorageError::Backend("invalid acceptance field".to_owned())),
        };
        conn.execute_cached(&format!("UPDATE local_message_submissions SET state=1, payload=NULL, request_json=NULL WHERE group_id_hex=?1 AND {column}=?2 AND state=0"), params![group.as_ref(), value]).storage()?;
        Ok(())
    }

    pub fn finish_local_submission(
        &self,
        group: &str,
        token: &str,
        outcome: Option<&str>,
    ) -> StorageResult<()> {
        let group = canonical_group_id_hex(group);
        self.lock()?.execute_cached(
            "UPDATE local_message_submissions SET state=CASE WHEN state=0 THEN 3 ELSE state END, payload=NULL, request_json=NULL, outcome_json=?3 WHERE group_id_hex=?1 AND client_token=?2",
            params![group.as_ref(), token, outcome],
        ).storage()?;
        Ok(())
    }

    /// The engine refused the send because the group gained a member account
    /// its member list leaves out: nothing was sent, and nothing will be.
    pub fn refuse_local_submission(&self, group: &str, token: &str) -> StorageResult<()> {
        let conn = self.lock()?;
        Self::refuse_local_submission_tx(&conn, group, "client_token", &token)
    }

    /// [`Self::refuse_local_submission`] for a send the engine names by its
    /// payload, in the transaction that retires the engine's queued intent.
    pub(crate) fn refuse_local_submission_tx(
        conn: &rusqlite::Connection,
        group: &str,
        field: &str,
        value: &dyn rusqlite::ToSql,
    ) -> StorageResult<()> {
        let group = canonical_group_id_hex(group);
        let column = match field {
            "client_token" => "client_token",
            "payload_hash" => "payload_hash",
            _ => return Err(StorageError::Backend("invalid refusal field".to_owned())),
        };
        conn.execute_cached(&format!("UPDATE local_message_submissions SET state=4, payload=NULL, request_json=NULL, outcome_json=NULL WHERE group_id_hex=?1 AND {column}=?2 AND state IN (0, 1)"), params![group.as_ref(), value]).storage()?;
        Ok(())
    }

    /// The groups holding a refused send whose timeline row is still live.
    pub fn groups_with_refused_live_local_sends(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut statement = conn.prepare_cached(
            "SELECT DISTINCT local.group_id_hex FROM local_message_submissions local JOIN app_events event ON event.group_id_hex=local.group_id_hex AND event.message_id_hex=local.message_id_hex WHERE local.state=4 AND event.invalidated=0",
        ).storage()?;
        statement
            .query_map([], |row| row.get(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;

    fn submission(token: &str, payload_len: usize) -> LocalSubmission {
        LocalSubmission {
            group_id_hex: "aa".to_owned(),
            client_token: token.to_owned(),
            message_id_hex: format!("message-{token}"),
            request_hash: vec![1; 32],
            payload_hash: vec![2; 32],
            payload: Some(vec![3; payload_len]),
            request_json: Some("{}".to_owned()),
            state: 0,
            outcome_json: Some("private outcome".to_owned()),
            media_upload_receipt_json: None,
        }
    }

    fn store() -> SqliteAccountStorage {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex, endpoint, updated_at) VALUES ('aa', '', 0)",
                [],
            )
            .unwrap();
        store
    }

    fn refusal(result: StorageResult<()>) -> String {
        match result {
            Err(StorageError::Backend(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Private source data: Debug shows only the state.
    #[test]
    fn debug_shows_only_the_state() {
        assert_eq!(
            format!("{:?}", submission("private-token", 4)),
            "LocalSubmission { state: 0, .. }"
        );
    }

    /// The app-owned queue holds at most 256 pending sends and 16 MiB of
    /// payload plus request JSON; sends the engine accepted do not count.
    #[test]
    fn the_pending_queue_is_bounded_by_count_and_bytes() {
        let store = store();
        let app = store.app_storage();
        for index in 0..256 {
            app.insert_local_submission(&submission(&index.to_string(), 1))
                .unwrap();
        }
        assert_eq!(
            refusal(app.insert_local_submission(&submission("next", 1))),
            "local submission queue is full"
        );
        assert!(app.local_submission("aa", "next").unwrap().is_none());
        SqliteAppStorage::accept_local_submission_tx(
            &store.lock().unwrap(),
            "aa",
            "app_event_id",
            &rusqlite::types::Value::Text("message-0".to_owned()),
        )
        .unwrap();
        app.insert_local_submission(&submission("next", 1)).unwrap();

        let half = 8 * 1024 * 1024;
        let store = self::store();
        let app = store.app_storage();
        let mut first = submission("first", half);
        first.group_id_hex = "AA".to_owned();
        first.request_json = None;
        let receipt = r#"{"file":"שלום"}"#.to_owned();
        let receipt_bytes = receipt.len();
        first.media_upload_receipt_json = Some(receipt);
        app.insert_local_submission(&first).unwrap();

        let request = r#"{"caption":"שלום"}"#.to_owned();
        let request_bytes = request.len();
        let mut second = submission("second", half - receipt_bytes - request_bytes - 2);
        second.request_json = Some(request);
        app.insert_local_submission(&second).unwrap();

        let over = submission("over", 1);
        assert_eq!(
            refusal(app.insert_local_submission(&over)),
            "local submission queue is full"
        );
        assert!(app.local_submission("aa", "over").unwrap().is_none());
        app.insert_local_submission(&submission("exact", 0))
            .unwrap();
    }
}
