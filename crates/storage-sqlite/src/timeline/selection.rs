//! Account-private, disk-backed message selection for complete local conversations.

use crate::{SqliteAccountStorage, SqliteResultExt, unix_now_seconds_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};

/// Opaque handle and exact count captured at one SQLite transaction boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSelectionSnapshot {
    pub token: String,
    pub count: u64,
}

/// One bounded page in the snapshot's frozen canonical timeline order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSelectionPage {
    pub message_ids: Vec<String>,
    pub next_ordinal: Option<u64>,
}

const MAX_SELECTION_PAGE: usize = 200;
const STALE_SELECTION_SECONDS: i64 = 24 * 60 * 60;

impl SqliteAccountStorage {
    /// Freeze eligible kind-9 message ids across the complete visible local group timeline.
    /// The SQL statement copies ids and order into the encrypted account DB without hydrating
    /// bodies, media, or profiles into Rust. Call off the UI thread; release the returned token
    /// when the transient selection ends. Later incoming rows are never added to this token.
    pub fn create_message_selection_snapshot(
        &self,
        group_id_hex: &str,
    ) -> StorageResult<MessageSelectionSnapshot> {
        if group_id_hex.is_empty() {
            return Err(StorageError::Serialization(
                "selection group is empty".into(),
            ));
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let now = unix_now_seconds_i64();
        // A process death cannot release its opaque handles. Bound retained encrypted rows
        // without invalidating other active selections from the current process.
        tx.execute(
            "DELETE FROM message_selection_snapshots WHERE created_at < ?1",
            [now.saturating_sub(STALE_SELECTION_SECONDS)],
        )
        .storage()?;
        let random_token: String = tx
            .query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))
            .storage()?;
        let token = format!("{}:{random_token}", self.selection_nonce);
        tx.execute(
            "INSERT INTO message_selection_snapshots(token, group_id_hex, created_at) VALUES (?1, ?2, ?3)",
            params![token, group_id_hex, now],
        )
        .storage()?;
        tx.execute(
            "INSERT INTO message_selection_snapshot_items(token, ordinal, message_id_hex)
             SELECT ?1, row_number() OVER (
                 ORDER BY timeline.timeline_order_class,
                          timeline.timeline_order_primary,
                          timeline.timeline_order_phase,
                          timeline.timeline_order_at,
                          timeline.message_id_hex
             ), timeline.message_id_hex
             FROM visible_message_timeline AS timeline
             WHERE timeline.group_id_hex = ?2
               AND timeline.kind = 9
               AND timeline.deleted = 0
               AND timeline.invalidation_status IS NULL
               AND (timeline.direction = 'received'
                    OR (timeline.direction = 'sent' AND timeline.source_message_id_hex IS NOT NULL))",
            params![token, group_id_hex],
        )
        .storage()?;
        let count = tx.changes();
        tx.execute(
            "UPDATE message_selection_snapshots SET selected_count = ?2 WHERE token = ?1",
            params![
                token,
                i64::try_from(count).map_err(|err| StorageError::Serialization(err.to_string()))?
            ],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(MessageSelectionSnapshot { token, count })
    }

    /// Read at most 200 frozen ids. Callers must revalidate each current message before an
    /// action: deletion, invalidation, blocking, and permissions may change after capture.
    pub fn message_selection_page(
        &self,
        token: &str,
        after_ordinal: Option<u64>,
        limit: usize,
    ) -> StorageResult<MessageSelectionPage> {
        self.validate_selection_token(token)?;
        if !(1..=MAX_SELECTION_PAGE).contains(&limit) {
            return Err(StorageError::Serialization(
                "selection page limit must be 1..=200".into(),
            ));
        }
        let conn = self.lock()?;
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM message_selection_snapshots WHERE token = ?1",
                [token],
                |_| Ok(true),
            )
            .optional()
            .storage()?
            .unwrap_or(false);
        if !exists {
            return Err(StorageError::NotFound);
        }
        let cursor = i64::try_from(after_ordinal.unwrap_or(0))
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT ordinal, message_id_hex FROM message_selection_snapshot_items
                 WHERE token = ?1 AND ordinal > ?2 ORDER BY ordinal LIMIT ?3",
            )
            .storage()?;
        let rows = stmt
            .query_map(params![token, cursor, (limit + 1) as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let has_more = rows.len() > limit;
        let message_ids = rows.iter().take(limit).map(|(_, id)| id.clone()).collect();
        let next_ordinal = if has_more {
            rows.get(limit - 1).map(|(ordinal, _)| *ordinal as u64)
        } else {
            None
        };
        Ok(MessageSelectionPage {
            message_ids,
            next_ordinal,
        })
    }

    /// Read current membership without materializing a page or a message body.
    pub fn message_selection_contains(
        &self,
        token: &str,
        message_id_hex: &str,
    ) -> StorageResult<bool> {
        self.validate_selection_token(token)?;
        let conn = self.lock()?;
        conn.query_row(
            "SELECT 1 FROM message_selection_snapshot_items WHERE token = ?1 AND message_id_hex = ?2",
            params![token, message_id_hex],
            |_| Ok(true),
        )
        .optional()
        .storage()
        .map(|value| value.unwrap_or(false))
    }

    /// Discard the transient selection and its disk-backed ids.
    pub fn release_message_selection_snapshot(&self, token: &str) -> StorageResult<()> {
        self.validate_selection_token(token)?;
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM message_selection_snapshots WHERE token = ?1",
            [token],
        )
        .storage()?;
        Ok(())
    }

    fn validate_selection_token(&self, token: &str) -> StorageResult<()> {
        if token
            .strip_prefix(self.selection_nonce.as_str())
            .and_then(|suffix| suffix.strip_prefix(':'))
            .is_none()
        {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqlCipherKey;

    fn insert(
        store: &SqliteAccountStorage,
        group: &str,
        id: &str,
        at: i64,
        kind: i64,
        deleted: bool,
    ) {
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO message_timeline(group_id_hex,message_id_hex,source_message_id_hex,
                 direction,sender,plaintext,kind,tags_json,timeline_at,received_at,reactions_json,deleted)
                 VALUES (?1,?2,?3,'received','alice','body',?4,'[]',?5,?5,'{}',?6)",
                params![group, id, format!("source-{id}"), kind, at, i64::from(deleted)],
            )
            .unwrap();
    }

    #[test]
    fn snapshot_is_complete_stable_bounded_and_released() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for i in 0..451 {
            insert(&store, "group-a", &format!("msg-{i:04}"), i, 9, false);
        }
        insert(&store, "group-a", "system", 451, 1210, false);
        insert(&store, "group-a", "deleted", 452, 9, true);
        insert(&store, "group-b", "other-group", 453, 9, false);
        let snapshot = store.create_message_selection_snapshot("group-a").unwrap();
        assert_eq!(snapshot.count, 451);
        assert!(
            store
                .message_selection_contains(&snapshot.token, "msg-0000")
                .unwrap()
        );
        assert!(
            !store
                .message_selection_contains(&snapshot.token, "system")
                .unwrap()
        );

        insert(&store, "group-a", "new-after-capture", 454, 9, false);
        store
            .lock()
            .unwrap()
            .execute(
                "UPDATE message_timeline SET deleted=1 WHERE message_id_hex='msg-0000'",
                [],
            )
            .unwrap();
        let mut cursor = None;
        let mut all = Vec::new();
        loop {
            let page = store
                .message_selection_page(&snapshot.token, cursor, 100)
                .unwrap();
            assert!(page.message_ids.len() <= 100);
            all.extend(page.message_ids);
            cursor = page.next_ordinal;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(all.len(), 451);
        assert_eq!(all.first().map(String::as_str), Some("msg-0000"));
        assert_eq!(all.last().map(String::as_str), Some("msg-0450"));
        assert!(!all.contains(&"new-after-capture".to_string()));
        assert_eq!(
            store
                .message_selection_page(&snapshot.token, None, 0)
                .unwrap_err()
                .to_string(),
            "serialization failure: selection page limit must be 1..=200"
        );
        store
            .release_message_selection_snapshot(&snapshot.token)
            .unwrap();
        assert!(matches!(
            store.message_selection_page(&snapshot.token, None, 1),
            Err(StorageError::NotFound)
        ));
    }

    #[test]
    fn reopened_account_store_rejects_prior_runtime_token() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("account.db");
        let key = SqlCipherKey::new("selection-test-key").unwrap();
        let first = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        insert(&first, "group-a", "message", 1, 9, false);
        let old = first.create_message_selection_snapshot("group-a").unwrap();
        first.close().unwrap();

        let second = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(matches!(
            second.message_selection_page(&old.token, None, 1),
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            second.release_message_selection_snapshot(&old.token),
            Err(StorageError::NotFound)
        ));
        let new = second.create_message_selection_snapshot("group-a").unwrap();
        assert_eq!(new.count, 1);
        assert_ne!(old.token, new.token);
    }

    #[test]
    fn snapshot_excludes_invalid_pending_blocked_and_other_groups() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        for (index, id) in [
            "text", "media", "invalid", "pending", "blocked", "system", "deleted",
        ]
        .into_iter()
        .enumerate()
        {
            insert(
                &store,
                "group-a",
                id,
                index as i64,
                if id == "system" { 1210 } else { 9 },
                id == "deleted",
            );
        }
        insert(&store, "group-b", "other", 9, 9, false);
        store.lock().unwrap().execute_batch(
            "UPDATE message_timeline SET media_json='{}' WHERE message_id_hex='media';
             UPDATE message_timeline SET invalidation_status='LosingBranch' WHERE message_id_hex='invalid';
             UPDATE message_timeline SET direction='sent', source_message_id_hex=NULL WHERE message_id_hex='pending';
             UPDATE message_timeline SET sender='bob' WHERE message_id_hex='blocked';
             INSERT INTO user_blocks(public_key,is_private,created_at_ms) VALUES('bob',0,1);",
        ).unwrap();
        let snapshot = store.create_message_selection_snapshot("group-a").unwrap();
        assert_eq!(snapshot.count, 2);
        let page = store
            .message_selection_page(&snapshot.token, None, 200)
            .unwrap();
        assert_eq!(page.message_ids, ["text", "media"]);
        assert_eq!(page.next_ordinal, None);
        let empty = store.create_message_selection_snapshot("group-c").unwrap();
        assert_eq!(empty.count, 0);
        assert!(
            store
                .message_selection_page(&empty.token, None, 1)
                .unwrap()
                .message_ids
                .is_empty()
        );
    }
}
