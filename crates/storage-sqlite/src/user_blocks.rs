//! Account-private NIP-51 state. Never stored in the shared directory database.
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageResult;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedUser {
    pub public_key: String,
    pub is_private: bool,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockListSnapshot {
    pub revision: u64,
    pub users: Vec<BlockedUser>,
}

#[derive(Clone, Default)]
pub struct StoredBlockList {
    pub event_id: String,
    pub event_created_at: u64,
    pub public_tags: Vec<Vec<String>>,
    pub private_tags: Vec<Vec<String>>,
}

#[derive(Clone)]
pub struct PendingBlockPublication {
    pub target: String,
    pub blocked: bool,
    pub event_json: String,
}

impl SqliteAccountStorage {
    /// Cheap policy probes for live subscriptions; never materialize the list.
    pub fn has_blocked_users(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row("SELECT EXISTS(SELECT 1 FROM user_blocks)", [], |row| {
                row.get(0)
            })
            .storage()
    }

    pub fn block_list_revision(&self) -> StorageResult<u64> {
        let revision: i64 = self
            .lock()?
            .query_row("SELECT revision FROM user_block_list", [], |row| row.get(0))
            .storage()?;
        crate::i64_to_u64(revision)
    }

    pub fn block_list_snapshot(&self) -> StorageResult<BlockListSnapshot> {
        let conn = self.lock()?;
        let revision: i64 = conn
            .query_row("SELECT revision FROM user_block_list", [], |r| r.get(0))
            .storage()?;
        let mut stmt = conn.prepare("SELECT public_key, is_private, created_at_ms FROM user_blocks ORDER BY created_at_ms DESC, public_key").storage()?;
        let users = stmt
            .query_map([], |r| {
                Ok(BlockedUser {
                    public_key: r.get(0)?,
                    is_private: r.get(1)?,
                    created_at_ms: r.get(2)?,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        Ok(BlockListSnapshot {
            revision: crate::i64_to_u64(revision)?,
            users,
        })
    }

    pub fn direct_conversation_has_blocked_user(&self, group_id_hex: &str) -> StorageResult<bool> {
        self.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM direct_conversation_members WHERE group_id_hex=?1 AND member_id_hex IN (SELECT public_key FROM user_blocks))",[group_id_hex],|r|r.get(0)).storage()
    }

    pub fn is_app_author_visible(&self, sender: &str, group_id_hex: &str) -> StorageResult<bool> {
        self.lock()?.query_row("SELECT NOT EXISTS(SELECT 1 FROM user_blocks WHERE public_key=?1) AND NOT EXISTS(SELECT 1 FROM blocked_pending_invites WHERE group_id_hex=?2)",params![sender,group_id_hex],|r|r.get(0)).storage()
    }

    pub fn is_user_blocked(&self, public_key: &str) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM user_blocks WHERE public_key=?1)",
                [public_key],
                |r| r.get(0),
            )
            .storage()
    }

    pub fn stored_block_list(&self) -> StorageResult<StoredBlockList> {
        let conn = self.lock()?;
        let (event_id, event_created_at, public, private): (String, i64, String, String) = conn
            .query_row(
                "SELECT event_id,event_created_at,public_tags,private_tags FROM user_block_list",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .storage()?;
        Ok(StoredBlockList {
            event_id,
            event_created_at: crate::i64_to_u64(event_created_at)?,
            public_tags: serde_json::from_str(&public).map_err(json_error)?,
            private_tags: serde_json::from_str(&private).map_err(json_error)?,
        })
    }

    /// NIP-01: newest timestamp wins; lowest event id breaks equal-time ties.
    /// Entries and accepted version become visible in one transaction.
    pub fn adopt_block_list(
        &self,
        list: &StoredBlockList,
        entries: &[(String, bool)],
        now_ms: i64,
        local_account_id: &str,
        mention_classifier: &crate::chat_list::MentionClassifier<'_>,
    ) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let (id, at): (String, i64) = tx
            .query_row(
                "SELECT event_id,event_created_at FROM user_block_list",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .storage()?;
        let at = crate::i64_to_u64(at)?;
        if !id.is_empty()
            && (list.event_created_at < at || (list.event_created_at == at && list.event_id >= id))
        {
            return Ok(false);
        }
        tx.execute_batch("CREATE TEMP TABLE IF NOT EXISTS incoming_user_blocks(public_key TEXT PRIMARY KEY, is_private INTEGER NOT NULL); DELETE FROM incoming_user_blocks;").storage()?;
        for (key, private) in entries {
            tx.execute("INSERT INTO incoming_user_blocks VALUES (?1,?2) ON CONFLICT(public_key) DO UPDATE SET is_private=min(is_private,excluded.is_private)",params![key,private]).storage()?;
        }
        tx.execute("DELETE FROM user_blocks WHERE public_key NOT IN (SELECT public_key FROM incoming_user_blocks)", []).storage()?;
        tx.execute("INSERT INTO user_blocks SELECT public_key,is_private,?1 FROM incoming_user_blocks WHERE true ON CONFLICT(public_key) DO UPDATE SET is_private=excluded.is_private", [now_ms]).storage()?;
        tx.execute("UPDATE user_block_list SET event_id=?1,event_created_at=?2,public_tags=?3,private_tags=?4,revision=revision+1",params![list.event_id,crate::u64_to_i64(list.event_created_at)?,serde_json::to_string(&list.public_tags).map_err(json_error)?,serde_json::to_string(&list.private_tags).map_err(json_error)?]).storage()?;
        tx.execute("DELETE FROM chat_list_unread_ready_groups", [])
            .storage()?;
        crate::chat_list::rebuild_all_chat_list_rows_tx(&tx, local_account_id, mention_classifier)?;
        tx.execute(
            "UPDATE chat_list_navigation_meta SET revision=revision+1",
            [],
        )
        .storage()?;
        tx.commit().storage()?;
        Ok(true)
    }

    /// An authenticated but unreadable replacement must not be overwritten even
    /// if a subsequent complete relay read happens not to return it.
    pub fn record_unreadable_block_list(
        &self,
        event_id: &str,
        created_at: u64,
    ) -> StorageResult<()> {
        self.lock()?.execute("UPDATE user_block_list SET unreadable_event_id=?1,unreadable_event_created_at=?2 WHERE unreadable_event_id='' OR unreadable_event_created_at < ?2 OR (unreadable_event_created_at=?2 AND unreadable_event_id > ?1)",params![event_id,crate::u64_to_i64(created_at)?]).storage()?;
        Ok(())
    }

    pub fn block_list_has_unreadable_replacement(&self) -> StorageResult<bool> {
        self.lock()?.query_row("SELECT unreadable_event_id!='' AND (event_id='' OR unreadable_event_created_at > event_created_at OR (unreadable_event_created_at=event_created_at AND unreadable_event_id < event_id)) FROM user_block_list",[],|r|r.get(0)).storage()
    }

    pub fn pending_block_publication(&self) -> StorageResult<Option<PendingBlockPublication>> {
        self.lock()?
            .query_row(
                "SELECT target,blocked,event_json FROM user_block_publication",
                [],
                |r| {
                    Ok(PendingBlockPublication {
                        target: r.get(0)?,
                        blocked: r.get(1)?,
                        event_json: r.get(2)?,
                    })
                },
            )
            .optional()
            .storage()
    }
    pub fn stage_block_publication(&self, pending: &PendingBlockPublication) -> StorageResult<()> {
        self.lock()?.execute("INSERT INTO user_block_publication VALUES (1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET target=excluded.target,blocked=excluded.blocked,event_json=excluded.event_json",params![pending.target,pending.blocked,pending.event_json]).storage()?;
        Ok(())
    }
    pub fn clear_block_publication(&self) -> StorageResult<()> {
        self.lock()?
            .execute("DELETE FROM user_block_publication", [])
            .storage()?;
        Ok(())
    }
    /// Persist suppression when notification generation itself observes a block,
    /// including events received before the block was adopted.
    pub fn suppress_blocked_notification(
        &self,
        sender: &str,
        group_id: &str,
        message_id: &str,
    ) -> StorageResult<bool> {
        let conn = self.lock()?;
        conn.execute("INSERT OR IGNORE INTO blocked_notification_suppressions SELECT ?1,?2 WHERE EXISTS(SELECT 1 FROM user_blocks WHERE public_key=?3)",params![group_id,message_id,sender]).storage()?;
        conn.query_row("SELECT EXISTS(SELECT 1 FROM blocked_notification_suppressions WHERE group_id=?1 AND message_id=?2)",params![group_id,message_id],|r|r.get(0)).storage()
    }

    pub fn blocked_notification_suppressed(
        &self,
        group_id: &str,
        message_id: &str,
    ) -> StorageResult<bool> {
        self.lock()?.query_row("SELECT EXISTS(SELECT 1 FROM blocked_notification_suppressions WHERE group_id=?1 AND message_id=?2)",params![group_id,message_id],|r|r.get(0)).storage()
    }
    pub fn dismiss_blocked_welcome(&self, message_id: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT OR IGNORE INTO blocked_welcome_dismissals VALUES (?1)",
                [message_id],
            )
            .storage()?;
        Ok(())
    }
    pub fn is_blocked_welcome_dismissed(&self, message_id: &str) -> StorageResult<bool> {
        self.lock()?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blocked_welcome_dismissals WHERE message_id=?1)",
                [message_id],
                |r| r.get(0),
            )
            .storage()
    }
}

fn json_error(_: serde_json::Error) -> cgka_traits::storage::StorageError {
    cgka_traits::storage::StorageError::Serialization("invalid block-list state".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn adopt(store: &SqliteAccountStorage, id: &str, at: u64, entries: &[(&str, bool)]) -> bool {
        store
            .adopt_block_list(
                &StoredBlockList {
                    event_id: id.into(),
                    event_created_at: at,
                    ..Default::default()
                },
                &entries
                    .iter()
                    .map(|(k, p)| (k.to_string(), *p))
                    .collect::<Vec<_>>(),
                100,
                "local",
                &|_, _| false,
            )
            .unwrap()
    }
    #[test]
    fn user_blocks_versions_isolation_and_public_precedence() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let other = SqliteAccountStorage::in_memory().unwrap();
        assert!(adopt(
            &store,
            "bb",
            10,
            &[("alice", true), ("alice", false), ("bob", true)]
        ));
        let first = store.block_list_snapshot().unwrap();
        assert_eq!(
            first
                .users
                .iter()
                .map(|u| u.public_key.as_str())
                .collect::<Vec<_>>(),
            ["alice", "bob"]
        );
        assert!(!first.users[0].is_private);
        assert!(other.block_list_snapshot().unwrap().users.is_empty());
        assert!(!adopt(&store, "cc", 10, &[]));
        assert!(!adopt(&store, "aa", 9, &[]));
        assert_eq!(store.block_list_snapshot().unwrap(), first);
        assert!(adopt(&store, "aa", 10, &[]));
        assert!(store.block_list_snapshot().unwrap().users.is_empty());
        assert_eq!(
            store.block_list_snapshot().unwrap().revision,
            first.revision + 1
        );
    }
    #[test]
    fn user_blocks_transaction_failure_preserves_list_and_revision() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        adopt(&store, "a", 1, &[("alice", true)]);
        let before = store.block_list_snapshot().unwrap();
        store.lock().unwrap().execute_batch("CREATE TRIGGER fail_block_version BEFORE UPDATE ON user_block_list BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        assert!(
            store
                .adopt_block_list(
                    &StoredBlockList {
                        event_id: "b".into(),
                        event_created_at: 2,
                        ..Default::default()
                    },
                    &[],
                    200,
                    "local",
                    &|_, _| false
                )
                .is_err()
        );
        assert_eq!(store.block_list_snapshot().unwrap(), before);
    }
    #[test]
    fn user_blocks_pending_and_dismissal_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.sqlite");
        let key = crate::SqlCipherKey::new("test block key").unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        adopt(&store, "a", 1, &[("alice", true)]);
        store
            .stage_block_publication(&PendingBlockPublication {
                target: "bob".into(),
                blocked: true,
                event_json: "signed bytes".into(),
            })
            .unwrap();
        store.dismiss_blocked_welcome("welcome").unwrap();
        drop(store);
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        assert!(reopened.is_user_blocked("alice").unwrap());
        assert_eq!(
            reopened
                .pending_block_publication()
                .unwrap()
                .unwrap()
                .event_json,
            "signed bytes"
        );
        assert!(reopened.is_blocked_welcome_dismissed("welcome").unwrap());
    }
}
