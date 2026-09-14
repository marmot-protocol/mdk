//! Account aggregates over the same durable eligibility keys as the Unread list.
use super::ChatListView;
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt, i64_to_u64};
use cgka_traits::storage::{StorageError, StorageResult};

/// Screen-effective counters. No separate counter store, history or roster reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountAttentionTotal {
    pub unread_count: u64,
    pub unread_mention_count: u64,
    pub unread_conversations: u64,
    /// Manual reminders with no unread messages; never fabricates message counts.
    pub attention_only_conversations: u64,
}
impl AccountAttentionTotal {
    pub fn has_unread(&self) -> bool {
        self.unread_conversations > 0
    }
}
impl SqliteAccountStorage {
    /// One statement observes readiness and aggregates at the same SQLite snapshot.
    /// NotFound means missing base rows: the total is unavailable, never zero.
    pub fn account_attention_total(&self) -> StorageResult<AccountAttentionTotal> {
        let (missing, total) = self.account_attention_totals_with_readiness()?;
        if missing {
            Err(StorageError::NotFound)
        } else {
            Ok(total)
        }
    }

    pub(super) fn account_attention_totals_with_readiness(
        &self,
    ) -> StorageResult<(bool, AccountAttentionTotal)> {
        let conn = self.lock()?;
        // Without the index constraint SQLite can prefer the broad Chats index,
        // making even a two-chat unread total scan every quiet conversation.
        conn.query_row_cached(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work),
                COALESCE(SUM(unread_count), 0),
                COALESCE(SUM(unread_mention_count), 0), COUNT(*),
                COUNT(CASE WHEN unread_count = 0 THEN 1 END)
                FROM chat_list_rows INDEXED BY idx_chat_list_unread_page WHERE {}",
                ChatListView::Unread.predicate()
            ),
            [],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .storage()
        .and_then(|(missing, unread, mentions, conversations, manual)| {
            Ok((
                missing,
                AccountAttentionTotal {
                    unread_count: i64_to_u64(unread)?,
                    unread_mention_count: i64_to_u64(mentions)?,
                    unread_conversations: i64_to_u64(conversations)?,
                    attention_only_conversations: i64_to_u64(manual)?,
                },
            ))
        })
    }
}
