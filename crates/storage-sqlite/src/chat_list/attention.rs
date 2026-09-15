//! Account badges combine Unread-list attention with active pending invitations.
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
    /// Active pending invitations and accepted manual reminders with no unread messages.
    /// Each invite contributes one, regardless of retained messages or manual intent.
    /// `unread_count + attention_only_conversations` is the application badge.
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
        // Pin both partial indexes so quiet/archived/Left rows cannot turn this into
        // a full-list scan. The branches are disjoint: Unread suppresses invitations.
        // Invites add one attention item, never their retained message/mention counts.
        conn.query_row_cached(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work),
                COALESCE(SUM(unread_count), 0),
                COALESCE(SUM(unread_mention_count), 0), COUNT(*),
                COUNT(CASE WHEN unread_count = 0 THEN 1 END)
                FROM (
                    SELECT unread_count, unread_mention_count
                    FROM chat_list_rows INDEXED BY idx_chat_list_unread_page WHERE {}
                    UNION ALL
                    SELECT 0, 0 FROM chat_list_rows INDEXED BY idx_chat_list_invite_attention
                    WHERE list_scope = 0 AND list_pending_invite = 1 AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)
                )",
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
        .and_then(
            |(missing, unread, mentions, conversations, attention_only)| {
                Ok((
                    missing,
                    AccountAttentionTotal {
                        unread_count: i64_to_u64(unread)?,
                        unread_mention_count: i64_to_u64(mentions)?,
                        unread_conversations: i64_to_u64(conversations)?,
                        attention_only_conversations: i64_to_u64(attention_only)?,
                    },
                ))
            },
        )
    }
}
