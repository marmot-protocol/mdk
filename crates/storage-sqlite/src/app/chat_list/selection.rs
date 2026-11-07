//! Complete chat-list ID sets, independent of the live display window.
use super::pages;
use super::query::{ChatListQueryError, ChatListViewQuery};
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::{Connection, params_from_iter};
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum ChatListSelectionError {
    /// Base rows, or for a `Text` query the view's presentation, are still
    /// being prepared. Nothing partial was returned; retry later.
    #[error("chat-list base projection is not ready")]
    ProjectionNotReady,
    #[error(transparent)]
    InvalidQuery(#[from] ChatListQueryError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAppStorage {
    /// Every ID matching `query`, in display order, read in one transaction with
    /// the same compiled condition the live window pages through, before any
    /// display paging. The count is the length. Work and memory grow with the
    /// view's chats, never with profile or history size. Pending base-row work,
    /// or for a query with a `Text` leaf pending presentation anywhere in the
    /// view, returns `ProjectionNotReady`, never a partial set. `now_ms` (Unix ms) is
    /// the time a `Muted` leaf tests mute expiry against.
    pub fn chat_list_ids(
        &self,
        query: impl Into<ChatListViewQuery>,
        now_ms: i64,
    ) -> Result<Vec<String>, ChatListSelectionError> {
        let query = query.into();
        self.connection
            .with_deferred_read(|conn| eligible_ids(conn, &query, now_ms))
    }

    /// The subset of `group_ids` still matching `query`, in the caller's order with
    /// duplicates dropped. It only removes: chats that joined the view since the
    /// caller read it are never added. This read does not authorize a later write;
    /// each per-chat command still checks its own preconditions.
    pub fn revalidate_chat_list_ids(
        &self,
        query: impl Into<ChatListViewQuery>,
        group_ids: &[String],
        now_ms: i64,
    ) -> Result<Vec<String>, ChatListSelectionError> {
        let query = query.into();
        self.connection.with_deferred_read(|conn| {
            let mut eligible: HashSet<String> =
                eligible_ids(conn, &query, now_ms)?.into_iter().collect();
            Ok(group_ids
                .iter()
                .filter(|id| eligible.remove(id.as_str()))
                .cloned()
                .collect())
        })
    }
}

fn eligible_ids(
    conn: &Connection,
    query: &ChatListViewQuery,
    now_ms: i64,
) -> Result<Vec<String>, ChatListSelectionError> {
    let compiled = query.compile(now_ms)?;
    let missing_base: bool = conn
        .query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work)",
            [],
            |row| row.get(0),
        )
        .storage()?;
    if missing_base {
        return Err(ChatListSelectionError::ProjectionNotReady);
    }
    // Search text is written with presentation; a pending row could match.
    if query.references_text()
        && !super::query::pending_search_text(conn, query.view, 1)
            .storage()?
            .is_empty()
    {
        return Err(ChatListSelectionError::ProjectionNotReady);
    }
    let sql = format!(
        "SELECT group_id_hex FROM chat_list_rows INDEXED BY {} WHERE {} ORDER BY {}",
        compiled.view.index(),
        compiled.predicate,
        pages::KEY_COLUMNS,
    );
    let mut statement = conn.prepare_cached(&sql).storage()?;
    Ok(statement
        .query_map(params_from_iter(&compiled.params), |row| row.get(0))
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?)
}

#[cfg(test)]
mod tests;
