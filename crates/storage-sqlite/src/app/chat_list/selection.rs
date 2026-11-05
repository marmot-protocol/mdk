//! Complete chat-list ID sets, independent of the live display window.
use super::{ChatListView, pages};
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::Connection;
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum ChatListSelectionError {
    #[error("chat-list base projection is not ready")]
    ProjectionNotReady,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAppStorage {
    /// Every ID in a native view, in display order, read in one transaction with
    /// the view's indexed predicate before any display paging. The count is the
    /// length. Work and memory grow with the view's chats, never with profile or
    /// history size. Pending base-row work returns `ProjectionNotReady`, never a
    /// partial set.
    pub fn chat_list_ids(&self, view: ChatListView) -> Result<Vec<String>, ChatListSelectionError> {
        self.connection
            .with_deferred_read(|conn| eligible_ids(conn, view))
    }

    /// The subset of `group_ids` still in `view`, in the caller's order with
    /// duplicates dropped. It only removes: chats that joined the view since the
    /// caller read it are never added. This read does not authorize a later write;
    /// each per-chat command still checks its own preconditions.
    pub fn revalidate_chat_list_ids(
        &self,
        view: ChatListView,
        group_ids: &[String],
    ) -> Result<Vec<String>, ChatListSelectionError> {
        self.connection.with_deferred_read(|conn| {
            let mut eligible: HashSet<String> = eligible_ids(conn, view)?.into_iter().collect();
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
    view: ChatListView,
) -> Result<Vec<String>, ChatListSelectionError> {
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
    let sql = format!(
        "SELECT group_id_hex FROM chat_list_rows INDEXED BY {} WHERE {} ORDER BY {}",
        view.index(),
        view.predicate(),
        pages::KEY_COLUMNS,
    );
    let mut statement = conn.prepare_cached(&sql).storage()?;
    Ok(statement
        .query_map([], |row| row.get(0))
        .storage()?
        .collect::<Result<_, _>>()
        .storage()?)
}

#[cfg(test)]
mod tests;
