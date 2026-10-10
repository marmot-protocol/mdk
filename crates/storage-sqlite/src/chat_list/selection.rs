//! Complete, compact selection intent, independent of the live display window.
use super::{ChatFolderSelectionRule, ChatListView, pages};
use crate::connection::{CachedSql, ConnectionLifetime};
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::Connection;
use std::collections::HashSet;

/// Frozen account/view-local IDs only; no presentation, roster or message bodies.
/// A snapshot is transient and must be revalidated before each batch action.
#[derive(Clone)]
pub struct ChatListSelectionSnapshot {
    lifetime: ConnectionLifetime,
    store_epoch: Vec<u8>,
    scope: SelectionScope,
    group_ids: Vec<String>,
}

impl std::fmt::Debug for ChatListSelectionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListSelectionSnapshot")
            .field("scope", &self.scope)
            .field("count", &self.group_ids.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChatListSelectionError {
    #[error("selection page requires 1 to 200 IDs and an offset within the selection")]
    InvalidPage,
    #[error("selection belongs to a different or reopened account store")]
    StaleSelection,
    #[error("chat-list base projection is not ready")]
    ProjectionNotReady,
    #[error("unsupported or invalid bounded chat-folder rule")]
    InvalidFilter,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

#[derive(Clone, Debug)]
pub(super) enum SelectionScope {
    View(ChatListView),
    Folder(ChatFolderSelectionRule),
}
impl SelectionScope {
    fn eligible_ids(&self, conn: &Connection) -> Result<Vec<String>, ChatListSelectionError> {
        match self {
            Self::View(view) => eligible_ids(conn, *view),
            Self::Folder(rule) => {
                ensure_base_ready(conn)?;
                rule.eligible_ids(conn)
            }
        }
    }
}

impl SqliteAccountStorage {
    /// Capture every eligible ID in one read transaction, using the same indexed
    /// predicate and order as the native view, before any presentation pagination.
    /// Work and memory are proportional to eligible IDs, never to profile/history size.
    pub fn chat_list_selection_snapshot(
        &self,
        view: ChatListView,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        self.connection.with_deferred_read(|conn| {
            Ok(ChatListSelectionSnapshot {
                lifetime: self.connection.lifetime(),
                store_epoch: store_epoch(conn)?,
                scope: SelectionScope::View(view),
                group_ids: eligible_ids(conn, view)?,
            })
        })
    }

    /// Freeze all matching IDs in one transaction. Rule edits cannot retarget
    /// this intent; capture a new selection instead. Required missing projection
    /// inputs return not-ready, never an empty or partially successful result.
    pub fn chat_folder_selection_snapshot(
        &self,
        rule: ChatFolderSelectionRule,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        rule.validate()?;
        self.connection.with_deferred_read(|conn| {
            let scope = SelectionScope::Folder(rule);
            Ok(ChatListSelectionSnapshot {
                lifetime: self.connection.lifetime(),
                store_epoch: store_epoch(conn)?,
                group_ids: scope.eligible_ids(conn)?,
                scope,
            })
        })
    }

    /// The complete frozen count; closing/reopening the store invalidates it.
    pub fn chat_list_selection_count(
        &self,
        selection: &ChatListSelectionSnapshot,
    ) -> Result<usize, ChatListSelectionError> {
        self.check_selection_lifetime(selection)?;
        self.connection.with_deferred_read(|conn| {
            check_epoch(conn, selection)?;
            Ok(selection.group_ids.len())
        })
    }

    /// Read at most 200 frozen IDs. Activity reorder, window eviction and new
    /// arrivals do not change the captured order or silently expand the selection.
    pub fn chat_list_selection_page(
        &self,
        selection: &ChatListSelectionSnapshot,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<String>, ChatListSelectionError> {
        if !(1..=200).contains(&limit) || offset > selection.group_ids.len() {
            return Err(ChatListSelectionError::InvalidPage);
        }
        self.check_selection_lifetime(selection)?;
        self.connection.with_deferred_read(|conn| {
            check_epoch(conn, selection)?;
            let end = offset.saturating_add(limit).min(selection.group_ids.len());
            Ok(selection.group_ids[offset..end].to_vec())
        })
    }

    /// Remove IDs no longer eligible in this native view. Never add late arrivals
    /// or reconstruct eligibility from client rows. Capture and validation each
    /// use one consistent transaction; mutations still validate their own preconditions.
    pub fn revalidate_chat_list_selection(
        &self,
        selection: &ChatListSelectionSnapshot,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        self.check_selection_lifetime(selection)?;
        self.connection.with_deferred_read(|conn| {
            check_epoch(conn, selection)?;
            let eligible: HashSet<_> = selection.scope.eligible_ids(conn)?.into_iter().collect();
            Ok(ChatListSelectionSnapshot {
                lifetime: selection.lifetime.clone(),
                store_epoch: selection.store_epoch.clone(),
                scope: selection.scope.clone(),
                group_ids: selection
                    .group_ids
                    .iter()
                    .filter(|id| eligible.contains(*id))
                    .cloned()
                    .collect(),
            })
        })
    }

    /// Explicit deselection only removes an existing frozen ID. It never
    /// consults display rows or admits IDs supplied by a different account.
    pub fn deselect_chat_list_selection_id(
        &self,
        selection: &mut ChatListSelectionSnapshot,
        group_id_hex: &str,
    ) -> Result<bool, ChatListSelectionError> {
        self.check_selection_lifetime(selection)?;
        self.connection
            .with_deferred_read(|conn| check_epoch(conn, selection))?;
        let before = selection.group_ids.len();
        selection.group_ids.retain(|id| id != group_id_hex);
        Ok(selection.group_ids.len() != before)
    }

    fn check_selection_lifetime(
        &self,
        selection: &ChatListSelectionSnapshot,
    ) -> Result<(), ChatListSelectionError> {
        if !selection.lifetime.matches(&self.connection) {
            return Err(ChatListSelectionError::StaleSelection);
        }
        Ok(())
    }
}

fn store_epoch(conn: &Connection) -> Result<Vec<u8>, ChatListSelectionError> {
    Ok(conn
        .query_row_cached(
            "SELECT store_epoch FROM chat_presentation_meta WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .storage()?)
}

fn check_epoch(
    conn: &Connection,
    selection: &ChatListSelectionSnapshot,
) -> Result<(), ChatListSelectionError> {
    if store_epoch(conn)? != selection.store_epoch {
        return Err(ChatListSelectionError::StaleSelection);
    }
    Ok(())
}

fn eligible_ids(
    conn: &Connection,
    view: ChatListView,
) -> Result<Vec<String>, ChatListSelectionError> {
    ensure_base_ready(conn)?;
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

fn ensure_base_ready(conn: &Connection) -> Result<(), ChatListSelectionError> {
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
    Ok(())
}

#[cfg(test)]
mod tests;
