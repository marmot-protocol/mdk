//! Complete, compact selection intent, independent of the live display window.
use super::{ChatListView, pages};
use crate::base::connection::{CachedSql, ConnectionLifetime};
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::Connection;
use std::collections::HashSet;

// Storage-only prerequisite: no runtime/FFI folder admission until all required
// native and host context contracts are implemented.
mod context;
pub use context::{
    AcceptedSourceFacts, ContextCaptureError, ContextError, ProjectionFacts, RequiredContext,
    SelectionContextRequest, SelectionPresentation, SelectionSearchPreviewInput,
    SelectionSourceContext, SelectionTitleInputs,
};

/// Existing native view or the active+archived union needed by smart folders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionBaseScope {
    View(ChatListView),
    ActiveAndArchived,
}

/// Frozen account/view-local IDs only; no presentation, roster or message bodies.
/// A snapshot is transient and must be revalidated before each batch action.
#[derive(Clone)]
pub struct ChatListSelectionSnapshot {
    lifetime: ConnectionLifetime,
    store_epoch: Vec<u8>,
    view: ChatListView,
    group_ids: Vec<String>,
}

impl std::fmt::Debug for ChatListSelectionSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListSelectionSnapshot")
            .field("view", &self.view)
            .field("count", &self.group_ids.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChatListSelectionError {
    #[error("selection capture was cancelled")]
    Cancelled,
    #[error("selection page requires 1 to 200 IDs and an offset within the selection")]
    InvalidPage,
    #[error("selection belongs to a different or reopened account store")]
    StaleSelection,
    #[error("chat-list base projection is not ready")]
    ProjectionNotReady,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAppStorage {
    /// Private-integration prerequisite: native scalar/roster context from one
    /// snapshot. Returned IDs are ephemeral and confer no later action authority.
    /// The synchronous readiness checker must perform no SQL or host effects.
    #[expect(
        clippy::too_many_arguments,
        reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
    )]
    pub fn capture_chat_list_context_ids_with_members<R: std::fmt::Debug + std::fmt::Display>(
        &self,
        view: ChatListView,
        request: SelectionContextRequest,
        capture_now_ms: i64,
        cancelled: &impl Fn() -> bool,
        members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
        check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
        matches: &mut impl FnMut(&SelectionSourceContext<'_>) -> bool,
    ) -> Result<Vec<String>, ContextCaptureError<R>> {
        self.connection.with_deferred_read(|conn| {
            context::context_filtered_ids_with_members(
                conn,
                view,
                request,
                capture_now_ms,
                cancelled,
                members,
                check_members,
                matches,
            )
        })
    }

    /// Source-owned synchronous visitor for complete capture composition. A
    /// visitor error invalidates the whole scan; no successful prefix escapes.
    #[expect(
        clippy::too_many_arguments,
        reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
    )]
    pub fn visit_chat_list_context_with_members<R: std::fmt::Debug + std::fmt::Display>(
        &self,
        view: ChatListView,
        request: SelectionContextRequest,
        capture_now_ms: i64,
        cancelled: &impl Fn() -> bool,
        members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
        check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
        visit: &mut impl FnMut(&SelectionSourceContext<'_>) -> Result<bool, ContextError>,
    ) -> Result<Vec<String>, ContextCaptureError<R>> {
        self.connection.with_deferred_read(|conn| {
            context::visit_context_ids_with_members(
                conn,
                view,
                request,
                capture_now_ms,
                cancelled,
                members,
                check_members,
                visit,
            )
        })
    }

    /// The original-ID path is a keyed shrink: it never scans or adds new
    /// arrivals. Callers supply only IDs retained by their native handle.
    #[expect(
        clippy::too_many_arguments,
        reason = "The synchronous transaction boundary keeps source-owned scope, roster readiness and visitor callbacks explicit."
    )]
    pub fn visit_selection_scope_context<R: std::fmt::Debug + std::fmt::Display>(
        &self,
        scope: SelectionBaseScope,
        original_ids: Option<&[String]>,
        request: SelectionContextRequest,
        capture_now_ms: i64,
        cancelled: &impl Fn() -> bool,
        members: Option<(&crate::SelectedMemberKeys, crate::PeerInputs<'_>)>,
        check_members: &mut impl FnMut(&cgka_traits::GroupId) -> Result<(), R>,
        visit: &mut impl FnMut(&SelectionSourceContext<'_>) -> Result<bool, ContextError>,
    ) -> Result<Vec<String>, ContextCaptureError<R>> {
        self.connection.with_deferred_read(|conn| {
            context::visit_scope_context(
                conn,
                scope,
                original_ids,
                request,
                capture_now_ms,
                cancelled,
                members,
                check_members,
                visit,
            )
        })
    }

    /// Capture every eligible ID in one read transaction, using the same indexed
    /// predicate and order as the native view, before any presentation pagination.
    /// Work and memory are proportional to eligible IDs, never to profile/history size.
    pub fn chat_list_selection_snapshot(
        &self,
        view: ChatListView,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        self.chat_list_selection_snapshot_cancellable(view, &|| false)
    }

    /// As above, checking cancellation between ID rows; this does not interrupt a
    /// SQLite step or a wait for the connection. A cancelled capture returns no prefix.
    pub fn chat_list_selection_snapshot_cancellable(
        &self,
        view: ChatListView,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        check_cancelled(cancelled)?;
        self.connection.with_deferred_read(|conn| {
            Ok(ChatListSelectionSnapshot {
                lifetime: self.connection.lifetime(),
                store_epoch: store_epoch(conn)?,
                view,
                group_ids: eligible_ids(conn, view, cancelled)?,
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
        self.revalidate_chat_list_selection_cancellable(selection, &|| false)
    }

    /// Cancellation never installs a partially revalidated selection.
    pub fn revalidate_chat_list_selection_cancellable(
        &self,
        selection: &ChatListSelectionSnapshot,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ChatListSelectionSnapshot, ChatListSelectionError> {
        check_cancelled(cancelled)?;
        self.check_selection_lifetime(selection)?;
        self.connection.with_deferred_read(|conn| {
            check_epoch(conn, selection)?;
            let eligible: HashSet<_> = eligible_ids(conn, selection.view, cancelled)?
                .into_iter()
                .collect();
            let mut group_ids = Vec::new();
            for id in &selection.group_ids {
                check_cancelled(cancelled)?;
                if eligible.contains(id) {
                    group_ids.push(id.clone());
                }
            }
            check_cancelled(cancelled)?;
            Ok(ChatListSelectionSnapshot {
                lifetime: selection.lifetime.clone(),
                store_epoch: selection.store_epoch.clone(),
                view: selection.view,
                group_ids,
            })
        })
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
    cancelled: &impl Fn() -> bool,
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
    let mut ids = Vec::new();
    let mut rows = statement.query([]).storage()?;
    loop {
        check_cancelled(cancelled)?;
        let Some(row) = rows.next().storage()? else {
            break;
        };
        ids.push(row.get(0).storage()?);
    }
    check_cancelled(cancelled)?;
    Ok(ids)
}

fn check_cancelled(cancelled: &impl Fn() -> bool) -> Result<(), ChatListSelectionError> {
    if cancelled() {
        Err(ChatListSelectionError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
