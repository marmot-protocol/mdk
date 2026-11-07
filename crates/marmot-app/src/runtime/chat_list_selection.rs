//! Select all for chat-list queries: every ID a query matches, beyond any
//! window, plus remove-only revalidation before a bulk action.
use super::{MarmotAppRuntime, blocking_app_task};
use crate::AppError;
use storage_sqlite::{ChatListSelectionError, ChatListViewQuery, SqliteAppStorage};

/// Check a query's bounds and normalize its group IDs to lowercase hex before
/// any read. A malformed ID fails like any other host-supplied group ID.
pub(super) fn prepare_query(
    query: impl Into<ChatListViewQuery>,
) -> Result<ChatListViewQuery, AppError> {
    let mut query = query.into();
    query.validate().map_err(AppError::InvalidChatListQuery)?;
    if let Some(filter) = query.filter.as_mut() {
        for ids in filter.group_id_lists_mut() {
            for id in ids.iter_mut() {
                *id = crate::ids::normalize_group_id_hex_app(id)?;
            }
        }
    }
    Ok(query)
}

impl MarmotAppRuntime {
    /// Every chat ID `query` matches, in display order; the count is the length.
    /// A fixed view (`ChatListView`) is a query without a filter. The window
    /// pages through the same compiled query, so list, count and selection agree.
    /// The set is complete or the call fails: while base rows are still being
    /// prepared, for a `Text` filter while any chat in the view still has
    /// presentation pending, or for a `MessageText` filter while retained
    /// deletions and edits are still being backfilled into the timeline, it
    /// returns `ChatPresentationNotReady`, and the caller retries. Unlike a
    /// window, this accepts `MessageText`, whose cost grows with history.
    pub async fn chat_list_ids(
        &self,
        account_ref: &str,
        query: impl Into<ChatListViewQuery>,
    ) -> Result<Vec<String>, AppError> {
        let query = prepare_query(query)?;
        let search_view = query.references_text().then_some(query.view);
        self.read_selection(account_ref, search_view, move |storage, now_ms| {
            storage.chat_list_ids(query, now_ms)
        })
        .await
    }

    /// The subset of `group_ids` still matching `query`, in the caller's order
    /// with duplicates dropped. IDs are normalized to lowercase hex; a malformed
    /// ID fails the call. Never adds chats that matched since. Call it right
    /// before a bulk action; each per-chat command still checks its own
    /// preconditions.
    pub async fn revalidate_chat_list_ids(
        &self,
        account_ref: &str,
        query: impl Into<ChatListViewQuery>,
        group_ids: Vec<String>,
    ) -> Result<Vec<String>, AppError> {
        let query = prepare_query(query)?;
        let group_ids = group_ids
            .iter()
            .map(|id| crate::ids::normalize_group_id_hex_app(id))
            .collect::<Result<Vec<_>, _>>()?;
        let search_view = query.references_text().then_some(query.view);
        self.read_selection(account_ref, search_view, move |storage, now_ms| {
            storage.revalidate_chat_list_ids(query, &group_ids, now_ms)
        })
        .await
    }

    /// `search_view` is the view of a query with a `Text` leaf, whose pending
    /// presentation gets one bounded batch of preparation before the read.
    async fn read_selection(
        &self,
        account_ref: &str,
        search_view: Option<storage_sqlite::ChatListView>,
        read: impl FnOnce(&SqliteAppStorage, i64) -> Result<Vec<String>, ChatListSelectionError>
        + Send
        + 'static,
    ) -> Result<Vec<String>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        let now_ms = app.chat_list_now_ms();
        blocking_app_task(move || {
            // The label may have been reused by another identity since it was
            // resolved; never read the replacement account's chats.
            if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex
            {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            let account_storage = app.account_storage(&account.label)?;
            let storage = account_storage.app_storage();
            // Legacy/imported accounts can lack base rows. Repair one bounded
            // batch here, as the window does; the rest is "not ready".
            crate::chat_presentation::maintenance::prepare_base_rows(
                &storage,
                &account.account_id_hex,
            )?;
            if let Some(view) = search_view {
                crate::chat_presentation::maintenance::prepare_search_batch(
                    &app,
                    &account.label,
                    &account_storage,
                    &account.account_id_hex,
                    view,
                )?;
            }
            read(&storage, now_ms).map_err(|error| match error {
                ChatListSelectionError::ProjectionNotReady => AppError::ChatPresentationNotReady,
                ChatListSelectionError::InvalidQuery(error) => {
                    AppError::InvalidChatListQuery(error)
                }
                ChatListSelectionError::Storage(error) => AppError::Storage(error),
            })
        })
        .await
    }
}
