//! Select all for the native chat-list views: every ID in a view, beyond any
//! window, plus remove-only revalidation before a bulk action.
use super::{MarmotAppRuntime, blocking_app_task};
use crate::AppError;
use storage_sqlite::{ChatListSelectionError, ChatListView, SqliteAppStorage};

impl MarmotAppRuntime {
    /// Every chat ID in `view`, in display order; the count is the length. The
    /// set is complete or the call fails: while base rows are still being
    /// prepared it returns `ChatPresentationNotReady`, and the caller retries.
    pub async fn chat_list_ids(
        &self,
        account_ref: &str,
        view: ChatListView,
    ) -> Result<Vec<String>, AppError> {
        self.read_selection(account_ref, move |storage| storage.chat_list_ids(view))
            .await
    }

    /// The subset of `group_ids` still in `view`, in the caller's order with
    /// duplicates dropped. IDs are normalized to lowercase hex; a malformed ID
    /// fails the call. Never adds chats that joined the view since. Call it
    /// right before a bulk action; each per-chat command still checks its own
    /// preconditions.
    pub async fn revalidate_chat_list_ids(
        &self,
        account_ref: &str,
        view: ChatListView,
        group_ids: Vec<String>,
    ) -> Result<Vec<String>, AppError> {
        let group_ids = group_ids
            .iter()
            .map(|id| crate::ids::normalize_group_id_hex_app(id))
            .collect::<Result<Vec<_>, _>>()?;
        self.read_selection(account_ref, move |storage| {
            storage.revalidate_chat_list_ids(view, &group_ids)
        })
        .await
    }

    async fn read_selection(
        &self,
        account_ref: &str,
        read: impl FnOnce(&SqliteAppStorage) -> Result<Vec<String>, ChatListSelectionError>
        + Send
        + 'static,
    ) -> Result<Vec<String>, AppError> {
        self.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account_ref)?;
        let app = self.accounts.app.clone();
        blocking_app_task(move || {
            // The label may have been reused by another identity since it was
            // resolved; never read the replacement account's chats.
            if app.account_home().account(&account.label)?.account_id_hex != account.account_id_hex
            {
                return Err(marmot_account::AccountHomeError::AccountIdMismatch.into());
            }
            let storage = app.account_storage(&account.label)?.app_storage();
            // Legacy/imported accounts can lack base rows. Repair one bounded
            // batch here, as the window does; the rest is "not ready".
            crate::chat_presentation::maintenance::prepare_base_rows(
                &storage,
                &account.account_id_hex,
            )?;
            read(&storage).map_err(|error| match error {
                ChatListSelectionError::ProjectionNotReady => AppError::ChatPresentationNotReady,
                ChatListSelectionError::Storage(error) => AppError::Storage(error),
            })
        })
        .await
    }
}
