//! The app's side of the engine's confirm path: the local submission and the
//! draft a confirmed message came from, consumed in the engine's transaction,
//! and the draft observer the app registers.

use crate::app::message_drafts::revisioned::{DraftAcceptance, accept_submission_tx};
use crate::{SqliteAccountStorage, SqliteAppStorage};
use cgka_traits::storage::StorageResult;

/// Accepts the submission and draft of a queued app message, identified by its
/// payload. Returns whether a draft changed.
pub(crate) fn accept_confirmed_payload(
    conn: &rusqlite::Connection,
    group_hex: &str,
    payload: &[u8],
) -> StorageResult<bool> {
    use sha2::{Digest, Sha256};
    SqliteAppStorage::accept_local_submission_tx(
        conn,
        group_hex,
        "payload_hash",
        &rusqlite::types::Value::Blob(Sha256::digest(payload).to_vec()),
    )?;
    accept_submission_tx(conn, group_hex, DraftAcceptance::Payload(payload))
}

/// Accepts the submission and draft of a fanned-out app message, identified by
/// its app event id. Returns whether a draft changed.
pub(crate) fn accept_confirmed_event(
    conn: &rusqlite::Connection,
    group_hex: &str,
    app_event_id: &str,
) -> StorageResult<bool> {
    SqliteAppStorage::accept_local_submission_tx(
        conn,
        group_hex,
        "app_event_id",
        &rusqlite::types::Value::Text(app_event_id.to_owned()),
    )?;
    accept_submission_tx(conn, group_hex, DraftAcceptance::Event(app_event_id))
}

/// Post-commit wakeup only; consumers reload the durable selected revision.
pub type MessageDraftCommitObserver = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

/// The account handle's slot for the app's draft observer, shared by every clone.
pub(crate) type DraftObserverSlot =
    std::sync::Arc<std::sync::Mutex<Option<MessageDraftCommitObserver>>>;

/// Wakes the app's draft observer after a confirm that changed a draft.
pub(crate) fn notify_draft_committed(storage: &SqliteAccountStorage, group_hex: &str) {
    storage.notify_message_draft_committed(group_hex);
}

impl SqliteAccountStorage {
    /// Install the app owner's coalesced wakeup. The callback must not panic.
    /// Nested writes defer notification until the outer transaction commits.
    #[doc(hidden)]
    pub fn set_message_draft_commit_observer(&self, observer: MessageDraftCommitObserver) {
        *self
            .draft_commit_observer
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(observer);
    }
    pub(crate) fn notify_message_draft_committed(&self, group: &str) {
        let observer = self
            .draft_commit_observer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(observer) = observer {
            let group = group.to_owned();
            self.connection.after_commit(move || observer(&group));
        }
    }
}
