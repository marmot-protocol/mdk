//! One immutable account read for a conversation window. Engine lifecycle and
//! directory identities have separate owners; neither is guessed by storage.
use super::*;
use crate::{ChatPresentationInput, SelectedMessageDraft};

/// Persisted inputs captured together. The timeline has a single owner in
/// `page`; provenance cannot be replaced independently of its rows.
#[derive(Clone)]
pub struct ConversationAccountSnapshot {
    pub page: ConversationPresentationPage,
    pub presentation_input: ChatPresentationInput,
    pub read_state: ConversationOpenReadState,
    pub pending_confirmation: bool,
    pub anchor: ConversationOpenAnchorOutcome,
    pub anchors: Vec<ConversationAnchor>,
    pub draft: SelectedMessageDraft,
    pub archived: bool,
    pub leave_request_pending: bool,
    /// Persisted admin projection; app selection derives the local scalar role.
    pub admin_keys_hex: String,
}

impl std::fmt::Debug for ConversationAccountSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationAccountSnapshot")
            .field("rows", &self.page.page().messages.len())
            .field("anchor", &self.anchor)
            .finish_non_exhaustive()
    }
}

impl SqliteAccountStorage {
    /// Read history, provenance, presentation inputs, composer descriptors and
    /// local controls under one deferred read snapshot. No attachment bytes,
    /// full group record, roster, network, preparation or read acknowledgement.
    /// An existing caller-owned transaction remains caller-owned.
    pub fn conversation_account_snapshot(
        &self,
        group: &str,
        query: ConversationWindowQuery,
    ) -> Result<ConversationAccountSnapshot, ConversationOpenError> {
        opening::validate_window_query(&query)?;
        let group_bytes = hex::decode(group)
            .map_err(|_| StorageError::Serialization("invalid conversation group id".into()))?;
        let conn = self.lock()?;
        let owned = if conn.is_autocommit() {
            Some(conn.unchecked_transaction().storage()?)
        } else {
            None
        };
        let snapshot = capture_tx(&conn, group, &group_bytes, query)?;
        if let Some(tx) = owned {
            tx.commit().storage()?;
        }
        Ok(snapshot)
    }
}

fn capture_tx(
    conn: &Connection,
    group: &str,
    group_bytes: &[u8],
    query: ConversationWindowQuery,
) -> Result<ConversationAccountSnapshot, ConversationOpenError> {
    let opening = opening::opening_tx(conn, group, query.opening, query.before_anchor)?;
    let presentation_input = crate::chat_presentation::presentation_input_tx(conn, group)?
        .ok_or(StorageError::NotFound)?;
    let draft = crate::message_drafts::revisioned::selected_tx(conn, group)?;
    let (archived, admin_keys_hex, leave_request_pending) = conn
        .query_row_cached(
            "SELECT archived, admin_keys_hex,
             EXISTS(SELECT 1 FROM cgka_leave_requests WHERE group_id = ?2)
         FROM account_groups WHERE group_id_hex = ?1",
            params![group, group_bytes],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .storage()?;
    Ok(ConversationAccountSnapshot {
        page: presentation::presentation_page_tx(conn, opening.page)?,
        presentation_input,
        read_state: opening.read_state,
        pending_confirmation: opening.pending_confirmation,
        anchor: opening.anchor,
        anchors: opening.anchors,
        draft,
        archived,
        leave_request_pending,
        admin_keys_hex,
    })
}
