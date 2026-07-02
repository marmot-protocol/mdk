//! Durable chat-list and chat read-state commands.

use crate::conversions::{ChatListRowFfi, group_id_from_hex};
use crate::errors::MarmotKitError;
use crate::{Marmot, optional_message_id_hex};

#[uniffi::export]
impl Marmot {
    /// Durable chat-list rows for fast app launch. Rows include the group
    /// title/avatar, last kind-9 preview, unread count, and read anchors.
    pub fn chat_list(
        &self,
        account_ref: String,
        include_archived: bool,
    ) -> Result<Vec<ChatListRowFfi>, MarmotKitError> {
        let rows = self.runtime.chat_list(&account_ref, include_archived)?;
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "chat_list_conversion",
            method = "chat_list"
        )
        .entered();
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Establish the unread baseline the first time a user opens a group.
    /// Existing kind-9 history remains read; later remote kind-9 messages count
    /// until marked visible via `mark_timeline_message_read`.
    pub fn initialize_chat_read_state(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        Ok(self
            .runtime
            .initialize_chat_read_state(&account_ref, &group_id_hex)?
            .map(Into::into))
    }

    /// Mark a kind-9 timeline message visible/read. Own kind-9 messages can
    /// advance the marker too, which clears any earlier unread messages.
    pub fn mark_timeline_message_read(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id_hex: String,
    ) -> Result<Option<ChatListRowFfi>, MarmotKitError> {
        let group_id_hex = hex::encode(group_id_from_hex(&group_id_hex)?.as_slice());
        let message_id_hex = optional_message_id_hex(Some(message_id_hex))?.ok_or_else(|| {
            MarmotKitError::InvalidHex {
                details: "message id is required".to_owned(),
            }
        })?;
        Ok(self
            .runtime
            .mark_timeline_message_read(&account_ref, &group_id_hex, &message_id_hex)?
            .map(Into::into))
    }
}
