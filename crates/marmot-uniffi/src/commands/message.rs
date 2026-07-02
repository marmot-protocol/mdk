//! Message history read plus send/react/reply/edit/delete commands.

use marmot_app::AppMessageQuery;

use crate::Marmot;
use crate::conversions::{
    AppMessageRecordFfi, SecureDeleteExpiredResultFfi, SendSummaryFfi, group_id_from_hex,
};
use crate::errors::MarmotKitError;
use crate::optional_group_id_hex;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    // -----------------------------------------------------------------------
    // Messaging
    // -----------------------------------------------------------------------

    /// Send a plain UTF-8 text message. Structured payloads (reactions,
    /// replies, deletes, media) go through dedicated methods.
    pub async fn send_text(
        &self,
        account_ref: String,
        group_id_hex: String,
        text: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .send_message(&account_ref, &group_id, text.into_bytes())
            .await?;
        Ok(summary.into())
    }

    /// Re-attempt publishing a group's pending (committed-but-undelivered)
    /// commit(s) without minting a new event.
    ///
    /// An own send commits and projects locally *before* it publishes, so a
    /// message sent while offline (or when the relay was unreachable) lands in
    /// the timeline with `source_message_id_hex == null` — committed, not yet
    /// delivered. Re-sending the same text would mint a fresh commit and event
    /// id, duplicating the bubble. This drives the existing pending commit to
    /// the relays via convergence instead, so the original timeline row flips
    /// to delivered (`source_message_id_hex == Some(..)`) on success and no new
    /// event is created. Returns the delivery summary; `published == 0` means
    /// nothing was pending or publishing is still failing.
    pub async fn retry_group_convergence(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .retry_group_convergence(&account_ref, &group_id)
            .await?;
        Ok(summary.into())
    }

    /// React to `target_message_id` with `emoji` (an "add" reaction).
    pub async fn react_to_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        emoji: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .react_to_message(&account_ref, &group_id, &target_message_id, &emoji)
            .await?;
        Ok(summary.into())
    }

    /// Remove this account's reaction from `target_message_id`.
    pub async fn unreact_from_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .unreact_from_message(&account_ref, &group_id, &target_message_id)
            .await?;
        Ok(summary.into())
    }

    /// Send `text` as a reply that quotes `target_message_id`.
    pub async fn reply_to_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        text: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .reply_to_message(&account_ref, &group_id, &target_message_id, &text)
            .await?;
        Ok(summary.into())
    }

    /// Mark `target_message_id` deleted for the whole group. This is a
    /// tombstone — the original stays in everyone's store; clients render a
    /// "message deleted" placeholder.
    pub async fn delete_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .delete_message(&account_ref, &group_id, &target_message_id)
            .await?;
        Ok(summary.into())
    }

    /// Securely scrub and prune expired disappearing-message plaintext for a
    /// group according to its active retention component. The media hash list
    /// identifies pruned encrypted-media blobs so host apps can purge their own
    /// decrypted-media disk caches keyed by ciphertext hash.
    pub async fn secure_delete_expired(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<SecureDeleteExpiredResultFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let outcome = self
            .runtime
            .secure_delete_expired_plaintext(&account_ref, &group_id)
            .await?;
        Ok(outcome.into())
    }

    /// Edit `target_message_id` by publishing a kind-1009 event that
    /// references it and carries the replacement plaintext in `content`.
    /// Recipients honour the edit only when its authenticated author matches
    /// the target's author; mismatched edits are ignored client-side.
    ///
    /// The chat-list preview deliberately does not bump on an edit — an edit
    /// to a stale message must not reorder a conversation back to the top of
    /// the list. Host apps that aggregate edit history (e.g. an "(edited · N)"
    /// affordance) read the kind-1009 versions back from the timeline
    /// projection and resolve the latest text per target message id.
    pub async fn edit_message(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id: String,
        content: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .edit_message(&account_ref, &group_id, &target_message_id, &content)
            .await?;
        Ok(summary.into())
    }

    /// Initial history fetch for a group (or, when `group_id_hex` is None,
    /// the account-wide tail). Used to populate the conversation view before
    /// the subscription stream takes over.
    pub fn messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
    ) -> Result<Vec<AppMessageRecordFfi>, MarmotKitError> {
        let query = AppMessageQuery {
            group_id_hex: optional_group_id_hex(group_id_hex)?,
            limit: limit.map(|n| n as usize),
        };
        let records = self.runtime.messages_with_query(&account_ref, query)?;
        Ok(records.into_iter().map(Into::into).collect())
    }
}
