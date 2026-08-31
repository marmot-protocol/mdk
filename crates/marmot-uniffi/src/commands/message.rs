//! Message history read plus send/react/reply/edit/delete commands.

use marmot_app::AppMessageQuery;

use crate::Marmot;
use crate::conversions::{
    AppMessageRecordFfi, RetentionSweepReportFfi, SecureDeleteExpiredResultFfi, SendSummaryFfi,
    group_id_from_hex,
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
    /// delivered. Re-sending the same text mints a fresh commit, so it is the
    /// wrong tool here: it either duplicates the bubble or — inside the same
    /// second as the original, where the NIP-01 id collides — silently reuses
    /// the same timeline row. This drives the existing pending commit to the
    /// relays via convergence instead, so the original timeline row flips to
    /// delivered (`source_message_id_hex == Some(..)`) on success and no new
    /// event is created.
    ///
    /// (A resend after a send that *failed* is still safe and still supported:
    /// the send path clears that row's `local_publish_failed` retraction before
    /// re-recording it. This call is for sends that are pending, not failed.) Returns the delivery summary; `published == 0` means
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

    /// Remove all of this account's active reactions from `target_message_id`.
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

    /// Run the engine-owned disappearing-message sweep for one account using
    /// the supplied Unix wall-clock time in milliseconds. Each group reports
    /// pruning, a fail-closed deferral, or a privacy-safe failure category.
    pub async fn sweep_expired_retention(
        &self,
        account_ref: String,
        now_ms: u64,
    ) -> Result<RetentionSweepReportFfi, MarmotKitError> {
        Ok(self
            .runtime
            .sweep_expired_retention(&account_ref, now_ms)
            .await?
            .into())
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

    /// Send an app-defined event with an arbitrary non-reserved kind. `tags`
    /// and `content` pass through verbatim; kinds MDK owns (chat, reaction,
    /// edit, delete, agent, group system, push token) are rejected so an app
    /// cannot forge protocol events. Custom events appear in the timeline as
    /// standalone rows and can be fetched via [`Marmot::messages`] with a
    /// `kinds` filter.
    pub async fn send_custom_event(
        &self,
        account_ref: String,
        group_id_hex: String,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<SendSummaryFfi, MarmotKitError> {
        let group_id = group_id_from_hex(&group_id_hex)?;
        let summary = self
            .runtime
            .send_custom_event(&account_ref, &group_id, kind, tags, content)
            .await?;
        Ok(summary.into())
    }

    /// Initial history fetch for a group (or, when `group_id_hex` is None,
    /// the account-wide tail). Used to populate the conversation view before
    /// the subscription stream takes over.
    ///
    /// `kinds` restricts to the listed inner app-event kinds (e.g. an
    /// app-defined custom kind); `None` or an empty list returns all kinds.
    pub fn messages(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: Option<u32>,
        kinds: Option<Vec<u64>>,
    ) -> Result<Vec<AppMessageRecordFfi>, MarmotKitError> {
        let query = AppMessageQuery {
            group_id_hex: optional_group_id_hex(group_id_hex)?,
            kinds: kinds.filter(|kinds| !kinds.is_empty()),
            limit: limit.map(|n| n as usize),
        };
        let records = self.runtime.messages_with_query(&account_ref, query)?;
        Ok(records.into_iter().map(Into::into).collect())
    }
}
