use crate::conversions::{
    AttachmentStorageUsageFfi, ChatStorageCursor, ChatStoragePageFfi, RetainedAttachmentsCursor,
    RetainedAttachmentsPageFfi, group_id_from_hex,
};
use crate::{Marmot, MarmotKitError};
use std::sync::Arc;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Account-wide attachment storage across both body layouts: media-store
    /// bytes (a shared file counted once), legacy database bytes, the
    /// retained attachment count, and the database's size and free pages.
    /// Reads no bodies; needs no started runtime.
    pub async fn attachment_storage_usage(
        &self,
        account_ref: String,
    ) -> Result<AttachmentStorageUsageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .attachment_storage_usage(&account_ref)
            .await?
            .into())
    }

    /// Chats by retained attachment bytes, largest first, `limit` (1..=256)
    /// per page. Pass the page's `next_cursor` to continue.
    pub async fn attachment_storage_by_chat(
        &self,
        account_ref: String,
        limit: u32,
        cursor: Option<Arc<ChatStorageCursor>>,
    ) -> Result<ChatStoragePageFfi, MarmotKitError> {
        let chats = self
            .runtime
            .attachment_storage_by_chat(
                &account_ref,
                cursor.map(|cursor| cursor.inner.clone()),
                limit as usize,
            )
            .await?;
        Ok(ChatStoragePageFfi::new(chats, limit as usize))
    }

    /// Retained attachments, largest first, `limit` (1..=256) per page,
    /// optionally within one chat. Pass the page's `next_cursor` to
    /// continue.
    pub async fn largest_retained_attachments(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        limit: u32,
        cursor: Option<Arc<RetainedAttachmentsCursor>>,
    ) -> Result<RetainedAttachmentsPageFfi, MarmotKitError> {
        let group = group_id_hex.as_deref().map(group_id_from_hex).transpose()?;
        let attachments = self
            .runtime
            .largest_retained_attachments(
                &account_ref,
                group.as_ref(),
                cursor.map(|cursor| cursor.inner.clone()),
                limit as usize,
            )
            .await?;
        Ok(RetainedAttachmentsPageFfi::new(attachments, limit as usize))
    }

    /// Removes every retained attachment in one chat, as `control_attachment`
    /// Remove does (shown as removed; download-again stays allowed), and
    /// returns how many it removed. Media-store space is freed before this
    /// returns; legacy database bodies free database pages.
    pub async fn remove_chat_attachments(
        &self,
        account_ref: String,
        group_id_hex: String,
    ) -> Result<u64, MarmotKitError> {
        let group = group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .remove_chat_attachments(&account_ref, &group)
            .await?)
    }

    /// Removes retained attachments of messages received before
    /// `received_before` (Unix seconds), across the account or within one
    /// chat, as Remove does. Returns how many it removed.
    pub async fn remove_attachments_older_than(
        &self,
        account_ref: String,
        received_before: u64,
        group_id_hex: Option<String>,
    ) -> Result<u64, MarmotKitError> {
        let group = group_id_hex.as_deref().map(group_id_from_hex).transpose()?;
        Ok(self
            .runtime
            .remove_attachments_older_than(&account_ref, received_before, group.as_ref())
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marmot_account::AccountHome;
    use marmot_app::MarmotApp;

    /// An account with nothing retained reports zeros and empty pages;
    /// invalid limits and group ids are refused.
    #[tokio::test]
    async fn an_empty_account_reports_nothing_and_inputs_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let kit = Marmot {
            runtime: app.runtime(),
            app,
        };
        let usage = kit.attachment_storage_usage("alice".into()).await.unwrap();
        assert_eq!(
            (
                usage.media_bytes,
                usage.legacy_bytes,
                usage.attachment_count
            ),
            (0, 0, 0)
        );
        assert!(usage.database_bytes > 0);
        let chats = kit
            .attachment_storage_by_chat("alice".into(), 8, None)
            .await
            .unwrap();
        assert!(chats.chats.is_empty() && chats.next_cursor.is_none());
        let largest = kit
            .largest_retained_attachments("alice".into(), Some("ab".repeat(16)), 8, None)
            .await
            .unwrap();
        assert!(largest.attachments.is_empty() && largest.next_cursor.is_none());
        assert!(
            kit.attachment_storage_by_chat("alice".into(), 0, None)
                .await
                .is_err()
        );
        assert!(
            kit.largest_retained_attachments("alice".into(), None, 257, None)
                .await
                .is_err()
        );
        assert!(
            kit.largest_retained_attachments("alice".into(), Some("zz".into()), 8, None)
                .await
                .is_err()
        );
        assert_eq!(
            kit.remove_chat_attachments("alice".into(), "ab".repeat(16))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            kit.remove_attachments_older_than("alice".into(), u64::MAX, None)
                .await
                .unwrap(),
            0
        );
        assert!(
            kit.remove_chat_attachments("alice".into(), "not-hex".into())
                .await
                .is_err()
        );
        kit.shutdown_and_close().await.unwrap();
    }
}
