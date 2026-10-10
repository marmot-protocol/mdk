use crate::{Marmot, MarmotKitError, conversions::*};
use std::sync::Arc;
#[derive(uniffi::Object)]
pub struct AttachmentManagementSubscription {
    inner: Arc<marmot_app::RuntimeAttachmentManagementSubscription>,
}
#[uniffi::export(async_runtime = "tokio")]
impl AttachmentManagementSubscription {
    /// First frame is revalidated; later frames are coalesced replacements. None means closed.
    pub async fn next(&self) -> Result<Option<AttachmentManagementSnapshotFfi>, MarmotKitError> {
        Ok(self.inner.next().await?.map(Into::into))
    }
    /// Close observation without cancelling transfers or dismissing notices.
    pub fn cancel(&self) {
        self.inner.close();
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// One indexed candidate page; limit1..50. Empty filtered pages can continue. Errors discard the cursor.
    pub async fn managed_attachment_page(
        &self,
        account_ref: String,
        query: AttachmentJobQueryFfi,
        limit: u32,
        cursor: Option<Arc<AttachmentJobCursor>>,
    ) -> Result<ManagedAttachmentPageFfi, MarmotKitError> {
        Ok(self
            .runtime
            .managed_attachment_page(
                &account_ref,
                query.into(),
                limit as usize,
                cursor.map(|v| v.inner.clone()),
            )
            .await?
            .into())
    }
    /// One local global/chat head and independent recovery health. Incomplete counts are lower bounds.
    pub async fn attachment_management_snapshot(
        &self,
        account_ref: String,
        query: AttachmentJobQueryFfi,
    ) -> Result<AttachmentManagementSnapshotFfi, MarmotKitError> {
        Ok(self
            .runtime
            .attachment_management_snapshot(&account_ref, query.into())
            .await?
            .into())
    }
    /// Capture existing intent; automatic_only excludes explicit requests. Read-only, no cancellation yet.
    pub async fn begin_attachment_cancellation(
        &self,
        account_ref: String,
        group_id_hex: Option<String>,
        automatic_only: bool,
    ) -> Result<Arc<AttachmentCancellationCursor>, MarmotKitError> {
        Ok(Arc::new(AttachmentCancellationCursor {
            inner: self
                .runtime
                .begin_attachment_cancellation(&account_ref, group_id_hex, automatic_only)
                .await?,
        }))
    }
    /// Cancel at most64 old candidates before waking workers. Requested counts do not mean network stopped.
    pub async fn cancel_attachment_batch(
        &self,
        account_ref: String,
        cursor: Arc<AttachmentCancellationCursor>,
    ) -> Result<AttachmentCancellationBatchFfi, MarmotKitError> {
        Ok(self
            .runtime
            .cancel_attachment_batch(&account_ref, cursor.inner.clone())
            .await?
            .into())
    }
    /// Cancel or explicitly retry only the observed intent generation. False means stale or unavailable.
    pub async fn control_managed_attachment(
        &self,
        account_ref: String,
        action: Arc<AttachmentJobActionToken>,
        retry: bool,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .control_managed_attachment(&account_ref, action.inner.clone(), retry)
            .await?)
    }
    /// Event-driven replacement heads, at most4Hz, with one-shot retention expiry and no idle polling.
    pub async fn subscribe_attachment_management(
        &self,
        account_ref: String,
        query: AttachmentJobQueryFfi,
    ) -> Result<Arc<AttachmentManagementSubscription>, MarmotKitError> {
        Ok(Arc::new(AttachmentManagementSubscription {
            inner: self
                .runtime
                .subscribe_attachment_management(&account_ref, query.into())
                .await?,
        }))
    }
}
