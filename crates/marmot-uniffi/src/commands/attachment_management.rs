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
    /// One local per-chat head and independent recovery health. Incomplete counts are lower bounds.
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
    /// Event-driven replacement heads, at most 4 Hz, with one-shot retention expiry and no idle polling.
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
