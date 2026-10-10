//! Lifecycle-bound fixed-view selection. IDs never come from a host display window.
use crate::MarmotKitError;
use crate::conversions::{ChatSelectionPageFfi, ChatSelectionSummaryFfi};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct ChatListSelection {
    inner: marmot_app::ChatListSelectionHandle,
}
impl ChatListSelection {
    pub(crate) fn new(inner: marmot_app::ChatListSelectionHandle) -> Arc<Self> {
        Arc::new(Self { inner })
    }
}
impl Drop for ChatListSelection {
    fn drop(&mut self) {
        self.inner.close();
    }
}
#[uniffi::export(async_runtime = "tokio")]
impl ChatListSelection {
    /// Complete frozen count and current revision, without loading presentation rows.
    pub async fn count(&self) -> Result<ChatSelectionSummaryFfi, MarmotKitError> {
        Ok(self.inner.count().await?.into())
    }
    /// At most 200 IDs, using the exact current selection revision.
    pub async fn page(
        &self,
        revision: u64,
        offset: u64,
        limit: u32,
    ) -> Result<ChatSelectionPageFfi, MarmotKitError> {
        let offset =
            usize::try_from(offset).map_err(|_| MarmotKitError::ChatSelectionInvalidPage)?;
        Ok(self
            .inner
            .page(revision, offset, limit as usize)
            .await?
            .into())
    }
    /// Remove one ID; an absent ID is a no-op, never an added selection.
    pub async fn deselect(
        &self,
        revision: u64,
        group_id_hex: String,
    ) -> Result<ChatSelectionSummaryFfi, MarmotKitError> {
        Ok(self.inner.deselect(revision, &group_id_hex).await?.into())
    }
    /// Remove IDs that left the captured view before a bulk action. The new
    /// revision supersedes all old pages; commands still validate authorization.
    pub async fn revalidate(
        &self,
        revision: u64,
    ) -> Result<ChatSelectionSummaryFfi, MarmotKitError> {
        Ok(self.inner.revalidate(revision).await?.into())
    }
    /// Idempotent terminal close. Cancels pending reads and releases compact intent.
    pub fn close(&self) {
        self.inner.close();
    }
}
