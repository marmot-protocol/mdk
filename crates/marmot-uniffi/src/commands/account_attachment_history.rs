use crate::{Marmot, MarmotKitError, conversions::*};
use std::sync::Arc;
#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Read at most100 indexed account candidates; filtered empty pages can still have a continuation.
    /// Cursors are account-incarnation/query bound and must be discarded on runtime reconstruction or source mutation.
    pub async fn account_attachment_history_page(
        &self,
        account_ref: String,
        query: AccountAttachmentQueryFfi,
        limit: u32,
        cursor: Option<Arc<AccountAttachmentCursor>>,
    ) -> Result<AccountAttachmentPageReadFfi, MarmotKitError> {
        Ok(self
            .runtime
            .account_attachment_history_page(
                &account_ref,
                query.into(),
                limit as usize,
                cursor.map(|v| v.inner.clone()),
            )
            .await?
            .into())
    }
    /// Read the constant-work local change token without starting transfers or loading history.
    pub async fn account_attachment_history_version(
        &self,
        account_ref: String,
    ) -> Result<Arc<AccountAttachmentVersion>, MarmotKitError> {
        Ok(Arc::new(AccountAttachmentVersion {
            inner: self
                .runtime
                .account_attachment_history_version(&account_ref)
                .await?,
        }))
    }
}
