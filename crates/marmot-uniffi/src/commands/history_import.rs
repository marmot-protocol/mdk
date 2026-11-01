//! Chat history from another of this account's devices (mdk#2628 4.2d).

use crate::Marmot;
use crate::conversions::ChatHistoryImportFfi;
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// The held chats whose history from another of this account's devices
    /// is arriving or has arrived: `Receiving` while a delivery waits to be
    /// imported, with `retrying` once an attempt to get its bundle failed,
    /// then `Imported` with the device it came from and when. Facts only: an
    /// empty history sends nothing, and an expired delivery leaves nothing.
    /// Empty while device groups are off. Refresh on
    /// `ChatHistoryImportsChanged`, which also fires when a source device is
    /// renamed or removed.
    pub async fn chat_history_imports(
        &self,
        account_ref: String,
    ) -> Result<Vec<ChatHistoryImportFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .chat_history_imports(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}
