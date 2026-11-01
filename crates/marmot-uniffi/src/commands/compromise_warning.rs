//! The account's compromise warning.

use crate::Marmot;
use crate::conversions::CompromiseWarningItemFfi;
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// The account's open compromise warning on this device: each item the
    /// user has not seen here, the earliest gathered first. Empty when no
    /// warning is open. An item means someone holding the account's signing
    /// key, or a session with its remote signer, published where the
    /// account's devices did not. The app writes the wording, and never says
    /// the account's devices stopped them. Always empty in release builds
    /// until the roster's spec lands. Refresh on `CompromiseWarningChanged`.
    pub async fn compromise_warning(
        &self,
        account_ref: String,
    ) -> Result<Vec<CompromiseWarningItemFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .compromise_warning(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Dismiss the compromise warning on this device: everything it gathers
    /// now is seen here, and it stays closed until something new arrives.
    /// Other devices' warnings are unchanged.
    pub async fn dismiss_compromise_warning(
        &self,
        account_ref: String,
    ) -> Result<(), MarmotKitError> {
        Ok(self
            .runtime
            .dismiss_compromise_warning(&account_ref)
            .await?)
    }
}
