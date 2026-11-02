//! "History may be incomplete" notices, their durable dismissal, and the
//! account's recovery status.

use crate::Marmot;
use crate::conversions::{AccountRecoveryStatusFfi, HistoryNoticeFfi};
use crate::errors::MarmotKitError;

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Durable, local "history may be incomplete" notices for the account,
    /// oldest first. Refresh on `HistoryNoticesChanged`; group-scoped ones
    /// also appear in that group's recovery status.
    pub async fn history_notices(
        &self,
        account_ref: String,
    ) -> Result<Vec<HistoryNoticeFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .history_notices(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// The account's recovery status: the groups whose history is still
    /// being fetched, whether the inbox's is, and every notice as
    /// `history_notices` lists them. Refresh on `RecoveryStatusChanged`.
    /// Until the recovery runner owns history, nothing is ever catching up.
    pub async fn account_recovery_status(
        &self,
        account_ref: String,
    ) -> Result<AccountRecoveryStatusFfi, MarmotKitError> {
        Ok(self
            .runtime
            .account_recovery_status(&account_ref)
            .await?
            .into())
    }

    /// Dismiss one notice once the user accepts that this history may be
    /// incomplete. Durable, and recorded as its own outcome, never as
    /// recovered history. Returns false for a stale id; `InvalidHex` for a
    /// malformed one.
    pub async fn dismiss_history_notice(
        &self,
        account_ref: String,
        notice_id: String,
    ) -> Result<bool, MarmotKitError> {
        Ok(self
            .runtime
            .dismiss_history_notice(&account_ref, &notice_id)
            .await?)
    }
}
