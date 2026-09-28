//! "History may be incomplete" notices and their durable dismissal.

use crate::Marmot;
use crate::conversions::HistoryNoticeFfi;
use crate::errors::MarmotKitError;

#[uniffi::export(async_runtime = "tokio")]
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
