//! Materialized timeline read command.

use crate::conversions::{TimelineMessageQueryFfi, TimelinePageFfi};
use crate::errors::MarmotKitError;
use crate::{Marmot, timeline_query_from_ffi};

#[uniffi::export]
impl Marmot {
    /// Accepted edit versions, oldest first within a latest-first page (1..=100).
    /// Supply both cursor fields from the first version to load older versions.
    /// Run this synchronous details query off the UI thread; screens already carry effective content.
    pub fn message_edit_history(
        &self,
        account_ref: String,
        group_id_hex: String,
        target_message_id_hex: String,
        before_edited_at: Option<u64>,
        before_message_id_hex: Option<String>,
        limit: u32,
    ) -> Result<crate::conversions::TimelineEditHistoryPageFfi, MarmotKitError> {
        let group = crate::conversions::group_id_from_hex(&group_id_hex)?;
        let before = match (before_edited_at, before_message_id_hex) {
            (Some(at), Some(id)) => Some((at, id)),
            (None, None) => None,
            _ => {
                return Err(MarmotKitError::Runtime {
                    details: "edit cursor requires timestamp and id".into(),
                });
            }
        };
        Ok(self
            .runtime
            .message_edit_history(
                &account_ref,
                &hex::encode(group.as_slice()),
                &target_message_id_hex,
                before,
                limit as usize,
            )?
            .into())
    }

    /// Materialized conversation timeline for a group or account-wide tail.
    ///
    /// This is the app-facing aggregated view: kind-9 chat/reply/media rows,
    /// kind-1200 stream-start rows, stream-final metadata pointing back to the
    /// start, reaction summaries, delete tombstones, and pagination flags. Raw
    /// kind-7/kind-5 events remain available through `messages(...)` for
    /// diagnostics.
    ///
    /// This call is **synchronous** and runs the store read on the calling
    /// thread; clients should not use it for scroll-back. Prefer
    /// [`subscribe_timeline_messages`](Self::subscribe_timeline_messages) plus
    /// `TimelineMessagesSubscription::paginate_backwards` /
    /// `paginate_forwards`, which own a bounded window and run off the caller
    /// thread. Retained for one-shot diagnostics/tooling only.
    pub fn timeline_messages(
        &self,
        account_ref: String,
        query: TimelineMessageQueryFfi,
    ) -> Result<TimelinePageFfi, MarmotKitError> {
        let page = self
            .runtime
            .timeline_messages_with_query(&account_ref, timeline_query_from_ffi(query)?)?;
        let _span = tracing::debug_span!(
            target: "marmot_uniffi::conversion",
            "timeline_page_conversion",
            method = "timeline_messages"
        )
        .entered();
        Ok(page.into())
    }
}
