//! Materialized timeline read command.

use crate::conversions::{TimelineMessageQueryFfi, TimelinePageFfi};
use crate::errors::MarmotKitError;
use crate::{Marmot, timeline_query_from_ffi};

#[uniffi::export]
impl Marmot {
    /// Complete effective reaction participants for one account/group/message.
    ///
    /// Unlike a conversation window's bounded reactor preview, this includes
    /// every distinct sender/emoji pair, selecting the latest event per pair.
    /// The local materialized read applies block visibility;
    /// missing, hidden, retention-pruned, deleted or invalidated targets return an empty list.
    /// Results are ordered by timestamp, sender and emoji in one snapshot.
    /// Re-read on conversation updates; no network request is made. This
    /// synchronous read must run off the UI thread. Use matching generated
    /// bindings and native libraries; returned records are owned by the caller.
    pub fn message_reactions(
        &self,
        account_ref: String,
        group_id_hex: String,
        message_id_hex: String,
    ) -> Result<Vec<crate::conversions::TimelineUserReactionFfi>, MarmotKitError> {
        let group = crate::conversions::group_id_from_hex(&group_id_hex)?;
        Ok(self
            .runtime
            .message_reactions(
                &account_ref,
                &hex::encode(group.as_slice()),
                &message_id_hex,
            )?
            .into_iter()
            .map(Into::into)
            .collect())
    }

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

    /// Who voted for what in one poll: each voter's effective (latest valid)
    /// selection, using the same rules as the row's `PollProjectionFfi`, so all
    /// pages together hold `participants` entries that sum to each option's
    /// `votes`. Polls in this profile are not anonymous: every member can
    /// already read each response and its sender. Blocked voters stay listed
    /// because the tally still counts them; mark them with the account's block
    /// list. Hidden, deleted, missing, or non-poll rows return an empty page.
    /// Votes are ordered by `(voted_at, voter_account_id_hex)`; pass both
    /// cursor fields from the last vote to read the next page (limit 1..=100).
    /// Re-read from the start when the poll row is reprojected. Run this
    /// synchronous details query off the UI thread.
    pub fn poll_votes(
        &self,
        account_ref: String,
        group_id_hex: String,
        poll_event_id: String,
        after_voted_at: Option<u64>,
        after_voter_account_id_hex: Option<String>,
        limit: u32,
    ) -> Result<crate::conversions::PollVotePageFfi, MarmotKitError> {
        let group = crate::conversions::group_id_from_hex(&group_id_hex)?;
        let after = match (after_voted_at, after_voter_account_id_hex) {
            (Some(at), Some(voter)) => Some((at, voter)),
            (None, None) => None,
            _ => {
                return Err(MarmotKitError::Runtime {
                    details: "poll vote cursor requires timestamp and voter".into(),
                });
            }
        };
        Ok(self
            .runtime
            .poll_votes(
                &account_ref,
                &hex::encode(group.as_slice()),
                &poll_event_id,
                after,
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
