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
    /// Pages always return `messages` in ascending display order, including
    /// when selecting the latest tail or paging backwards. With no cursor,
    /// the query selects the last `limit` matching rows (default 50, cap 200).
    /// `before` selects the nearest preceding rows; `after` selects the nearest
    /// following rows. Both boundaries are exclusive in MarmotKit.
    ///
    /// To load older rows, copy the first row's `timeline_at` and `message_id_hex`
    /// into `before` and `before_message_id`. To load newer rows, copy the last
    /// row into `after` and `after_message_id`. Each pair is required together;
    /// supplying both directions is an error. Keep the query scope and filters.
    ///
    /// Group queries use canonical display order unless `search_wall_clock` is
    /// true: epoch boundaries precede their authenticated application rows,
    /// even when timestamps run backwards between epochs. Storage resolves the
    /// cursor row's canonical key by message id; do not sort by `timeline_at`
    /// or manufacture a timestamp-only cursor. A cursor row no longer retained
    /// causes an error; restart without a cursor. Account-wide and wall-clock
    /// queries order by `(timeline_at, message_id_hex)`. Equal timestamps still
    /// require the id tie-breaker. Account-wide `search_wall_clock` queries add
    /// `group_id_hex` as the final tie-breaker and require that row's group in
    /// `cursor_group_id` when paging.
    ///
    /// `has_more_before` reports overflow toward older matching rows for an
    /// initial or Before query; `has_more_after` reports overflow toward newer
    /// matching rows for an After query. The initial tail has no more after.
    /// Before queries set `has_more_after = true`; After queries set
    /// `has_more_before = true`, even for empty pages. These cursor-side flags
    /// describe navigation context, not a separate existence check. Flags refer
    /// to locally stored matching rows, not remote history completeness.
    ///
    /// This supported lower-level read is **synchronous**; run it off the UI
    /// thread. Complete chat screens start from
    /// [`open_conversation_window`](Self::open_conversation_window).
    /// Custom live timelines can use
    /// [`subscribe_timeline_messages`](Self::subscribe_timeline_messages) with
    /// [`paginate_backwards`](crate::subscriptions::TimelineMessagesSubscription::paginate_backwards)
    /// and [`paginate_forwards`](crate::subscriptions::TimelineMessagesSubscription::paginate_forwards),
    /// which own a bounded replacement window and run off the caller thread.
    ///
    /// # Example
    ///
    /// Initial tail, then an older page and the page following it. Each result
    /// stays in display order; the boundary row is not repeated.
    ///
    /// ```no_run
    /// # use marmot_uniffi::{Marmot, MarmotKitError, TimelineMessageQueryFfi};
    /// # fn pages(kit: &Marmot, account: String, group: String) -> Result<(), MarmotKitError> {
    /// let query = TimelineMessageQueryFfi {
    ///     group_id_hex: Some(group),
    ///     limit: Some(50),
    ///     ..Default::default()
    /// };
    /// let initial = kit.timeline_messages(account.clone(), query.clone())?;
    /// if !initial.has_more_before {
    ///     return Ok(());
    /// }
    /// let Some(first) = initial.messages.first() else { return Ok(()); };
    /// let older = kit.timeline_messages(account.clone(), TimelineMessageQueryFfi {
    ///     before: Some(first.timeline_at),
    ///     before_message_id: Some(first.message_id_hex.clone()),
    ///     ..query.clone()
    /// })?;
    /// let Some(last) = older.messages.last() else { return Ok(()); };
    /// let newer = kit.timeline_messages(account, TimelineMessageQueryFfi {
    ///     after: Some(last.timeline_at),
    ///     after_message_id: Some(last.message_id_hex.clone()),
    ///     ..query
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
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
