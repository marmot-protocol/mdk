//! Kind 447 announces (mdk#2611; push-notifications spec: "Announce"). A
//! device announces in a group once when its join window there ends, instead
//! of a plain self-update when it shares a new or changed record after the
//! window, and with the next group message it sends after the announce
//! interval has passed. Every announce owed is stored before it is sent, so
//! one the outbox drops or a restart interrupts is sent again.

use std::collections::BTreeMap;
use std::time::Duration;

use cgka_traits::GroupId;
use storage_sqlite::AccountGroupPushGossipState;

use super::PushGossipGate;
use crate::AppError;
use crate::client::AppClient;
use crate::messages::AppMessageIntent;
use crate::notifications;

/// How long a device's push join window lasts once its join completes, how
/// long it may go without announcing in a group it sends to, and how it tells
/// that it can fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PushAnnounceTiming {
    /// T: at least one minute, so the adder's snapshot normally arrives before
    /// the device announces. Only time during which the device could fetch
    /// counts.
    pub(crate) join_window: Duration,
    pub(crate) interval: Duration,
    /// How long a client waits for every endpoint of its live subscriptions
    /// to serve its stored history before it counts the catch-up as run once
    /// any subscription has been served: a relay that never answers cannot
    /// hold every window open.
    pub(crate) catch_up_timeout: Duration,
    /// How long this client must have watched the device able to fetch
    /// before it announces: time for the worker to process what the catch-up
    /// placed.
    pub(crate) catch_up_settle: Duration,
}

impl Default for PushAnnounceTiming {
    fn default() -> Self {
        Self {
            join_window: Duration::from_secs(2 * 60),
            interval: Duration::from_secs(7 * 24 * 60 * 60),
            catch_up_timeout: Duration::from_secs(5 * 60),
            catch_up_settle: Duration::from_secs(15),
        }
    }
}

/// The most one look at the fetch clock counts. The worker looks every 15
/// seconds, so a longer gap is time the process did not run, such as a
/// suspended host.
const PUSH_FETCH_MAX_STEP_MS: i64 = 30_000;

/// What this client has seen of the time during which this device could fetch
/// its groups' messages. A client starts out unable to: it can only once its
/// own catch-up has run, so after a reconnect nothing counts, and nothing is
/// announced, until that reconnect's catch-up has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PushFetchClock {
    /// When this client opened, for the catch-up timeout.
    opened_at_ms: i64,
    /// Whether the device could fetch at the last look: a stretch is under
    /// way.
    fetching: bool,
    /// How far the current stretch has been counted.
    counted_to_ms: i64,
    /// How much of the current stretch this client watched, in steps no
    /// longer than [`PUSH_FETCH_MAX_STEP_MS`]. Only this counts toward the
    /// catch-up settle.
    watched_ms: i64,
}

impl PushFetchClock {
    pub(crate) fn new(opened_at_ms: i64) -> Self {
        Self {
            opened_at_ms,
            fetching: false,
            counted_to_ms: opened_at_ms,
            watched_ms: 0,
        }
    }

    /// Look at the clock at `now_ms`, when the device `can_fetch` or not.
    /// Returns the time to count toward the join windows: time since the last
    /// look, within one stretch, at most [`PUSH_FETCH_MAX_STEP_MS`]. A longer
    /// step is time the process did not run, and it counts nothing toward
    /// the settle: the worker processed nothing then.
    fn advance(&mut self, can_fetch: bool, now_ms: i64) -> i64 {
        if !can_fetch {
            self.fetching = false;
            return 0;
        }
        let step = if self.fetching {
            now_ms.saturating_sub(self.counted_to_ms).max(0)
        } else {
            self.fetching = true;
            self.watched_ms = 0;
            0
        };
        self.counted_to_ms = now_ms;
        if step <= PUSH_FETCH_MAX_STEP_MS {
            self.watched_ms = self.watched_ms.saturating_add(step);
        }
        step.min(PUSH_FETCH_MAX_STEP_MS)
    }

    /// Whether this client has watched the device able to fetch for at least
    /// `settle` in the current stretch.
    fn settled(&self, settle: Duration) -> bool {
        self.fetching && self.watched_ms >= millis(settle)
    }
}

/// Where this device stands in its push join window in one group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PushJoinWindow {
    /// It has none: it created the group, joined before migration 0122, or
    /// announced once its window ended.
    Closed,
    /// It joined, and its join has not completed or T has not been counted
    /// since. It sends no `have` there and shares its record in a plain
    /// self-update.
    Open,
    /// T has been counted since its join completed, and it owes the announce
    /// that closes the window.
    Ended,
}

impl PushAnnounceTiming {
    fn join_window(&self, state: Option<&AccountGroupPushGossipState>) -> PushJoinWindow {
        let Some(state) = state.filter(|state| state.joining_since_ms.is_some()) else {
            return PushJoinWindow::Closed;
        };
        if state.joined_at_ms.is_some() && state.join_window_counted_ms >= millis(self.join_window)
        {
            PushJoinWindow::Ended
        } else {
            PushJoinWindow::Open
        }
    }

    /// Whether a group message sent now owes the group the periodic announce:
    /// the join window is over and the device has not announced there within
    /// the interval, or ever.
    fn periodic_due(&self, state: Option<&AccountGroupPushGossipState>, now_ms: i64) -> bool {
        self.join_window(state) != PushJoinWindow::Open
            && state
                .and_then(|state| state.last_announced_at_ms)
                .is_none_or(|announced| now_ms.saturating_sub(announced) >= millis(self.interval))
    }
}

/// How a device shares its push record in a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PushShareForm {
    /// A plain self-update, with no `have`.
    Plain,
    /// An announce. Once published, it settles the owed announce stored as
    /// `settles_owed`, unless another was owed since.
    Announce { settles_owed: i64 },
    /// Not now: what the choice needs could not be read, or the announce owed
    /// could not be recorded. The share stays pending for its retry.
    Defer,
}

/// An announce the runtime accepted into a group's outbox without publishing
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcceptedPushAnnounce {
    /// The join window it was sent in.
    pub(crate) joining_since_ms: Option<i64>,
    pub(crate) app_event_id: String,
    /// The owed announce it was built under: once published, it settles that
    /// debt if nothing was owed since.
    pub(crate) settles_owed: Option<i64>,
}

fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

impl AppClient {
    /// How this device shares `record` in `group_id`. A new or changed record
    /// after the join window, or with none opened, owes the group an
    /// announce, recorded before anything is sent. It goes in this share
    /// unless an announce of this device's waits in the group's outbox or the
    /// device has not been able to fetch for the settle time; then the share
    /// is a plain self-update, which is always valid, and the announce owed
    /// is sent once it can be. Inside the window, and when re-sharing a record
    /// members may have, the share is a plain self-update too. When what the
    /// decision needs cannot be read, or the debt cannot be recorded, the
    /// share waits, so its retry decides again.
    pub(super) fn push_share_form(
        &self,
        group_id: &GroupId,
        record: &notifications::GroupPushTokenRecord,
    ) -> PushShareForm {
        let state = match self
            .app
            .group_push_gossip_state(&self.state.label, &record.group_id_hex)
        {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "push_share_form",
                    error_kind = error.privacy_safe_kind(),
                    "push join window read failed",
                );
                return PushShareForm::Defer;
            }
        };
        if self.push_announce_timing.join_window(state.as_ref()) == PushJoinWindow::Open {
            return PushShareForm::Plain;
        }
        match self.is_new_own_push_record(record) {
            Some(true) => {}
            Some(false) => return PushShareForm::Plain,
            None => return PushShareForm::Defer,
        }
        let Ok(owed) = self.record_push_announce_owed(group_id, notifications::unix_now_ms())
        else {
            return PushShareForm::Defer;
        };
        // No debt without a projected membership; the send decides the rest.
        let Some(settles_owed) = owed else {
            return PushShareForm::Plain;
        };
        if self.announce_left_in_outbox(group_id, state.as_ref())
            || !self
                .push_fetch_clock
                .settled(self.push_announce_timing.catch_up_settle)
        {
            return PushShareForm::Plain;
        }
        PushShareForm::Announce { settles_owed }
    }

    /// Record that this device owes `group_id` an announce as of
    /// `owed_at_ms`. Returns the value stored, or `None` without a projected
    /// membership to record it for.
    fn record_push_announce_owed(
        &self,
        group_id: &GroupId,
        owed_at_ms: i64,
    ) -> Result<Option<i64>, AppError> {
        #[cfg(test)]
        if self.test_fail_push_announce_owed_write {
            return Err(AppError::BlockingTask(
                "injected owed push announce write failure".to_owned(),
            ));
        }
        self.app
            .record_group_push_announce_owed(
                &self.state.label,
                &hex::encode(group_id.as_slice()),
                owed_at_ms,
            )
            .inspect_err(|error| {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "record_push_announce_owed",
                    error_kind = error.privacy_safe_kind(),
                    "owed push announce was not recorded",
                );
            })
    }

    /// Count the time since the last look during which this device could
    /// fetch toward every join window whose join has completed, then record,
    /// for each open window, whether its join has now completed: the group
    /// state is stored and stable, and the post-join history fetch has ended.
    /// T counts from then.
    pub(crate) async fn advance_push_join_windows(&mut self) {
        let can_fetch = self.push_device_can_fetch().await;
        let counted_ms = self
            .push_fetch_clock
            .advance(can_fetch, notifications::unix_now_ms());
        if counted_ms > 0
            && let Err(error) = self
                .app
                .count_push_join_window_time(&self.state.label, counted_ms)
        {
            tracing::warn!(
                target: "marmot_app::notifications",
                method = "advance_push_join_windows",
                error_kind = error.privacy_safe_kind(),
                "push join window time was not counted",
            );
        }
        let joining = match self.app.joining_group_push_gossip_states(&self.state.label) {
            Ok(joining) => joining,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "advance_push_join_windows",
                    error_kind = error.privacy_safe_kind(),
                    "push join window read failed",
                );
                return;
            }
        };
        for state in joining {
            if state.joined_at_ms.is_some() {
                continue;
            }
            let Ok(group_id) = hex::decode(&state.group_id_hex).map(GroupId::new) else {
                continue;
            };
            let Some(completed_at_ms) = self.push_join_completed_at(&group_id) else {
                continue;
            };
            if let Err(error) = self.app.record_group_push_gossip_join(
                &self.state.label,
                &state.group_id_hex,
                completed_at_ms,
            ) {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "advance_push_join_windows",
                    error_kind = error.privacy_safe_kind(),
                    "push join completion was not recorded",
                );
            }
        }
    }

    /// Whether this device can fetch its groups' messages now: a relay is
    /// connected, and this client's catch-up has run. That is every endpoint
    /// of its live subscriptions serving its stored history, or, once the
    /// catch-up timeout has passed since the client opened, any subscription
    /// served by one: a subscription whose relays never answer cannot hold
    /// back every announce in the account.
    async fn push_device_can_fetch(&self) -> bool {
        #[cfg(test)]
        if let Some(can_fetch) = self.test_push_device_can_fetch {
            return can_fetch;
        }
        let eose = self.adapter.account_subscription_eose().await;
        let caught_up = eose.complete()
            || (eose.with_eose > 0
                && notifications::unix_now_ms().saturating_sub(self.push_fetch_clock.opened_at_ms)
                    >= millis(self.push_announce_timing.catch_up_timeout));
        caught_up && self.relay_plane.relay_health().await.connected > 0
    }

    /// When this device's join to `group_id` completed, or `None` while it
    /// has not: the group must be stable and its post-join history fetch
    /// ended, as fetched or at its deadline. The announce at the end of the
    /// window finds what an expired fetch missed. A copy with no fetch
    /// recorded completes once stable.
    fn push_join_completed_at(&self, group_id: &GroupId) -> Option<i64> {
        if !matches!(
            self.runtime.epoch_state(group_id),
            Some(cgka_traits::EpochState::Stable { .. })
        ) {
            return None;
        }
        match self.runtime.post_join_history_fetch(group_id) {
            Ok(Some(fetch)) => fetch
                .completion
                .map(|completion| i64::try_from(completion.completed_at_ms).unwrap_or(i64::MAX)),
            Ok(None) => Some(notifications::unix_now_ms()),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "push_join_completed_at",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "post-join history fetch read failed",
                );
                None
            }
        }
    }

    /// This device sent a group message in `group_id`, published or accepted
    /// into the group's outbox: owe the group the periodic announce if it is
    /// due, for the account worker to send right after. An announce sent
    /// while the message waits in the outbox waits behind it. An announce
    /// already waiting in the outbox stands for it: once published it
    /// restarts the interval, and if the outbox drops it, the debt it was
    /// sent for is still owed.
    pub(crate) fn note_push_announce_after_send(&mut self, group_id: &GroupId) {
        let group_id_hex = hex::encode(group_id.as_slice());
        let state = match self
            .app
            .group_push_gossip_state(&self.state.label, &group_id_hex)
        {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "note_push_announce_after_send",
                    error_kind = error.privacy_safe_kind(),
                    "push announce state read failed",
                );
                return;
            }
        };
        let now_ms = notifications::unix_now_ms();
        if self
            .push_announce_timing
            .periodic_due(state.as_ref(), now_ms)
            && !self.announce_left_in_outbox(group_id, state.as_ref())
            && matches!(
                self.record_push_announce_owed(group_id, now_ms),
                Ok(Some(_))
            )
        {
            self.push_registration_share_queued = true;
        }
    }

    /// Groups that are owed an announce now, by group id, each with the owed
    /// announce stored for it (see [`Self::record_push_announce`]): those whose join
    /// window has ended, and those with another announce owed, outside an
    /// open window. A group whose announce this client left in the outbox in
    /// its current window is skipped. None is owed until the device has been
    /// able to fetch for the settle time, so an announce names what this
    /// client's catch-up brought.
    fn owed_push_announces(&self) -> Result<BTreeMap<String, Option<i64>>, AppError> {
        let mut owed = BTreeMap::new();
        if !self
            .push_fetch_clock
            .settled(self.push_announce_timing.catch_up_settle)
        {
            return Ok(owed);
        }
        for state in self
            .app
            .joining_group_push_gossip_states(&self.state.label)?
        {
            let Ok(group_id) = hex::decode(&state.group_id_hex).map(GroupId::new) else {
                continue;
            };
            if self.push_announce_timing.join_window(Some(&state)) == PushJoinWindow::Ended
                && !self.announce_left_in_outbox(&group_id, Some(&state))
            {
                owed.insert(state.group_id_hex, state.announce_owed_at_ms);
            }
        }
        for state in self
            .app
            .owed_group_push_announce_states(&self.state.label)?
        {
            let Ok(group_id) = hex::decode(&state.group_id_hex).map(GroupId::new) else {
                continue;
            };
            if self.push_announce_timing.join_window(Some(&state)) != PushJoinWindow::Open
                && !self.announce_left_in_outbox(&group_id, Some(&state))
            {
                owed.insert(state.group_id_hex, state.announce_owed_at_ms);
            }
        }
        Ok(owed)
    }

    /// Whether this client left an announce in `group_id`'s outbox in the
    /// join window `state` records. A Welcome since then opened a new window,
    /// which owes its own announce.
    fn announce_left_in_outbox(
        &self,
        group_id: &GroupId,
        state: Option<&AccountGroupPushGossipState>,
    ) -> bool {
        self.accepted_push_announces
            .get(group_id)
            .is_some_and(|accepted| {
                accepted.joining_since_ms == state.and_then(|state| state.joining_since_ms)
            })
    }

    /// The runtime accepted the announce `app_event_id` in `group_id`, built
    /// under the owed announce `settles_owed`, into the outbox without
    /// publishing it: send no other there in this join window until the
    /// outbox publishes or drops it.
    pub(super) fn note_push_announce_left_in_outbox(
        &mut self,
        group_id: &GroupId,
        app_event_id: String,
        settles_owed: Option<i64>,
    ) {
        let joining_since_ms = match self
            .app
            .group_push_gossip_state(&self.state.label, &hex::encode(group_id.as_slice()))
        {
            Ok(state) => state.and_then(|state| state.joining_since_ms),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "note_push_announce_left_in_outbox",
                    error_kind = error.privacy_safe_kind(),
                    "push join window read failed",
                );
                None
            }
        };
        self.accepted_push_announces.insert(
            group_id.clone(),
            AcceptedPushAnnounce {
                joining_since_ms,
                app_event_id,
                settles_owed,
            },
        );
    }

    /// Settle the announces this client left in an outbox that `effects`
    /// report published or dropped. A published one counts as an announce
    /// published at once, unless a Welcome has opened a new join window
    /// since, which owes its own. A dropped one lifts the hold, and the
    /// announce it was sent for, still owed, is sent again.
    pub(crate) fn settle_accepted_push_announces(
        &mut self,
        effects: &marmot_session::AccountDeviceEffects,
    ) {
        if self.accepted_push_announces.is_empty() {
            return;
        }
        let published = effects
            .published_app_messages
            .iter()
            .map(|published| (&published.group_id, &published.app_event_id, true));
        let dropped = effects
            .failed_app_messages
            .iter()
            .map(|failed| (&failed.group_id, &failed.app_event_id, false));
        for (group_id, app_event_id, was_published) in published.chain(dropped) {
            if self
                .accepted_push_announces
                .get(group_id)
                .is_none_or(|accepted| accepted.app_event_id != *app_event_id)
            {
                continue;
            }
            let Some(accepted) = self.accepted_push_announces.remove(group_id) else {
                continue;
            };
            if !was_published {
                self.push_registration_share_queued = true;
                continue;
            }
            match self
                .app
                .group_push_gossip_state(&self.state.label, &hex::encode(group_id.as_slice()))
            {
                Ok(state)
                    if state.as_ref().and_then(|state| state.joining_since_ms)
                        == accepted.joining_since_ms =>
                {
                    self.record_push_announce(group_id, accepted.settles_owed);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "settle_accepted_push_announces",
                        error_kind = error.privacy_safe_kind(),
                        "push join window read failed",
                    );
                    self.push_registration_share_queued = true;
                }
            }
        }
    }

    /// Whether an announce this device owes can be sent now.
    pub(crate) fn has_due_push_announce(&self) -> bool {
        match self.owed_push_announces() {
            Ok(owed) => owed.keys().any(|group_id_hex| {
                matches!(
                    self.push_gossip_gate(group_id_hex, None),
                    PushGossipGate::Due
                )
            }),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "has_due_push_announce",
                    error_kind = error.privacy_safe_kind(),
                    "owed push announce read failed",
                );
                true
            }
        }
    }

    /// Send every announce this device owes in a group that can take it now.
    /// Returns whether one that could be sent remains owed.
    ///
    /// Only a published announce counts: it closes the join window and
    /// restarts the interval. One the runtime only accepted into the group's
    /// outbox stays owed, and this client sends no other there in that join
    /// window, not even for a changed record, so an offline device does not
    /// fill its outbox with announces.
    pub(crate) async fn send_due_push_announces(&mut self) -> bool {
        self.advance_push_join_windows().await;
        let owed = match self.owed_push_announces() {
            Ok(owed) => owed,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "send_due_push_announces",
                    error_kind = error.privacy_safe_kind(),
                    "owed push announce read failed",
                );
                return true;
            }
        };
        let mut pending = false;
        for (group_id_hex, settles_owed) in owed {
            let Ok(group_id) = hex::decode(&group_id_hex).map(GroupId::new) else {
                continue;
            };
            if !matches!(
                self.push_gossip_gate(&group_id_hex, None),
                PushGossipGate::Due
            ) {
                continue;
            }
            match self.send_push_announce(&group_id).await {
                Ok((cgka_traits::SendAcceptDisposition::Published, _)) => {
                    pending |= !self.record_push_announce(&group_id, settles_owed);
                }
                Ok((_, app_event_id)) => {
                    self.note_push_announce_left_in_outbox(&group_id, app_event_id, settles_owed);
                }
                // The group's state changed since it was checked; the next
                // check sends the announce or finds the group gone.
                Err(
                    AppError::GroupRemoved(_)
                    | AppError::GroupDisbanding(_)
                    | AppError::UserBlocked,
                ) => {}
                Err(error) => {
                    tracing::warn!(
                        target: "marmot_app::notifications",
                        method = "send_due_push_announces",
                        error_kind = error.privacy_safe_kind(),
                        "push announce remains owed",
                    );
                    pending = true;
                }
            }
        }
        pending
    }

    /// Record that an announce in `group_id` was published, closing its join
    /// window. It settles the owed announce it was built under,
    /// `settles_owed`, unless another was owed since. Returns false when the
    /// write failed.
    pub(super) fn record_push_announce(
        &mut self,
        group_id: &GroupId,
        settles_owed: Option<i64>,
    ) -> bool {
        self.accepted_push_announces.remove(group_id);
        match self.app.record_group_push_gossip_announce(
            &self.state.label,
            &hex::encode(group_id.as_slice()),
            notifications::unix_now_ms(),
            settles_owed,
        ) {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "record_push_announce",
                    error_kind = error.privacy_safe_kind(),
                    "published push announce was not recorded",
                );
                false
            }
        }
    }

    /// Send an announce carrying this device's own stored records in
    /// `group_id`, or `tokens: []` when it has none. Returns how the runtime
    /// accepted it, and its app event id.
    async fn send_push_announce(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(cgka_traits::SendAcceptDisposition, String), AppError> {
        let (member_id_hex, leaf_index) = self.local_member_leaf(group_id)?;
        let own = self
            .app
            .stored_group_push_tokens(&self.state.label, &hex::encode(group_id.as_slice()))?
            .into_iter()
            .filter(|stored| {
                stored.record_digest.is_some()
                    && stored.record.member_id_hex == member_id_hex
                    && stored.record.leaf_index == leaf_index
            })
            .map(|stored| stored.record)
            .collect::<Vec<_>>();
        let content = self.build_push_announce(group_id, &own)?;
        let (event, summary) = self
            .send_app_event(group_id, AppMessageIntent::PushTokenUpdate { content })
            .await?;
        Ok((summary.accept_disposition, event.id))
    }

    /// Whether sharing `record` shares a new or changed record of this
    /// device's: none is stored for its record key, or the stored one names
    /// another token or relay hint. Re-sharing the stored registration, as
    /// after a member add, shares neither. `None` when the read failed.
    fn is_new_own_push_record(&self, record: &notifications::GroupPushTokenRecord) -> Option<bool> {
        match self
            .app
            .group_push_tokens(&self.state.label, &record.group_id_hex)
        {
            Ok(stored) => Some(!stored.iter().any(|stored| {
                stored.member_id_hex == record.member_id_hex
                    && stored.leaf_index == record.leaf_index
                    && stored.platform == record.platform
                    && stored.server_pubkey_hex == record.server_pubkey_hex
                    && stored.token_fingerprint == record.token_fingerprint
                    && stored.relay_hint == record.relay_hint
            })),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::notifications",
                    method = "is_new_own_push_record",
                    error_kind = error.privacy_safe_kind(),
                    "stored push token read failed",
                );
                None
            }
        }
    }

    /// The content of an announce in `group_id` carrying `own`, this device's
    /// current records there, and naming every record and tombstone it holds
    /// there that fits.
    pub(super) fn build_push_announce(
        &self,
        group_id: &GroupId,
        own: &[notifications::GroupPushTokenRecord],
    ) -> Result<String, AppError> {
        let group_id_hex = hex::encode(group_id.as_slice());
        let held = self
            .app
            .stored_group_push_tokens(&self.state.label, &group_id_hex)?;
        let tombstones = self
            .app
            .group_push_token_tombstones(&self.state.label, &group_id_hex)?;
        let sender_hex = self
            .app
            .account_home()
            .account(&self.state.label)?
            .account_id_hex;
        let announce = notifications::push_announce(
            own,
            &held,
            &tombstones,
            &sender_hex,
            group_id.as_slice().len(),
        )?;
        tracing::debug!(
            target: "marmot_app::notifications",
            method = "build_push_announce",
            own_records = own.len(),
            listed = announce.listed,
            unlisted = announce.unlisted,
            unknown_digests = announce.unknown_digests,
            "push announce prepared",
        );
        Ok(announce.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Time counts only within a stretch during which the device can fetch,
    /// from the look after the one that began it, a look at a time at most
    /// one step. The settle counts only steps this client watched, so a
    /// suspended process counts nothing toward it.
    #[test]
    fn the_fetch_clock_counts_only_while_the_device_can_fetch() {
        let settle = Duration::from_secs(10);
        let mut clock = PushFetchClock::new(0);
        assert_eq!(clock.advance(false, 1_000), 0);
        assert!(!clock.settled(Duration::ZERO));
        assert_eq!(clock.advance(true, 2_000), 0, "a stretch begins");
        assert!(clock.settled(Duration::ZERO));
        assert_eq!(clock.advance(true, 7_000), 5_000);
        assert_eq!(clock.advance(true, 7_000), 0);
        assert!(!clock.settled(settle));
        assert_eq!(clock.advance(true, 12_000), 5_000);
        assert!(clock.settled(settle));
        assert_eq!(clock.advance(false, 13_000), 0, "the stretch ends");
        assert!(!clock.settled(Duration::ZERO));
        assert_eq!(
            clock.advance(true, 100_000),
            0,
            "offline time is not counted"
        );
        assert_eq!(
            clock.advance(true, 100_000 + 3_600_000),
            PUSH_FETCH_MAX_STEP_MS,
            "a suspended process counts one step"
        );
        assert!(!clock.settled(settle), "and nothing toward the settle");
        assert_eq!(clock.advance(true, 3_706_000), 6_000);
        assert!(!clock.settled(settle));
        assert_eq!(clock.advance(true, 3_710_000), 4_000);
        assert!(clock.settled(settle));
    }
}
