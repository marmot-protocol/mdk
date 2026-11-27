//! What the account worker's scheduled jobs owe, read cheaply, so each runs
//! on its own wake or deadline instead of on every maintenance tick
//! (mdk#2923 step B). Memory and at most a few indexed reads; a failed read
//! counts as owed, so the job still runs.
use super::AppClient;
use cgka_traits::storage::SiblingAddStorage as _;
use tokio::sync::broadcast;

/// A change [`DeviceGroupWakes`] carries to the account workers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeviceGroupWake {
    /// A live KeyPackage of this account id arrived: its sign-in check comes
    /// due within a minute.
    SignInNudged(String),
    /// This account label's user changed small state outside its worker.
    SmallStateEdited(String),
}

/// Changes made outside an account worker that can make its device-group
/// maintenance owed (mdk#3265). Each worker hears every account's and keeps
/// its own.
#[derive(Debug)]
pub(crate) struct DeviceGroupWakes(broadcast::Sender<DeviceGroupWake>);

impl Default for DeviceGroupWakes {
    fn default() -> Self {
        Self(broadcast::channel(64).0)
    }
}

impl DeviceGroupWakes {
    pub(crate) fn sign_in_nudged(&self, account_id_hex: &str) {
        let _ = self
            .0
            .send(DeviceGroupWake::SignInNudged(account_id_hex.to_owned()));
    }

    pub(crate) fn small_state_edited(&self, label: &str) {
        let _ = self
            .0
            .send(DeviceGroupWake::SmallStateEdited(label.to_owned()));
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<DeviceGroupWake> {
        self.0.subscribe()
    }
}

/// What [`AppClient::epoch_gap_hold_ends`] found across the live groups.
pub(crate) struct EpochGapHolds {
    /// Each group whose due self-update the epoch-gap hold holds, and when
    /// that hold ends.
    pub(crate) held: Vec<(cgka_traits::GroupId, cgka_traits::Timestamp)>,
    /// A group is unrecoverable.
    pub(crate) unrecoverable: bool,
    /// A group could not be read now.
    pub(crate) group_unread: bool,
}

impl AppClient {
    /// Whether the content-report backfill has batches left for the opened
    /// database. Memory only once it has finished.
    pub(crate) fn content_report_backfill_owed(&self) -> bool {
        self.app
            .account_storage(&self.state.label)
            .map_or(true, |storage| {
                self.content_report_backfill_done != Some(storage.app_storage().connection_serial())
            })
    }

    /// Whether linking has anything its timers still run: state in memory,
    /// a pairing message to read, a roster change to check failed links
    /// against, or stored linking still under way (mdk#3265). A settled
    /// device group and its decided links owe nothing. Never with device
    /// pairing compiled out or device groups off.
    pub(crate) fn device_pairing_owed(&self) -> bool {
        if self.app.device_groups_enabled() && !self.signing_out() {
            return self.device_pairing.has_state()
                || self
                    .app
                    .account_storage(&self.state.label)
                    .and_then(|storage| Ok(storage.app_storage().device_pairing_state_exists()?))
                    .unwrap_or(true);
        }
        false
    }

    /// Whether push gossip waits on fetch time: a join window open, an
    /// announce owed, or a repair ask held. The fetch clock counts only when
    /// sampled, so the worker samples it every 15 s while this holds.
    pub(crate) fn push_timing_owed(&self) -> bool {
        self.push_repairs.holds_asks()
            || self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| Ok(storage.app_storage().push_gossip_timing_pending()?))
                .unwrap_or(true)
    }

    /// When the KeyPackage catch-up next comes due by time alone, in unix
    /// seconds. A failed read gives none; the catch-up check itself still
    /// runs on its wakes.
    pub(crate) fn key_package_catch_up_next_at(&self) -> Option<u64> {
        if !matches!(self.maintenance_passes(), Ok(super::MaintenancePasses::Run)) {
            return None;
        }
        self.runtime
            .key_package_maintenance_next_due()
            .ok()
            .flatten()
            .map(|at| at.0)
    }

    /// What the KeyPackage catch-up's schedule reads: whether a catch-up is
    /// due now, and when it next comes due by time alone. `None` when a read
    /// fails, which counts as a change.
    pub(crate) fn key_package_catch_up_state(&self) -> Option<(bool, Option<u64>)> {
        Some((
            self.runtime
                .key_package_maintenance_requires_catch_up()
                .ok()?,
            self.runtime
                .key_package_maintenance_next_due()
                .ok()?
                .map(|at| at.0),
        ))
    }

    /// When history dispatch next has work, in unix seconds: a restore
    /// waiting for a slot now; with device groups on and maintenance
    /// running, the earliest history upload or fetch deadline, and while
    /// backups may be configured the backup pass's and condemned blobs'.
    /// `None` when nothing is owed.
    pub(crate) fn history_dispatch_next_at(&self) -> Option<u64> {
        if self.backup_restore.waiting() {
            return Some(0);
        }
        if !self.app.device_groups_enabled() || self.runtime.maintenance_is_paused() {
            return None;
        }
        self.app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                Ok(storage
                    .app_storage()
                    .history_dispatch_next_at(self.backups_may_be_configured())?)
            })
            .unwrap_or(Some(0))
    }

    /// Whether backups may be configured: unless the backup pass last found
    /// none, under the same trusted roster epoch or kept-key state as now.
    /// Unknown counts as configured, so a configured account's first pass
    /// is due at once.
    fn backups_may_be_configured(&self) -> bool {
        match &self.backups_configured {
            Some((eligibility, false)) => self.backup_eligibility().as_ref() != Some(eligibility),
            _ => true,
        }
    }

    /// Whether the backup pass found backups off and what decides that has
    /// changed since: a recovery key kept or forgotten, or a commit to the
    /// trusted device group, whose roster carries the account's key. The
    /// worker then wakes history dispatch to read its deadline again.
    pub(crate) fn backup_eligibility_changed(&self) -> bool {
        matches!(self.backups_configured, Some((_, false))) && self.backups_may_be_configured()
    }

    /// A history delivery was owed, parked or backed off: the worker
    /// re-reads the dispatch deadline on its next turn.
    pub(crate) fn note_history_dispatch_changed(&self) {
        self.history_dispatch_changed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether an app-owned local submission waits to be published.
    pub(crate) fn local_submission_pending(&self) -> bool {
        self.app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().next_local_submission()?))
            .map_or(true, |next| next.is_some())
    }
}

impl AppClient {
    /// When session maintenance (`run_due_maintenance`) next has work
    /// (mdk#3265): the session's own deadlines, each held self-update at
    /// the end of its epoch-gap hold, private KeyPackage expiries, and the
    /// app's retries, which with no stored time are owed every 15 s while
    /// they last. It reads every live group, so the worker runs it once per
    /// wake. A failed read counts as owed with no stored time: maintenance
    /// retries 15 s after its last run, never back to back.
    pub(crate) fn maintenance_due(&self) -> marmot_session::MaintenanceDue {
        self.try_maintenance_due()
            .unwrap_or(marmot_session::MaintenanceDue {
                at: None,
                retry_while_owed: true,
            })
    }

    /// Each live group whose due self-update the epoch-gap hold holds now,
    /// with the second that hold ends: 24 h after the gap opened (mdk#2258).
    /// Also whether a group is unrecoverable, and whether a group could not
    /// be read now, such as one not yet hydrated, which leaves the others'
    /// due times standing and counts as owed.
    pub(crate) fn epoch_gap_hold_ends(&self) -> Result<EpochGapHolds, super::AppError> {
        let now_ms = super::recovery::wall_now_ms()?;
        let mut held = Vec::new();
        let mut unrecoverable = false;
        let mut group_unread = false;
        for group_id in self.runtime.live_group_ids()? {
            unrecoverable |= matches!(
                self.runtime.epoch_state(&group_id),
                Some(cgka_traits::EpochState::Unrecoverable { .. })
            );
            let Ok(record) = self.runtime.group_record(&group_id) else {
                group_unread = true;
                continue;
            };
            if let Some(since) = self.epoch_gap_open_since(&group_id, record.epoch)?
                && super::self_update_waits_for_epoch_gap(since, now_ms)
            {
                let until_ms = since.saturating_add(super::EPOCH_GAP_SELF_UPDATE_HOLD_MS);
                held.push((group_id, cgka_traits::Timestamp(until_ms.div_ceil(1_000))));
            }
        }
        Ok(EpochGapHolds {
            held,
            unrecoverable,
            group_unread,
        })
    }

    fn try_maintenance_due(&self) -> Result<marmot_session::MaintenanceDue, super::AppError> {
        let EpochGapHolds {
            held,
            unrecoverable,
            group_unread,
        } = self.epoch_gap_hold_ends()?;
        let mut due = self.runtime.maintenance_due(&held)?;
        let mut at = |at: u64| {
            due.at = Some(due.at.map_or(cgka_traits::Timestamp(at), |earliest| {
                earliest.min(cgka_traits::Timestamp(at))
            }));
        };
        if let Some(expiry) = self.runtime.private_key_packages_next_expiry()? {
            at(expiry);
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        if let Some(expiry) = storage.received_private_key_packages_next_expiry()? {
            at(expiry);
        }
        let mut reinvite_owed = false;
        for record in self.runtime.pending_reinvites()? {
            match record.reinvite.as_ref() {
                Some(retry) => at(retry.next_attempt_at_ms.div_ceil(1_000)),
                None => reinvite_owed = true,
            }
        }
        // Device-group passes run at their own times and retry only what
        // they still owe with no time (mdk#3265).
        let device_groups = self.device_group_due(&held)?;
        if let Some(next) = device_groups.at {
            at(next);
        }
        if unrecoverable
            || group_unread
            || reinvite_owed
            || device_groups.owed
            || self.runtime.has_rejoin_offers()?
        {
            due.retry_while_owed = true;
        }
        Ok(due)
    }

    /// When the device-group passes of `run_due_maintenance` next have work
    /// (mdk#3265), with device groups on and maintenance running.
    ///
    /// By time: the sign-in check, for every account. With a trusted device
    /// group also its heartbeat, small-state broadcast, private KeyPackage
    /// request pacing, a leaving sibling's decision, gap filling and a
    /// recently linked device's inventory pages. Times a week or more out
    /// (history expiry, inactivity, takeover) ride the run the hourly
    /// heartbeat brings, at most an hour late.
    ///
    /// Owed with no time: an invitation decision changed or held, and with a
    /// trusted device group device-group work stored unsent or undone, a
    /// sibling added to a chat, a device-group event, a link this device
    /// made, a small-state edit or a pass's failure since the last run. Each
    /// retries 15 s after the last run.
    ///
    /// `held` is each live group whose self-update an epoch gap holds, with
    /// the second that hold ends: a held device group sends no heartbeat
    /// until then.
    pub(crate) fn device_group_due(
        &self,
        held: &[(cgka_traits::GroupId, cgka_traits::Timestamp)],
    ) -> Result<DeviceGroupDue, super::AppError> {
        let mut due = DeviceGroupDue::default();
        // Where maintenance runs no pass, nothing it owes can be done, so
        // none of it holds the 15 s retry.
        if !self.app.device_groups_enabled()
            || self.runtime.maintenance_is_paused()
            || self.maintenance_passes()? != super::MaintenancePasses::Run
        {
            return Ok(due);
        }
        let mut at = |next: u64| due.at = Some(due.at.map_or(next, |at| at.min(next)));
        let account_id_hex = hex::encode(self.runtime.self_id().as_slice());
        if let Some(next) = self.sign_in_schedule.next_due_unix(
            self.app.sign_in_nudges.peek(&account_id_hex),
            std::time::Instant::now(),
            crate::unix_now_seconds(),
        ) {
            at(next);
        }
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        // An invitation answered here applies here, linked or not.
        let mut owed = self.invitation_turn_owed() || self.invitation_work_held;
        // The rest only a linked device sends or applies: an unlinked one
        // keeps its decisions and edits unsent until it links. A sibling this
        // device added to a chat is owed that chat's history.
        if let Some(group_id) = self.trusted_device_group()? {
            owed |= self.device_group_work_changed
                || self.small_state_edited
                || storage.device_group_work_owed()?
                || !self
                    .app
                    .account_storage(&self.state.label)?
                    .sibling_adds()?
                    .is_empty();
            let group_id_hex = hex::encode(group_id.as_slice());
            let heartbeat = match storage.device_heartbeat_sent()? {
                Some(sent) if sent.group_id_hex == group_id_hex => Some(
                    sent.sent_at
                        .saturating_add(super::device_heartbeats::HEARTBEAT_INTERVAL_SECS),
                ),
                // None sent from this group yet: owed once the device tags
                // from it, which settling its join or its tag commit sets.
                _ if self.runtime.device_tag_group() == Some(&group_id) => Some(0),
                _ => None,
            };
            if let Some(next) = heartbeat {
                // A held device group sends none until its hold ends.
                let hold_end = held
                    .iter()
                    .find(|(held, _)| *held == group_id)
                    .map_or(0, |(_, until)| until.0);
                at(next.max(hold_end));
            }
            if let Some(schedule) = storage.small_state_schedule()? {
                at(crate::small_state::broadcast_next_at(&schedule));
            }
            if let Some(requested) = storage.private_key_package_earliest_request()? {
                at(requested.saturating_add(super::private_key_packages::REQUEST_INTERVAL_SECS));
            }
            for next in self
                .leaving_siblings
                .values()
                .copied()
                .chain(self.sibling_chat_gaps.next_due())
                .chain(self.device_group_retry_at)
                .chain(self.link_chat_progress.next_due())
            {
                at(next);
            }
        }
        due.owed = owed;
        Ok(due)
    }
}

/// What [`AppClient::device_group_due`] found: the earliest time a device-
/// group pass has work, and whether one owes work with no time.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeviceGroupDue {
    pub(crate) at: Option<u64>,
    pub(crate) owed: bool,
}
