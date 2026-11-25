//! The sender's view of each outbound Welcome's delivery (mdk#1706), which a
//! host reads to tell an invite a relay stored from one still being sent or
//! one that will never be sent.
//!
//! A Welcome's state is never stored: [`AccountDeviceRuntime::welcome_delivery_outcomes`]
//! derives it from the engine's stored Welcome row on every read, without
//! loading the group, so it always says what the engine will do. The ledger
//! (`cgka_welcome_delivery_ledger`) keeps only what nothing else holds: which
//! invite the Welcome belongs to, and what its publish attempts found, which
//! must outlive the 24-hour retry record. A record is made only when an
//! invite's Welcomes are created, so an invite sent before this device kept
//! records (an upgrade) is never listed; it is delivered as before and stays
//! in the pending Welcome list. A relay pass saves its counts on an existing
//! record in the same transaction as the retry record (`put_pass_fanout`),
//! so there is no second write to lose.
//!
//! Each place that changes a Welcome's delivery queues its group and recipient
//! for [`AccountDeviceRuntime::take_welcome_delivery_changes`], so a host
//! re-reads only those answers after the turn. A change left unqueued only
//! delays a host's notice; the query is always current.

use super::*;
use crate::session::{OutboundWelcomeStatus, WelcomeSettlement};
use cgka_traits::maintenance::{
    WelcomeCancelReason, WelcomeDeliveryProblem, WelcomeDeliveryRecord, WelcomeDeliveryState,
    WelcomeRelayCounts,
};

/// How long an invite whose Welcomes have all settled stays listed after its
/// last activity (its newest record, attempt or acceptance).
pub const INVITE_DELIVERY_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// One outbound Welcome's delivery as read now: its record, and the state and
/// delivery deadline its stored row gives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeDeliveryOutcome {
    pub record: WelcomeDeliveryRecord,
    pub state: WelcomeDeliveryState,
    pub deliver_until: Option<Timestamp>,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Each invited account's newest invite, for `group_id` and `recipient`
    /// or every one: one entry per invite, holding its Welcomes in the order
    /// they were first recorded, each with its state derived now from its
    /// stored row. The newest invite is chosen first; it is then left out once
    /// all its Welcomes have settled and its last activity is more than
    /// [`INVITE_DELIVERY_RETENTION_SECS`] old, so an older invite never shows
    /// in its place. A group that is not live is read from its stored rows
    /// too.
    pub fn welcome_delivery_outcomes(
        &self,
        group_id: Option<&GroupId>,
        recipient: Option<&MemberId>,
    ) -> AccountResult<Vec<Vec<WelcomeDeliveryOutcome>>> {
        let now = self.wall_clock.now();
        let records = self
            .session
            .welcome_delivery_records(group_id)?
            .into_iter()
            .filter(|record| recipient.is_none_or(|recipient| &record.recipient == recipient))
            .collect::<Vec<_>>();
        let mut outcomes = Vec::new();
        for invite in newest_invites(records) {
            let mut devices = Vec::with_capacity(invite.len());
            for record in invite {
                let status = self
                    .session
                    .stored_outbound_welcome_status(&record.welcome_id, now)?;
                let Some(mut state) = derived_state(&status, &record) else {
                    continue;
                };
                if status == OutboundWelcomeStatus::PastDeadline
                    && self.expired_welcome_can_still_close(&record.welcome_id)?
                {
                    state = WelcomeDeliveryState::Sending {
                        last_problem: record.last_problem,
                    };
                }
                let deliver_until = self
                    .session
                    .sent_welcome_deliver_until(&record.welcome_id)?;
                devices.push(WelcomeDeliveryOutcome {
                    record,
                    state,
                    deliver_until,
                });
            }
            if !devices.is_empty() && !past_retention(&devices, now) {
                outcomes.push(devices);
            }
        }
        Ok(outcomes)
    }

    /// Whether a Welcome past its deadline, not yet marked expired, may still
    /// close as delivered, so it is not yet undeliverable: a detached pass
    /// started before the deadline holds it, or its saved relay acceptances
    /// meet its policy and only its delivered mark is missing. A marked one
    /// is undeliverable for good. The watcher's
    /// `expired_welcome_may_still_close` asks the same and also makes that
    /// mark; this read changes nothing.
    fn expired_welcome_can_still_close(
        &self,
        welcome_id: &cgka_traits::MessageId,
    ) -> AccountResult<bool> {
        if self.session.detached_welcome_publishes.contains(welcome_id) {
            return Ok(true);
        }
        Ok(self
            .session
            .transport_fanout(welcome_id)?
            .is_some_and(|fanout| accepted_fanout_targets(&fanout) >= fanout.required_acks.max(1)))
    }

    /// The `(group, recipient)` pairs whose Welcome delivery may have changed
    /// since the last call, each once: the only answers a host needs to read
    /// again after a turn. Empty when no Welcome's delivery changed.
    pub fn take_welcome_delivery_changes(&self) -> Vec<(GroupId, MemberId)> {
        std::mem::take(
            &mut *self
                .welcome_delivery_changes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    /// Queue the Welcome `welcome_id`'s group and recipient as changed, when
    /// it has a delivery record. False when its record could not be read now,
    /// so a caller that can keep the Welcome watched notes it again later.
    pub(super) fn note_welcome_delivery_changed(
        &self,
        welcome_id: &cgka_traits::MessageId,
    ) -> bool {
        match self.session.welcome_delivery_record(welcome_id) {
            Ok(Some(record)) => {
                self.queue_welcome_delivery_change(&record);
                true
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub(super) fn queue_welcome_delivery_change(&self, record: &WelcomeDeliveryRecord) {
        let mut changes = self
            .welcome_delivery_changes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let change = (record.group_id.clone(), record.recipient.clone());
        if !changes.contains(&change) {
            changes.push(change);
        }
    }

    /// Record the Welcomes of an invite this runtime just staged or created,
    /// so a host lists the invite before its first attempt: each of
    /// `welcome_ids` of a live group with no record yet gets one, all of a
    /// group's in one transaction. This is the only place a record is made: a
    /// Welcome that existed before this device kept records (an upgrade) gets
    /// none, is never listed, and is delivered as before.
    pub(super) fn record_new_welcomes(&self, welcome_ids: &[cgka_traits::MessageId]) {
        let mut new: Vec<(GroupId, Vec<WelcomeDeliveryRecord>)> = Vec::new();
        for welcome_id in welcome_ids {
            match self.new_welcome_delivery_record(welcome_id) {
                Ok(Some(record)) => {
                    match new.iter_mut().find(|(group, _)| *group == record.group_id) {
                        Some((_, records)) => records.push(record),
                        None => new.push((record.group_id.clone(), vec![record])),
                    }
                }
                Ok(None) => {}
                // Part of an invite would list it with too few devices: one
                // read that fails records none of the batch, as a failed write
                // does. It is then delivered as usual but never listed.
                Err(error) => {
                    log_unrecorded_welcome_delivery(&error);
                    return;
                }
            }
        }
        for (group_id, records) in new {
            match self
                .session
                .insert_missing_welcome_delivery_records(&group_id, &records)
            {
                Ok(()) => records
                    .iter()
                    .for_each(|record| self.queue_welcome_delivery_change(record)),
                Err(error) => log_unrecorded_welcome_delivery(&error.into()),
            }
        }
    }

    /// Count a publish of the Welcome `welcome_id` that found no route to the
    /// recipient's inbox relays on its record. It stores no retry record, so
    /// this is the attempt's only write. A Welcome with no record is left
    /// without one.
    pub(super) fn record_welcome_route_failure(&self, welcome_id: &cgka_traits::MessageId) {
        let recorded = match self.session.welcome_delivery_record(welcome_id) {
            Ok(Some(mut record)) => {
                record.attempts = record.attempts.saturating_add(1);
                record.last_attempt_at = Some(self.wall_clock.now());
                record.last_problem = Some(WelcomeDeliveryProblem::NoInboxRelays);
                record.relays = WelcomeRelayCounts::default();
                self.session
                    .put_welcome_delivery_record(&record)
                    .map(|()| Some(record))
            }
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        };
        match recorded {
            Ok(Some(record)) => self.queue_welcome_delivery_change(&record),
            Ok(None) => {}
            Err(error) => log_unrecorded_welcome_delivery(&error.into()),
        }
    }

    /// The group of the Welcome `fanout` carries, when `put_pass_fanout` may
    /// count its pass on its record (read in the save's transaction): a
    /// retained outbound Welcome of a live group. `Ok(None)` for anything
    /// else; a read that fails is an error, which fails the save.
    pub(super) fn welcome_delivery_group(
        &self,
        fanout: &DurableTransportFanout,
    ) -> AccountResult<Option<GroupId>> {
        if !matches!(
            fanout.exact_message.envelope,
            TransportEnvelope::Welcome { .. }
        ) {
            return Ok(None);
        }
        let Some(facts) = self
            .session
            .outbound_welcome_audit_facts(&fanout.exact_message.id)?
        else {
            return Ok(None);
        };
        Ok(self
            .session
            .check_group_live(&facts.group_id)
            .is_ok()
            .then_some(facts.group_id))
    }

    /// A new record for the Welcome `welcome_id` of a live group that has
    /// none; `None` for one already recorded, or anything else.
    fn new_welcome_delivery_record(
        &self,
        welcome_id: &cgka_traits::MessageId,
    ) -> AccountResult<Option<WelcomeDeliveryRecord>> {
        let Some(facts) = self.session.outbound_welcome_audit_facts(welcome_id)? else {
            return Ok(None);
        };
        if self.session.check_group_live(&facts.group_id).is_err()
            || self.session.welcome_delivery_record(welcome_id)?.is_some()
        {
            return Ok(None);
        }
        Ok(Some(WelcomeDeliveryRecord {
            welcome_id: welcome_id.clone(),
            group_id: facts.group_id,
            recipient: facts.recipient,
            origin_commit_id: facts.origin_commit_id,
            created_at: self.wall_clock.now(),
            attempts: 0,
            last_attempt_at: None,
            accepted_at: None,
            relays: WelcomeRelayCounts::default(),
            last_problem: None,
        }))
    }
}

fn log_unrecorded_welcome_delivery(error: &AccountError) {
    tracing::warn!(
        target: TRACE_TARGET,
        method = "welcome_delivery_record",
        transient = error.as_engine_error().is_some_and(EngineError::is_transient),
        "Welcome delivery record not written"
    );
}

type Invite = (GroupId, MemberId, Option<cgka_traits::MessageId>);

fn invite_of(record: &WelcomeDeliveryRecord) -> Invite {
    (
        record.group_id.clone(),
        record.recipient.clone(),
        record.origin_commit_id.clone(),
    )
}

/// The records of each `(group, recipient)` pair's newest invite: the one
/// first recorded last. Records are made only as an invite's Welcomes are
/// created, all of an invite's together, so the order they were first
/// recorded (`records`' order), which a wall clock set back cannot change, is
/// the order the invites were made.
fn newest_invites(records: Vec<WelcomeDeliveryRecord>) -> Vec<Vec<WelcomeDeliveryRecord>> {
    // Per pair, its invites in the order each was first seen.
    let mut pairs: Vec<Vec<Vec<WelcomeDeliveryRecord>>> = Vec::new();
    let mut pair_index: HashMap<(GroupId, MemberId), usize> = HashMap::new();
    let mut invite_index: HashMap<Invite, usize> = HashMap::new();
    for record in records {
        let invite = invite_of(&record);
        let pair = *pair_index
            .entry((invite.0.clone(), invite.1.clone()))
            .or_insert_with(|| {
                pairs.push(Vec::new());
                pairs.len() - 1
            });
        let invites = &mut pairs[pair];
        let at = *invite_index.entry(invite).or_insert_with(|| {
            invites.push(Vec::new());
            invites.len() - 1
        });
        invites[at].push(record);
    }
    pairs
        .into_iter()
        .filter_map(|mut invites| invites.pop())
        .collect()
}

/// Whether an invite whose Welcomes read `devices` has settled and been quiet
/// for longer than retention.
fn past_retention(devices: &[WelcomeDeliveryOutcome], now: Timestamp) -> bool {
    let last_activity = devices
        .iter()
        .flat_map(|device| {
            [
                Some(device.record.created_at),
                device.record.last_attempt_at,
                device.record.accepted_at,
            ]
        })
        .flatten()
        .max();
    devices.iter().all(|device| device.state.is_settled())
        && last_activity
            .is_some_and(|at| now.0 >= at.0.saturating_add(INVITE_DELIVERY_RETENTION_SECS))
}

/// The state the Welcome's stored row `status` and `record`'s attempts add up
/// to; `None` when the engine no longer holds the Welcome.
fn derived_state(
    status: &OutboundWelcomeStatus,
    record: &WelcomeDeliveryRecord,
) -> Option<WelcomeDeliveryState> {
    Some(match status {
        OutboundWelcomeStatus::Waiting => WelcomeDeliveryState::Waiting,
        OutboundWelcomeStatus::Owed { .. } => WelcomeDeliveryState::Sending {
            last_problem: record.last_problem,
        },
        OutboundWelcomeStatus::Settled(WelcomeSettlement::Delivered) => {
            WelcomeDeliveryState::RelayAccepted
        }
        OutboundWelcomeStatus::Settled(WelcomeSettlement::CommitSuperseded) => {
            WelcomeDeliveryState::Cancelled {
                reason: WelcomeCancelReason::SupersededByGroupChange,
            }
        }
        OutboundWelcomeStatus::Settled(WelcomeSettlement::Withdrawn) => {
            WelcomeDeliveryState::Cancelled {
                reason: WelcomeCancelReason::Withdrawn,
            }
        }
        // Its delivery deadline passed with no relay acknowledging it,
        // marked expired or about to be.
        OutboundWelcomeStatus::PastDeadline
        | OutboundWelcomeStatus::Settled(WelcomeSettlement::Expired) => {
            WelcomeDeliveryState::Undeliverable {
                cause: record
                    .last_problem
                    .unwrap_or(WelcomeDeliveryProblem::RelaysUnreachable),
            }
        }
        OutboundWelcomeStatus::Settled(WelcomeSettlement::Untracked) => return None,
    })
}

/// What a relay pass found, for its Welcome's delivery record.
pub(super) struct PassCounts<'a> {
    /// The relays the attempt tried.
    pub(super) attempted: &'a [TransportEndpoint],
    /// Their answers; `None` when the adapter named none.
    pub(super) report: Option<&'a TransportPublishReport>,
    /// Whether this is an attempt of its own. A remaining pass's late
    /// answers end the attempt its first pass already counted.
    pub(super) counts_attempt: bool,
}

/// Count a relay pass over `fanout` on `record`.
pub(super) fn record_pass(
    record: &mut WelcomeDeliveryRecord,
    fanout: &DurableTransportFanout,
    pass: &PassCounts<'_>,
    now: Timestamp,
) {
    let relays = relay_counts(fanout, pass.attempted, pass.report);
    if pass.counts_attempt {
        record.attempts = record.attempts.saturating_add(1);
        record.last_attempt_at = Some(now);
    }
    record.last_problem = relay_problem(relays, fanout.required_acks);
    record.relays = relays;
    if relays.accepted > 0 && record.accepted_at.is_none() {
        record.accepted_at = Some(now);
    }
}

/// The Welcome's relays after a pass: from its retry record, which relays
/// stored it and which were never tried; from the pass's answers, how each
/// relay it tried and that did not store it failed.
fn relay_counts(
    fanout: &DurableTransportFanout,
    attempted: &[TransportEndpoint],
    report: Option<&TransportPublishReport>,
) -> WelcomeRelayCounts {
    let mut counts = WelcomeRelayCounts::default();
    for target in &fanout.targets {
        counts.total = counts.total.saturating_add(1);
        let count = if target.state == TransportFanoutAttemptState::Accepted {
            &mut counts.accepted
        } else if !attempted.contains(&target.endpoint) {
            &mut counts.untried
        } else if report
            .and_then(|report| {
                report
                    .failed
                    .iter()
                    .find(|failure| failure.endpoint == target.endpoint)
            })
            .is_some_and(relay_refused)
        {
            &mut counts.refused
        } else {
            &mut counts.unreachable
        };
        *count = count.saturating_add(1);
    }
    counts
}

/// Whether `failure` is the relay's own answer refusing it, for now or for
/// good (blocked, rate-limited, auth-required...), rather than a relay that
/// gave no answer or whose answer is unknown.
fn relay_refused(failure: &cgka_traits::TransportEndpointFailure) -> bool {
    failure.kind == TransportEndpointFailureKind::TerminalRejected
        || failure
            .rejection_category
            .is_some_and(|category| category != TransportEndpointRejectionCategory::Error)
}

/// Why a pass whose relays answered `counts` fell short of `required_acks`;
/// `None` when enough relays stored the Welcome or none was refused or
/// unreachable.
fn relay_problem(
    counts: WelcomeRelayCounts,
    required_acks: usize,
) -> Option<WelcomeDeliveryProblem> {
    if usize::try_from(counts.accepted).unwrap_or(usize::MAX) >= required_acks.max(1) {
        return None;
    }
    match (counts.refused > 0, counts.unreachable > 0) {
        (true, true) => Some(WelcomeDeliveryProblem::Mixed),
        (true, false) => Some(WelcomeDeliveryProblem::RefusedByRelays),
        (false, true) => Some(WelcomeDeliveryProblem::RelaysUnreachable),
        (false, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(welcome: u8, commit: u8) -> WelcomeDeliveryRecord {
        WelcomeDeliveryRecord {
            welcome_id: cgka_traits::MessageId::new(vec![welcome; 32]),
            group_id: GroupId::new(vec![1; 16]),
            recipient: MemberId::new(vec![2; 32]),
            origin_commit_id: Some(cgka_traits::MessageId::new(vec![commit; 32])),
            created_at: Timestamp(0),
            attempts: 1,
            last_attempt_at: None,
            accepted_at: None,
            relays: WelcomeRelayCounts::default(),
            last_problem: None,
        }
    }

    /// An account's newest invite is the one first recorded last, and only
    /// its Welcomes are listed, so an older invite never answers for it, even
    /// when one of the older invite's devices is recorded after the newer
    /// invite.
    #[test]
    fn only_an_accounts_newest_invite_is_listed() {
        let invites = newest_invites(vec![
            record(1, 10),
            record(2, 20),
            record(3, 20),
            record(4, 10),
        ]);
        let ids = invites
            .iter()
            .map(|invite| {
                invite
                    .iter()
                    .map(|record| record.welcome_id.as_slice()[0])
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(ids, [[2, 3]]);
    }

    /// An invite drops out only once every device's Welcome has settled and
    /// its last activity is past retention: one device still being sent to
    /// keeps the whole invite listed.
    #[test]
    fn an_invite_is_retained_until_all_its_welcomes_settle() {
        let outcome = |state| WelcomeDeliveryOutcome {
            record: record(1, 10),
            state,
            deliver_until: None,
        };
        let now = Timestamp(INVITE_DELIVERY_RETENTION_SECS);
        let accepted = outcome(WelcomeDeliveryState::RelayAccepted);
        let sending = outcome(WelcomeDeliveryState::Sending { last_problem: None });
        assert!(past_retention(std::slice::from_ref(&accepted), now));
        assert!(!past_retention(&[accepted.clone(), sending], now));
        assert!(!past_retention(&[accepted], Timestamp(now.0 - 1)));
    }

    /// A pass short of a two-acknowledgement policy keeps its problem though
    /// one relay stored the Welcome; one that meets it has none.
    #[test]
    fn a_pass_short_of_its_policy_keeps_its_problem() {
        let counts = WelcomeRelayCounts {
            total: 2,
            accepted: 1,
            refused: 1,
            ..WelcomeRelayCounts::default()
        };
        assert_eq!(
            relay_problem(counts, 2),
            Some(WelcomeDeliveryProblem::RefusedByRelays)
        );
        assert_eq!(relay_problem(counts, 1), None);
    }
}
