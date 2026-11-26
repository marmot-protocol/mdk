//! The sender's v5 Welcome audit rows (`welcome_prepared`,
//! `welcome_event_size`, `welcome_publish_started`/`_finished`,
//! `welcome_publish_not_started`, `welcome_withdrawn`) for every retained
//! outbound Welcome a transport wrapped as a Nostr event. Each row is built
//! from the Welcome's own stored row, so a Welcome is described the same way
//! whichever path prepares, sends, retries or retires it, and every row of one
//! Welcome carries the operation id derived from its outer event
//! ([`welcome_audit_operation_id`]).

use super::*;
use crate::session::{OutboundWelcomeStatus, WelcomeExpiry, WelcomeSettlement};

/// The most Welcome ids remembered as already prepared in this process. A
/// prepared row is written once per Welcome; past this many the memory is
/// cleared, and a Welcome prepared again after that may be recorded twice.
const MAX_PREPARED_WELCOMES_REMEMBERED: usize = 4096;

/// The v5 operation id of one outbound Welcome, named by its id: its
/// `welcome_prepared` row and every other row of it share this id, whichever
/// path prepares or sends it.
pub(super) fn welcome_audit_operation_id(welcome_id: &cgka_traits::MessageId) -> audit_v5::LocalId {
    v5_local_id(b"welcome-operation", welcome_id.as_slice(), 0)
}

/// A retained outbound Welcome as its v5 rows name it.
pub(super) struct V5Welcome {
    pub(super) op_id: audit_v5::LocalId,
    pub(super) outer: audit_v5::NostrEventRef,
    pub(super) recipient_ref: audit_v5::MemberRef,
    pub(super) group_ref: audit_v5::GroupRef,
    pub(super) facts: cgka_engine::engine::OutboundWelcomeAuditFacts,
}

/// Why an invite is refused as too large: the event the host is told of,
/// and each Welcome the size check itself refused, with its own size.
#[derive(Clone, Debug)]
pub(super) struct InviteRefusal {
    pub(super) oversized: OversizedEvent,
    pub(super) oversized_welcomes: HashMap<cgka_traits::MessageId, cgka_traits::EventSizeClass>,
}

impl From<OversizedEvent> for InviteRefusal {
    fn from(oversized: OversizedEvent) -> Self {
        Self {
            oversized,
            oversized_welcomes: HashMap::new(),
        }
    }
}

/// One publish pass over a Welcome's relays: its started row, recorded with a
/// fresh attempt id only when the transport is called, and what its finished
/// row needs. A pass a hold stops before the transport is called records
/// neither row.
pub(super) struct V5WelcomePass {
    welcome_id: cgka_traits::MessageId,
    group_ref: audit_v5::GroupRef,
    started: audit_v5::WelcomePublishStarted,
    recorded: bool,
}

impl V5WelcomePass {
    /// Record the started row, at the moment the transport is called.
    pub(super) fn start(&mut self, audit: &SharedRecorder) {
        let Ok(attempt_id) = hex::encode(rand::random::<[u8; 16]>()).try_into() else {
            return;
        };
        self.started.attempt_id = attempt_id;
        audit.record_v5_event(
            Some(self.group_ref.clone()),
            audit_v5::Event::WelcomePublishStarted(self.started.clone()),
        );
        self.recorded = true;
    }
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// What the audit reads of the retained Welcome `message`, when audit is
    /// on; `None` for anything else, or a row that cannot be read now. One
    /// read serves every row of a publish pass.
    pub(super) fn welcome_audit_facts(
        &self,
        message: &TransportMessage,
    ) -> Option<cgka_engine::engine::OutboundWelcomeAuditFacts> {
        if !self.audit.is_enabled()
            || !matches!(message.envelope, TransportEnvelope::Welcome { .. })
        {
            return None;
        }
        self.session
            .outbound_welcome_audit_facts(&message.id)
            .ok()
            .flatten()
    }

    /// The Welcome `facts` describe as its v5 rows name it; `None` without a
    /// v5 recorder or for a Welcome another transport wrapped.
    fn v5_welcome_of(
        &self,
        facts: cgka_engine::engine::OutboundWelcomeAuditFacts,
    ) -> Option<V5Welcome> {
        if !self.audit.records_v5() {
            return None;
        }
        let outer = v5_outbound_welcome_ref(&facts.id, &facts.source)?;
        let recipient_ref =
            audit_v5::MemberRef::from_member_identity(facts.recipient.as_slice()).ok()?;
        let group_ref = audit_v5::GroupRef::from_group_id(facts.group_id.as_slice()).ok()?;
        Some(V5Welcome {
            op_id: welcome_audit_operation_id(&facts.id),
            outer,
            recipient_ref,
            group_ref,
            facts,
        })
    }

    /// Record `welcome_prepared` and `welcome_event_size` for each Welcome
    /// just retained, exactly as the engine stored it: the commit it waits
    /// on (none for a founding Welcome) and the KeyPackage it answers.
    /// Called where each first reaches the runtime: a create, a host's
    /// accepted commit, and a drained or automatic commit when published.
    /// Each is watched from here, so it is seen to settle. With a v5
    /// recorder, a Welcome is remembered once its row is read, so a failed
    /// read is tried again.
    pub(super) fn note_retained_welcomes(&mut self, welcomes: &[TransportMessage]) {
        self.watch_welcomes(welcomes.iter().map(|welcome| welcome.id.clone()));
        if !self.audit.records_v5() {
            return;
        }
        for welcome in welcomes {
            if self.v5_prepared_welcomes.contains(&welcome.id) {
                continue;
            }
            let Ok(facts) = self.session.outbound_welcome_audit_facts(&welcome.id) else {
                continue;
            };
            if self.v5_prepared_welcomes.len() >= MAX_PREPARED_WELCOMES_REMEMBERED {
                self.v5_prepared_welcomes.clear();
            }
            self.v5_prepared_welcomes.insert(welcome.id.clone());
            if let Some(v5) = facts.and_then(|facts| self.v5_welcome_of(facts)) {
                self.record_v5_welcome_prepared(&v5);
                self.record_v5_welcome_size(&v5, welcome);
            }
        }
    }

    /// Note each Welcome a create retained ([`Self::note_retained_welcomes`]).
    pub(super) fn note_founding_welcomes(&mut self, effects: &SessionEffects) {
        for work in &effects.publish {
            if let PublishWork::FoundingGroupCreated { welcomes }
            | PublishWork::GroupCreated { welcomes, .. } = work
            {
                self.note_retained_welcomes(welcomes);
            }
        }
    }

    fn record_v5_welcome_prepared(&self, v5: &V5Welcome) {
        // A constructed row names the KeyPackage it answers.
        let Some(key_package_ref) = v5
            .facts
            .key_package_event_id
            .as_ref()
            .and_then(|id| <[u8; 32]>::try_from(id.as_slice()).ok())
            .map(|id| audit_v5::NostrEventRef::from_validated_event_id(&id))
        else {
            return;
        };
        let (mode, basis) = match &v5.facts.origin_commit_id {
            None => (audit_v5::Mode::Founding, audit_v5::Basis::Founding {}),
            Some(origin) => {
                let Ok(commit_ref) = audit_v5::EngineMessageRef::from_message_id(origin.as_slice())
                else {
                    return;
                };
                (
                    audit_v5::Mode::Invite,
                    audit_v5::Basis::Commit { commit_ref },
                )
            }
        };
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomePrepared(audit_v5::WelcomePrepared {
                op_id: v5.op_id.clone(),
                recipient_ref: v5.recipient_ref.clone(),
                mode,
                basis,
                key_package_event_ref: Some(key_package_ref),
                outer_event_ref: Some(v5.outer.clone()),
                construction: audit_v5::Construction::Constructed,
                // Retained: canonical for a founding Welcome, staged with its
                // commit for an invite's.
                retention: audit_v5::Retention::Committed,
                failure_stage: None,
                reason: None,
                elapsed_us: None,
            }),
        );
    }

    fn record_v5_welcome_size(&self, v5: &V5Welcome, welcome: &TransportMessage) {
        let Some(size_class) = self.adapter.event_size_class(welcome) else {
            return;
        };
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomeEventSize(audit_v5::WelcomeEventSize {
                op_id: v5.op_id.clone(),
                outer_event_ref: v5.outer.clone(),
                event_size_class: v5_size_class(size_class),
            }),
        );
    }

    /// What the audit knows of each of `welcome_ids` still retained and not
    /// withdrawn, read just before a size refusal's rollback: those it may
    /// retire ([`Self::retired_welcomes`]). Empty without a v5 recorder.
    pub(super) fn unretired_welcomes(
        &self,
        welcome_ids: impl IntoIterator<Item = cgka_traits::MessageId>,
    ) -> Vec<V5Welcome> {
        if !self.audit.records_v5() {
            return Vec::new();
        }
        welcome_ids
            .into_iter()
            .filter_map(|id| {
                self.session
                    .outbound_welcome_audit_facts(&id)
                    .ok()
                    .flatten()
            })
            .filter(|facts| facts.state == MessageState::Sent)
            .filter_map(|facts| self.v5_welcome_of(facts))
            .collect()
    }

    /// The Welcomes a rollback of `fanout`'s commit may retire: those it
    /// carries and those still staged with its commit. Empty without a v5
    /// recorder.
    pub(super) fn staged_welcomes_of_fanout(
        &self,
        fanout: &OutboundFanout,
    ) -> Vec<cgka_traits::MessageId> {
        if !self.audit.records_v5() {
            return Vec::new();
        }
        let mut ids = fanout
            .pending_post_confirmation_welcomes()
            .iter()
            .map(|welcome| welcome.id.clone())
            .collect::<Vec<_>>();
        if let Ok(staged) = self.session.staged_invite_welcome_ids(fanout.message_id()) {
            for id in staged {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        ids
    }

    /// Those of `unretired`, read just before a rollback, that the rollback
    /// retired: their rows went from `Sent` to `Failed`.
    pub(super) fn retired_welcomes(&self, unretired: Vec<V5Welcome>) -> Vec<V5Welcome> {
        unretired
            .into_iter()
            .filter(|v5| {
                matches!(
                    self.session.stored_message_state(&v5.facts.id),
                    Ok(Some(MessageState::Failed))
                )
            })
            .collect()
    }

    /// Record `welcome_withdrawn` for each Welcome a size refusal's rollback
    /// retired, then stop watching it: the reason is known here, not to the
    /// watcher. A refused commit stopped them all, with the commit's size; a
    /// refused invite names each Welcome the size check refused, with its own
    /// size, and any other the rollback retired is withdrawn with it.
    pub(super) fn record_v5_welcomes_refused(
        &mut self,
        retired: &[V5Welcome],
        refusal: &InviteRefusal,
    ) {
        for v5 in retired {
            let welcome_id = &v5.facts.id;
            let (reason, size_class) = match refusal.oversized.artifact {
                OversizedArtifact::Commit => (
                    audit_v5::WithdrawalReason::CommitTooLarge,
                    Some(refusal.oversized.size_class),
                ),
                _ => match refusal.oversized_welcomes.get(welcome_id) {
                    Some(size_class) => (
                        audit_v5::WithdrawalReason::WelcomeTooLarge,
                        Some(*size_class),
                    ),
                    None => (audit_v5::WithdrawalReason::Withdrawn, None),
                },
            };
            self.record_v5_welcome_withdrawn(v5, reason, size_class.map(v5_size_class));
            // The watch ends here: a host reads its settled state.
            self.note_welcome_delivery_changed(welcome_id);
            self.watched_welcomes
                .retain(|watched| watched != welcome_id);
        }
    }

    /// `welcome_id` as its v5 rows name it, from its stored row. `Ok(None)`
    /// when there is nothing to record (no v5 recorder, no such Welcome, or
    /// another transport's); `Err` when the row could not be read now.
    fn v5_welcome_from_store(
        &self,
        welcome_id: &cgka_traits::MessageId,
    ) -> Result<Option<V5Welcome>, ()> {
        if !self.audit.records_v5() {
            return Ok(None);
        }
        let facts = self
            .session
            .outbound_welcome_audit_facts(welcome_id)
            .map_err(|_| ())?;
        Ok(facts.and_then(|facts| self.v5_welcome_of(facts)))
    }

    /// Record `welcome_withdrawn`, with `reason`, for a Welcome its sender
    /// just withdrew, watched or not; the watcher then leaves that
    /// settlement alone.
    pub(super) fn record_v5_welcome_withdrawal(
        &self,
        welcome_id: &cgka_traits::MessageId,
        reason: audit_v5::WithdrawalReason,
    ) {
        // A row that cannot be read now is left to the watcher, if it holds
        // the Welcome.
        let Ok(Some(v5)) = self.v5_welcome_from_store(welcome_id) else {
            return;
        };
        self.record_v5_welcome_withdrawn(&v5, reason, None);
        let mut recorded = self
            .v5_withdrawn_welcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if recorded.len() >= MAX_PREPARED_WELCOMES_REMEMBERED {
            recorded.clear();
        }
        recorded.insert(welcome_id.clone());
    }

    /// Mark a still-owed Welcome delivered when its stored acceptances meet
    /// its policy: from the attempt that met it, or after a stop interrupted
    /// that attempt's mark.
    pub(super) fn settle_met_welcome(
        &self,
        message: &TransportMessage,
        accepted: usize,
        required_acks: usize,
    ) {
        if matches!(message.envelope, TransportEnvelope::Welcome { .. })
            && accepted >= required_acks.max(1)
            && matches!(
                self.session.stored_message_state(&message.id),
                Ok(Some(MessageState::Sent))
            )
        {
            self.mark_welcome_delivered_best_effort(&message.id);
        }
    }

    /// Whether `fanout` is a Welcome's whose stored acceptances meet its
    /// policy while a later delivered mark can still close it: the Welcome is
    /// owed, waiting on its group or commit, or past its deadline but not yet
    /// marked expired. The acceptance must not be dropped then; a Welcome
    /// past its deadline is never published again to replace it. A Welcome
    /// settled any way (marked expired, withdrawn, its commit lost,
    /// delivered) owes nothing.
    pub(super) fn welcome_still_owes_met_policy(
        &self,
        fanout: &DurableTransportFanout,
        accepted: usize,
    ) -> bool {
        matches!(
            fanout.exact_message.envelope,
            TransportEnvelope::Welcome { .. }
        ) && accepted >= fanout.required_acks.max(1)
            && match self
                .session
                .outbound_welcome_status(&fanout.exact_message.id, self.wall_clock.now())
            {
                Ok(
                    OutboundWelcomeStatus::Owed { .. }
                    | OutboundWelcomeStatus::Waiting
                    | OutboundWelcomeStatus::PastDeadline,
                ) => true,
                Ok(OutboundWelcomeStatus::Settled(_)) => false,
                // Unreadable now: keep it for a later pass.
                Err(_) => true,
            }
    }

    /// Whether a Welcome past its deadline may still close as delivered, so
    /// the watcher does not mark it expired yet: a detached pass started before the
    /// deadline holds it and may yet be acknowledged, or its stored
    /// acceptances meet its policy (marked here, if the mark can land now).
    /// A fanout that cannot be read now is asked again on a later pass.
    pub(super) fn expired_welcome_may_still_close(
        &self,
        welcome_id: &cgka_traits::MessageId,
    ) -> bool {
        if self.session.detached_welcome_publishes.contains(welcome_id) {
            return true;
        }
        let fanout = match self.session.transport_fanout(welcome_id) {
            Ok(Some(fanout)) => fanout,
            Ok(None) => return false,
            Err(_) => return true,
        };
        let accepted = accepted_fanout_targets(&fanout);
        if accepted < fanout.required_acks.max(1) {
            return false;
        }
        self.settle_met_welcome(&fanout.exact_message, accepted, fanout.required_acks);
        true
    }

    /// Mark the Welcome `welcome_id`, past its delivery deadline at `now`,
    /// expired, and record that once: its delivery notice, its
    /// `welcome_withdrawn` (`expired`) row, then the mark's recorded flag
    /// (mdk#3589). The caller has reconciled any acknowledgement it holds.
    ///
    /// The mark is written first and alone settles the Welcome. A stop before
    /// the row leaves the mark unrecorded, and the next start records it; a
    /// stop between the row and the flag records the row again on the next
    /// start, under the same operation id.
    ///
    /// True once the expiry is recorded, now or before; false when a step
    /// could not be done now, or the Welcome is not past its deadline any
    /// more (a clock set back before the mark), so the watcher reads it again
    /// on a later pass.
    pub(super) fn expire_welcome(
        &self,
        welcome_id: &cgka_traits::MessageId,
        now: Timestamp,
    ) -> bool {
        match self.session.expire_sent_welcome(welcome_id, now) {
            Ok(Some(WelcomeExpiry::Unrecorded)) => self.record_welcome_expiry(welcome_id),
            Ok(Some(WelcomeExpiry::Recorded)) => true,
            Ok(None) => false,
            Err(error) => {
                log_unrecorded_welcome_expiry(&error);
                false
            }
        }
    }

    /// Record the expiry of `welcome_id`, marked and not yet recorded: the
    /// steps of [`Self::expire_welcome`] after the mark. False when one could
    /// not be done now; the watcher, or else the next start, retries.
    pub(super) fn record_welcome_expiry(&self, welcome_id: &cgka_traits::MessageId) -> bool {
        let recorded = || {
            self.v5_expired_welcomes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        // The notice goes first, so a retry never records the row twice; one
        // this process already recorded only has its flag written again.
        if !recorded().contains(welcome_id) {
            if !self.note_welcome_delivery_changed(welcome_id)
                || !self.record_v5_welcome_settled(welcome_id, WelcomeSettlement::Expired)
            {
                return false;
            }
            recorded().insert(welcome_id.clone());
        }
        match self.session.record_sent_welcome_expiry(welcome_id) {
            Ok(()) => {
                recorded().remove(welcome_id);
                true
            }
            Err(error) => {
                log_unrecorded_welcome_expiry(&error);
                false
            }
        }
    }

    /// Record `welcome_withdrawn` for a watched Welcome that settled without
    /// being delivered. False when its row could not be read now, so the
    /// watcher keeps it for a later pass.
    pub(super) fn record_v5_welcome_settled(
        &self,
        welcome_id: &cgka_traits::MessageId,
        settlement: WelcomeSettlement,
    ) -> bool {
        // Its sender's withdrawal was recorded when it happened, whatever
        // the Welcome reads as since (its commit may have lost after).
        let recorded = self
            .v5_withdrawn_welcomes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(welcome_id);
        if recorded {
            return true;
        }
        let reason = match settlement {
            WelcomeSettlement::Withdrawn => audit_v5::WithdrawalReason::Withdrawn,
            WelcomeSettlement::CommitSuperseded => audit_v5::WithdrawalReason::CommitSuperseded,
            WelcomeSettlement::Expired => audit_v5::WithdrawalReason::Expired,
            WelcomeSettlement::Delivered | WelcomeSettlement::Untracked => return true,
        };
        match self.v5_welcome_from_store(welcome_id) {
            Ok(Some(v5)) => {
                self.record_v5_welcome_withdrawn(&v5, reason, None);
                true
            }
            Ok(None) => true,
            Err(()) => false,
        }
    }

    fn record_v5_welcome_withdrawn(
        &self,
        v5: &V5Welcome,
        reason: audit_v5::WithdrawalReason,
        oversized_size_class: Option<audit_v5::EventSizeClass>,
    ) {
        self.audit.record_v5_event(
            Some(v5.group_ref.clone()),
            audit_v5::Event::WelcomeWithdrawn(audit_v5::WelcomeWithdrawn {
                op_id: v5.op_id.clone(),
                outer_event_ref: v5.outer.clone(),
                recipient_ref: v5.recipient_ref.clone(),
                reason,
                oversized_size_class,
            }),
        );
    }

    /// Record `welcome_publish_not_started` for a Welcome whose publish found
    /// no route.
    pub(super) fn record_v5_welcome_not_started(
        &self,
        facts: Option<cgka_engine::engine::OutboundWelcomeAuditFacts>,
        reason: audit_v5::NotStartedReason,
    ) {
        if let Some(v5) = facts.and_then(|facts| self.v5_welcome_of(facts)) {
            self.audit.record_v5_event(
                Some(v5.group_ref.clone()),
                audit_v5::Event::WelcomePublishNotStarted(audit_v5::WelcomePublishNotStarted {
                    op_id: v5.op_id,
                    outer_event_ref: v5.outer,
                    recipient_ref: v5.recipient_ref,
                    reason,
                    elapsed_us: None,
                }),
            );
        }
    }

    /// The v5 rows of one publish pass over `endpoints` of the Welcome
    /// `facts` describe, ready for [`V5WelcomePass::start`].
    pub(super) fn v5_welcome_pass(
        &self,
        facts: Option<cgka_engine::engine::OutboundWelcomeAuditFacts>,
        endpoints: &[TransportEndpoint],
        required_acks: usize,
        accepted_before: usize,
        route_source: audit_v5::RouteSource,
    ) -> Option<V5WelcomePass> {
        let v5 = self.v5_welcome_of(facts?)?;
        let (targets, target_count, targets_complete) = v5_pass_targets(endpoints)?;
        let required_acks = u32::try_from(required_acks).ok()?;
        let accepted_before_count = u32::try_from(accepted_before).ok()?;
        Some(V5WelcomePass {
            welcome_id: v5.facts.id.clone(),
            group_ref: v5.group_ref,
            started: audit_v5::WelcomePublishStarted {
                op_id: v5.op_id,
                // Replaced by a fresh id when the pass starts.
                attempt_id: "00".repeat(16).try_into().ok()?,
                outer_event_ref: v5.outer,
                recipient_ref: v5.recipient_ref,
                route_source,
                targets,
                target_count: Some(target_count),
                targets_complete,
                required_acks,
                accepted_before_count,
            },
            recorded: false,
        })
    }

    /// Record the finished row of a pass that started, after the pass's
    /// delivered mark, if any. The cumulative acceptance count comes from the
    /// Welcome's stored fanout, so it holds even when this pass's own
    /// endpoint results are incomplete, and is `None` when the pass's
    /// bookkeeping could not be saved; retention is the Welcome's delivery
    /// status as the pass left it.
    pub(super) fn record_v5_welcome_publish_finished(
        &self,
        pass: &Option<V5WelcomePass>,
        report: Option<&TransportPublishReport>,
        attempted: &[TransportEndpoint],
        accepted_total: Option<usize>,
        required_acks: usize,
    ) {
        let Some(pass) = pass.as_ref().filter(|pass| pass.recorded) else {
            return;
        };
        // The Welcome's delivery status as the pass left it: delivered,
        // still owed, or settled undelivered (expired, its commit lost).
        let status = accepted_total
            .is_some()
            .then(|| {
                self.session
                    .outbound_welcome_status(&pass.welcome_id, self.wall_clock.now())
                    .ok()
            })
            .flatten();
        pass.record_finished(
            &self.audit,
            report,
            attempted,
            accepted_total,
            required_acks,
            status,
        );
    }
}

/// A pass's started-row targets for `endpoints`: their references, their
/// count, and whether the references name them all.
fn v5_pass_targets(
    endpoints: &[TransportEndpoint],
) -> Option<(Vec<audit_v5::EndpointRef>, u32, bool)> {
    let target_count = u32::try_from(endpoints.len()).ok()?;
    let mut targets = endpoints
        .iter()
        .filter_map(v5_endpoint_ref)
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    let targets_complete =
        targets.len() == endpoints.len() && targets.len() <= audit_v5::MAX_ENDPOINTS;
    targets.truncate(audit_v5::MAX_ENDPOINTS);
    Some((targets, target_count, targets_complete))
}

impl V5WelcomePass {
    /// The pass over `endpoints`, the relays this pass was still waiting on
    /// when it was done, after `accepted_before` acceptances; ready for
    /// [`Self::start`].
    pub(super) fn remaining(
        &self,
        endpoints: &[TransportEndpoint],
        accepted_before: usize,
    ) -> Option<Self> {
        let (targets, target_count, targets_complete) = v5_pass_targets(endpoints)?;
        Some(Self {
            welcome_id: self.welcome_id.clone(),
            group_ref: self.group_ref.clone(),
            started: audit_v5::WelcomePublishStarted {
                route_source: audit_v5::RouteSource::RetainedTarget,
                targets,
                target_count: Some(target_count),
                targets_complete,
                accepted_before_count: u32::try_from(accepted_before).ok()?,
                ..self.started.clone()
            },
            recorded: false,
        })
    }

    /// Record this pass's finished row, if it started, from the relays'
    /// answers it observed, without its stored total, policy or retention:
    /// for a pass whose results are dropped unreconciled, as when its
    /// group's chat was deleted while it ran.
    pub(super) fn record_dropped(
        &self,
        audit: &SharedRecorder,
        result: &Result<TransportPublishReport, TransportAdapterError>,
        attempted: &[TransportEndpoint],
        required_acks: usize,
    ) {
        let endpoint_report;
        let report = match result {
            Ok(report) => Some(report),
            Err(error) if !error.publish_endpoint_failures().is_empty() => {
                endpoint_report = TransportPublishReport {
                    message_id: self.welcome_id.clone(),
                    accepted: Vec::new(),
                    failed: error.publish_endpoint_failures().to_vec(),
                    required_acks,
                };
                Some(&endpoint_report)
            }
            Err(_) => None,
        };
        self.record_finished(audit, report, attempted, None, required_acks, None);
    }

    /// The finished row; `status` is the Welcome's delivery status after
    /// the pass, read only when `accepted_total` was stored.
    fn record_finished(
        &self,
        audit: &SharedRecorder,
        report: Option<&TransportPublishReport>,
        attempted: &[TransportEndpoint],
        accepted_total: Option<usize>,
        required_acks: usize,
        status: Option<OutboundWelcomeStatus>,
    ) {
        if !self.recorded {
            return;
        }
        let Ok(required_acks) = u32::try_from(required_acks) else {
            return;
        };
        let mut results = Vec::new();
        let mut source_count = 0usize;
        if let Some(report) = report {
            source_count = report.accepted.len() + report.failed.len();
            for receipt in &report.accepted {
                if let Some(endpoint_ref) = v5_endpoint_ref(&receipt.endpoint) {
                    results.push(audit_v5::EndpointResult {
                        endpoint_ref,
                        status: audit_v5::EndpointStatus::Acknowledged,
                        failure_kind: None,
                        rejection_category: (receipt.ack_kind
                            == Some(TransportEndpointAckKind::Duplicate))
                        .then_some(audit_v5::RejectionCategory::Duplicate),
                    });
                }
            }
            for failure in &report.failed {
                if let Some(result) = v5_failed_endpoint_result(failure) {
                    results.push(result);
                }
            }
        }
        results.sort_by(|a, b| a.endpoint_ref.cmp(&b.endpoint_ref));
        let unique = results
            .windows(2)
            .all(|pair| pair[0].endpoint_ref < pair[1].endpoint_ref);
        results.dedup_by(|a, b| a.endpoint_ref == b.endpoint_ref);
        let results_complete = report.is_some()
            && unique
            && results.len() == attempted.len()
            && source_count == attempted.len()
            && results.len() <= audit_v5::MAX_ENDPOINTS;
        results.truncate(audit_v5::MAX_ENDPOINTS);
        let accepted_this_attempt_count = results_complete
            .then(|| report.and_then(|report| u32::try_from(report.accepted.len()).ok()))
            .flatten();
        // `None` when the pass's bookkeeping could not be saved: the relays'
        // answers above are observed, the stored total is not.
        let accepted_total_count = accepted_total.and_then(|total| u32::try_from(total).ok());
        // Met by the stored total whatever this pass's detail; unmet only
        // when every endpoint of the pass answered.
        let policy = match accepted_total_count {
            Some(total) if total >= required_acks => audit_v5::Policy::Met,
            Some(_) if results_complete => audit_v5::Policy::Unmet,
            _ => audit_v5::Policy::Unknown,
        };
        let retained_state = match (status, policy) {
            (
                Some(OutboundWelcomeStatus::Settled(WelcomeSettlement::Delivered)),
                audit_v5::Policy::Met,
            ) => audit_v5::RetainedState::Completed,
            (
                Some(OutboundWelcomeStatus::Owed { .. } | OutboundWelcomeStatus::Waiting),
                audit_v5::Policy::Unmet | audit_v5::Policy::Unknown,
            ) => audit_v5::RetainedState::Pending,
            _ => audit_v5::RetainedState::Unknown,
        };
        audit.record_v5_event(
            Some(self.group_ref.clone()),
            audit_v5::Event::WelcomePublishFinished(audit_v5::WelcomePublishFinished {
                attempt_id: self.started.attempt_id.clone(),
                outer_event_ref: self.started.outer_event_ref.clone(),
                results,
                results_complete,
                accepted_this_attempt_count,
                accepted_total_count,
                required_acks,
                policy,
                retained_state,
                elapsed_us: None,
            }),
        );
    }
}

/// The outer event reference of a retained outbound Welcome the Nostr
/// transport wrapped. Its id is the one this account's own peeler gave the
/// wrap it built, the event's NIP-01 hash, which is the id the recipient
/// observes; the session parses no transport event to check it again.
/// `None` for another transport's Welcome.
fn v5_outbound_welcome_ref(
    id: &cgka_traits::MessageId,
    source: &cgka_traits::transport::TransportSource,
) -> Option<audit_v5::NostrEventRef> {
    if source.0 != "nostr" {
        return None;
    }
    let id = <[u8; 32]>::try_from(id.as_slice()).ok()?;
    Some(audit_v5::NostrEventRef::from_validated_event_id(&id))
}

fn v5_size_class(size_class: cgka_traits::EventSizeClass) -> audit_v5::EventSizeClass {
    match size_class {
        cgka_traits::EventSizeClass::Under64Kib => audit_v5::EventSizeClass::Under64Kib,
        cgka_traits::EventSizeClass::From64To128Kib => audit_v5::EventSizeClass::From64To128Kib,
        cgka_traits::EventSizeClass::From128To256Kib => audit_v5::EventSizeClass::From128To256Kib,
        cgka_traits::EventSizeClass::From256To512Kib => audit_v5::EventSizeClass::From256To512Kib,
        cgka_traits::EventSizeClass::From512KibTo1Mib => audit_v5::EventSizeClass::From512KibTo1Mib,
        cgka_traits::EventSizeClass::From1To2Mib => audit_v5::EventSizeClass::From1To2Mib,
        cgka_traits::EventSizeClass::From2To4Mib => audit_v5::EventSizeClass::From2To4Mib,
        cgka_traits::EventSizeClass::Over4Mib => audit_v5::EventSizeClass::Over4Mib,
    }
}

fn log_unrecorded_welcome_expiry(error: &crate::session::SessionError) {
    tracing::warn!(
        target: TRACE_TARGET,
        method = "expire_welcome",
        transient = error.is_transient(),
        "Welcome expiry not written; retried on a later pass"
    );
}
