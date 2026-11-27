//! Outbound Welcome delivery (mdk#2628 item 3.5a).
//!
//! The engine's Welcome row is the obligation: staged with its commit, owed
//! once the commit confirms (or at a founding create), delivered, withdrawn,
//! or marked expired. Every publish reads that row first (`welcome_hold`), so
//! a withdrawn or expired Welcome never goes out again, a staged one waits
//! for its commit, and no Welcome goes out once its delivery deadline passes
//! (a device link's at the end of the new device's wait, any other seven
//! days after it was staged, mdk#3589). The watcher marks a Welcome past its
//! deadline expired once nothing it has received can still deliver it, and
//! records that once (`expire_welcome`). Per-endpoint
//! attempts and backoff live on the Welcome's `DurableTransportFanout`,
//! which maintenance retries; only `redeliver_welcome` skips that backoff.

use super::*;
use crate::session::{OutboundWelcomeStatus, WelcomeSettlement};

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Publish retained Welcome obligations with bounded concurrency. An id
    /// that has not been bound or is no longer retained cannot be published.
    pub async fn publish_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, group_id, &mut output, Some(context))
            .await?;
        Ok(output)
    }

    /// Publish now each of `welcome_ids` that the engine holds as owed: the
    /// trigger a host fires once it has replied to an invite, naming the
    /// Welcomes by id. One still staged with its commit is left for
    /// maintenance to send once the commit confirms; a delivered, withdrawn
    /// or expired one is skipped.
    pub async fn deliver_owed_welcomes_with_audit_context(
        &mut self,
        welcome_ids: &[cgka_traits::MessageId],
        group_id: GroupId,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let now = self.wall_clock.now();
        let mut owed = Vec::with_capacity(welcome_ids.len());
        for id in welcome_ids {
            if let OutboundWelcomeStatus::Owed { message, .. } =
                self.session.outbound_welcome_status(id, now)?
            {
                owed.push(message);
            }
        }
        let mut output = AccountDeviceEffects::default();
        if !owed.is_empty() {
            self.publish_welcome_fanout(owed, Some(group_id), &mut output, Some(context))
                .await?;
        }
        Ok(output)
    }

    /// Retry retained Welcome obligations with the shared bounded fanout, as
    /// the startup pass does: a relay that already failed one is asked again
    /// only once its backoff has passed, and one never asked is asked now.
    pub async fn retry_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, None, &mut output, Some(context))
            .await?;
        Ok(output)
    }

    /// Prepare a startup Welcome retry whose relay I/O can run independently
    /// from the serialized account worker.
    ///
    /// Preparation persists the exact event/endpoint attempts and reserves
    /// their message ids in-memory before this returns. The returned task owns
    /// only a cloned transport adapter; callers must pass its completion to
    /// [`Self::finish_welcome_publish_task`] or release its reservation with
    /// [`Self::abandon_welcome_publish_task`].
    #[doc(hidden)]
    pub fn prepare_welcome_retry_task_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        context: AuditEventContext,
    ) -> AccountResult<PreparedWelcomePublishTask>
    where
        A: Clone + 'static,
    {
        let prepared = self.prepare_welcome_publish(welcomes, None, Some(context))?;
        Ok(self.reserve_welcome_publish_task(Arc::new(self.adapter.clone()), prepared))
    }

    /// Have the host run every Welcome wave this runtime would publish,
    /// or stop. While detached, each wave that has a relay attempt to make is
    /// prepared and reserved as the startup retry is, and waits in
    /// [`Self::take_prepared_welcome_tasks`] instead of being awaited: a
    /// founding create's Welcomes, the owed Welcomes a host names, the
    /// Welcomes a confirmed commit releases, and maintenance's release of
    /// watched Welcomes. A wave keeps its own group and retry policy. A
    /// pending create's first Welcome, which confirms its group, and
    /// [`Self::redeliver_welcome`] still publish inline.
    ///
    /// A host that turns this on must take and run every prepared task, and
    /// pass each completion to [`Self::finish_welcome_publish_task`] or
    /// release it with [`Self::abandon_welcome_publish_task`].
    #[doc(hidden)]
    pub fn set_detached_welcome_waves(&mut self, detached: bool)
    where
        A: Clone + 'static,
    {
        self.detached_welcome_adapter =
            detached.then(|| Arc::new(self.adapter.clone()) as Arc<dyn TransportAdapter>);
    }

    /// The waves prepared while detached, in the order they were prepared.
    /// Each is reserved until its completion is finished or abandoned.
    #[doc(hidden)]
    pub fn take_prepared_welcome_tasks(&mut self) -> Vec<PreparedWelcomePublishTask> {
        std::mem::take(&mut self.prepared_welcome_tasks)
    }

    fn reserve_welcome_publish_task(
        &mut self,
        adapter: Arc<dyn TransportAdapter>,
        prepared: PreparedWelcomePublish,
    ) -> PreparedWelcomePublishTask {
        let message_ids = prepared.network_message_ids();
        self.session
            .detached_welcome_publishes
            .extend(message_ids.iter().cloned());
        self.session
            .detached_welcome_holds
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend(message_ids.iter().cloned().map(|id| (id, None)));
        PreparedWelcomePublishTask {
            message_ids,
            run: WelcomeTaskRun::Wave {
                adapter,
                wall_clock: self.wall_clock.clone(),
                prepared,
                holds: self.session.detached_welcome_holds.clone(),
                selection: self.session.welcome_selection.clone(),
            },
        }
    }

    /// Reconcile every relay result from a detached Welcome publish in input
    /// order, then release its in-memory exact-event reservations.
    #[doc(hidden)]
    pub async fn finish_welcome_publish_task(
        &mut self,
        task: CompletedWelcomePublishTask,
    ) -> AccountResult<AccountDeviceEffects> {
        // Relays left answering that the host did not take stop here.
        let CompletedWelcomePublishTask {
            completed,
            message_ids,
            remaining: _,
        } = task;
        let mut output = AccountDeviceEffects::default();
        let result = self.finish_welcome_publish(completed, &mut output).await;
        self.abandon_welcome_publish_task(&message_ids);
        result.map(|()| output)
    }

    /// Release the in-memory reservation after a detached relay task is
    /// cancelled or panics. Durable fanout remains retryable.
    #[doc(hidden)]
    pub fn abandon_welcome_publish_task(&mut self, message_ids: &[cgka_traits::MessageId]) {
        let mut holds = self
            .session
            .detached_welcome_holds
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for message_id in message_ids {
            self.session.detached_welcome_publishes.remove(message_id);
            holds.remove(message_id);
        }
    }

    /// Bounded-concurrency Welcome publication used by founding creates and by
    /// deferred existing-group invite fanout after the commit is confirmed.
    /// While detached, a wave with a relay attempt to make is reserved and
    /// left for the host to run (`set_detached_welcome_waves`); one with none
    /// is finished here, as it always was.
    pub(super) async fn publish_welcome_fanout(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
    ) -> AccountResult<()> {
        let prepared = self.prepare_welcome_publish(welcomes, group_id, context)?;
        if !prepared.pending.is_empty()
            && let Some(adapter) = self.detached_welcome_adapter.clone()
        {
            let task = self.reserve_welcome_publish_task(adapter, prepared);
            self.prepared_welcome_tasks.push(task);
            return Ok(());
        }
        let adapter = &self.adapter;
        let (completed, remaining) = prepared
            .publish(
                &|request| adapter.publish(request),
                self.wall_clock.as_ref(),
                None,
                None,
            )
            .await;
        // Inline, nothing waits for the relays a pass left answering: they
        // stop here, and maintenance retries them after their backoff.
        drop(remaining);
        self.finish_welcome_publish(completed, output).await
    }

    pub(super) fn prepare_welcome_publish(
        &self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: Option<AuditEventContext>,
    ) -> AccountResult<PreparedWelcomePublish> {
        let mut metadata = Vec::with_capacity(welcomes.len());
        let mut completions = Vec::with_capacity(welcomes.len());
        completions.resize_with(welcomes.len(), || None);
        let mut pending = VecDeque::new();
        for (index, welcome) in welcomes.into_iter().enumerate() {
            let recipient = welcome_recipient(&welcome);
            let welcome_id = welcome.id.clone();
            let mut effects = AccountDeviceEffects::default();
            match self.prepare_legacy_publish(welcome, &mut effects, context.clone(), false)? {
                PreparedLegacyPublish::Complete(status) => {
                    completions[index] = Some(LegacyPublishCompletion::Complete(status));
                }
                PreparedLegacyPublish::Network(attempt) => pending.push_back((index, attempt)),
            }
            metadata.push(WelcomePublishMetadata {
                recipient,
                welcome_id,
                group_id: group_id.clone(),
                effects,
            });
        }

        Ok(PreparedWelcomePublish {
            group_id,
            metadata,
            completions,
            pending,
            audit: self.audit.clone(),
        })
    }

    pub(super) async fn finish_welcome_publish(
        &mut self,
        completed: CompletedWelcomePublish,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let CompletedWelcomePublish {
            group_id,
            metadata,
            completions,
            audit: _,
        } = completed;
        // Every network attempt above has already been exposed to relays, so a
        // finish-stage failure for one recipient must not skip completion
        // bookkeeping for the rest: reconcile every completion in input order
        // and surface the first error only after all exposed publishes have
        // been durably finished. Otherwise later recipients' fanout state
        // would stay `Unattempted` and a restart could republish Welcomes that
        // were already delivered.
        let mut first_error = None;
        for (metadata, completion) in metadata.into_iter().zip(completions) {
            let WelcomePublishMetadata {
                recipient,
                welcome_id,
                group_id: _,
                mut effects,
            } = metadata;
            let completion = completion.expect("every Welcome publish completed");
            // A Welcome no relay was asked for, every relay inside its backoff
            // or a wave holding it, has not failed again.
            let deferred_unasked = matches!(
                &completion,
                LegacyPublishCompletion::Complete(status) if status.retry_deferred
            );
            let status = match completion {
                LegacyPublishCompletion::Complete(status) => Ok(status),
                LegacyPublishCompletion::Network(attempt, result) => {
                    self.finish_prepared_legacy_publish(*attempt, result, &mut effects)
                        .await
                }
                LegacyPublishCompletion::Remaining(pass) => self.finish_remaining_pass(*pass),
            };
            let status = match status {
                Ok(status) => Some(status),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    None
                }
            };
            // The attempt that met the policy marked the Welcome delivered.
            if let Some(status) = status
                && !status.withdrawn
                && !status.awaits_commit
                && !status.met_required_acks
                && !deferred_unasked
                && !self.welcome_past_deadline_now(&welcome_id)
                && let Some(recipient) = recipient
            {
                effects.welcome_failures.push(self.welcome_delivery_failure(
                    welcome_id,
                    recipient,
                    group_id.clone(),
                    &effects,
                    0,
                ));
            }
            output.extend(effects);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Why a Welcome must not reach a relay now, checked by both places that
    /// publish one: the publish preparation step and maintenance's retry of a
    /// stored fanout. A row it cannot read holds the Welcome, so nothing that
    /// fails here publishes it. A Welcome it clears may still carry a
    /// delivery deadline, which a batch checks again before it starts each
    /// relay attempt.
    pub(super) fn welcome_hold(
        &self,
        message_id: &cgka_traits::MessageId,
        envelope: &TransportEnvelope,
    ) -> AccountResult<Option<WelcomeHold>> {
        if !matches!(envelope, TransportEnvelope::Welcome { .. }) {
            return Ok(None);
        }
        if self.session.stored_message_state(message_id)?.is_none()
            || self.session.sent_welcome_withdrawn(message_id)?
        {
            return Ok(Some(WelcomeHold::Withdrawn));
        }
        if self.session.sent_welcome_awaits_commit(message_id)? {
            return Ok(Some(WelcomeHold::AwaitsCommit));
        }
        if self.welcome_past_deadline(message_id)? {
            return Ok(Some(WelcomeHold::Expired));
        }
        Ok(None)
    }

    /// Whether the retained Welcome `message_id` is past its delivery
    /// deadline (`Engine::sent_welcome_deliver_until`) by this runtime's
    /// wall clock, so that nothing publishes it again (mdk#3589).
    pub(super) fn welcome_past_deadline(
        &self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<bool> {
        Ok(self
            .session
            .sent_welcome_deliver_until(message_id)?
            .is_some_and(|deliver_until| self.wall_clock.now() >= deliver_until))
    }

    /// Whether an attempt on `message_id` that fell short ended past its
    /// deadline, or with its Welcome marked expired whatever the clock, so it
    /// is never published again and is not pending: no delivery failure is
    /// reported for it. A row that cannot be read now reports the failure, as
    /// before deadlines existed.
    pub(super) fn welcome_past_deadline_now(&self, message_id: &cgka_traits::MessageId) -> bool {
        self.welcome_past_deadline(message_id).unwrap_or(false)
            || matches!(
                self.session
                    .outbound_welcome_status(message_id, self.wall_clock.now()),
                Ok(OutboundWelcomeStatus::Settled(WelcomeSettlement::Expired))
            )
    }

    /// `welcomes` without those past their delivery deadline, which are no
    /// longer owed to anyone.
    fn welcomes_before_deadline(
        &self,
        welcomes: Vec<(GroupId, TransportMessage)>,
    ) -> AccountResult<Vec<(GroupId, TransportMessage)>> {
        let mut owed = Vec::with_capacity(welcomes.len());
        for (group_id, welcome) in welcomes {
            if !self.welcome_past_deadline(&welcome.id)? {
                owed.push((group_id, welcome));
            }
        }
        Ok(owed)
    }

    /// Re-publish a stored welcome whose original delivery failed after its
    /// commit was already confirmed (mdk#352).
    ///
    /// The wrapped welcome is loaded from the engine's sent-message store, so
    /// no re-commit happens and no pending confirm/rollback lifecycle is
    /// involved — the group evolution this welcome belongs to was confirmed
    /// when the failure was recorded. A re-delivery that again misses the ack
    /// threshold records a fresh [`WelcomeDeliveryFailure`] on the returned
    /// effects, so the caller can keep retrying from the same handle. A
    /// Welcome a detached wave holds is left to that wave: nothing is
    /// published and no failure is recorded.
    pub async fn redeliver_welcome(
        &mut self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        // An expired Welcome is never published again: nothing is published
        // and no failure recorded. One this call finds past its deadline is
        // marked expired and recorded here (mdk#3589), after any acceptance
        // it holds is reconciled, unless that acceptance or a wave may still
        // deliver it, so a clock set back before the next maintenance pass
        // cannot let a second call publish it.
        let now = self.wall_clock.now();
        match self.session.outbound_welcome_status(message_id, now)? {
            OutboundWelcomeStatus::Settled(WelcomeSettlement::Expired) => return Ok(output),
            OutboundWelcomeStatus::PastDeadline => {
                // An acceptance it holds was reconciled, or a wave holding it
                // settles it: nothing to publish.
                if self.expired_welcome_may_still_close(message_id) {
                    return Ok(output);
                }
                if self.session.expire_sent_welcome(message_id, now)?.is_some() {
                    self.record_welcome_expiry_or_retry(message_id);
                    return Ok(output);
                }
                // Not owed (staged with its commit): refused below, as before.
            }
            _ => {}
        }
        let (group_id, message) = self.session.stored_sent_welcome(message_id)?;
        // A detached wave holds this Welcome: it is the Welcome's one
        // publisher, and until it settles the Welcome is in flight, not
        // undelivered.
        if self.session.detached_welcome_publishes.contains(message_id) {
            return Ok(output);
        }
        // `stored_sent_welcome` only returns welcome envelopes.
        let recipient = welcome_recipient(&message);
        let failures_before = output.failures.len();
        // This is an explicit operator/user retry, so do not make the caller
        // wait for the automatic fanout backoff window. The original exact
        // Welcome and target snapshot are still reused.
        let status = self
            .publish_one_with_retry_policy(message, &mut output, None, true)
            .await?;
        // The attempt that met the policy marked the Welcome delivered.
        if !status.met_required_acks
            && !status.withdrawn
            && !self.welcome_past_deadline_now(message_id)
            && let Some(recipient) = recipient
        {
            let failure = self.welcome_delivery_failure(
                message_id.clone(),
                recipient,
                Some(group_id),
                &output,
                failures_before,
            );
            output.welcome_failures.push(failure);
        }
        Ok(output)
    }

    /// Withdraw one retained delivery-aware outbound Welcome (see
    /// `Engine::withdraw_sent_welcome`), owed or still staged with its
    /// commit, so that no path publishes it again: not
    /// startup recovery, maintenance retries, explicit redelivery, nor
    /// release after its commit confirms. Its remaining relay retries are
    /// dropped with it. A relay attempt already started cannot be recalled;
    /// a detached wave skips every attempt it has not started.
    ///
    /// A Welcome whose stored relay acceptances already meet its policy,
    /// its delivered mark interrupted, is marked delivered instead and
    /// reported `AlreadyDelivered`.
    ///
    /// This touches only the Welcome, never group state, so it works before
    /// hydration reaches the Welcome's group.
    pub fn withdraw_welcome(
        &self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<WelcomeWithdrawal> {
        // A prepared Welcome has only a local row until the commit's fanout
        // binds it. Binding preserves a withdrawn row's state.
        if let Some(seal) = self
            .prepared_welcome_seals
            .values()
            .flat_map(|seals| &seals.sealed)
            .find(|seal| &seal.message.id == message_id)
        {
            return Ok(self.session.withdraw_sent_welcome(&seal.local_id)?);
        }
        // Relays that already took it make it delivered, not withdrawn: a
        // saved acceptance that meets its policy, whose mark a stop
        // interrupted, is reconciled first. A record that cannot be read now
        // does not stop the withdrawal.
        let fanout = self.session.transport_fanout(message_id);
        if let Ok(Some(fanout)) = &fanout {
            self.settle_met_welcome(
                &fanout.exact_message,
                accepted_fanout_targets(fanout),
                fanout.required_acks,
            );
        }
        // An acceptance whose delivered mark did not land, or a record that
        // cannot be read now, may still deliver it.
        let may_deliver = match &fanout {
            Ok(Some(fanout)) => accepted_fanout_targets(fanout) >= fanout.required_acks.max(1),
            Ok(None) => false,
            Err(_) => true,
        };
        // Read before the withdrawal hides it, from the stored rows, so a
        // group not loaded yet reads as its rows stand: one past its deadline
        // ends expired, not withdrawn.
        let now = self.wall_clock.now();
        let status = self.session.stored_outbound_welcome_status(message_id, now);
        // A Welcome past its deadline has expired, which is why it was never
        // delivered: withdrawing it marks and records that expiry, once, even
        // while a wave holds it, since the withdrawal stops that wave too,
        // unless `may_deliver`. A record step that fails now is retried by
        // the watcher or the next start; a mark that cannot be written fails
        // the call.
        if matches!(status, Ok(OutboundWelcomeStatus::PastDeadline))
            && !may_deliver
            && self.session.expire_sent_welcome(message_id, now)?.is_some()
        {
            self.record_welcome_expiry_or_retry(message_id);
            if !self.session.detached_welcome_publishes.contains(message_id) {
                self.session.delete_transport_fanout(message_id)?;
            }
            return Ok(WelcomeWithdrawal::Withdrawn);
        }
        // The Welcome's terminal reason, as its row will read: `withdrawn`
        // for a live one, or one past its deadline withdrawn as is; for one
        // whose commit lost that the watcher has not recorded yet, that. One
        // no watcher holds was recorded when it settled, or settled before
        // this process watched it. An expired one was recorded when marked.
        let reason = match status {
            _ if !self.audit.records_v5() => None,
            Ok(
                OutboundWelcomeStatus::Owed { .. }
                | OutboundWelcomeStatus::Waiting
                | OutboundWelcomeStatus::PastDeadline,
            ) => Some(audit_v5::WithdrawalReason::Withdrawn),
            Ok(OutboundWelcomeStatus::Settled(WelcomeSettlement::CommitSuperseded))
                if self.watched_welcomes.contains(message_id) =>
            {
                Some(audit_v5::WithdrawalReason::CommitSuperseded)
            }
            _ => None,
        };
        let withdrawal = self.session.withdraw_sent_welcome(message_id)?;
        self.note_welcome_delivery_changed(message_id);
        if withdrawal == WelcomeWithdrawal::AlreadyDelivered {
            return Ok(withdrawal);
        }
        if withdrawal == WelcomeWithdrawal::Withdrawn
            && let Some(reason) = reason
        {
            self.record_v5_welcome_withdrawal(message_id, reason);
        }
        // A reserved wave owns its fanout until finish; maintenance prunes
        // the withdrawn retry after that reservation is released.
        if !self.session.detached_welcome_publishes.contains(message_id) {
            self.session.delete_transport_fanout(message_id)?;
        }
        Ok(withdrawal)
    }

    /// The retained outbound Welcomes of `group_id` answering the KeyPackage
    /// whose `KeyPackageRef` is `key_package_ref` (see
    /// `Engine::sent_welcomes_for_key_package`), for a caller that lost a
    /// Welcome's id and still has to withdraw it. Like withdrawal, it works
    /// before hydration reaches the group.
    pub fn welcomes_for_key_package(
        &self,
        group_id: &GroupId,
        key_package_ref: &[u8],
    ) -> AccountResult<Vec<cgka_traits::MessageId>> {
        Ok(self
            .session
            .sent_welcomes_for_key_package(group_id, key_package_ref)?)
    }

    /// Retained outbound Welcome obligations that have not met their
    /// acknowledgement policy and are not past their delivery deadline.
    /// Unlike app projections, this list is rooted in the engine transaction
    /// that made the corresponding group state canonical, so non-app callers
    /// and cold restarts can recover it.
    pub fn outstanding_welcome_deliveries(
        &self,
    ) -> AccountResult<Vec<(GroupId, TransportMessage)>> {
        self.welcomes_before_deadline(self.session.outstanding_sent_welcomes()?)
    }

    /// IDs of delivery-aware outbound Welcomes, including completed ones.
    ///
    /// This lets app projections clear a completed founding intent without
    /// disturbing older pending-delivery rows whose engine payloads predate
    /// delivery-aware tagging.
    pub fn tracked_outbound_welcome_ids(&self) -> AccountResult<Vec<cgka_traits::MessageId>> {
        Ok(self.session.tracked_outbound_welcome_ids()?)
    }

    /// Outstanding Welcome obligations and tracked IDs from one engine scan.
    /// A Welcome past its delivery deadline is tracked but not outstanding.
    pub fn welcome_delivery_index(&self) -> AccountResult<crate::session::WelcomeDeliveryIndex> {
        let mut index = self.session.welcome_delivery_index()?;
        index.outstanding = self.welcomes_before_deadline(index.outstanding)?;
        Ok(index)
    }

    /// Delivery is already externally visible when this runs. A local state
    /// write failure must therefore leave the Welcome conservatively retryable
    /// rather than turn canonical creation/evolution into a false hard error.
    pub(super) fn mark_welcome_delivered_best_effort(&self, message_id: &cgka_traits::MessageId) {
        if let Err(error) = self.session.mark_sent_welcome_delivered(message_id) {
            tracing::warn!(
                target: TRACE_TARGET,
                method = "mark_welcome_delivered_best_effort",
                transient = error.is_transient(),
                "acknowledged Welcome remains conservatively retryable"
            );
        }
        self.note_welcome_delivery_changed(message_id);
    }

    /// Build the structured re-delivery record for a welcome that just failed
    /// to publish, pairing the recipient with the reason `publish_one` pushed.
    pub(super) fn welcome_delivery_failure(
        &self,
        message_id: cgka_traits::MessageId,
        recipient: MemberId,
        group_id: Option<GroupId>,
        output: &AccountDeviceEffects,
        failures_before: usize,
    ) -> WelcomeDeliveryFailure {
        // `publish_one` pushes exactly one `PublishFailure` on each failing
        // path (routing, adapter, required_acks); the defensive fallback only
        // guards against that contract changing.
        let failure = output.failures.get(failures_before..).and_then(|failures| {
            failures
                .iter()
                .rev()
                .find(|failure| failure.message_id == message_id)
        });
        let reason = failure
            .map(|failure| failure.reason.clone())
            .unwrap_or_else(|| "welcome publish failed".into());
        let group_id = group_id.or_else(|| {
            self.session
                .stored_sent_welcome(&message_id)
                .ok()
                .map(|(group_id, _)| group_id)
        });
        WelcomeDeliveryFailure {
            size_class: failure
                .and_then(|failure| failure.oversized)
                .filter(|cause| cause.artifact == super::OversizedArtifact::Welcome)
                .map(|cause| cause.size_class),
            message_id,
            recipient,
            group_id,
            reason,
        }
    }

    /// Startup pass: one read of the message store prepares a detached retry
    /// of every owed Welcome not past its delivery deadline, as
    /// [`Self::prepare_welcome_retry_task_with_audit_context`] does, and
    /// watches every staged or owed one, so maintenance publishes each once it
    /// is owed, unless an attempt record holds it by then. It marks and
    /// records the expiry of every one past its deadline itself, and records
    /// every mark a stop left unrecorded, once each (mdk#3589); only what
    /// cannot be done now is left to maintenance. The retry respects
    /// each relay's backoff. Returns the owed Welcomes' ids beside the task, or
    /// `None` when nothing is owed.
    #[doc(hidden)]
    pub fn prepare_owed_welcome_retry_task_with_audit_context(
        &mut self,
        context: AuditEventContext,
    ) -> AccountResult<Option<(Vec<cgka_traits::MessageId>, PreparedWelcomePublishTask)>>
    where
        A: Clone + 'static,
    {
        let work = self.session.outbound_welcome_work()?;
        self.adopt_unrecorded_expiries();
        self.welcome_store_read = true;
        self.unread_welcome_groups = work.unread_groups;
        self.adopt_stored_welcomes(work.staged);
        self.adopt_stored_welcomes(work.owed.iter().map(|(_, welcome)| welcome.id.clone()));
        let owed = self.welcomes_before_deadline(work.owed)?;
        if owed.is_empty() {
            return Ok(None);
        }
        let (groups, welcomes): (Vec<_>, Vec<_>) = owed.into_iter().unzip();
        let ids = welcomes.iter().map(|welcome| welcome.id.clone()).collect();
        let mut prepared = self.prepare_welcome_publish(welcomes, None, Some(context))?;
        // The retry spans groups: each Welcome keeps its own, so a host can
        // drop the results of a group it left while the retry ran.
        for (metadata, group_id) in prepared.metadata.iter_mut().zip(groups) {
            metadata.group_id = Some(group_id);
        }
        let task = self.reserve_welcome_publish_task(Arc::new(self.adapter.clone()), prepared);
        Ok(Some((ids, task)))
    }

    /// Watch Welcomes until each is settled. The runtime watches those it
    /// stages with a commit: the caller
    /// publishes them only if the commit was published, and a commit left
    /// for retry confirms later.
    /// Each also gets its delivery record ([`Self::record_new_welcomes`]).
    pub(super) fn watch_welcomes(&mut self, ids: impl IntoIterator<Item = cgka_traits::MessageId>) {
        let ids = ids.into_iter().collect::<Vec<_>>();
        self.record_new_welcomes(&ids);
        for id in ids {
            if !self.watched_welcomes.contains(&id) {
                self.watched_welcomes.push(id);
            }
        }
    }

    /// Watch Welcomes read from the store, except one already settled: it
    /// settled before this process watched it, and a later start reads it
    /// again, so its settlement is neither this process's to audit nor to
    /// announce. A host reads it from the delivery query. The exception is
    /// expiry, which is recorded once from its durable mark (mdk#3589): one
    /// whose deadline passed while no process ran is marked and recorded
    /// here, unless an acceptance may still deliver it, and so is one marked
    /// before a stop that came before its record. Whatever cannot be done now
    /// is left to the watcher.
    fn adopt_stored_welcomes(&mut self, ids: impl IntoIterator<Item = cgka_traits::MessageId>) {
        let now = self.wall_clock.now();
        for id in ids {
            if self.watched_welcomes.contains(&id) {
                continue;
            }
            let settled = match self.session.outbound_welcome_status(&id, now) {
                Ok(OutboundWelcomeStatus::Settled(WelcomeSettlement::Expired)) => {
                    self.expire_welcome(&id, now)
                }
                Ok(OutboundWelcomeStatus::PastDeadline) => {
                    !self.expired_welcome_may_still_close(&id) && self.expire_welcome(&id, now)
                }
                Ok(OutboundWelcomeStatus::Settled(_)) => true,
                _ => false,
            };
            if !settled {
                self.watched_welcomes.push(id);
            }
        }
    }

    /// [`Self::record_welcome_expiry`] for a Welcome this call just marked,
    /// leaving it for the next pass to record if that cannot be done now.
    fn record_welcome_expiry_or_retry(&self, message_id: &cgka_traits::MessageId) {
        if !self.record_welcome_expiry(message_id) {
            self.expiries_to_record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(message_id.clone());
        }
    }

    /// Whether the search for unrecorded Welcome expiries still has work: it
    /// ran and could not read the group list, a group could not be read, or
    /// a mark is left to record. A search not yet run is not owed: the
    /// startup pass or the first maintenance pass runs it.
    pub(super) fn welcome_expiries_unfinished(&self) -> bool {
        (self.welcome_store_read && !self.welcome_expiries_read)
            || !self.unread_expiry_groups.is_empty()
            || !self
                .expiries_to_record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
    }

    /// Watch every Welcome marked expired whose expiry a stop left
    /// unrecorded, so it is recorded: every group's on the first call, then,
    /// on each later call, each group whose rows could not be read before,
    /// until they read. A read that fails is logged and stops nothing else:
    /// owed Welcomes are read and published as usual.
    fn adopt_unrecorded_expiries(&mut self) {
        let to_record = std::mem::take(
            &mut *self
                .expiries_to_record
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        self.adopt_stored_welcomes(to_record);
        for group_id in std::mem::take(&mut self.unread_expiry_groups) {
            match self.session.unrecorded_welcome_expiries_in(&group_id) {
                Ok(ids) => self.adopt_stored_welcomes(ids),
                Err(error) => {
                    log_unread_welcome_expiries(1, Some(&error));
                    self.unread_expiry_groups.push(group_id);
                }
            }
        }
        if self.welcome_expiries_read {
            return;
        }
        match self.session.unrecorded_welcome_expiries() {
            Ok(found) => {
                self.welcome_expiries_read = true;
                if !found.unread_groups.is_empty() {
                    log_unread_welcome_expiries(found.unread_groups.len(), None);
                }
                self.unread_expiry_groups = found.unread_groups;
                self.adopt_stored_welcomes(found.ids);
            }
            Err(error) => log_unread_welcome_expiries(0, Some(&error)),
        }
    }

    /// Read the store for Welcomes to watch: all of it the first time, unless
    /// the startup pass did, then each group a read skipped, once it is live.
    fn read_welcome_store(&mut self) -> AccountResult<()> {
        self.adopt_unrecorded_expiries();
        if !self.welcome_store_read {
            let work = self.session.outbound_welcome_work()?;
            self.welcome_store_read = true;
            self.unread_welcome_groups = work.unread_groups;
            self.adopt_stored_welcomes(work.staged);
            self.adopt_stored_welcomes(work.owed.into_iter().map(|(_, welcome)| welcome.id));
        }
        for group_id in std::mem::take(&mut self.unread_welcome_groups) {
            match self.session.outbound_welcome_work_in(&group_id) {
                Ok(Some(work)) => {
                    self.adopt_stored_welcomes(work.staged);
                    self.adopt_stored_welcomes(
                        work.owed.into_iter().map(|(_, welcome)| welcome.id),
                    );
                }
                Ok(None) => self.unread_welcome_groups.push(group_id),
                Err(error) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "read_welcome_store",
                        transient = error.is_transient(),
                        "group Welcome read failed"
                    );
                    self.unread_welcome_groups.push(group_id);
                }
            }
        }
        Ok(())
    }

    /// Seal and bind founding Welcomes a create left unsealed, because its
    /// seal failed or the process stopped first, and watch them so this pass
    /// publishes them. One that fails to seal stays owed for the next pass
    /// and holds back none of the others.
    async fn seal_owed_welcomes(&mut self) -> AccountResult<bool> {
        let messages = self.session.seal_owed_founding_welcomes().await?;
        self.note_retained_welcomes(messages.iter(), None);
        Ok(!messages.is_empty())
    }

    /// Publish each watched Welcome that is owed and that no attempt record
    /// holds. A Welcome stays watched until its row is settled. While a stored
    /// fanout or a detached wave holds it, that record retries it;
    /// once none does, as after a fanout that expired, the next pass publishes
    /// it again, as the startup pass would. One whose last publish found no
    /// route waits for its recipient's paced retry (`welcome_routes`).
    pub(super) async fn deliver_watched_welcomes(
        &mut self,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        self.read_welcome_store()?;
        self.drive_watched_welcomes(output).await?;
        // The owner starts detached waves only after maintenance returns.
        if !self.prepared_welcome_tasks.is_empty() {
            return Ok(());
        }
        if self.seal_owed_welcomes().await? {
            self.drive_watched_welcomes(output).await?;
        }
        Ok(())
    }

    async fn drive_watched_welcomes(
        &mut self,
        output: &mut AccountDeviceEffects,
    ) -> AccountResult<()> {
        let mut due: Vec<(GroupId, Vec<TransportMessage>)> = Vec::new();
        let mut watching = Vec::with_capacity(self.watched_welcomes.len());
        // The recipients of every owed Welcome, unless a status read failed.
        let mut owed_recipients = Some(HashSet::new());
        for id in std::mem::take(&mut self.watched_welcomes) {
            let now = self.wall_clock.now();
            let status = self
                .session
                .outbound_welcome_status(&id, now)
                .and_then(|status| {
                    let held = matches!(status, OutboundWelcomeStatus::Owed { .. })
                        && (self.session.detached_welcome_publishes.contains(&id)
                            || self.session.transport_fanout(&id)?.is_some());
                    Ok((status, held))
                });
            match status {
                Ok((OutboundWelcomeStatus::PastDeadline, _))
                    if self.expired_welcome_may_still_close(&id) =>
                {
                    // Marked once a delivered mark or the pass settles it.
                    watching.push(id);
                }
                Ok((
                    OutboundWelcomeStatus::PastDeadline
                    | OutboundWelcomeStatus::Settled(WelcomeSettlement::Expired),
                    _,
                )) => {
                    if !self.expire_welcome(&id, now) {
                        watching.push(id);
                    }
                }
                Ok((OutboundWelcomeStatus::Settled(settlement), _)) => {
                    // Its watch ends only once a host is told and the
                    // settlement recorded; the notice goes first, so a retry
                    // never records the settlement twice.
                    if !self.note_welcome_delivery_changed(&id)
                        || !self.record_v5_welcome_settled(&id, settlement)
                    {
                        watching.push(id);
                    }
                }
                Ok((OutboundWelcomeStatus::Waiting, _)) => watching.push(id),
                Ok((OutboundWelcomeStatus::Owed { group_id, message }, held)) => {
                    watching.push(id);
                    if let (Some(owed), Some(recipient)) =
                        (owed_recipients.as_mut(), welcome_recipient(&message))
                    {
                        owed.insert(recipient);
                    }
                    if held || self.welcome_route_retry_holds(&message) {
                        continue;
                    }
                    match due.iter_mut().find(|(group, _)| *group == group_id) {
                        Some((_, welcomes)) => welcomes.push(message),
                        None => due.push((group_id, vec![message])),
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        target: TRACE_TARGET,
                        method = "deliver_watched_welcomes",
                        transient = error.is_transient(),
                        "watched Welcome status unreadable"
                    );
                    owed_recipients = None;
                    watching.push(id);
                }
            }
        }
        self.watched_welcomes = watching;
        if let Some(owed) = owed_recipients {
            self.retain_welcome_route_retries(&owed);
        }
        for (group_id, welcomes) in due {
            self.publish_welcome_fanout(welcomes, Some(group_id), output, None)
                .await?;
        }
        Ok(())
    }
}

/// A search for unrecorded Welcome expiries that could not read `groups`
/// groups (0: the group list itself), retried on the next maintenance pass.
fn log_unread_welcome_expiries(groups: usize, error: Option<&crate::session::SessionError>) {
    tracing::warn!(
        target: TRACE_TARGET,
        method = "adopt_unrecorded_expiries",
        groups,
        transient = error.map(crate::session::SessionError::is_transient),
        "unrecorded Welcome expiries not read; retried on a later pass"
    );
}
