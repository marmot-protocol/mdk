//! Outbound Welcome delivery (mdk#2628 item 3.5a).
//!
//! The engine's Welcome row is the obligation: staged with its commit, owed
//! once the commit confirms (or at a founding create), delivered, or
//! withdrawn. Every publish reads that row first (`welcome_hold`), so a
//! withdrawn Welcome never goes out again and a staged one waits for its
//! commit. Per-endpoint attempts and backoff live on the Welcome's
//! `DurableTransportFanout`, which maintenance retries.

use super::*;

/// Why a Welcome is not published (see `welcome_hold`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WelcomeHold {
    /// Withdrawn, or retired with its rolled-back commit: never published
    /// again, and nothing is owed.
    Withdrawn,
    /// Staged with its unconfirmed invite commit: held until the commit
    /// confirms and promotes it (mdk#2726).
    AwaitsCommit,
}

impl<A, R, K> AccountDeviceRuntime<A, R, K>
where
    A: TransportAdapter,
    R: TransportRoutingPolicy,
    K: KeyPackagePublisher,
{
    /// Publish previously deferred Welcome obligations with bounded concurrency.
    pub async fn publish_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, group_id, &mut output, Some(context), false)
            .await?;
        Ok(output)
    }

    /// Retry retained Welcome obligations immediately with the shared bounded
    /// fanout, bypassing the automatic backoff for this explicit startup pass.
    pub async fn retry_welcome_messages_with_audit_context(
        &mut self,
        welcomes: Vec<TransportMessage>,
        context: AuditEventContext,
    ) -> AccountResult<AccountDeviceEffects> {
        let mut output = AccountDeviceEffects::default();
        self.publish_welcome_fanout(welcomes, None, &mut output, Some(context), true)
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
        let prepared = self.prepare_welcome_publish(welcomes, None, Some(context), true)?;
        let message_ids = prepared.network_message_ids();
        self.detached_welcome_publishes
            .extend(message_ids.iter().cloned());
        Ok(PreparedWelcomePublishTask {
            adapter: Arc::new(self.adapter.clone()),
            prepared,
            message_ids,
            withdrawals: self.detached_welcome_withdrawals.clone(),
        })
    }

    /// Reconcile every relay result from a detached Welcome publish in input
    /// order, then release its in-memory exact-event reservations.
    #[doc(hidden)]
    pub async fn finish_welcome_publish_task(
        &mut self,
        task: CompletedWelcomePublishTask,
    ) -> AccountResult<AccountDeviceEffects> {
        let CompletedWelcomePublishTask {
            completed,
            message_ids,
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
        let mut withdrawals = self
            .detached_welcome_withdrawals
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for message_id in message_ids {
            self.detached_welcome_publishes.remove(message_id);
            withdrawals.remove(message_id);
        }
    }

    /// Bounded-concurrency Welcome publication used by founding creates and by
    /// deferred existing-group invite fanout after the commit is confirmed.
    pub(super) async fn publish_welcome_fanout(
        &mut self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        output: &mut AccountDeviceEffects,
        context: Option<AuditEventContext>,
        force_retry: bool,
    ) -> AccountResult<()> {
        let prepared = self.prepare_welcome_publish(welcomes, group_id, context, force_retry)?;
        let completed = prepared.publish(&self.adapter, None).await;
        self.finish_welcome_publish(completed, output).await
    }

    pub(super) fn prepare_welcome_publish(
        &self,
        welcomes: Vec<TransportMessage>,
        group_id: Option<GroupId>,
        context: Option<AuditEventContext>,
        force_retry: bool,
    ) -> AccountResult<PreparedWelcomePublish> {
        let mut metadata = Vec::with_capacity(welcomes.len());
        let mut completions = Vec::with_capacity(welcomes.len());
        completions.resize_with(welcomes.len(), || None);
        let mut pending = VecDeque::new();
        for (index, welcome) in welcomes.into_iter().enumerate() {
            let recipient = welcome_recipient(&welcome);
            let welcome_id = welcome.id.clone();
            let mut effects = AccountDeviceEffects::default();
            match self.prepare_legacy_publish(
                welcome,
                &mut effects,
                context.clone(),
                force_retry,
            )? {
                PreparedLegacyPublish::Complete(status) => {
                    completions[index] = Some(LegacyPublishCompletion::Complete(status));
                }
                PreparedLegacyPublish::Network(attempt) => pending.push_back((index, attempt)),
            }
            metadata.push(WelcomePublishMetadata {
                recipient,
                welcome_id,
                effects,
            });
        }

        Ok(PreparedWelcomePublish {
            group_id,
            metadata,
            completions,
            pending,
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
                mut effects,
            } = metadata;
            let status = match completion.expect("every Welcome publish completed") {
                LegacyPublishCompletion::Complete(status) => Ok(status),
                LegacyPublishCompletion::Network(attempt, result) => {
                    self.finish_prepared_legacy_publish(*attempt, result, &mut effects)
                        .await
                }
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
            if let Some(status) = status
                && !status.withdrawn
                && !status.awaits_commit
            {
                if status.met_required_acks {
                    self.mark_welcome_delivered_best_effort(&welcome_id);
                } else if let Some(recipient) = recipient {
                    effects.welcome_failures.push(self.welcome_delivery_failure(
                        welcome_id,
                        recipient,
                        group_id.clone(),
                        &effects,
                        0,
                    ));
                }
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
    /// stored fanout.
    pub(super) fn welcome_hold(
        &self,
        message_id: &cgka_traits::MessageId,
        envelope: &TransportEnvelope,
    ) -> AccountResult<Option<WelcomeHold>> {
        if !matches!(envelope, TransportEnvelope::Welcome { .. }) {
            return Ok(None);
        }
        if self.session.sent_welcome_withdrawn(message_id)? {
            return Ok(Some(WelcomeHold::Withdrawn));
        }
        if self.session.sent_welcome_awaits_commit(message_id)? {
            return Ok(Some(WelcomeHold::AwaitsCommit));
        }
        Ok(None)
    }

    /// Re-publish a stored welcome whose original delivery failed after its
    /// commit was already confirmed (mdk#352).
    ///
    /// The wrapped welcome is loaded from the engine's sent-message store, so
    /// no re-commit happens and no pending confirm/rollback lifecycle is
    /// involved — the group evolution this welcome belongs to was confirmed
    /// when the failure was recorded. A re-delivery that again misses the ack
    /// threshold records a fresh [`WelcomeDeliveryFailure`] on the returned
    /// effects, so the caller can keep retrying from the same handle.
    pub async fn redeliver_welcome(
        &mut self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<AccountDeviceEffects> {
        let (group_id, message) = self.session.stored_sent_welcome(message_id)?;
        // `stored_sent_welcome` only returns welcome envelopes.
        let recipient = welcome_recipient(&message);
        let mut output = AccountDeviceEffects::default();
        let failures_before = output.failures.len();
        // This is an explicit operator/user retry, so do not make the caller
        // wait for the automatic fanout backoff window. The original exact
        // Welcome and target snapshot are still reused.
        let status = self
            .publish_one_with_retry_policy(message, &mut output, None, true)
            .await?;
        if status.met_required_acks {
            self.mark_welcome_delivered_best_effort(message_id);
        } else if !status.withdrawn
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
    /// a detached startup retry skips every attempt it has not started.
    ///
    /// This touches only the Welcome, never group state, so it works before
    /// hydration reaches the Welcome's group.
    pub fn withdraw_welcome(
        &self,
        message_id: &cgka_traits::MessageId,
    ) -> AccountResult<WelcomeWithdrawal> {
        let withdrawal = self.session.withdraw_sent_welcome(message_id)?;
        if withdrawal == WelcomeWithdrawal::AlreadyDelivered {
            return Ok(withdrawal);
        }
        if self.detached_welcome_publishes.contains(message_id) {
            // A detached startup publish holds the Welcome and its record: it
            // skips the attempt if not started, and the next maintenance pass
            // drops the record.
            self.detached_welcome_withdrawals
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .insert(message_id.clone());
        } else {
            self.session.delete_transport_fanout(message_id)?;
        }
        Ok(withdrawal)
    }

    /// Retained outbound Welcome obligations that have not met their
    /// acknowledgement policy. Unlike app projections, this list is rooted in
    /// the engine transaction that made the corresponding group state
    /// canonical, so non-app callers and cold restarts can recover it.
    pub fn outstanding_welcome_deliveries(
        &self,
    ) -> AccountResult<Vec<(GroupId, TransportMessage)>> {
        Ok(self.session.outstanding_sent_welcomes()?)
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
    pub fn welcome_delivery_index(&self) -> AccountResult<crate::session::WelcomeDeliveryIndex> {
        Ok(self.session.welcome_delivery_index()?)
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
        let reason = output
            .failures
            .get(failures_before..)
            .and_then(<[PublishFailure]>::last)
            .map(|failure| failure.reason.clone())
            .unwrap_or_else(|| "welcome publish failed".into());
        WelcomeDeliveryFailure {
            message_id,
            recipient,
            group_id,
            reason,
        }
    }
}
