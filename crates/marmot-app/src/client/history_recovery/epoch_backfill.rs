//! Epoch-gap backfill on the account client: feeding the stall detector,
//! arming and escalating epoch-gap backfill, persisting the detector's
//! evidence, and retiring a terminal group's recovery (mdk#2782).

use std::collections::HashSet;

use cgka_traits::GroupId;
use cgka_traits::ingest::IngestOutcome;
use marmot_forensics::{AuditEventContext, EpochStallBackfillTrigger};

use super::epoch_stall::BackfillDecision;
use crate::client::AppClient;
use crate::client::sync::{EpochBackfillRunOutcome, epoch_stall_now_ms};
use crate::config::CursorPersistence;
use crate::{AppError, SyncSummary};

impl AppClient {
    /// Feed one effects batch's epoch-gap recovery evidence to the stall
    /// detector: a resource refusal arms a replay, and an epoch passage or a
    /// convergence reorg reports the activity that can end an unrecovered run.
    ///
    /// Both directions matter, and only this seam carries the second one. A
    /// delivery reports the epoch it was *read* at, which is where the device
    /// already sits; the epochs a fold, a confirmed publish, or a maintenance
    /// tick's own evolution carried it *through* are read at by nothing, so
    /// without the engine's own `EpochChanged` the detector cannot tell a device
    /// that recovered from one that is still stuck (see
    /// [`EpochStallDetector::observe_epoch_passage`](super::epoch_stall::EpochStallDetector::observe_epoch_passage)).
    /// Of the three emitting sites only a convergence reorg spans more than one
    /// epoch; publish-confirm and peer-commit ingest are always adjacent, which
    /// is the case the passage rule is tuned for.
    ///
    /// Events are consumed in engine order, so a passage later in the same batch
    /// supersedes an arm an earlier refusal just made: the durable
    /// `epoch_stall_backfill_armed` row still records that the replay was armed,
    /// while the detector's run counter starts over. That split is intended — the
    /// arm happened and stays on the forensic record, and the run is what the
    /// later evidence contradicts.
    pub(crate) fn observe_recovery_evidence(
        &mut self,
        effects: &marmot_session::AccountDeviceEffects,
    ) {
        // Every engine effect passes here. A group's lifecycle decides what the
        // recovery runner may serve, so it reads its debt again.
        if effects.events.iter().any(|event| {
            use cgka_traits::engine::GroupEvent;
            matches!(
                event,
                GroupEvent::GroupCreated { .. }
                    | GroupEvent::GroupJoined { .. }
                    | GroupEvent::LocalGroupCopyTerminated { .. }
                    | GroupEvent::LocalGroupCopyRestored { .. }
                    | GroupEvent::GroupUnrecoverable { .. }
                    | GroupEvent::GroupStateInvalidated { .. }
                    | GroupEvent::GroupStateRevalidated { .. }
            )
        }) {
            self.wake_recovery_runner();
        }
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        for event in &effects.events {
            use cgka_traits::engine::GroupEvent;
            let transition = match event {
                GroupEvent::GroupStateInvalidated { .. } => Some(("invalidation", "performed")),
                GroupEvent::GroupStateRevalidated { .. } => Some(("revalidation", "success")),
                GroupEvent::GroupUnrecoverable { .. } => Some(("unrecoverable", "failure")),
                GroupEvent::PendingCommitRecovered { .. } => Some(("pending_commit", "success")),
                GroupEvent::GroupHydrationRecovered { .. } => Some(("hydration", "success")),
                _ => None,
            };
            if let Some((operation, outcome)) = transition {
                self.app.product_analytics.observe(
                    crate::ProductFamily::Recovery,
                    operation,
                    outcome,
                    crate::ProductUnit::Transition,
                    None,
                );
            }
            match event {
                cgka_traits::engine::GroupEvent::EpochChanged { group_id, from, to } => {
                    self.history_recovery
                        .state
                        .epoch_stall
                        .observe_epoch_passage(group_id, *from, *to);
                }
                cgka_traits::engine::GroupEvent::TransportObjectResourceRefused {
                    group_id,
                    ..
                } => {
                    let Ok(record) = self.runtime.group_record(group_id) else {
                        continue;
                    };
                    // A terminal copy has no servable history, so arming here
                    // could only mint a durable intent and a forensic row for
                    // work that is never coming.
                    if record.is_terminal() {
                        continue;
                    }
                    // Recording the recovery intent before the recovery job
                    // acquires any history, and recording an
                    // escalation this arm raises, are both the shared decision
                    // handler's job: a resource-refusal arm counts toward the
                    // same unrecovered run as a deferred-delivery arm, and the
                    // detector raises the run's escalation only once, at
                    // whichever path happens to arm third.
                    let decision = self
                        .history_recovery
                        .state
                        .epoch_stall
                        .observe_resource_refusal(
                            group_id.clone(),
                            record.epoch,
                            epoch_stall_now_ms(),
                        );
                    self.apply_backfill_decision(
                        group_id,
                        record.epoch.0,
                        decision,
                        EpochStallBackfillTrigger::ResourceRefusal,
                    );
                }
                // A convergence reorg is the third kind of recovery evidence,
                // and the only one that never moves an epoch. Branch selection
                // superseded an authenticated commit this device had applied;
                // when the two branches carry the same epoch number the engine
                // emits no `EpochChanged` for it at all, so without this arm a
                // device that just crossed a fork resolution is indistinguishable
                // from one that saw nothing.
                //
                // Matching the withdrawal rather than its `CommitRolledBack`
                // twin is not a choice about which is better evidence: the
                // engine pushes the pair back to back, once per rolled-back
                // commit, with nothing fallible between them, so the two arms
                // would decide identically and the second would only re-decide
                // what the first already did.
                cgka_traits::engine::GroupEvent::GroupStateInvalidated {
                    group_id,
                    reason:
                        cgka_traits::engine::GroupStateInvalidationReason::SupersededByBranchSelection,
                    ..
                } => {
                    // Deliberately not fed the carried `epoch`: that is the
                    // source epoch of the fork the superseded commit lost, which
                    // sits *behind* where this device is now. The detector's
                    // observed epoch only ever moves forward, and handing it a
                    // backward position would walk the per-epoch suppression
                    // back with it.
                    self.history_recovery
                        .state
                        .epoch_stall
                        .observe_convergence_reorg(group_id);
                }
                _ => {}
            }
        }
    }

    /// Feed an unavailable group delivery to the epoch-stall detector.
    /// Transport-deferred input arms a backfill after the stalled-epoch
    /// threshold; resource refusal arms it immediately because it directly
    /// proves the fetched history was not fully retained. A deferral whose
    /// engine-reported lineage is fork-side arms on the same threshold and
    /// carries its own trigger — see
    /// [`backfill_trigger_for`](super::epoch_stall::backfill_trigger_for) for
    /// why the label moves and the decision does not. Repeated arming that
    /// never recovers the group escalates onto the next successful sync summary,
    /// the seam every worker surface already publishes. Only observed under
    /// `CursorPersistence::Advance`: a `Frozen` wake-collection pass must not
    /// own recovery. Its deferrals still reach the detector, but not on the
    /// main app's next sync, where they arrive as duplicates: the next
    /// `Advance` open rebuilds them from the retained rows instead
    /// ([`Self::seed_epoch_stall_from_deferred_rows`]).
    pub(in crate::client) fn detect_epoch_stall(
        &mut self,
        group_id_hint: Option<cgka_traits::GroupId>,
        message_id_hex: &str,
        outcome: &IngestOutcome,
        transport_at: cgka_traits::transport::Timestamp,
    ) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        let Some(group_id) = group_id_hint else {
            return;
        };
        // A group we cannot resolve (unknown or quarantined) has its own recovery
        // surface; do not track it here.
        let Ok(record) = self.runtime.group_record(&group_id) else {
            return;
        };
        // A terminal copy has no servable history, so arming here could only
        // mint a durable intent and a forensic row for work that is never
        // coming. Defense in depth: a removed copy classifies
        // `LocalState { Removed }` and a disbanded one
        // `Ignored { UnknownGroup }`, so both already reach the `Skip` arm
        // below.
        if record.is_terminal() {
            return;
        }
        // A contested fork is eligible local work, not proof of a missing
        // transport object. Independent existing loss/gap obligations survive.
        if crate::client::history_recovery::epoch_stall::backfill_trigger_for(outcome)
            == EpochStallBackfillTrigger::ContestedForkDeferral
        {
            self.history_recovery
                .state
                .epoch_stall
                .observe_group_epoch(&group_id, record.epoch);
            self.pending_convergence_groups.insert(group_id);
            return;
        }
        let now_ms = epoch_stall_now_ms();
        let decision = match outcome {
            // Traffic older than this copy's Welcome is expected after a join,
            // and after a re-add it is most of what the relay serves: the
            // absent stretch was sealed under epochs this copy never entered
            // and never will. Unopenable, but not evidence this device is
            // behind — and a backfill armed from it could only re-fetch more of
            // the same. Land the epoch like every other non-evidence outcome
            // below and stop there. Soft by design: an application message
            // carries its sender's compose time, so a message drained from the
            // offline outbox can look old while being live. Dropping one piece
            // of evidence costs nothing, because every other undecryptable
            // message this device receives still arms.
            IngestOutcome::TransportDeferred { .. }
                if record.transport_message_predates_local_copy(transport_at) =>
            {
                self.history_recovery
                    .state
                    .epoch_stall
                    .observe_group_epoch(&group_id, record.epoch);
                BackfillDecision::Skip
            }
            IngestOutcome::TransportDeferred { .. } => self
                .history_recovery
                .state
                .epoch_stall
                .observe_undecryptable(
                    group_id.clone(),
                    message_id_hex.to_owned(),
                    record.epoch,
                    now_ms,
                ),
            IngestOutcome::ResourceRefused { .. } => self
                .history_recovery
                .state
                .epoch_stall
                .observe_resource_refusal(group_id.clone(), record.epoch, now_ms),
            // Any other outcome carries no stall evidence, but it does tell the
            // detector where this device now sits. This is a landing position
            // only: the epochs a folded commit carried the device *through* reach
            // the detector as an `EpochChanged` passage, from this same delivery's
            // effects in `observe_recovery_evidence`. The landing report stays
            // because it is the fallback for movement no passage covers — an
            // engine seam that advances a group without emitting `EpochChanged`,
            // or a batch this delivery never sees — and because two landings at
            // different epochs can end a run on their own. Where both fire they
            // agree, since observing an epoch already recorded is a no-op.
            _ => {
                self.history_recovery
                    .state
                    .epoch_stall
                    .observe_group_epoch(&group_id, record.epoch);
                BackfillDecision::Skip
            }
        };
        self.apply_backfill_decision(
            &group_id,
            record.epoch.0,
            decision,
            crate::client::history_recovery::epoch_stall::backfill_trigger_for(outcome),
        );
    }

    /// Rebuild undecryptable-traffic evidence from durable deferred rows.
    ///
    /// [`Self::detect_epoch_stall`] counts only deferrals this process ingests
    /// in `Advance` mode. A `Frozen` wake (an iOS notification extension) still
    /// retains each undecryptable object as a `PeelDeferred` row, but when the
    /// main app next syncs those objects arrive as duplicates, so live
    /// detection never sees them. A device woken mostly by notifications then
    /// arms only when one app session happens to see enough live traffic
    /// (mdk#2257). This feeds the rows retained at each group's current epoch
    /// through the same detector and filters instead, for groups the detector
    /// has not already signalled at that epoch. It changes no durable state
    /// unless the detector arms.
    pub(crate) fn seed_epoch_stall_from_deferred_rows(&mut self) {
        if self.app.cursor_persistence() != CursorPersistence::Advance {
            return;
        }
        let limit = self.history_recovery.state.epoch_stall.threshold();
        let groups = self
            .state
            .groups
            .iter()
            .filter_map(|group| hex::decode(&group.group_id_hex).ok())
            .map(GroupId::new)
            .collect::<Vec<_>>();
        for group_id in groups {
            let Ok(evidence) = self.runtime.deferred_stall_evidence(&group_id, limit) else {
                continue;
            };
            // Retained rows supply only the first arm. Once this group has
            // signalled at the evidence epoch, here or in the durable state
            // restored before hydration, rows replayed on every later open are
            // not fresh traffic and must not pace re-arms or end the run.
            if evidence.rows.is_empty()
                || self
                    .history_recovery
                    .state
                    .epoch_stall
                    .has_signalled_at(&group_id, evidence.epoch)
            {
                continue;
            }
            let outcome = IngestOutcome::TransportDeferred {
                group_id: group_id.clone(),
                lineage: evidence.lineage,
            };
            for row in evidence.rows {
                self.detect_epoch_stall(
                    Some(group_id.clone()),
                    &hex::encode(row.message_id.as_slice()),
                    &outcome,
                    row.transport_timestamp,
                );
            }
        }
    }

    /// Apply an epoch-stall backfill decision: arm the replay, and record an
    /// escalation the detector raises.
    ///
    /// Every site that takes a [`BackfillDecision`] must route it through here.
    /// Callers guard `record.is_terminal()` before deciding — both already hold
    /// the group record, so re-reading it per arm here would buy nothing.
    /// The detector latches `escalated` when it raises
    /// [`BackfillDecision::ArmAndEscalate`], so it raises that decision exactly
    /// once per unrecovered run. That makes reporting exactly-once by
    /// construction rather than by caller discipline: the escalation lands in
    /// `pending_epoch_stall_escalations` instead of on whatever [`SyncSummary`]
    /// the calling pass is building, so a later `?` on that pass cannot drop it
    /// — it rides out on the next seam that returns `Ok` (see
    /// [`Self::drain_epoch_stall_escalations`]).
    pub(crate) fn apply_backfill_decision(
        &mut self,
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
        decision: BackfillDecision,
        trigger: EpochStallBackfillTrigger,
    ) {
        if decision == BackfillDecision::Reassess {
            self.pending_convergence_groups.insert(group_id.clone());
            self.persist_epoch_stall_evidence([group_id]);
        }
        if decision.arms_backfill() {
            let demand_ticket = |client: &Self| {
                client
                    .app
                    .account_storage(&client.state.label)
                    .ok()
                    .and_then(|storage| storage.app_storage().pending_recovery_demands().ok())
                    .and_then(|demands| {
                        demands.into_iter().find(|demand| {
                            demand.cause == storage_sqlite::RecoveryCause::EpochGap
                                && demand.group_id.as_deref() == Some(group_id.as_slice())
                        })
                    })
                    .map(|demand| demand.ticket)
            };
            let before = demand_ticket(self);
            let buffered_before = self
                .history_recovery
                .state
                .pending_recovery_arm_writes
                .get(group_id)
                .copied();
            let durable_intent = storage_sqlite::StoredEpochBackfillIntent {
                group_id_hex: hex::encode(group_id.as_slice()),
                stalled_epoch,
            };
            let result = self.arm_epoch_gap_recovery(std::slice::from_ref(&durable_intent));
            match result {
                Ok(()) => {
                    self.history_recovery
                        .state
                        .pending_recovery_arm_writes
                        .remove(group_id);
                }
                Err(error) => {
                    self.history_recovery
                        .state
                        .pending_recovery_arm_writes
                        .entry(group_id.clone())
                        .and_modify(|epoch| *epoch = (*epoch).max(stalled_epoch))
                        .or_insert(stalled_epoch);
                    tracing::warn!(target: "marmot_app::epoch_stall", method = "apply_backfill_decision",
                        error_kind = error.privacy_safe_kind(), "recovery demand persistence will be retried before acquisition");
                }
            }
            let after = demand_ticket(self);
            if before != after
                || buffered_before
                    != self
                        .history_recovery
                        .state
                        .pending_recovery_arm_writes
                        .get(group_id)
                        .copied()
            {
                let context = AuditEventContext {
                    operation_id: Some(hex::encode(
                        after
                            .map(|ticket| ticket.id)
                            .unwrap_or_else(rand::random::<[u8; 16]>),
                    )),
                    ..AuditEventContext::default()
                };
                self.record_epoch_stall_backfill_armed(group_id, stalled_epoch, trigger, &context);
            }
            // The arm mark is what paces the next one, so it has to outlive the
            // process: a device wedged for six hours must not buy a re-arm by
            // being force-killed.
            self.persist_epoch_stall_evidence(std::slice::from_ref(group_id));
        }
        if let BackfillDecision::ArmAndEscalate { arms } = decision {
            // The replay is armed above regardless: escalating reports that
            // replay alone is not repairing this group, it does not replace the
            // attempt (see EPOCH_STALL_ESCALATION_ARM_THRESHOLD for why
            // reporting is all this decision does).
            self.report_epoch_stall_escalation(
                group_id,
                stalled_epoch,
                arms,
                self.history_recovery
                    .state
                    .epoch_stall
                    .escalation_arm_threshold(),
                "apply_backfill_decision",
            );
        }
    }

    /// Report that repeated full-history replay is not recovering a group.
    ///
    /// Two rules reach here and the report they produce is deliberately the
    /// same shape, because the claim is the same one: this many armed
    /// full-history replays did not return this group to the tip. An arm run
    /// across moving epochs counts arms
    /// ([`EPOCH_STALL_ESCALATION_ARM_THRESHOLD`]); a group frozen at one epoch
    /// counts the relay-confirmed fruitless completions those arms produced
    /// ([`EPOCH_STALL_FRUITLESS_COMPLETION_THRESHOLD`]). The detector latches
    /// `escalated` for the run either way, so a run reports once.
    pub(crate) fn report_epoch_stall_escalation(
        &mut self,
        group_id: &cgka_traits::GroupId,
        stalled_epoch: u64,
        arms: u32,
        decided_by_threshold: u32,
        method: &'static str,
    ) {
        // The threshold logged is the one that actually decided, which is not
        // always the arm-run threshold the audit row carries: `method` names the
        // rule and this names the count it reached.
        tracing::warn!(
            target: "marmot_app::epoch_stall",
            method = method,
            arms,
            decided_by_threshold,
            "epoch-gap backfill armed repeatedly without recovering a group; escalating"
        );
        self.record_epoch_stall_backfill_escalated(group_id, stalled_epoch, arms);
        if self.host_may_see_group(group_id) {
            self.history_recovery
                .state
                .pending_epoch_stall_escalations
                .push(crate::EpochStallEscalation {
                    group_id: group_id.clone(),
                    stalled_epoch,
                    arms,
                });
        }
    }

    /// Merge durable arms into their existing retry owners. Counters describe
    /// account-wide replay attempts, so new groups get a fresh queued intent
    /// instead of inheriting another run's EOSE failures or resetting that run.
    ///
    /// Ends by dropping terminal groups. On a hydrated open that is also how a
    /// row for a group no owner holds is retired: this admits it, and the drop
    /// clears it. Before hydration every record reads non-terminal, so the row
    /// survives to the next pass.
    pub(crate) fn restore_persisted_epoch_backfill_intents(
        &mut self,
        _intents: Vec<storage_sqlite::StoredEpochBackfillIntent>,
    ) {
        // Demand is already authoritative in SQL. Hydration does not rebuild
        // an independent execution queue or reset retry cost.
        self.drop_settled_epoch_backfill_intents();
    }

    /// Write the detector's frozen-epoch evidence for `groups` to durable
    /// storage.
    ///
    /// Best-effort like the durable arm marker beside it: losing a row costs
    /// the affected group one more paced attempt after a restart, which is the
    /// same cost the pre-persistence behavior paid every time. Failing the
    /// replay over it would trade a delayed report for a lost one.
    pub(crate) fn persist_epoch_stall_evidence<'groups>(
        &mut self,
        groups: impl IntoIterator<Item = &'groups cgka_traits::GroupId>,
    ) {
        let evidence = groups
            .into_iter()
            .filter_map(|group_id| {
                let evidence = self
                    .history_recovery
                    .state
                    .epoch_stall
                    .wedge_evidence(group_id)?;
                Some(storage_sqlite::StoredEpochStallEvidence {
                    group_id_hex: hex::encode(group_id.as_slice()),
                    stalled_epoch: evidence.stalled_epoch,
                    fruitless_completions: evidence.fruitless_completions,
                    fruitless_reported: evidence.fruitless_reported,
                    last_arm_at_ms: evidence.last_arm_at_ms,
                })
            })
            .collect::<Vec<_>>();
        match self.app.record_epoch_stall_evidence(
            &self.state.label,
            &evidence,
            self.history_recovery
                .state
                .epoch_stall
                .fruitless_completion_threshold(),
        ) {
            Ok(changed) => {
                for group_id in changed {
                    self.mark_recovery_status_changed(&group_id);
                }
            }
            Err(error) => {
                tracing::warn!(target: "marmot_app::epoch_stall", method = "persist_epoch_stall_evidence",
                    error_kind = error.privacy_safe_kind(),
                    "recovery evidence and warning remain pending persistence");
            }
        }
    }

    /// Rebuild the frozen-epoch evidence a previous process gathered.
    pub(crate) fn restore_persisted_epoch_stall_evidence(
        &mut self,
        evidence: Vec<storage_sqlite::StoredEpochStallEvidence>,
    ) {
        let mut malformed = 0_u64;
        let restored = evidence
            .into_iter()
            .filter_map(|entry| {
                let Ok(group_id) = hex::decode(&entry.group_id_hex) else {
                    malformed = malformed.saturating_add(1);
                    return None;
                };
                Some((
                    cgka_traits::GroupId::new(group_id),
                    super::epoch_stall::EpochStallEvidence {
                        stalled_epoch: entry.stalled_epoch,
                        fruitless_completions: entry.fruitless_completions,
                        fruitless_reported: entry.fruitless_reported,
                        last_arm_at_ms: entry.last_arm_at_ms,
                    },
                ))
            })
            .collect::<Vec<_>>();
        if malformed > 0 {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "restore_persisted_epoch_stall_evidence",
                malformed,
                "ignored malformed durable frozen-epoch recovery evidence"
            );
        }
        self.history_recovery
            .state
            .epoch_stall
            .restore_wedge_evidence(restored);
    }

    #[cfg(test)]
    pub(in crate::client) fn persist_epoch_backfill_intent(
        &self,
        pending: &[storage_sqlite::StoredEpochBackfillIntent],
    ) -> Result<(), AppError> {
        self.app
            .arm_epoch_backfill_intents(&self.state.label, pending)
    }

    /// End the failed recovery run for a group this device is terminal in:
    /// retire its durable recovery-health rows, drop the in-memory run, and
    /// mark the group's recovery status dirty when the durable clear changed
    /// something.
    ///
    /// The same pair an authenticated rejoin runs, in the same order: durable
    /// first, so a failed clear leaves nothing changed for the next pass to
    /// retry rather than a run memory forgot and storage still remembers.
    ///
    /// Dropping the intent alone leaves the run behind to accumulate
    /// fruitless-completion evidence, and nothing else retires that evidence
    /// row while the group row is kept.
    ///
    /// Returns whether the durable rows are gone. Best-effort either way — the
    /// warn is in here so both callers share it — but a caller holding
    /// something that would strand the evidence row on failure has to be able
    /// to see it, which is what
    /// [`Self::drop_settled_epoch_backfill_intents`] does with the intent row.
    fn retire_terminal_group_recovery(&mut self, group_id: &cgka_traits::GroupId) -> bool {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_terminal_recovery_retire) {
            tracing::warn!(
                target: "marmot_app::epoch_stall",
                method = "retire_terminal_group_recovery",
                error_kind = "injected_terminal_retire_failure",
                "terminal recovery run kept its durable rows and will be retired on a later pass"
            );
            return false;
        }
        match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| {
                Ok(storage
                    .app_storage()
                    .retire_terminal_group_recovery(group_id)?)
            }) {
            Ok(changed) => {
                self.history_recovery
                    .state
                    .epoch_stall
                    .clear_recovered_group(group_id);
                if changed {
                    self.mark_recovery_status_changed(group_id);
                }
                true
            }
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::epoch_stall",
                    method = "retire_terminal_group_recovery",
                    error_kind = error.privacy_safe_kind(),
                    "terminal recovery run kept its durable rows and will be retired on a later pass"
                );
                false
            }
        }
    }

    /// Drop every armed epoch-gap intent for a group this device is terminal in
    /// (removed, or the group disbanded), clear its durable marker, and retire
    /// its recovery run.
    ///
    /// Such an intent is unservable. `refresh_group_routes` / `refresh_routing`
    /// have already pruned the group's routes, and the replay is account-wide
    /// rather than intent-scoped, so no replay can ever fetch that group's
    /// history. Keeping the intent only spends the one account-wide replay
    /// budget and gathers wedge evidence about a group we left. The host's
    /// recovery warning is already terminality-gated
    /// (`GroupRecoveryStatus::automatic_recovery_failed`); what leaked was the
    /// `EpochStallEscalated` event, its forensic escalation row, and a durable
    /// evidence row nothing else retires while the group row is kept.
    ///
    /// [`crate::client::group_is_terminal`] reads the engine record, so a deferred open
    /// answers `false` for everything before hydration. That makes the
    /// restore-time call an early-out only; the guarantee is the call at the top
    /// of [`Self::refresh_pending_recovery`], which runs after hydration.
    ///
    /// Terminal retirement applies to every epoch of the group. Ordinary
    /// completion instead uses the owner's exact obligation revision and scope
    /// tokens, so stale attempts cannot retire newer demand.
    ///
    /// An epoch gap also completes on its own evidence: once the group's local
    /// epoch moves past the stalled one, that exact gap no longer applies. A
    /// later stall arms a new gap at its own epoch.
    pub(in crate::client) fn drop_settled_epoch_backfill_intents(&mut self) {
        let intents = match self
            .app
            .account_storage(&self.state.label)
            .and_then(|storage| Ok(storage.app_storage().pending_epoch_backfill_intents()?))
        {
            Ok(intents) => intents,
            Err(error) => {
                tracing::warn!(target: "marmot_app::epoch_stall", method = "drop_settled_epoch_backfill_intents",
                    error_kind=error.privacy_safe_kind(), "could not inspect settled recovery demand");
                return;
            }
        };
        let resolved = intents
            .iter()
            .filter(|intent| {
                hex::decode(&intent.group_id_hex)
                    .ok()
                    .and_then(|group| self.local_epoch_for_group(&cgka_traits::GroupId::new(group)))
                    .is_some_and(|epoch| epoch > intent.stalled_epoch)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !resolved.is_empty()
            && let Err(error) = self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    Ok(storage
                        .app_storage()
                        .clear_epoch_backfill_intents(&resolved)?)
                })
        {
            tracing::warn!(target: "marmot_app::epoch_stall", method = "drop_settled_epoch_backfill_intents",
                error_kind=error.privacy_safe_kind(), "could not retire resolved epoch-gap demand");
        }
        let mut terminal = self
            .history_recovery
            .state
            .pending_recovery_arm_writes
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        terminal.extend(intents.into_iter().filter_map(|intent| {
            hex::decode(intent.group_id_hex)
                .ok()
                .map(cgka_traits::GroupId::new)
        }));
        terminal.retain(|group| crate::client::group_is_terminal(&self.runtime, group));
        for group in terminal {
            if self.retire_terminal_group_recovery(&group) {
                self.history_recovery
                    .state
                    .pending_recovery_arm_writes
                    .remove(&group);
            }
        }
    }

    /// Move every recorded escalation onto the summary a seam is about to
    /// return.
    ///
    /// Call this as the LAST step before `Ok(summary)`, at every outermost seam
    /// — the ones whose `Ok` is handed to a caller rather than followed by more
    /// fallible work. Partial-progress sync also calls it on `Err`, moving the
    /// one-shot decision into `SyncFailure::partial_summary` before a managed
    /// worker can discard and rebuild the client. The compatibility `sync()`
    /// path leaves it stashed on failure because its `AppError` contract has no
    /// partial-summary channel. Moving (not copying) keeps delivery exactly
    /// once across either path.
    ///
    /// One nested case needs care: [`Self::drain_pending_session_events`] drains
    /// while nested inside `sync_inner`, so its escalations leave the stash and
    /// ride `summary` from the merge onwards. Nothing fallible may be inserted
    /// between that merge and `sync_inner`'s `Ok` — past the merge they sit on a
    /// local summary again, and a `?` would take them down with the pass. (Which
    /// also makes `sync_inner`'s own call belt-and-braces rather than
    /// load-bearing: the nested drain has already emptied the stash.)
    ///
    /// A run is still forgotten when a caller discards the client outright; the
    /// [`super::epoch_stall`] module header covers that case and what
    /// re-escalating then costs.
    pub(crate) fn drain_epoch_stall_escalations(&mut self, summary: &mut SyncSummary) {
        summary
            .epoch_stall_escalations
            .append(&mut self.history_recovery.state.pending_epoch_stall_escalations);
    }

    /// Whether an epoch-gap backfill is armed and awaiting its replay. Read by
    /// the account worker to schedule a forensic audit-tracker upload for the
    /// just-recorded `epoch_stall_backfill_armed` row without poking the field.
    pub(crate) fn has_pending_epoch_backfill(&self) -> bool {
        !self
            .history_recovery
            .state
            .pending_recovery_arm_writes
            .is_empty()
            || self
                .app
                .account_storage(&self.state.label)
                .and_then(|storage| {
                    Ok(!storage
                        .app_storage()
                        .pending_epoch_backfill_intents()?
                        .is_empty())
                })
                .unwrap_or(true)
    }

    /// Read a group's current local epoch, or `None` when it cannot be read.
    ///
    /// `None` is deliberately not a claim about the group: it covers a group
    /// that is gone as well as a storage backend that was busy or closed.
    /// Callers must treat it as "unobserved", never as "unchanged". The read
    /// error itself has no audit field to land in, so name its privacy-safe
    /// kind here — that is the difference between chasing a deleted group and
    /// chasing lock contention.
    pub(crate) fn local_epoch_for_group(&self, group_id: &cgka_traits::GroupId) -> Option<u64> {
        match self.runtime.group_record(group_id) {
            Ok(record) => Some(record.epoch.0),
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::epoch_stall",
                    method = "local_epoch_for_group",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "local group epoch could not be read; treating it as unobserved"
                );
                None
            }
        }
    }

    /// Whether recovery debt or a buffered recovery observation is pending.
    fn recovery_pending(&self) -> Result<bool, AppError> {
        let storage = self.app.account_storage(&self.state.label)?.app_storage();
        Ok(!self
            .history_recovery
            .state
            .pending_recovery_arm_writes
            .is_empty()
            || !storage.pending_recovery_demands()?.is_empty())
    }

    /// The recovery seam of the receive path and the worker: flush recovery
    /// observations (see [`Self::refresh_account_recovery`]), and report
    /// pending recovery debt `Deferred` to the recovery runner, which owns
    /// every history fetch (mdk#2660 phase 4). The flush runs at every seam,
    /// debt or not: it imports new loss into the ledger and wakes the runner.
    pub(crate) async fn refresh_pending_recovery(
        &mut self,
    ) -> Result<EpochBackfillRunOutcome, AppError> {
        self.drop_settled_epoch_backfill_intents();
        self.refresh_account_recovery().await?;
        Ok(if self.recovery_pending()? {
            EpochBackfillRunOutcome::Deferred
        } else {
            EpochBackfillRunOutcome::NotPending
        })
    }
}
