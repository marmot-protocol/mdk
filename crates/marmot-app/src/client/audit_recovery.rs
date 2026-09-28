//! Audit v5 rows for the account recovery owner and the transport cursor.
//!
//! The owner records its decisions at the seams where they become durable:
//! need changes (`recovery_need_changed`), attempt start and finish
//! (`recovery_attempt_started`, `recovery_attempt_finished`), its per-obligation
//! verdict after settlement (`recovery_obligation_reassessed`), and committed
//! transport-cursor advances (`transport_cursor_advanced`). Every row is
//! transition-driven, never a scheduler poll, and carries enums, counts and
//! the hashed references v5 derives from owner identifiers only.
//!
//! Recording is best effort and never blocks or fails a recovery step: every
//! helper returns nothing, and a failed audit-only storage read skips the row.
//! None of these kinds exists in audit v4, so each helper first checks that a
//! v5 recorder is installed.
use std::collections::BTreeSet;

use cgka_traits::GroupId;
use marmot_forensics::{
    AuditEventContext, AuditEventKind, RECOVERY_AUDIT_MAX_ENDPOINTS,
    RECOVERY_AUDIT_MAX_OBLIGATIONS, RecoveryAttemptScope, RecoveryGoalBound, RecoveryNeedChange,
    RecoveryNextAttempt, RecoveryObligationCause, RecoveryObligationVerdict, RecoveryPassOutcome,
    RecoveryScopeProgress, TransportCursorTrigger,
};
use storage_sqlite::{
    RecoveryCause, RecoveryDemandTicket, RecoveryDemandTransition, RecoveryEligibility,
    RecoveryLossCause, RecoveryLossImport, RecoveryObligationState, RecoveryPassProgress,
    SqliteAccountStorage,
};

use super::AppClient;
use super::recovery::AttemptGrant;
use super::sync::{DrainCounts, RouteComparison, SealedTransportCursor};
use crate::AppError;

/// What one compared route's relays returned. Audit-only; settlement never
/// reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RouteAcquisition {
    /// Events the relays handed over.
    pub(crate) retrieved: usize,
    /// Handed-over events that could not be read as a transport message or
    /// no longer routed to this account.
    pub(crate) rejected: usize,
    pub(crate) relays_failed: usize,
    /// Failed relays that answered but withheld a claimed event.
    pub(crate) relays_incomplete: usize,
}

impl RouteAcquisition {
    pub(crate) fn from_summary(
        summary: &transport_nostr_adapter::NostrReconciliationSummary,
    ) -> Self {
        Self {
            retrieved: summary.received_items,
            rejected: 0,
            relays_failed: summary.relays_failed,
            relays_incomplete: summary.incomplete_endpoints.len(),
        }
    }
}

/// What one pass's settlement saw, for its finished row.
#[derive(Clone, Debug, Default)]
pub(crate) struct RecoveryPassTally {
    progress: Option<RecoveryScopeProgress>,
    routes_compared: u64,
    routes_certified: u64,
    retrieved: u64,
    rejected: u64,
    relays_failed: u64,
    relays_incomplete: u64,
}

impl RecoveryPassTally {
    pub(crate) fn observe_routes(&mut self, compared: &[RouteComparison]) {
        let count = |value: usize| u64::try_from(value).unwrap_or(u64::MAX);
        for route in compared {
            self.routes_compared = self.routes_compared.saturating_add(1);
            self.routes_certified = self
                .routes_certified
                .saturating_add(u64::from(route.certified));
            let acquired = &route.acquisition;
            self.retrieved = self.retrieved.saturating_add(count(acquired.retrieved));
            self.rejected = self.rejected.saturating_add(count(acquired.rejected));
            self.relays_failed = self
                .relays_failed
                .saturating_add(count(acquired.relays_failed));
            self.relays_incomplete = self
                .relays_incomplete
                .saturating_add(count(acquired.relays_incomplete));
        }
    }

    /// Fold one scope's progress into the pass aggregate.
    pub(crate) fn observe_progress(&mut self, progress: RecoveryPassProgress) {
        self.progress = Some(merge_progress(self.progress, progress));
    }
}

/// Progressed beats quiet beats unserved: a pass progressed if any scope did,
/// and is quiet only if no scope progressed and some scope was served.
pub(crate) fn merge_progress(
    current: Option<RecoveryScopeProgress>,
    next: RecoveryPassProgress,
) -> RecoveryScopeProgress {
    let next = match next {
        RecoveryPassProgress::Progressed => RecoveryScopeProgress::Progressed,
        RecoveryPassProgress::Quiet => RecoveryScopeProgress::Quiet,
        RecoveryPassProgress::Unserved => RecoveryScopeProgress::Unserved,
        RecoveryPassProgress::WindowCertified => RecoveryScopeProgress::WindowCertified,
    };
    let rank = |progress: RecoveryScopeProgress| match progress {
        RecoveryScopeProgress::Progressed => 3,
        RecoveryScopeProgress::WindowCertified => 2,
        RecoveryScopeProgress::Quiet => 1,
        RecoveryScopeProgress::Unserved => 0,
    };
    match current {
        Some(current) if rank(current) >= rank(next) => current,
        _ => next,
    }
}

/// One settled obligation, as the settlement loop saw it.
pub(crate) struct ReassessedObligation {
    pub(crate) id: [u8; 16],
    pub(crate) progress: Option<RecoveryScopeProgress>,
    pub(crate) scopes_certified: u64,
    /// Quiet streaks count only for comparison-owned causes.
    pub(crate) comparison_owned: bool,
    /// Settlement closed this explicit request below the retained window,
    /// which deletes its row.
    pub(crate) closed_below_window: bool,
}

pub(crate) fn obligation_cause(cause: RecoveryCause) -> RecoveryObligationCause {
    match cause {
        RecoveryCause::QueueLoss => RecoveryObligationCause::QueueLoss,
        RecoveryCause::NotificationLoss => RecoveryObligationCause::NotificationLoss,
        RecoveryCause::EpochGap => RecoveryObligationCause::EpochGap,
        RecoveryCause::Maintenance => RecoveryObligationCause::Maintenance,
        RecoveryCause::ExplicitHistory => RecoveryObligationCause::ExplicitHistory,
        RecoveryCause::KnownEvent => RecoveryObligationCause::KnownEvent,
        RecoveryCause::IncrementalHistory => RecoveryObligationCause::IncrementalHistory,
    }
}

fn need_change(transition: RecoveryDemandTransition) -> Option<RecoveryNeedChange> {
    match transition {
        RecoveryDemandTransition::Recorded => Some(RecoveryNeedChange::Recorded),
        RecoveryDemandTransition::Joined => Some(RecoveryNeedChange::Joined),
        RecoveryDemandTransition::Resumed => Some(RecoveryNeedChange::Resumed),
        RecoveryDemandTransition::Unchanged => None,
    }
}

/// The verdict storage reports for one obligation after a settled pass at
/// `revision`, and whether another automatic attempt may follow.
pub(crate) fn obligation_verdict(
    status: Option<&storage_sqlite::RecoveryObligationStatus>,
    revision: u64,
) -> (RecoveryObligationVerdict, RecoveryNextAttempt) {
    use RecoveryNextAttempt as Next;
    use RecoveryObligationVerdict as Verdict;
    let Some(status) = status.filter(|status| status.revision == revision) else {
        return (Verdict::Superseded, Next::NewerRevision);
    };
    match status.state {
        RecoveryObligationState::Satisfied => (Verdict::Satisfied, Next::NotNeeded),
        RecoveryObligationState::Retired => (Verdict::Retired, Next::NotNeeded),
        RecoveryObligationState::Pending => match status.eligibility {
            RecoveryEligibility::NeedsDeepRepair => (Verdict::Parked, Next::ExplicitRepairOnly),
            RecoveryEligibility::WaitingCapacity => (Verdict::WaitingCapacity, Next::AfterCapacity),
            RecoveryEligibility::WaitingCapability => {
                (Verdict::WaitingCapability, Next::AfterCapabilityChange)
            }
            RecoveryEligibility::Ready | RecoveryEligibility::Retry => {
                (Verdict::Deferred, Next::PacedRetry)
            }
        },
    }
}

/// How a pass ended, from its result, how it stopped, and its settlement.
pub(crate) fn pass_outcome(
    failed: bool,
    interruption: Option<RecoveryPassOutcome>,
    tally: &RecoveryPassTally,
    retained: u64,
) -> RecoveryPassOutcome {
    if failed {
        return RecoveryPassOutcome::Failed;
    }
    if let Some(interruption) = interruption {
        return interruption;
    }
    match tally.progress {
        // A certified window of an unbounded explicit goal was searched:
        // progress, never quiet.
        Some(RecoveryScopeProgress::Progressed | RecoveryScopeProgress::WindowCertified) => {
            RecoveryPassOutcome::Progressed
        }
        _ if retained > 0 => RecoveryPassOutcome::Progressed,
        // Nothing compared (a maintenance boundary) and nothing failed.
        Some(RecoveryScopeProgress::Quiet) | None => RecoveryPassOutcome::Quiet,
        Some(RecoveryScopeProgress::Unserved) => RecoveryPassOutcome::Unserved,
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Sorted, distinct values; at most `max` listed, with the exact count.
fn bounded<T: Ord + Clone>(values: BTreeSet<T>, max: usize) -> (Vec<T>, u64, bool) {
    let total = count(values.len());
    let listed = values.into_iter().take(max).collect::<Vec<_>>();
    let truncated = count(listed.len()) < total;
    (listed, total, truncated)
}

impl AppClient {
    /// Import unresolved delivery loss into its obligations, recording each
    /// change. The storage import is the authority; the rows follow it.
    pub(crate) fn synchronize_recovery_loss(
        &self,
        storage: &SqliteAccountStorage,
    ) -> Result<(), AppError> {
        let imports = storage.synchronize_account_delivery_loss(&self.state.label)?;
        self.record_recovery_loss_imports(storage, imports);
        Ok(())
    }

    /// One `recovery_need_changed` row per loss cause an import changed, with
    /// the goal bound the comparison will use after it.
    pub(crate) fn record_recovery_loss_imports(
        &self,
        storage: &SqliteAccountStorage,
        imports: Vec<RecoveryLossImport>,
    ) {
        if imports.is_empty() || !self.audit_v5_enabled() {
            return;
        }
        for import in imports {
            let Some(change) = need_change(import.transition) else {
                continue;
            };
            // An unreadable floor is reported as unknown, never as a bound.
            let floor = storage
                .recovery_loss_goal_floor(&self.state.label, import.cause)
                .ok()
                .flatten();
            self.record_need_changed(
                None,
                match import.cause {
                    RecoveryLossCause::Queue => RecoveryObligationCause::QueueLoss,
                    RecoveryLossCause::NotificationConsumer => {
                        RecoveryObligationCause::NotificationLoss
                    }
                },
                change,
                import.obligation,
                Some(floor.map_or(RecoveryGoalBound::Unbounded, |_| RecoveryGoalBound::Floor)),
                floor,
                Some(import.charged),
            );
        }
    }

    /// A caller-owned or startup request changed demand.
    pub(crate) fn record_recovery_request(
        &self,
        cause: RecoveryCause,
        ticket: RecoveryDemandTicket,
        transition: RecoveryDemandTransition,
    ) {
        let Some(change) = need_change(transition) else {
            return;
        };
        if !self.audit_v5_enabled() {
            return;
        }
        let bound = match cause {
            RecoveryCause::IncrementalHistory => Some(RecoveryGoalBound::RetainedWindow),
            // Explicit full-history repair stays unfloored by design.
            RecoveryCause::ExplicitHistory => Some(RecoveryGoalBound::Unbounded),
            _ => None,
        };
        self.record_need_changed(
            None,
            obligation_cause(cause),
            change,
            ticket,
            bound,
            None,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_need_changed(
        &self,
        group: Option<&GroupId>,
        cause: RecoveryObligationCause,
        change: RecoveryNeedChange,
        ticket: RecoveryDemandTicket,
        bound: Option<RecoveryGoalBound>,
        floor_secs: Option<u64>,
        charged: Option<u64>,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        self.runtime.session().record_audit_event(
            group,
            None,
            AuditEventKind::RecoveryNeedChanged {
                cause,
                change,
                obligation_id: hex::encode(ticket.id),
                obligation_revision: ticket.revision,
                bound,
                floor_secs: floor_secs.filter(|_| bound == Some(RecoveryGoalBound::Floor)),
                charged,
            },
        );
    }

    /// The owner started a reserved, frozen attempt.
    pub(crate) fn record_recovery_attempt_started(
        &self,
        grant: &AttemptGrant,
        context: &AuditEventContext,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        let plan = grant.plan().unwrap_or_default();
        let mut causes = BTreeSet::new();
        let mut kinds = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for obligation in plan {
            causes.insert(obligation_cause(obligation.cause));
            for scope in &obligation.scopes {
                kinds.insert(if obligation.cause == RecoveryCause::Maintenance {
                    RecoveryAttemptScope::MaintenanceBoundary
                } else if scope.goal.known_event_id.is_some() {
                    RecoveryAttemptScope::ExactEvent
                } else {
                    RecoveryAttemptScope::History
                });
                endpoints.extend(scope.goal.admitted_endpoints.iter().cloned());
            }
        }
        if let Some(comparison) = &grant.comparison_plan {
            kinds.insert(RecoveryAttemptScope::History);
            for route in &comparison.routes {
                endpoints.extend(route.admitted_endpoints.iter().cloned());
            }
        }
        let scope = match kinds.len() {
            0 => RecoveryAttemptScope::History,
            1 => kinds.pop_first().unwrap_or(RecoveryAttemptScope::History),
            _ => RecoveryAttemptScope::Mixed,
        };
        let obligations = grant
            .fence
            .obligations
            .iter()
            .map(|(id, _)| hex::encode(id))
            .collect::<BTreeSet<_>>();
        let (obligation_ids, obligation_count, obligations_truncated) =
            bounded(obligations, RECOVERY_AUDIT_MAX_OBLIGATIONS);
        let (relay_urls, endpoint_count, endpoints_truncated) =
            bounded(endpoints, RECOVERY_AUDIT_MAX_ENDPOINTS);
        self.runtime.session().record_audit_event(
            None,
            Some(context.clone()),
            AuditEventKind::RecoveryAttemptStarted {
                attempt_serial: grant.reservation.attempt_serial,
                retry_ordinal: grant.reservation.ordinal.saturating_sub(1),
                seam: grant.seam,
                scope,
                causes: causes.into_iter().collect(),
                obligation_count,
                obligation_ids,
                obligations_truncated,
                route_count: count(grant.inventory.len()),
                endpoint_count,
                relay_urls,
                endpoints_truncated,
                window_since_secs: grant.inventory.iter().map(|route| route.since).min(),
                window_until_secs: grant.inventory.iter().map(|route| route.until).max(),
                route_cap: count(super::sync::TRANSPORT_RECONCILIATION_MAX_ROUTES_PER_PASS),
                admission_per_turn: count(
                    super::sync::comparison_job::MAX_COMPARISON_ADMISSION_PER_TURN,
                ),
                quantum_ms: u64::try_from(
                    super::sync::TRANSPORT_RECONCILIATION_QUANTUM.as_millis(),
                )
                .unwrap_or(u64::MAX),
                park_after_quiet_passes: storage_sqlite::RECOVERY_PARK_AFTER_QUIET_PASSES,
            },
        );
    }

    /// One finished pass, on every exit of the execution bracket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_recovery_attempt_finished(
        &self,
        grant: &AttemptGrant,
        context: &AuditEventContext,
        duration_ms: u64,
        outcome: RecoveryPassOutcome,
        error_kind: Option<&'static str>,
        counts: &DrainCounts,
        tally: &RecoveryPassTally,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        let mut required = BTreeSet::new();
        let mut admitted = BTreeSet::new();
        for scope in grant
            .plan()
            .unwrap_or_default()
            .iter()
            .flat_map(|obligation| obligation.scopes.iter().map(|scope| &scope.goal))
            .chain(
                grant
                    .comparison_plan
                    .iter()
                    .flat_map(|comparison| comparison.routes.iter()),
            )
        {
            required.extend(scope.required_endpoints.iter());
            admitted.extend(scope.admitted_endpoints.iter());
        }
        self.runtime.session().record_audit_event(
            None,
            Some(context.clone()),
            AuditEventKind::RecoveryAttemptFinished {
                attempt_serial: grant.reservation.attempt_serial,
                duration_ms,
                outcome,
                error_kind: error_kind
                    .filter(|_| outcome == RecoveryPassOutcome::Failed)
                    .map(str::to_owned),
                obligation_count: count(grant.fence.obligations.len()),
                routes_compared: tally.routes_compared,
                routes_certified: tally.routes_certified,
                routes_uncertified: tally.routes_compared.saturating_sub(tally.routes_certified),
                events_retrieved: tally.retrieved,
                events_duplicate: counts.skipped,
                events_rejected: tally.rejected,
                events_retained: counts.deliveries.saturating_sub(counts.unpersisted),
                events_refused: counts.refused,
                relays_required: count(required.len()),
                relays_admitted: count(admitted.len()),
                relays_failed: tally.relays_failed,
                relays_incomplete: tally.relays_incomplete,
            },
        );
    }

    /// The owner's verdict on each obligation a pass settled, read back from
    /// storage after its checkpoint committed.
    pub(crate) fn record_recovery_reassessments(
        &self,
        storage: &SqliteAccountStorage,
        grant: &AttemptGrant,
        context: &AuditEventContext,
        settled: Vec<ReassessedObligation>,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        let plan = grant.plan().unwrap_or_default();
        for settled in settled.into_iter().take(RECOVERY_AUDIT_MAX_OBLIGATIONS) {
            let Some(obligation) = plan.iter().find(|obligation| obligation.id == settled.id)
            else {
                continue;
            };
            let Some(revision) = grant
                .fence
                .obligations
                .iter()
                .find(|(id, _)| *id == settled.id)
                .map(|(_, revision)| *revision)
            else {
                continue;
            };
            // Audit-only reads: a failure skips the row, never the pass.
            let Ok(status) = storage.recovery_obligation_status(settled.id) else {
                continue;
            };
            let (verdict, next_attempt) = if settled.closed_below_window {
                (
                    RecoveryObligationVerdict::ClosedBelowWindow,
                    RecoveryNextAttempt::NotNeeded,
                )
            } else {
                obligation_verdict(status.as_ref(), revision)
            };
            let quiet_passes = settled
                .comparison_owned
                .then(|| storage.recovery_scope_snapshots(settled.id).ok())
                .flatten()
                .and_then(|scopes| scopes.iter().map(|scope| scope.quiet_passes).max());
            self.runtime.session().record_audit_event(
                obligation.group_id.as_ref(),
                Some(context.clone()),
                AuditEventKind::RecoveryObligationReassessed {
                    attempt_serial: grant.reservation.attempt_serial,
                    cause: obligation_cause(obligation.cause),
                    obligation_id: hex::encode(settled.id),
                    obligation_revision: revision,
                    verdict,
                    next_attempt,
                    progress: settled.progress,
                    scopes_total: count(obligation.scopes.len()),
                    scopes_certified: settled.scopes_certified.min(count(obligation.scopes.len())),
                    quiet_passes,
                    park_after_quiet_passes: storage_sqlite::RECOVERY_PARK_AFTER_QUIET_PASSES,
                },
            );
        }
    }

    /// A cursor commit's save succeeded. Settled commits record every
    /// advance; a live promotion only a jump beyond the rebuild lookback.
    pub(crate) fn record_transport_cursor_advanced(
        &mut self,
        trigger: TransportCursorTrigger,
        sealed: &SealedTransportCursor,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        let Some(after) = self.checkpointed_transport_timestamp else {
            return;
        };
        let before = sealed.previous();
        let advance = after.saturating_sub(before.unwrap_or(0));
        if advance == 0 || before.is_some_and(|before| after <= before) {
            return;
        }
        let lookback_secs = self.relay_plane.subscription_rebuild_lookback_secs();
        if trigger == TransportCursorTrigger::LivePromotion
            && lookback_secs.is_none_or(|lookback| advance <= lookback)
        {
            return;
        }
        let counts = self.adapter.delivery_placement_counts();
        let since = std::mem::replace(&mut self.cursor_audit_placements, counts);
        // A replaced queue restarts its counters; report what it has.
        let delta = |now: u64, then: u64| if now >= then { now - then } else { now };
        self.runtime.session().record_audit_event(
            None,
            None,
            AuditEventKind::TransportCursorAdvanced {
                trigger,
                cursor_before_secs: before,
                cursor_after_secs: after,
                lookback_secs,
                spilled_below_floor: delta(counts.spilled_below_floor, since.spilled_below_floor),
                spilled_queue_full: delta(counts.spilled_queue_full, since.spilled_queue_full),
                spill_already_seen: delta(counts.spill_already_seen, since.spill_already_seen),
                queue_dropped: delta(counts.queue_dropped, since.queue_dropped),
            },
        );
    }
}

/// Every recorded v5 row of `kind`, in order, each checked against the v5
/// JSON Schema and the strict decoder: what a real consumer would accept.
#[cfg(test)]
pub(crate) fn recorded_v5_rows(app: &crate::MarmotApp, kind: &str) -> Vec<serde_json::Value> {
    let schema: serde_json::Value =
        serde_json::from_str(marmot_forensics::v5::JSON_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    app.audit_log_files()
        .unwrap()
        .into_iter()
        .flat_map(|file| {
            std::fs::read_to_string(file.path)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter_map(|line| {
            marmot_forensics::v5::Record::from_json(line.as_bytes())
                .unwrap_or_else(|error| panic!("strict v5 decoder rejected a row: {error}"));
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(
                validator.is_valid(&value),
                "v5 schema rejected {}: {:?}",
                value["event"]["type"],
                validator.iter_errors(&value).collect::<Vec<_>>()
            );
            assert!(!line.contains("wss://"), "relay URLs never reach v5 rows");
            (value["event"]["type"] == kind).then_some(value)
        })
        .collect()
}

#[cfg(test)]
mod scenario_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_progress_prefers_progress_then_service() {
        use RecoveryPassProgress::{Progressed, Quiet, Unserved, WindowCertified};
        let fold = |passes: &[RecoveryPassProgress]| {
            passes
                .iter()
                .fold(None, |current, next| Some(merge_progress(current, *next)))
        };
        assert_eq!(
            fold(&[Unserved, Quiet, Unserved]),
            Some(RecoveryScopeProgress::Quiet)
        );
        assert_eq!(
            fold(&[Quiet, Progressed, Unserved]),
            Some(RecoveryScopeProgress::Progressed)
        );
        assert_eq!(fold(&[Unserved]), Some(RecoveryScopeProgress::Unserved));
        assert_eq!(
            fold(&[Quiet, WindowCertified]),
            Some(RecoveryScopeProgress::WindowCertified)
        );
        assert_eq!(
            fold(&[WindowCertified, Progressed]),
            Some(RecoveryScopeProgress::Progressed)
        );
        assert_eq!(fold(&[]), None);
    }

    #[test]
    fn verdict_reads_the_settled_revision_only() {
        let status = |revision, state, eligibility| storage_sqlite::RecoveryObligationStatus {
            revision,
            cause: RecoveryCause::QueueLoss,
            state,
            eligibility,
            group_id: None,
        };
        use RecoveryEligibility as E;
        use RecoveryObligationState as S;
        let cases = [
            (
                status(2, S::Pending, E::Retry),
                RecoveryObligationVerdict::Superseded,
            ),
            (
                status(1, S::Satisfied, E::Retry),
                RecoveryObligationVerdict::Satisfied,
            ),
            (
                status(1, S::Retired, E::NeedsDeepRepair),
                RecoveryObligationVerdict::Retired,
            ),
            (
                status(1, S::Pending, E::NeedsDeepRepair),
                RecoveryObligationVerdict::Parked,
            ),
            (
                status(1, S::Pending, E::WaitingCapacity),
                RecoveryObligationVerdict::WaitingCapacity,
            ),
            (
                status(1, S::Pending, E::WaitingCapability),
                RecoveryObligationVerdict::WaitingCapability,
            ),
            (
                status(1, S::Pending, E::Retry),
                RecoveryObligationVerdict::Deferred,
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(obligation_verdict(Some(&status), 1).0, expected);
        }
        assert_eq!(
            obligation_verdict(None, 1),
            (
                RecoveryObligationVerdict::Superseded,
                RecoveryNextAttempt::NewerRevision
            )
        );
    }

    #[test]
    fn pass_outcome_names_how_the_pass_stopped() {
        let with = |progress| RecoveryPassTally {
            progress,
            ..Default::default()
        };
        let quiet = with(Some(RecoveryScopeProgress::Quiet));
        assert_eq!(
            pass_outcome(true, None, &quiet, 0),
            RecoveryPassOutcome::Failed
        );
        for stopped in [
            RecoveryPassOutcome::Superseded,
            RecoveryPassOutcome::Deadline,
            RecoveryPassOutcome::Cancelled,
        ] {
            assert_eq!(pass_outcome(false, Some(stopped), &quiet, 0), stopped);
        }
        assert_eq!(
            pass_outcome(false, None, &quiet, 0),
            RecoveryPassOutcome::Quiet
        );
        assert_eq!(
            pass_outcome(false, None, &quiet, 2),
            RecoveryPassOutcome::Progressed
        );
        assert_eq!(
            pass_outcome(
                false,
                None,
                &with(Some(RecoveryScopeProgress::WindowCertified)),
                0
            ),
            RecoveryPassOutcome::Progressed,
            "a searched window is progress, not quiet"
        );
        assert_eq!(
            pass_outcome(false, None, &with(Some(RecoveryScopeProgress::Unserved)), 0),
            RecoveryPassOutcome::Unserved
        );
    }
}
