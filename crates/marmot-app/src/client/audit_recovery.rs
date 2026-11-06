//! Audit v5 rows for the account recovery owner and the transport cursor.
//!
//! The owner records its decisions at the seams where they become durable:
//! need changes (`recovery_need_changed`) and committed transport-cursor
//! advances (`transport_cursor_advanced`). The attempt and reassessment rows
//! went with the owner's grant; the recovery runner records its own. Every row is
//! transition-driven, never a scheduler poll, and carries enums, counts and
//! the hashed references v5 derives from owner identifiers only.
//!
//! Recording is best effort and never blocks or fails a recovery step: every
//! helper returns nothing, and a failed audit-only storage read skips the row.
//! None of these kinds exists in audit v4, so each helper first checks that a
//! v5 recorder is installed.
use storage_sqlite::SqliteAppStorage;

use cgka_traits::GroupId;
use marmot_forensics::{
    AuditEventKind, RecoveryGoalBound, RecoveryNeedChange, RecoveryObligationCause,
    TransportCursorTrigger,
};
use storage_sqlite::{
    RecoveryCause, RecoveryDemandTicket, RecoveryDemandTransition, RecoveryLossCause,
    RecoveryLossImport,
};

use super::AppClient;
use super::sync::SealedTransportCursor;
use crate::AppError;

pub(crate) fn obligation_cause(cause: RecoveryCause) -> RecoveryObligationCause {
    match cause {
        RecoveryCause::QueueLoss => RecoveryObligationCause::QueueLoss,
        RecoveryCause::NotificationLoss => RecoveryObligationCause::NotificationLoss,
        RecoveryCause::EpochGap => RecoveryObligationCause::EpochGap,
        RecoveryCause::Maintenance => RecoveryObligationCause::Maintenance,
        RecoveryCause::ExplicitHistory => RecoveryObligationCause::ExplicitHistory,
        RecoveryCause::KnownEvent => RecoveryObligationCause::KnownEvent,
        RecoveryCause::IncrementalHistory => RecoveryObligationCause::IncrementalHistory,
        RecoveryCause::SubscriptionReplay => RecoveryObligationCause::SubscriptionReplay,
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

impl AppClient {
    /// Import unresolved delivery loss into its obligations, recording each
    /// change. The storage import is the authority; the rows follow it.
    pub(crate) fn synchronize_recovery_loss(
        &self,
        storage: &SqliteAppStorage,
    ) -> Result<(), AppError> {
        if self.app.recovery_runner_owns_debt() {
            if self.synchronize_runner_loss(storage)? {
                self.wake_recovery_runner();
            }
            return Ok(());
        }
        let imports = storage.synchronize_account_delivery_loss(&self.state.label)?;
        self.record_recovery_loss_imports(imports);
        Ok(())
    }

    /// One `recovery_need_changed` row per loss cause an import changed, with
    /// the goal bound the comparison will use after it.
    pub(crate) fn record_recovery_loss_imports(&self, imports: Vec<RecoveryLossImport>) {
        self.record_coverage_loss(&imports);
        // Imported loss un-covered its routes: new debt for the runner.
        if !imports.is_empty() {
            self.wake_recovery_runner();
        }
        if imports.is_empty() || !self.audit_v5_enabled() {
            return;
        }
        for import in imports {
            let Some(change) = need_change(import.transition) else {
                continue;
            };
            // Read in the import's own transaction, so it is the bound of
            // exactly the revision this row names.
            let floor = import.goal_floor;
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
        self.record_coverage_request(cause);
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
        self.record_audit_event(
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
        self.record_audit_event(
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
