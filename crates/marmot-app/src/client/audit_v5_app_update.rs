//! Bounded observations at app computation and persistence boundaries.
//!
//! These rows describe only the local work the app could observe. A failed
//! recorder never changes an app result, and no row implies host receipt.

use std::collections::HashSet;
use std::time::Duration;

use cgka_traits::engine::GroupEvent;
use marmot_forensics::v5::{
    AppUpdateCategory, AppUpdateCompute, AppUpdateFailureReason, AppUpdateFailureStage,
    AppUpdateInputScope, AppUpdateOutcome, AppUpdateTransaction, EngineMessageRef, Event,
};

use super::AppClient;
use crate::AppError;
use crate::app_telemetry::SyncErrorClass;

fn elapsed_ms(elapsed: Duration) -> marmot_forensics::v5::U64String {
    u64::try_from(elapsed.as_millis())
        .unwrap_or(u64::MAX)
        .into()
}

fn reason(error: &AppError) -> AppUpdateFailureReason {
    match error.sync_error_class() {
        SyncErrorClass::Storage
        | SyncErrorClass::StorageBusy
        | SyncErrorClass::StorageCorruption
        | SyncErrorClass::StorageCapacity => AppUpdateFailureReason::Storage,
        SyncErrorClass::Timeout | SyncErrorClass::TransportClosed | SyncErrorClass::Cancelled => {
            AppUpdateFailureReason::Unavailable
        }
        _ => AppUpdateFailureReason::Unknown,
    }
}

fn single_event_message_ref(events: &[GroupEvent]) -> Option<EngineMessageRef> {
    let [event] = events else { return None };
    let id = match event {
        GroupEvent::MessageReceived { message_id, .. } => message_id,
        GroupEvent::GroupJoined { via_welcome, .. } => via_welcome,
        _ => return None,
    };
    EngineMessageRef::from_message_id(id.as_slice()).ok()
}

pub(super) struct CheckpointObservation<'a> {
    pub message_ref: Option<EngineMessageRef>,
    pub changed_groups: usize,
    pub pending_inputs: usize,
    pub pending_acks: usize,
    pub pending_frontiers: usize,
    pub created_row: bool,
    pub error: Option<&'a AppError>,
    pub elapsed: Duration,
    pub known_not_committed: bool,
    pub failure_stage: AppUpdateFailureStage,
}

impl AppClient {
    pub(super) fn record_v5_app_checkpoint(&self, observed: CheckpointObservation<'_>) {
        if !self.audit_v5_enabled() {
            return;
        }
        let CheckpointObservation {
            message_ref,
            changed_groups,
            pending_inputs,
            pending_acks,
            pending_frontiers,
            created_row,
            error,
            elapsed,
            known_not_committed,
            failure_stage,
        } = observed;
        self.runtime.session().record_v5_event(
            None,
            Event::AppUpdateOutcome(AppUpdateOutcome {
                operation_ref: None,
                message_ref,
                category: AppUpdateCategory::AccountProjectionCheckpoint,
                input_scope: if pending_inputs != 0 || pending_acks != 0 || pending_frontiers != 0 {
                    AppUpdateInputScope::InboundOrEngineBatch
                } else {
                    AppUpdateInputScope::LocalOperation
                },
                compute: if changed_groups != 0
                    || pending_inputs != 0
                    || pending_acks != 0
                    || pending_frontiers != 0
                    || created_row
                {
                    AppUpdateCompute::Updated
                } else {
                    AppUpdateCompute::Unchanged
                },
                transaction: if error.is_none() {
                    AppUpdateTransaction::Committed
                } else if known_not_committed {
                    AppUpdateTransaction::NotCommitted
                } else {
                    AppUpdateTransaction::Unknown
                },
                failure_stage: error.map(|_| failure_stage),
                failure_reason: error.map(reason),
                elapsed_ms: elapsed_ms(elapsed),
                affected_group_count: Some(
                    u64::try_from(changed_groups).unwrap_or(u64::MAX).into(),
                ),
            }),
        );
    }

    pub(super) fn record_v5_event_projection_failure(
        &self,
        events: &[GroupEvent],
        error: &AppError,
        elapsed: Duration,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        self.runtime.session().record_v5_event(
            None,
            Event::AppUpdateOutcome(AppUpdateOutcome {
                operation_ref: None,
                message_ref: single_event_message_ref(events),
                category: AppUpdateCategory::EventProjection,
                input_scope: AppUpdateInputScope::InboundOrEngineBatch,
                compute: AppUpdateCompute::Failed,
                // Earlier event projections in a batch can have committed
                // independently; this failure cannot certify a batch rollback.
                transaction: AppUpdateTransaction::Unknown,
                failure_stage: Some(AppUpdateFailureStage::Projection),
                failure_reason: Some(reason(error)),
                elapsed_ms: elapsed_ms(elapsed),
                affected_group_count: None,
            }),
        );
    }

    pub(super) fn record_v5_content_report_backfill(
        &self,
        result: Result<&Vec<crate::AppProjectionUpdate>, &AppError>,
        elapsed: Duration,
    ) {
        if !self.audit_v5_enabled() {
            return;
        }
        self.runtime.session().record_v5_event(
            None,
            Event::AppUpdateOutcome(AppUpdateOutcome {
                operation_ref: None,
                message_ref: None,
                category: AppUpdateCategory::ContentReportBackfill,
                input_scope: AppUpdateInputScope::Reconciliation,
                compute: match result {
                    Ok(updates) if updates.is_empty() => AppUpdateCompute::Unchanged,
                    Ok(_) => AppUpdateCompute::Updated,
                    Err(_) => AppUpdateCompute::Failed,
                },
                transaction: if result.is_ok() {
                    AppUpdateTransaction::Committed
                } else {
                    // A failed commit path can be uncertain even when the
                    // closure itself returned an error.
                    AppUpdateTransaction::Unknown
                },
                failure_stage: result
                    .as_ref()
                    .err()
                    .map(|_| AppUpdateFailureStage::Unknown),
                failure_reason: result.err().map(reason),
                elapsed_ms: elapsed_ms(elapsed),
                affected_group_count: result
                    .as_ref()
                    .ok()
                    .map(|updates| {
                        updates
                            .iter()
                            .map(|update| update.group_id_hex.as_str())
                            .collect::<HashSet<_>>()
                            .len()
                    })
                    .map(|count| u64::try_from(count).unwrap_or(u64::MAX).into()),
            }),
        );
    }
}
