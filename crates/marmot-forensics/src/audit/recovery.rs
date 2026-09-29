//! Closed vocabularies for the account-recovery owner rows
//! (`recovery_need_changed`, `recovery_attempt_started`,
//! `recovery_attempt_finished`, `recovery_obligation_reassessed`) and the
//! transport-cursor row (`transport_cursor_advanced`). These kinds exist only
//! in audit v5; a v4 recorder drops them (see `AuditEventKind::is_v5_only`).
//!
//! Each enum mirrors a name the recovery code already uses, so a reader can
//! grep from a row value to its producer.
use serde::{Deserialize, Serialize};

/// Largest number of obligation references one row carries. A longer
/// selection sets the row's `*_truncated` flag; the count stays exact.
pub const RECOVERY_AUDIT_MAX_OBLIGATIONS: usize = 16;

/// Largest number of endpoint references one row carries. Matches the v5
/// endpoint list bound; a longer list sets `endpoints_truncated`.
pub const RECOVERY_AUDIT_MAX_ENDPOINTS: usize = 16;

/// Why an obligation exists: `storage_sqlite::RecoveryCause`, one to one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryObligationCause {
    /// The account delivery queue or its durable spill omitted deliveries.
    QueueLoss,
    /// An SDK notification consumer lagged and lost notifications.
    NotificationLoss,
    /// A group's epoch stalled on a commit this device never received.
    EpochGap,
    /// A post-join maintenance subscription boundary.
    Maintenance,
    /// An explicit, caller-owned full-history repair.
    ExplicitHistory,
    /// One exact event this device knows it lacks.
    KnownEvent,
    /// Cold-start or incremental history over the retained window.
    IncrementalHistory,
}

/// A meaningful change to recovery need. Unchanged scheduler evaluations
/// never produce one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNeedChange {
    /// New debt: no pending obligation existed for this demand, or a
    /// satisfied one reopened as fresh debt.
    Recorded,
    /// Charged to an obligation that was already pending and not parked.
    Joined,
    /// New evidence reopened an obligation that was parked for deep repair
    /// or retired by a dismissal.
    Resumed,
    /// The obligation parked; its "history may be incomplete" notice is now
    /// shown to the user.
    NoticeShown,
    /// The user dismissed the notice. The obligation is retired as "history
    /// may be incomplete", never as coverage.
    NoticeDismissed,
    /// A parked obligation completed with qualified coverage. Parked
    /// obligations get no automatic retries, so this is an explicit deep
    /// repair closing it.
    Closed,
    /// An explicit full-history request closed because its comparison
    /// certified the whole retained window and what remains lies below it,
    /// where no pass can search. Neither coverage nor a dismissal.
    ClosedBelowWindow,
}

/// The lower bound of an obligation's goal, as the comparison will use it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryGoalBound {
    /// Bounded below by `floor_secs`: the earliest charged wire `created_at`
    /// (queue loss) or the lowest REQ `since` (notification loss).
    Floor,
    /// No known lower bound. A comparison still fetches every difference
    /// inside its window, but cannot certify the goal.
    Unbounded,
    /// The retained-inventory window (cold-start and incremental history).
    RetainedWindow,
}

/// What an attempt acquires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAttemptScope {
    /// Route history over a window (comparison and difference fetch).
    History,
    /// Exact known event IDs only.
    ExactEvent,
    /// Maintenance subscription boundaries only.
    MaintenanceBoundary,
    /// More than one of the above.
    Mixed,
}

/// How one finished pass ended, from the owner's settlement. The first three
/// are `storage_sqlite::RecoveryPassProgress` aggregated over every compared
/// scope; the rest are how the pass stopped short of a full settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPassOutcome {
    /// Some scope certified or durably admitted fetched history.
    Progressed,
    /// Every compared scope's required relays answered, and nothing was
    /// certified or admitted.
    Quiet,
    /// No scope progressed and at least one required relay failed, timed out
    /// or was skipped, or admission was refused. Says nothing about history.
    Unserved,
    /// An explicit repair spent its whole budget and stopped admission at a
    /// turn boundary.
    Deadline,
    /// The pass was cancelled, or its network task ended without a result.
    Cancelled,
    /// The grant changed before or during admission. Before admission,
    /// nothing was admitted; during it, the admitted prefix stays durable.
    /// Either way the pass certifies nothing and newer demand owns the debt.
    Superseded,
    /// The pass failed; `error_kind` names the class.
    Failed,
}

/// One compared scope's progress in a pass, the owner's
/// `storage_sqlite::RecoveryPassProgress`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScopeProgress {
    Progressed,
    Quiet,
    Unserved,
    /// The comparison certified the retained window of a goal that reaches
    /// below it (explicit history). Searched, so progress, never quiet.
    WindowCertified,
}

/// The owner's verdict on one obligation after a settled pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryObligationVerdict {
    /// Qualified completion: certified coverage and durable admission, or
    /// the retained known event.
    Satisfied,
    /// Still pending; a later paced pass retries it.
    Deferred,
    /// Waiting for local capacity (admission was refused).
    WaitingCapacity,
    /// Waiting for a capability or route change (no eligible route, or no
    /// comparison backend).
    WaitingCapability,
    /// Parked for explicit deep repair after its quiet budget.
    Parked,
    /// Parked again on routes and relays the user already dismissed, so it
    /// retired silently without a new notice.
    Retired,
    /// New evidence moved the obligation to a newer revision, or it was
    /// reclaimed, during the pass; the newer revision owns the debt.
    Superseded,
    /// An explicit full-history request whose whole retained window was
    /// certified closed: nothing left can be searched. Not coverage.
    ClosedBelowWindow,
}

/// Why another automatic attempt is, or is not, permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNextAttempt {
    /// Nothing remains to acquire.
    NotNeeded,
    /// The shared, durable retry schedule runs it again.
    PacedRetry,
    /// Only once local capacity frees.
    AfterCapacity,
    /// Only once routes, relays or the comparison capability change.
    AfterCapabilityChange,
    /// No automatic attempt; only an explicit deep repair or new evidence.
    ExplicitRepairOnly,
    /// The newer revision's own schedule decides.
    NewerRevision,
}

/// What committed a transport-cursor advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportCursorTrigger {
    /// A catch-up drain checkpoint saved its prefix.
    DrainCheckpoint,
    /// A live ingest's own save promoted the cursor (recorded only when the
    /// jump exceeds the rebuild lookback).
    LivePromotion,
    /// Recovery settled the pending delivery loss.
    LossSettled,
    /// A dismissed loss notice released the cursor fence.
    NoticeRetired,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditEventKind, AuditRecord, EpochBackfillExecutionSeam, ForensicRecorder, JsonlRecorder,
    };
    use crate::v5;

    fn producer() -> v5::Producer {
        v5::Producer {
            mdk_revision: None,
            build_profile: v5::BuildProfile::Debug,
            platform: v5::Platform::Other,
            host_build: None,
        }
    }

    fn started(ids: usize, count: u64, truncated: bool) -> AuditEventKind {
        AuditEventKind::RecoveryAttemptStarted {
            attempt_serial: 4,
            retry_ordinal: 0,
            seam: EpochBackfillExecutionSeam::Startup,
            scope: RecoveryAttemptScope::History,
            causes: vec![RecoveryObligationCause::IncrementalHistory],
            obligation_count: count,
            obligation_ids: (0..ids).map(|i| format!("{i:032x}")).collect(),
            obligations_truncated: truncated,
            route_count: 1,
            endpoint_count: 1,
            relay_urls: vec!["wss://relay.secret.example".into()],
            endpoints_truncated: false,
            window_since_secs: Some(10),
            window_until_secs: Some(20),
            route_cap: 8,
            admission_per_turn: 4,
            quantum_ms: 30_000,
            park_after_quiet_passes: 3,
        }
    }

    fn v5_lines(kinds: Vec<AuditEventKind>) -> (tempfile::TempDir, Vec<String>) {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::audit::default_v5_jsonl_path(dir.path(), &"11".repeat(16));
        let recorder =
            JsonlRecorder::open_v5_with_account_ref(&path, "11".repeat(16), None, producer())
                .unwrap();
        for kind in kinds {
            recorder.record(AuditRecord::new(Some("ab".repeat(16)), kind));
        }
        let lines = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .filter(|line| line.contains("\"recovery_") || line.contains("\"transport_cursor"))
            .collect();
        (dir, lines)
    }

    #[test]
    fn v4_recorder_drops_v5_only_kinds_without_counting_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let recorder = JsonlRecorder::open_with_account_ref(&path, "e".repeat(32), None).unwrap();
        recorder.record(AuditRecord::new(None, started(1, 1, false)));
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::SyncDrain {
                duration_ms: 1,
                deliveries: 0,
                skipped: None,
                refused: None,
                cursor_before_secs: None,
                cursor_after_secs: None,
            },
        ));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("recovery_attempt_started"));
        assert!(body.contains("sync_drain"), "later v4 rows still record");
        assert_eq!(recorder.health_snapshot(), Default::default());
    }

    #[test]
    fn v5_recovery_rows_carry_only_hashed_references() {
        let raw_obligation = format!("{:032x}", 0);
        let (_dir, lines) = v5_lines(vec![
            started(1, 1, false),
            AuditEventKind::RecoveryNeedChanged {
                cause: RecoveryObligationCause::QueueLoss,
                change: RecoveryNeedChange::Recorded,
                obligation_id: raw_obligation.clone(),
                obligation_revision: 1,
                bound: Some(RecoveryGoalBound::Unbounded),
                floor_secs: None,
                charged: Some(2),
            },
        ]);
        assert_eq!(lines.len(), 2);
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let mut refs = Vec::new();
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(validator.is_valid(&value), "{line}");
            v5::Record::from_json(line.as_bytes()).unwrap();
            assert!(!line.contains("wss://"), "relay URLs never reach v5");
            assert!(!line.contains(&raw_obligation), "obligation ids are hashed");
            assert!(
                !line.contains("obligation_id"),
                "legacy field names are renamed"
            );
            let event = &value["event"];
            if let Some(list) = event["obligation_refs"].as_array() {
                refs.push(list[0].as_str().unwrap().to_owned());
                assert_eq!(event["endpoint_refs"].as_array().unwrap().len(), 1);
            } else {
                refs.push(event["obligation_ref"].as_str().unwrap().to_owned());
            }
        }
        // The same obligation hashes to one reference in both the single and
        // the list field, so the rows join.
        assert_eq!(refs[0], refs[1]);
        assert_eq!(refs[0].len(), 64);
    }

    #[test]
    fn strict_decoder_rejects_inconsistent_recovery_rows_the_schema_accepts() {
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let (_dir, lines) = v5_lines(vec![started(2, 2, false)]);
        let valid: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        for (pointer, value) in [
            ("/event/obligations_truncated", serde_json::json!(true)),
            ("/event/obligation_count", serde_json::json!(1)),
            ("/event/window_since_secs", serde_json::json!(30)),
        ] {
            let mut row = valid.clone();
            *row.pointer_mut(pointer).unwrap() = value;
            assert!(validator.is_valid(&row), "schema alone accepts {pointer}");
            assert!(
                v5::Record::from_json(&serde_json::to_vec(&row).unwrap()).is_err(),
                "the strict decoder rejects {pointer}"
            );
        }
    }

    #[test]
    fn v5_schema_tracks_the_recovery_enum_catalogs() {
        fn names<T: Serialize>(values: &[T]) -> std::collections::BTreeSet<String> {
            values
                .iter()
                .map(|value| {
                    serde_json::to_value(value)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect()
        }
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let defined = |name: &str| {
            schema["$defs"][name]["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} enum"))
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<std::collections::BTreeSet<_>>()
        };
        use RecoveryObligationCause as C;
        assert_eq!(
            names(&[
                C::QueueLoss,
                C::NotificationLoss,
                C::EpochGap,
                C::Maintenance,
                C::ExplicitHistory,
                C::KnownEvent,
                C::IncrementalHistory
            ]),
            defined("Operational_recoveryObligationCause")
        );
        use RecoveryNeedChange as N;
        assert_eq!(
            names(&[
                N::Recorded,
                N::Joined,
                N::Resumed,
                N::NoticeShown,
                N::NoticeDismissed,
                N::Closed,
                N::ClosedBelowWindow
            ]),
            defined("Operational_recoveryNeedChange")
        );
        use RecoveryGoalBound as B;
        assert_eq!(
            names(&[B::Floor, B::Unbounded, B::RetainedWindow]),
            defined("Operational_recoveryGoalBound")
        );
        use RecoveryAttemptScope as S;
        assert_eq!(
            names(&[S::History, S::ExactEvent, S::MaintenanceBoundary, S::Mixed]),
            defined("Operational_recoveryAttemptScope")
        );
        use RecoveryPassOutcome as O;
        assert_eq!(
            names(&[
                O::Progressed,
                O::Quiet,
                O::Unserved,
                O::Deadline,
                O::Cancelled,
                O::Superseded,
                O::Failed
            ]),
            defined("Operational_recoveryPassOutcome")
        );
        use RecoveryScopeProgress as P;
        assert_eq!(
            names(&[P::Progressed, P::Quiet, P::Unserved, P::WindowCertified]),
            defined("Operational_recoveryScopeProgress")
        );
        use RecoveryObligationVerdict as V;
        assert_eq!(
            names(&[
                V::Satisfied,
                V::Deferred,
                V::WaitingCapacity,
                V::WaitingCapability,
                V::Parked,
                V::Retired,
                V::Superseded,
                V::ClosedBelowWindow
            ]),
            defined("Operational_recoveryObligationVerdict")
        );
        use RecoveryNextAttempt as A;
        assert_eq!(
            names(&[
                A::NotNeeded,
                A::PacedRetry,
                A::AfterCapacity,
                A::AfterCapabilityChange,
                A::ExplicitRepairOnly,
                A::NewerRevision
            ]),
            defined("Operational_recoveryNextAttempt")
        );
        use TransportCursorTrigger as T;
        assert_eq!(
            names(&[
                T::DrainCheckpoint,
                T::LivePromotion,
                T::LossSettled,
                T::NoticeRetired
            ]),
            defined("Operational_transportCursorTrigger")
        );
    }
}
