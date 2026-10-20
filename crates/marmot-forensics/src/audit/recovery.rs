//! Closed vocabularies for the account-recovery owner rows
//! (`recovery_need_changed`, `recovery_attempt_started`,
//! `recovery_attempt_finished`, `recovery_obligation_reassessed`) and the
//! transport-cursor row (`transport_cursor_advanced`) and historical wire-reissue row
//! (`subscription_eose_repaired`). These kinds exist only
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
    /// Complete-range admission of an issued native subscription window.
    /// This is not exhaustive history or acknowledgment of delivery loss.
    SubscriptionReplay,
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
    /// The obligation's own predicate completed: qualified history, a retained
    /// known event, or limited native replay admission. Native admission does
    /// not certify history or acknowledge delivery loss.
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

/// Why one relay failed a recovery pass's comparison:
/// `transport_nostr_adapter::NostrReconciliationFailure`, one to one. Each
/// names the stage that failed the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRelayFailure {
    /// The relay answered NEG-OPEN with NEG-ERR; `refusal_category` names
    /// the reason's prefix.
    NegErr,
    /// The relay's concurrent-negentropy cap NOTICE refused the comparison.
    NegCapNotice,
    /// The relay does not support negentropy, or broke its protocol.
    NegentropyUnsupported,
    /// No first negentropy reply in time.
    FirstReplyTimeout,
    /// The pass deadline ended the comparison or its fetches.
    RouteTimeout,
    /// The account's relay pool does not hold the relay.
    NotInPool,
    /// The relay was not connected or not usable.
    NotOperational,
    /// The relay's matching set filled the comparison limit.
    LimitReached,
    /// The relay did not serve an exact-ID fetch for events it claimed.
    IdFetchRefused,
    /// The relay returned an event the pass did not ask for.
    UnrequestedEvent,
    /// The relay reached EOSE on an exact-ID fetch without a claimed event.
    Withheld,
    /// The pass's own budget or ordering left some of the relay's claimed
    /// events for a later pass. Not the relay's fault.
    PassLimit,
    /// A local fault, not attributable to the relay.
    LocalError,
}

/// One relay that failed a recovery pass, on
/// [`crate::AuditEventKind::RecoveryAttemptFinished`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRelayOutcome {
    /// The failing relay. v5 records it as a hashed endpoint reference.
    pub relay_url: String,
    /// Why it failed the first compared route it failed in this pass.
    pub failure: RecoveryRelayFailure,
    /// The NEG-ERR reason's prefix, present exactly when `failure` is
    /// `neg_err`. The reason text itself is never recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_category: Option<crate::audit::SubscriptionRefusalCategory>,
    /// Compared routes this relay failed in the pass. At least one.
    pub routes: u64,
}

/// Whose notification receiver lagged, for a lag-lost EOSE repair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EoseRepairReceiver {
    /// This account's own receiver.
    Account,
    /// A receiver shared across accounts; the pass covered every account on
    /// it, and the first account to record it carries the row.
    Shared,
}

/// What started a lag-lost EOSE repair pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EoseRepairTrigger {
    /// One or more notification lags, once the receiver settled.
    NotificationLag,
    /// An earlier pass left recovery pending and scheduled this one.
    FollowUp,
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
    fn subscription_replay_uses_existing_owner_rows_and_sorted_causes() {
        let mut native = started(1, 1, false);
        if let AuditEventKind::RecoveryAttemptStarted { causes, .. } = &mut native {
            *causes = vec![RecoveryObligationCause::SubscriptionReplay];
        }
        let mut mixed = native.clone();
        if let AuditEventKind::RecoveryAttemptStarted { causes, .. } = &mut mixed {
            *causes = vec![
                RecoveryObligationCause::NotificationLoss,
                RecoveryObligationCause::SubscriptionReplay,
            ];
        }
        let mut unsorted = mixed.clone();
        if let AuditEventKind::RecoveryAttemptStarted { causes, .. } = &mut unsorted {
            causes.reverse();
        }
        let mut duplicate = native.clone();
        if let AuditEventKind::RecoveryAttemptStarted { causes, .. } = &mut duplicate {
            causes.push(RecoveryObligationCause::SubscriptionReplay);
        }
        let need = AuditEventKind::RecoveryNeedChanged {
            cause: RecoveryObligationCause::SubscriptionReplay,
            change: RecoveryNeedChange::Recorded,
            obligation_id: "0a".repeat(16),
            obligation_revision: 1,
            bound: None,
            floor_secs: None,
            charged: None,
        };
        let mut charged_native = need.clone();
        if let AuditEventKind::RecoveryNeedChanged { charged, .. } = &mut charged_native {
            *charged = Some(1);
        }
        let (_dir, lines) = v5_lines(vec![
            need,
            native,
            mixed,
            unsorted,
            duplicate,
            charged_native,
        ]);
        assert_eq!(lines.len(), 3);
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert!(validator.is_valid(&value));
            let record = v5::Record::from_json(line.as_bytes()).unwrap();
            assert_eq!(
                v5::Record::from_json(&record.to_json().unwrap()).unwrap(),
                record
            );
            assert!(!line.contains("wss://"));
            assert!(!line.contains(&"0a".repeat(16)));
        }
    }

    fn outcome(relay: &str, failure: RecoveryRelayFailure) -> RecoveryRelayOutcome {
        RecoveryRelayOutcome {
            relay_url: format!("wss://{relay}.secret.example"),
            failure,
            refusal_category: (failure == RecoveryRelayFailure::NegErr)
                .then_some(crate::audit::SubscriptionRefusalCategory::Unclassified),
            routes: 1,
        }
    }

    fn finished(
        relays_failed: u64,
        relays_incomplete: u64,
        relay_outcomes: Vec<RecoveryRelayOutcome>,
    ) -> AuditEventKind {
        AuditEventKind::RecoveryAttemptFinished {
            attempt_serial: 4,
            duration_ms: 10,
            outcome: RecoveryPassOutcome::Progressed,
            error_kind: None,
            obligation_count: 1,
            routes_compared: 2,
            routes_certified: 0,
            routes_uncertified: 2,
            events_retrieved: 0,
            events_duplicate: 0,
            events_rejected: 0,
            events_retained: 0,
            events_refused: 0,
            relays_required: 2,
            relays_admitted: 2,
            relays_failed,
            relays_incomplete,
            relay_outcomes,
        }
    }

    /// Each failed relay says why it failed (mdk#2265), as a hashed endpoint
    /// reference; a list that cannot describe the counts is refused.
    #[test]
    fn finished_row_lists_each_failed_relay_once_with_its_class() {
        use RecoveryRelayFailure as F;
        let many = (0..RECOVERY_AUDIT_MAX_ENDPOINTS + 1)
            .map(|index| outcome(&format!("r{index:02}"), F::RouteTimeout))
            .collect::<Vec<_>>();
        let mut no_category = outcome("a", F::NegErr);
        no_category.refusal_category = None;
        let mut stray_category = outcome("a", F::FirstReplyTimeout);
        stray_category.refusal_category = Some(crate::audit::SubscriptionRefusalCategory::Blocked);
        let mut no_routes = outcome("a", F::Withheld);
        no_routes.routes = 0;
        let (_dir, lines) = v5_lines(vec![
            // Written: no failure, and two failed relays with their classes.
            finished(0, 0, Vec::new()),
            finished(
                2,
                1,
                vec![outcome("a", F::NegErr), outcome("b", F::Withheld)],
            ),
            // Written: a full list may stand for more failed relays, and a
            // failure the backend did not attribute to a relay is counted but
            // not listed.
            finished(20, 0, many[..RECOVERY_AUDIT_MAX_ENDPOINTS].to_vec()),
            finished(2, 0, vec![outcome("a", F::NotInPool)]),
            // Refused: more relays listed than failed, over the bound, a
            // repeated relay, a NEG-ERR without its category or a category
            // without NEG-ERR, a relay that failed no route, and more
            // incomplete relays than failed ones.
            finished(0, 0, vec![outcome("a", F::NotInPool)]),
            finished(17, 0, many),
            finished(
                2,
                0,
                vec![outcome("a", F::NotInPool), outcome("a", F::NotInPool)],
            ),
            finished(1, 0, vec![no_category]),
            finished(1, 0, vec![stray_category]),
            finished(1, 0, vec![no_routes]),
            finished(1, 2, vec![outcome("a", F::Withheld)]),
        ]);
        assert_eq!(
            lines.len(),
            4,
            "only consistent rows are written: {lines:#?}"
        );
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(validator.is_valid(&value), "{line}");
            v5::Record::from_json(line.as_bytes()).unwrap();
            assert!(!line.contains("wss://"), "relay URLs never reach v5");
        }
        let event = &serde_json::from_str::<serde_json::Value>(&lines[1]).unwrap()["event"];
        let outcomes = event["relay_outcomes"].as_array().unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0]["endpoint_ref"].is_string());
        assert_eq!(outcomes[0]["failure"], "neg_err");
        assert_eq!(outcomes[0]["refusal_category"], "unclassified");
        assert_eq!(outcomes[1]["failure"], "withheld");
        assert!(
            serde_json::from_str::<serde_json::Value>(&lines[0]).unwrap()["event"]
                .get("relay_outcomes")
                .is_none(),
            "an empty list is omitted"
        );
    }

    #[test]
    fn v4_recorder_drops_v5_only_kinds_without_counting_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let recorder = JsonlRecorder::open_with_account_ref(&path, "e".repeat(32), None).unwrap();
        recorder.record(AuditRecord::new(None, started(1, 1, false)));
        let mut native = started(1, 1, false);
        if let AuditEventKind::RecoveryAttemptStarted { causes, .. } = &mut native {
            *causes = vec![RecoveryObligationCause::SubscriptionReplay];
        }
        recorder.record(AuditRecord::new(None, native));
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
    fn strict_writer_refuses_eose_repair_counts_beyond_the_awaiting_relays() {
        let repaired =
            |failed_relays, follow_up_scheduled| AuditEventKind::SubscriptionEoseRepaired {
                receiver: EoseRepairReceiver::Account,
                trigger: EoseRepairTrigger::NotificationLag,
                lags: 1,
                awaiting_relays: 2,
                complete_relays: 1,
                reissued_relays: 1,
                reissued_earlier_relays: 0,
                failed_relays,
                follow_up_scheduled,
                dropped_before: 0,
            };
        let dir = tempfile::tempdir().unwrap();
        let path = crate::audit::default_v5_jsonl_path(dir.path(), &"11".repeat(16));
        let recorder =
            JsonlRecorder::open_v5_with_account_ref(&path, "11".repeat(16), None, producer())
                .unwrap();
        recorder.record(AuditRecord::new(None, repaired(0, false)));
        // Three outcomes for two awaiting relays, a follow-up scheduled with
        // no failed relay, and a follow-up pass that folded in a lag: all
        // inconsistent, none written.
        recorder.record(AuditRecord::new(None, repaired(1, true)));
        recorder.record(AuditRecord::new(None, repaired(0, true)));
        // A follow-up pass folds in no lag.
        let mut follow_up_with_lag = repaired(0, false);
        if let AuditEventKind::SubscriptionEoseRepaired { trigger, .. } = &mut follow_up_with_lag {
            *trigger = EoseRepairTrigger::FollowUp;
        }
        recorder.record(AuditRecord::new(None, follow_up_with_lag));
        let written = std::fs::read_to_string(&path).unwrap();
        let rows = written
            .lines()
            .filter(|line| line.contains("subscription_eose_repaired"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1, "only the consistent pass is written");
        let schema: serde_json::Value = serde_json::from_str(v5::JSON_SCHEMA).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(validator.is_valid(&serde_json::from_str(rows[0]).unwrap()));
        assert!(v5::Record::from_json(rows[0].as_bytes()).is_ok());
        assert!(recorder.health_snapshot().serialization_failures >= 3);
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
                C::IncrementalHistory,
                C::SubscriptionReplay
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
        assert_eq!(
            names(&[EoseRepairReceiver::Account, EoseRepairReceiver::Shared]),
            defined("Operational_eoseRepairReceiver")
        );
        assert_eq!(
            names(&[
                EoseRepairTrigger::NotificationLag,
                EoseRepairTrigger::FollowUp
            ]),
            defined("Operational_eoseRepairTrigger")
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
        use RecoveryRelayFailure as F;
        assert_eq!(
            names(&[
                F::NegErr,
                F::NegCapNotice,
                F::NegentropyUnsupported,
                F::FirstReplyTimeout,
                F::RouteTimeout,
                F::NotInPool,
                F::NotOperational,
                F::LimitReached,
                F::IdFetchRefused,
                F::UnrequestedEvent,
                F::Withheld,
                F::PassLimit,
                F::LocalError
            ]),
            defined("Operational_recoveryRelayFailure")
        );
    }
}
