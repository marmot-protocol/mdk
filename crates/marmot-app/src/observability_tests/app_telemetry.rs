//! App-telemetry tests that need `AppError`, the sync-failure classification or the SQLCipher
//! probe counters. They record through `PerformanceRecorder`, the view the rest of the crate
//! records through.

use std::time::Duration;

use cgka_traits::TransportAdapterError;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageError;

use crate::app_telemetry::AppPerformanceOperation;
use crate::observer::PerformanceRecorder;
use crate::{
    AccountCatchUpFailure, AppError, ClassifiedSyncFailure, SyncErrorClass,
    SyncFailureClassification, SyncFailureStage, SyncSummary,
};

mod runtime;

fn classified(stage: SyncFailureStage, error: AppError) -> SyncFailureClassification {
    ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, stage).classification()
}

#[test]
fn sync_failure_classification_is_typed_bounded_and_propagates() {
    let cases = [
        (
            classified(
                SyncFailureStage::AccountWorker,
                AppError::AccountWorkerResponseTimedOut,
            ),
            SyncFailureClassification::new(
                SyncFailureStage::AccountWorker,
                SyncErrorClass::Timeout,
            ),
        ),
        (
            classified(
                SyncFailureStage::RelayReceive,
                AppError::Transport(TransportAdapterError::Closed),
            ),
            SyncFailureClassification::new(
                SyncFailureStage::RelayReceive,
                SyncErrorClass::TransportClosed,
            ),
        ),
        (
            classified(
                SyncFailureStage::GroupSubscriptionSync,
                AppError::Transport(TransportAdapterError::Subscription(
                    "raw relay detail must not become an attribute".into(),
                )),
            ),
            SyncFailureClassification::new(
                SyncFailureStage::GroupSubscriptionSync,
                SyncErrorClass::Unknown,
            ),
        ),
        (
            classified(
                SyncFailureStage::CgkaIngest,
                AppError::Account(marmot_session::AccountError::Engine(
                    EngineError::InvalidWelcome,
                )),
            ),
            SyncFailureClassification::new(SyncFailureStage::CgkaIngest, SyncErrorClass::Protocol),
        ),
        (
            classified(
                SyncFailureStage::StatePersist,
                AppError::Storage(StorageError::Backend(
                    "/private/account.sqlite secret detail".into(),
                )),
            ),
            SyncFailureClassification::new(SyncFailureStage::StatePersist, SyncErrorClass::Storage),
        ),
        (
            classified(
                SyncFailureStage::Unknown,
                AppError::BlockingTask("untyped raw failure".into()),
            ),
            SyncFailureClassification::UNKNOWN,
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(actual, expected);
    }

    let child = cases[3].0;
    let propagated = AppError::AccountCatchUp(AccountCatchUpFailure::new(
        "runtime catch-up failed: attacker-controlled detail".into(),
        child,
    ));
    assert_eq!(propagated.sync_error_class(), child.error_class);

    let telemetry = PerformanceRecorder::default();
    telemetry.record_classified_result(
        AppPerformanceOperation::AccountSync,
        Duration::from_millis(1),
        Some(child),
    );
    telemetry.record_classified_result(
        AppPerformanceOperation::AccountCatchUp,
        Duration::from_millis(2),
        Some(child),
    );
    let snapshot = telemetry.snapshot();
    assert_eq!(snapshot.account_sync.attempts, 1);
    assert_eq!(snapshot.account_sync.successes, 0);
    assert_eq!(snapshot.account_sync.failures, 1);
    assert_eq!(snapshot.account_catch_up.attempts, 1);
    assert_eq!(snapshot.account_catch_up.successes, 0);
    assert_eq!(snapshot.account_catch_up.failures, 1);
    assert_eq!(
        snapshot.account_sync.failure_classifications[0].classification,
        child
    );
    assert_eq!(
        snapshot.account_catch_up.failure_classifications[0].classification,
        child
    );

    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(!serialized.contains("attacker-controlled"));
    assert!(!serialized.contains("account.sqlite"));
    assert!(!serialized.contains("raw relay detail"));
}

#[test]
fn snapshot_carries_the_process_wide_sqlcipher_probe_counters() {
    // The counters are process-global atomics shared with every test in
    // this process, so bracket the snapshot between two direct reads
    // instead of asserting exact values.
    let telemetry = PerformanceRecorder::default();
    let before = crate::sqlcipher::sqlcipher_migration_probe_counters();
    let snapshot = telemetry.snapshot();
    let after = crate::sqlcipher::sqlcipher_migration_probe_counters();

    assert!(before.0 <= snapshot.sqlcipher_migration_probe_runs);
    assert!(snapshot.sqlcipher_migration_probe_runs <= after.0);
    assert!(before.1 <= snapshot.sqlcipher_migration_probe_skips);
    assert!(snapshot.sqlcipher_migration_probe_skips <= after.1);
}
