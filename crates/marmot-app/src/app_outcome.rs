//! How an [`AppError`] records (#2627, rule 2). Recording takes outcome values and never names
//! `AppError`; these conversions classify an error into them, giving the answers the performance
//! recorder and the product collector's storage-failure counter gave when they matched on the
//! error themselves.

use crate::AppError;
use crate::app_telemetry::runtime::Outcome;
use crate::product_analytics::StorageFailureKind;

/// The performance outcome of a failed operation: a worker that did not answer in time is a
/// timeout, a busy worker is not ready, and any other error is a failure.
impl From<&AppError> for Outcome {
    fn from(error: &AppError) -> Self {
        match error {
            AppError::AccountWorkerResponseTimedOut => Self::Timeout,
            AppError::AccountWorkerBusy => Self::NotReady,
            _ => Self::Failure,
        }
    }
}

/// The storage failure an error counts as, by its sync error class. A forwarded catch-up failure
/// counts as none: the sync completion observation already owns it.
impl From<&AppError> for Option<StorageFailureKind> {
    fn from(error: &AppError) -> Self {
        if matches!(error, AppError::AccountCatchUp(_)) {
            return None;
        }
        StorageFailureKind::from_sync_class(error.sync_error_class())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product_analytics::observed::success_or_failure;
    use crate::{
        AccountCatchUpFailure, AppPerformanceTelemetry, RuntimePerformanceOperation,
        SyncErrorClass, SyncFailureClassification, SyncFailureStage,
    };
    use cgka_traits::StorageError;

    /// The performance recorder's `finish_app` before #2627 PR 1, verbatim but for its receiver.
    fn finish_app_before<T>(result: &Result<T, AppError>) -> Outcome {
        match result {
            Ok(_) => Outcome::Success,
            Err(AppError::AccountWorkerResponseTimedOut) => Outcome::Timeout,
            Err(AppError::AccountWorkerBusy) => Outcome::NotReady,
            Err(_) => Outcome::Failure,
        }
    }

    /// The operation the storage-failure counter recorded before #2627 PR 1.
    fn storage_failure_before(error: &AppError) -> Option<&'static str> {
        if matches!(error, AppError::AccountCatchUp(_)) {
            return None;
        }
        match error.sync_error_class() {
            SyncErrorClass::StorageBusy => Some("busy"),
            SyncErrorClass::StorageCorruption => Some("corruption"),
            SyncErrorClass::StorageCapacity => Some("capacity"),
            _ => None,
        }
    }

    fn sqlite(code: std::ffi::c_int) -> AppError {
        AppError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(code),
            None,
        ))
    }

    /// An operation's result, then what it records today: the performance outcome, the product
    /// outcome, and the storage failure the counter counts when the result is an error.
    type Row = (
        &'static str,
        Result<(), AppError>,
        Outcome,
        &'static str,
        Option<StorageFailureKind>,
    );

    #[test]
    fn app_results_record_what_the_recorders_matched_before() {
        let catch_up = AppError::AccountCatchUp(AccountCatchUpFailure::new(
            "private raw cause".into(),
            SyncFailureClassification::new(
                SyncFailureStage::StatePersist,
                SyncErrorClass::StorageCorruption,
            ),
        ));
        assert_eq!(
            catch_up.sync_error_class(),
            SyncErrorClass::StorageCorruption
        );
        let rows: Vec<Row> = vec![
            ("ok", Ok(()), Outcome::Success, "success", None),
            (
                "worker response timed out",
                Err(AppError::AccountWorkerResponseTimedOut),
                Outcome::Timeout,
                "failure",
                None,
            ),
            (
                "worker busy",
                Err(AppError::AccountWorkerBusy),
                Outcome::NotReady,
                "failure",
                None,
            ),
            (
                "generic failure",
                Err(AppError::TransportClosed),
                Outcome::Failure,
                "failure",
                None,
            ),
            (
                "storage, unclassified",
                Err(AppError::Storage(StorageError::Backend("private".into()))),
                Outcome::Failure,
                "failure",
                None,
            ),
            (
                "storage busy",
                Err(AppError::Storage(StorageError::Busy("private".into()))),
                Outcome::Failure,
                "failure",
                Some(StorageFailureKind::Busy),
            ),
            (
                "sqlite busy",
                Err(sqlite(rusqlite::ffi::SQLITE_BUSY)),
                Outcome::Failure,
                "failure",
                Some(StorageFailureKind::Busy),
            ),
            (
                "storage corruption",
                Err(AppError::Storage(StorageError::Corruption(
                    "private".into(),
                ))),
                Outcome::Failure,
                "failure",
                Some(StorageFailureKind::Corruption),
            ),
            (
                "storage capacity",
                Err(AppError::Storage(StorageError::Capacity("private".into()))),
                Outcome::Failure,
                "failure",
                Some(StorageFailureKind::Capacity),
            ),
            (
                "forwarded catch-up failure over corruption",
                Err(catch_up),
                Outcome::Failure,
                "failure",
                None,
            ),
        ];
        for (label, result, performance, product, storage) in rows {
            assert_eq!(Outcome::of(&result), performance, "{label}: performance");
            assert_eq!(
                finish_app_before(&result),
                performance,
                "{label}: performance before"
            );
            assert_eq!(success_or_failure(&result), product, "{label}: product");
            let counted = result
                .as_ref()
                .err()
                .and_then(Option::<StorageFailureKind>::from);
            assert_eq!(counted, storage, "{label}: storage failure");
            assert_eq!(
                result.as_ref().err().and_then(storage_failure_before),
                storage.map(StorageFailureKind::as_str),
                "{label}: storage failure before"
            );

            // Through a recorder, as the call sites record it.
            let telemetry = AppPerformanceTelemetry::default();
            let operation = RuntimePerformanceOperation::ConversationOpen;
            telemetry.observe(operation).finish_app(&result);
            let snapshot = telemetry
                .snapshot()
                .runtime_operations
                .into_iter()
                .find(|snapshot| snapshot.operation == operation)
                .unwrap();
            let counts = [
                (Outcome::Success, snapshot.successes),
                (Outcome::Failure, snapshot.failures),
                (Outcome::Timeout, snapshot.timeouts),
                (Outcome::NotReady, snapshot.not_ready),
                (Outcome::Cancelled, snapshot.cancelled),
            ];
            for (outcome, count) in counts {
                assert_eq!(
                    count,
                    u64::from(outcome == performance),
                    "{label}: {outcome:?}"
                );
            }
        }
    }
}
