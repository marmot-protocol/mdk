use marmot_app::{AppError, SyncFailure, SyncSummary};

#[test]
fn sync_failure_remains_constructible_with_its_original_public_fields() {
    let failure = SyncFailure {
        partial_summary: SyncSummary::default(),
        source: AppError::RuntimeStopping,
    };

    assert!(matches!(failure.source, AppError::RuntimeStopping));
}
