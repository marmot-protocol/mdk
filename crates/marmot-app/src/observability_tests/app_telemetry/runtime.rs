//! The runtime-operation recorder's cancellation test, which measures an `AppError` result.

use crate::{AppPerformanceTelemetry, RuntimePerformanceOperation, RuntimePerformanceSnapshot};
use marmot_observability::observer::PerformanceRecorder;

/// The live conversation-open series, read from the public snapshot.
fn sample(t: &AppPerformanceTelemetry) -> RuntimePerformanceSnapshot {
    t.snapshot()
        .runtime_operations
        .into_iter()
        .find(|s| s.operation == RuntimePerformanceOperation::ConversationOpen)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborted_caller_records_cancellation_without_a_completion_callback() {
    let t = PerformanceRecorder::default();
    let copy = t.clone();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        copy.measure_app(RuntimePerformanceOperation::ConversationOpen, async move {
            entered.send(()).unwrap();
            std::future::pending::<Result<(), crate::AppError>>().await
        })
        .await
    });
    waiting.await.unwrap();
    assert_eq!(sample(&t).in_flight, 1);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let s = sample(&t);
    assert_eq!(
        (s.started, s.completed, s.cancelled, s.in_flight),
        (1, 1, 1, 0)
    );
}
