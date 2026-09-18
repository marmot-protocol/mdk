//! Closed, bounded diagnostics for interactive work and its blockers.
//!
//! Observations own no runtime resources and never change scheduling. Dropping
//! one records cancellation, including cancellation before a queued command runs.
use super::*;

// Only age tracking is capped; all starts, outcomes and active counts remain exact.
const TRACKED_STARTS: usize = 64;

macro_rules! operations {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum RuntimePerformanceOperation { $($variant),+ }
        impl RuntimePerformanceOperation {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
            pub(crate) const fn metric_names(self) -> [&'static str; 11] {
                match self { $(Self::$variant => [
                    concat!("app_runtime_", $name, "_started"),
                    concat!("app_runtime_", $name, "_completed"),
                    concat!("app_runtime_", $name, "_successes"),
                    concat!("app_runtime_", $name, "_failures"),
                    concat!("app_runtime_", $name, "_cancelled"),
                    concat!("app_runtime_", $name, "_timeouts"),
                    concat!("app_runtime_", $name, "_not_ready"),
                    concat!("app_runtime_", $name, "_duration_ms"),
                    concat!("app_runtime_", $name, "_in_flight"),
                    concat!("app_runtime_", $name, "_oldest_tracked_in_flight_ms"),
                    concat!("app_runtime_", $name, "_untracked_in_flight"),
                ]),+ }
            }
        }
    };
}

operations! {
    ConversationOpen => "conversation_open",
    ConversationLocalRead => "conversation_local_read",
    ConversationWorkerAcquire => "conversation_worker_acquire",
    ConversationAuthorityAttempt => "conversation_authority_attempt",
    ConversationCaptureQueue => "conversation_capture_queue",
    ConversationCapture => "conversation_capture",
    ConversationPresentation => "conversation_presentation",
    ConversationAuthorityReady => "conversation_authority_ready",
    ConversationSendReady => "conversation_send_ready",
    DraftSendCaller => "draft_send_caller",
    DirectSendCaller => "direct_send_caller",
    SendWorkerAcquire => "send_worker_acquire",
    SendAdmission => "send_admission",
    SendQueue => "send_queue",
    SendExecution => "send_execution",
    CatchUpRequested => "catch_up_requested",
    CatchUpAfterMutation => "catch_up_after_mutation",
    CatchUpCoalesced => "catch_up_coalesced",
    ReconnectCommandRejected => "reconnect_command_rejected",
    IngestEngine => "ingest_engine",
    IngestEffectPublish => "ingest_effect_publish",
    WorkerAcquire => "worker_acquire",
    LifecycleLockWait => "lifecycle_lock_wait",
    AccountStartup => "account_startup",
    WorkerHydration => "worker_hydration",
    WorkerCatchUp => "worker_catch_up",
    WorkerSnapshot => "worker_snapshot",
    WorkerConvergence => "worker_convergence",
    WorkerReceive => "worker_receive",
    WorkerReconnectWait => "worker_reconnect_wait",
    WorkerReopen => "worker_reopen",
    WorkerMaintenance => "worker_maintenance",
    Ingest => "ingest",
    StorageConnectionWait => "storage_connection_wait",
    StorageTransaction => "storage_transaction",
    StorageWriteBegin => "storage_write_begin",
    ProjectionCheckpoint => "projection_checkpoint",
    HostConversationLocalVisible => "host_conversation_local_visible",
    HostConversationComposerReady => "host_conversation_composer_ready",
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePerformanceSnapshot {
    pub operation: RuntimePerformanceOperation,
    pub started: u64,
    /// All terminal outcomes, including cancellation, timeout and not-ready.
    pub completed: u64,
    pub successes: u64,
    pub failures: u64,
    pub cancelled: u64,
    pub timeouts: u64,
    pub not_ready: u64,
    pub in_flight: u64,
    /// Oldest of at most 64 tracked starts; a lower bound if tracking overflowed.
    pub oldest_tracked_in_flight_ms: u64,
    pub untracked_in_flight: u64,
    pub duration_ms: DurationHistogramSnapshot,
}

#[derive(Debug, Default)]
struct OperationState {
    started: u64,
    completed: u64,
    successes: u64,
    failures: u64,
    cancelled: u64,
    timeouts: u64,
    not_ready: u64,
    active: u64,
    starts: Vec<Option<Instant>>,
    duration: DurationHistogram,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Outcome {
    Success,
    Failure,
    Cancelled,
    Timeout,
    NotReady,
}

impl OperationState {
    fn finish(&mut self, outcome: Outcome, duration: Duration) {
        self.completed += 1;
        match outcome {
            Outcome::Success => self.successes += 1,
            Outcome::Failure => self.failures += 1,
            Outcome::Cancelled => self.cancelled += 1,
            Outcome::Timeout => self.timeouts += 1,
            Outcome::NotReady => self.not_ready += 1,
        }
        self.duration.record(duration);
    }
    fn snapshot(&self, operation: RuntimePerformanceOperation) -> RuntimePerformanceSnapshot {
        let tracked = self.starts.iter().flatten().count() as u64;
        RuntimePerformanceSnapshot {
            operation,
            started: self.started,
            completed: self.completed,
            successes: self.successes,
            failures: self.failures,
            cancelled: self.cancelled,
            timeouts: self.timeouts,
            not_ready: self.not_ready,
            in_flight: self.active,
            oldest_tracked_in_flight_ms: self
                .starts
                .iter()
                .flatten()
                .map(|s| millis(s.elapsed()))
                .max()
                .unwrap_or(0),
            untracked_in_flight: self.active.saturating_sub(tracked),
            duration_ms: self.duration.snapshot(),
        }
    }
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RuntimeTelemetry(
    Arc<Mutex<BTreeMap<RuntimePerformanceOperation, OperationState>>>,
);
impl RuntimeTelemetry {
    pub(super) fn snapshot(&self) -> Vec<RuntimePerformanceSnapshot> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        RuntimePerformanceOperation::ALL
            .iter()
            .map(|op| {
                state
                    .get(op)
                    .unwrap_or(&OperationState::default())
                    .snapshot(*op)
            })
            .collect()
    }
}

/// A cancellation-safe timing observation. Contains only a closed operation and
/// monotonic start; never holds a client, database, account or user identifier.
pub(crate) struct Observation {
    telemetry: RuntimeTelemetry,
    operation: RuntimePerformanceOperation,
    started: Instant,
    slot: Option<usize>,
    finished: bool,
}
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observation")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}
impl Observation {
    pub(crate) fn finish(mut self, outcome: Outcome) {
        self.complete(outcome);
    }
    pub(crate) fn finish_app<T>(self, result: &Result<T, crate::AppError>) {
        self.finish(match result {
            Ok(_) => Outcome::Success,
            Err(crate::AppError::AccountWorkerResponseTimedOut) => Outcome::Timeout,
            Err(crate::AppError::AccountWorkerBusy) => Outcome::NotReady,
            Err(_) => Outcome::Failure,
        });
    }
    fn complete(&mut self, outcome: Outcome) {
        if self.finished {
            return;
        }
        let mut states = self.telemetry.0.lock().unwrap_or_else(|e| e.into_inner());
        let state = states
            .get_mut(&self.operation)
            .expect("observation registered");
        state.active -= 1;
        if let Some(slot) = self.slot {
            state.starts[slot] = None;
        }
        state.finish(outcome, self.started.elapsed());
        self.finished = true;
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        self.complete(Outcome::Cancelled);
    }
}

impl AppPerformanceTelemetry {
    pub(crate) async fn measure_app<T>(
        &self,
        operation: RuntimePerformanceOperation,
        work: impl std::future::Future<Output = Result<T, crate::AppError>>,
    ) -> Result<T, crate::AppError> {
        let observation = self.observe(operation);
        let result = work.await;
        observation.finish_app(&result);
        result
    }
    pub(crate) fn observe(&self, operation: RuntimePerformanceOperation) -> Observation {
        let started = Instant::now();
        let mut states = self.runtime.0.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(operation).or_default();
        state.started += 1;
        state.active += 1;
        let slot = if let Some(index) = state.starts.iter().position(Option::is_none) {
            state.starts[index] = Some(started);
            Some(index)
        } else if state.starts.len() < TRACKED_STARTS {
            state.starts.push(Some(started));
            Some(state.starts.len() - 1)
        } else {
            None
        };
        Observation {
            telemetry: self.runtime.clone(),
            operation,
            started,
            slot,
            finished: false,
        }
    }
    pub(crate) fn record_runtime(
        &self,
        operation: RuntimePerformanceOperation,
        duration: Duration,
        outcome: Outcome,
    ) {
        let mut states = self.runtime.0.lock().unwrap_or_else(|e| e.into_inner());
        let state = states.entry(operation).or_default();
        state.started += 1;
        state.finish(outcome, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(t: &AppPerformanceTelemetry) -> RuntimePerformanceSnapshot {
        t.runtime
            .snapshot()
            .into_iter()
            .find(|s| s.operation == RuntimePerformanceOperation::ConversationOpen)
            .unwrap()
    }
    #[test]
    fn live_cancelled_and_terminal_outcomes_balance() {
        let t = AppPerformanceTelemetry::default();
        let live = t.observe(RuntimePerformanceOperation::ConversationOpen);
        assert_eq!(sample(&t).in_flight, 1);
        assert_eq!(sample(&t).completed, 0);
        drop(live);
        for outcome in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Timeout,
            Outcome::NotReady,
        ] {
            t.observe(RuntimePerformanceOperation::ConversationOpen)
                .finish(outcome);
        }
        let s = sample(&t);
        assert_eq!((s.started, s.completed, s.in_flight), (5, 5, 0));
        assert_eq!(
            (
                s.successes,
                s.failures,
                s.cancelled,
                s.timeouts,
                s.not_ready
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(
            s.duration_ms.buckets.iter().map(|b| b.count).sum::<u64>()
                + s.duration_ms.overflow_count,
            5
        );
    }
    #[test]
    fn age_tracking_is_bounded_but_counts_are_not_lost() {
        let t = AppPerformanceTelemetry::default();
        let mut live = (0..TRACKED_STARTS + 10)
            .map(|_| t.observe(RuntimePerformanceOperation::ConversationOpen))
            .collect::<Vec<_>>();
        assert_eq!(sample(&t).untracked_in_flight, 10);
        live.remove(0).finish(Outcome::Success);
        let reused = t.observe(RuntimePerformanceOperation::ConversationOpen);
        assert_eq!(sample(&t).untracked_in_flight, 10);
        drop(live);
        drop(reused);
        assert_eq!(
            (sample(&t).in_flight, sample(&t).untracked_in_flight),
            (0, 0)
        );
        assert_eq!(sample(&t).started, sample(&t).completed);
    }
    #[test]
    fn every_series_exists_before_its_first_observation() {
        let snapshots = RuntimeTelemetry::default().snapshot();
        assert_eq!(snapshots.len(), RuntimePerformanceOperation::ALL.len());
        assert!(
            snapshots
                .iter()
                .all(|s| s.started == 0 && s.duration_ms.buckets.len() == 27)
        );
    }
    #[tokio::test]
    async fn aborted_caller_records_cancellation_without_a_completion_callback() {
        let t = AppPerformanceTelemetry::default();
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
}
