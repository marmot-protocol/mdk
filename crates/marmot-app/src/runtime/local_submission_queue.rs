//! Bounded, process-local admission-to-first-execution observations.
//!
//! Private keys correlate an observation with its durable row; they never
//! leave this module in diagnostics. Restored rows have no monotonic admission
//! instant and produce no queue-duration sample. Capacity omissions and teardown
//! finish observations as cancelled, never as successful zero-length waits.
//! Signing out retains an admitted row's observation in this runtime: its wait
//! includes the inactive interval before a later sign-in executes it.

use super::*;
use crate::app_telemetry::runtime::Observation;

const OBSERVATION_LIMIT: usize = 1024;

#[derive(Default)]
pub(super) struct LocalSubmissionQueue {
    observations: HashMap<(String, String, String), QueueObservation>,
    // Weak entries coordinate only live local operations. Dead entries are
    // pruned on lookup; sign-out/worker replacement cannot create a second
    // gate while an admission or selection still owns the original Arc.
    gates: HashMap<String, std::sync::Weak<Mutex<()>>>,
}

pub(super) struct QueueObservation {
    started: Instant,
    observation: Observation,
}

impl QueueObservation {
    pub(super) fn finish(self, telemetry: &AppPerformanceTelemetry) {
        telemetry.record(
            AppPerformanceOperation::OutboundMessageQueueWait,
            self.started.elapsed(),
            true,
        );
        self.observation.finish(TelemetryOutcome::Success);
    }
}

impl LocalSubmissionQueue {
    pub(super) fn account_gate(&mut self, account: &str) -> Arc<Mutex<()>> {
        self.gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = self.gates.get(account).and_then(std::sync::Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(Mutex::new(()));
        self.gates.insert(account.to_owned(), Arc::downgrade(&gate));
        gate
    }

    /// Register only a newly committed admission. A repeated token cannot reset
    /// the first admission instant, even if the worker has already selected it.
    pub(super) fn admitted(
        &mut self,
        account: &str,
        group: &str,
        message: &str,
        telemetry: &AppPerformanceTelemetry,
    ) {
        let key = (account.to_owned(), group.to_owned(), message.to_owned());
        if self.observations.contains_key(&key) {
            return;
        }
        let observation = telemetry.observe(RuntimeOp::SendQueue);
        if self.observations.len() >= OBSERVATION_LIMIT {
            drop(observation);
            return;
        }
        self.observations.insert(
            key,
            QueueObservation {
                started: Instant::now(),
                observation,
            },
        );
    }

    pub(super) fn take(
        &mut self,
        account: &str,
        group: &str,
        message: &str,
    ) -> Option<QueueObservation> {
        self.observations
            .remove(&(account.to_owned(), group.to_owned(), message.to_owned()))
    }

    pub(super) fn cancel_account(&mut self, account: &str) {
        self.observations
            .retain(|(owner, _, _), _| owner != account);
    }

    pub(super) fn clear(&mut self) {
        self.observations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue_snapshot(telemetry: &AppPerformanceTelemetry) -> crate::RuntimePerformanceSnapshot {
        telemetry
            .snapshot()
            .runtime_operations
            .into_iter()
            .find(|snapshot| snapshot.operation == RuntimeOp::SendQueue)
            .unwrap()
    }

    #[test]
    fn duplicate_admission_preserves_start_and_first_execution_is_measured_once() {
        let telemetry = AppPerformanceTelemetry::default();
        let mut queue = LocalSubmissionQueue::default();
        queue.admitted(
            "private-account",
            "private-group",
            "private-message",
            &telemetry,
        );
        let started = queue.observations.values().next().unwrap().started;
        queue.admitted(
            "private-account",
            "private-group",
            "private-message",
            &telemetry,
        );
        assert_eq!(queue.observations.values().next().unwrap().started, started);
        queue
            .take("private-account", "private-group", "private-message")
            .unwrap()
            .finish(&telemetry);
        assert!(
            queue
                .take("private-account", "private-group", "private-message")
                .is_none()
        );
        let snapshot = queue_snapshot(&telemetry);
        assert_eq!(snapshot.started, 1);
        assert_eq!(snapshot.successes, 1);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(telemetry.snapshot().outbound_message_queue_wait.attempts, 1);
    }

    #[test]
    fn capacity_and_shutdown_are_bounded_cancellations_without_duration_samples() {
        let telemetry = AppPerformanceTelemetry::default();
        let mut queue = LocalSubmissionQueue::default();
        for message in 0..=OBSERVATION_LIMIT {
            queue.admitted(
                "private-account",
                "private-group",
                &message.to_string(),
                &telemetry,
            );
        }
        assert_eq!(queue.observations.len(), OBSERVATION_LIMIT);
        let snapshot = queue_snapshot(&telemetry);
        assert_eq!(snapshot.cancelled, 1);
        assert_eq!(snapshot.in_flight, OBSERVATION_LIMIT as u64);
        queue.clear();
        let snapshot = queue_snapshot(&telemetry);
        assert_eq!(snapshot.cancelled, (OBSERVATION_LIMIT + 1) as u64);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(telemetry.snapshot().outbound_message_queue_wait.attempts, 0);
    }

    #[test]
    fn private_keys_never_enter_snapshots_and_restored_rows_have_no_sample() {
        let telemetry = AppPerformanceTelemetry::default();
        let mut queue = LocalSubmissionQueue::default();
        queue.admitted(
            "private-account",
            "private-group",
            "private-message",
            &telemetry,
        );
        assert!(
            queue
                .take("private-account", "private-group", "restored-message")
                .is_none()
        );
        let encoded = serde_json::to_string(&telemetry.snapshot()).unwrap();
        for secret in [
            "private-account",
            "private-group",
            "private-message",
            "restored-message",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert_eq!(telemetry.snapshot().outbound_message_queue_wait.attempts, 0);
    }

    #[test]
    fn equal_message_ids_in_different_groups_have_independent_admission_waits() {
        let telemetry = AppPerformanceTelemetry::default();
        let mut queue = LocalSubmissionQueue::default();
        queue.admitted("account", "group-one", "same-message", &telemetry);
        queue.admitted("account", "group-two", "same-message", &telemetry);
        queue.admitted("account", "group-one", "same-message", &telemetry);
        queue
            .take("account", "group-one", "same-message")
            .unwrap()
            .finish(&telemetry);
        queue
            .take("account", "group-two", "same-message")
            .unwrap()
            .finish(&telemetry);
        assert_eq!(queue_snapshot(&telemetry).successes, 2);
        assert_eq!(telemetry.snapshot().outbound_message_queue_wait.attempts, 2);
    }

    #[test]
    fn account_gates_isolate_contended_owners_and_prune_dead_entries() {
        let mut queue = LocalSubmissionQueue::default();
        let account_a = queue.account_gate("a");
        let same_account_a = queue.account_gate("a");
        let account_b = queue.account_gate("b");
        assert!(Arc::ptr_eq(&account_a, &same_account_a));
        let _held = account_a.try_lock().unwrap();
        assert!(same_account_a.try_lock().is_err());
        assert!(account_b.try_lock().is_ok());
        drop(_held);
        drop(account_a);
        drop(same_account_a);
        drop(account_b);
        let _active = queue.account_gate("c");
        assert_eq!(queue.gates.len(), 1);
    }

    #[test]
    fn permanent_account_deletion_cancels_only_its_pending_observations() {
        let telemetry = AppPerformanceTelemetry::default();
        let mut queue = LocalSubmissionQueue::default();
        queue.admitted("deleted", "group", "message", &telemetry);
        queue.admitted("retained", "group", "message", &telemetry);
        queue.cancel_account("deleted");
        let snapshot = queue_snapshot(&telemetry);
        assert_eq!(snapshot.cancelled, 1);
        assert_eq!(snapshot.in_flight, 1);
        queue
            .take("retained", "group", "message")
            .unwrap()
            .finish(&telemetry);
        assert_eq!(queue_snapshot(&telemetry).successes, 1);
    }
}
