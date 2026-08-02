//! Adapter-neutral virtual-time quiescence driver.
//!
//! Quiescence is a structural fixed point: no runnable work, no future wake,
//! no deferred/retry work, no unresolved publication, and no external or
//! terminal blocker. Limits are watchdog evidence only and never redefine an
//! unfinished subject as quiescent.

use crate::{ConvergenceSubject, SubjectError, SubjectOutboundOutcome, SubjectProgressSnapshot};
use serde::{Deserialize, Serialize};

const fn default_max_iterations() -> u32 {
    256
}

const fn default_max_virtual_time_ms() -> u64 {
    60_000
}

const fn default_max_work_units() -> u64 {
    100_000
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceOutboundPolicy {
    #[default]
    AcceptAll,
    Manual,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceTransportPolicy {
    #[default]
    DeliverAll,
    Manual,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuiescencePolicy {
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,
    #[serde(default = "default_max_virtual_time_ms")]
    pub max_virtual_time_ms: u64,
    #[serde(default = "default_max_work_units")]
    pub max_work_units: u64,
    #[serde(default)]
    pub outbound: QuiescenceOutboundPolicy,
    #[serde(default)]
    pub transport: QuiescenceTransportPolicy,
}

impl Default for QuiescencePolicy {
    fn default() -> Self {
        Self {
            max_iterations: default_max_iterations(),
            max_virtual_time_ms: default_max_virtual_time_ms(),
            max_work_units: default_max_work_units(),
            outbound: QuiescenceOutboundPolicy::default(),
            transport: QuiescenceTransportPolicy::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceWatchdog {
    Iterations,
    VirtualTime,
    WorkUnits,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuiescenceStatus {
    Quiescent,
    Blocked {
        subsystems: Vec<String>,
    },
    TimedOut {
        watchdog: QuiescenceWatchdog,
        subsystems: Vec<String>,
    },
}

impl QuiescenceStatus {
    pub fn is_quiescent(&self) -> bool {
        matches!(self, Self::Quiescent)
    }
}

/// Serializable terminal artifact for one fixed-point attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuiescenceObservation {
    pub step_index: usize,
    pub policy: QuiescencePolicy,
    pub status: QuiescenceStatus,
    pub iterations: u32,
    pub work_units: u64,
    pub virtual_time_advanced_ms: u64,
    pub final_progress: SubjectProgressSnapshot,
}

pub async fn drive_subject_to_quiescence(
    subject: &mut dyn ConvergenceSubject,
    clients: &[String],
    policy: &QuiescencePolicy,
    step_index: usize,
) -> Result<QuiescenceObservation, SubjectError> {
    // Select controlled-time behavior before the first participant wake. This
    // prevents legacy harness adapters from substituting their historical
    // far-future one-shot drain shortcut without relying on a magic time delta.
    subject.activate_virtual_time()?;
    let initial = subject.structural_progress()?;
    let started_at = initial.current_monotonic_ms;
    let mut snapshot = initial;
    let mut iterations = 0u32;
    let mut work_units = 0u64;

    loop {
        if snapshot.is_quiescent() {
            return Ok(observation(
                step_index,
                policy,
                QuiescenceStatus::Quiescent,
                iterations,
                work_units,
                started_at,
                snapshot,
            ));
        }
        if !snapshot.terminal_blockers.is_empty() {
            return Ok(blocked_observation(
                step_index, policy, iterations, work_units, started_at, snapshot,
            ));
        }
        if (snapshot.outbound_awaiting_acknowledgement > 0
            && policy.outbound == QuiescenceOutboundPolicy::Manual)
            || (snapshot.transport_queued_messages > 0
                && policy.transport == QuiescenceTransportPolicy::Manual)
        {
            return Ok(blocked_observation(
                step_index, policy, iterations, work_units, started_at, snapshot,
            ));
        }
        if iterations >= policy.max_iterations {
            return Ok(timeout_observation(
                step_index,
                policy,
                QuiescenceWatchdog::Iterations,
                iterations,
                work_units,
                started_at,
                snapshot,
            ));
        }

        let will_ack = snapshot.outbound_awaiting_acknowledgement > 0
            && policy.outbound == QuiescenceOutboundPolicy::AcceptAll;
        let will_deliver = snapshot.transport_queued_messages > 0
            && policy.transport == QuiescenceTransportPolicy::DeliverAll;
        let will_tick = snapshot.runnable_engine_work > 0
            || snapshot.transport_mailbox_messages > 0
            || will_deliver;
        let planned_work = (if will_ack {
            snapshot.outbound_awaiting_acknowledgement as u64
        } else {
            0
        })
        .saturating_add(if will_deliver {
            snapshot.transport_queued_messages as u64
        } else {
            0
        })
        .saturating_add(if will_tick {
            snapshot
                .runnable_engine_work
                .saturating_add(snapshot.transport_mailbox_messages)
                .max(1) as u64
        } else {
            0
        });
        if planned_work > 0 && work_units.saturating_add(planned_work) > policy.max_work_units {
            return Ok(timeout_observation(
                step_index,
                policy,
                QuiescenceWatchdog::WorkUnits,
                iterations,
                work_units,
                started_at,
                snapshot,
            ));
        }
        if will_ack {
            for client in clients {
                for artifact in subject.poll_outbound(client)? {
                    subject
                        .acknowledge_outbound(
                            client,
                            &artifact.outbound_id,
                            SubjectOutboundOutcome::Accepted,
                        )
                        .await?;
                }
            }
        }

        if will_deliver {
            subject.deliver_all()?;
        }

        if will_tick {
            subject.tick(clients).await?;
        }

        if planned_work > 0 {
            work_units = work_units.saturating_add(planned_work);
            iterations = iterations.saturating_add(1);
            snapshot = subject.structural_progress()?;
            continue;
        }

        if let Some(next_wake) = snapshot.earliest_next_wake_monotonic_ms {
            let delta = next_wake.saturating_sub(snapshot.current_monotonic_ms);
            let advanced = snapshot.current_monotonic_ms.saturating_sub(started_at);
            if advanced.saturating_add(delta) > policy.max_virtual_time_ms {
                return Ok(timeout_observation(
                    step_index,
                    policy,
                    QuiescenceWatchdog::VirtualTime,
                    iterations,
                    work_units,
                    started_at,
                    snapshot,
                ));
            }
            if work_units.saturating_add(1) > policy.max_work_units {
                return Ok(timeout_observation(
                    step_index,
                    policy,
                    QuiescenceWatchdog::WorkUnits,
                    iterations,
                    work_units,
                    started_at,
                    snapshot,
                ));
            }
            subject.advance_time(delta).await?;
            subject.tick(clients).await?;
            iterations = iterations.saturating_add(1);
            work_units = work_units.saturating_add(1);
            snapshot = subject.structural_progress()?;
            continue;
        }

        return Ok(blocked_observation(
            step_index, policy, iterations, work_units, started_at, snapshot,
        ));
    }
}

fn observation(
    step_index: usize,
    policy: &QuiescencePolicy,
    status: QuiescenceStatus,
    iterations: u32,
    work_units: u64,
    started_at: u64,
    final_progress: SubjectProgressSnapshot,
) -> QuiescenceObservation {
    QuiescenceObservation {
        step_index,
        policy: policy.clone(),
        status,
        iterations,
        work_units,
        virtual_time_advanced_ms: final_progress
            .current_monotonic_ms
            .saturating_sub(started_at),
        final_progress,
    }
}

fn blocked_observation(
    step_index: usize,
    policy: &QuiescencePolicy,
    iterations: u32,
    work_units: u64,
    started_at: u64,
    final_progress: SubjectProgressSnapshot,
) -> QuiescenceObservation {
    let subsystems = blocker_names(&final_progress);
    observation(
        step_index,
        policy,
        QuiescenceStatus::Blocked { subsystems },
        iterations,
        work_units,
        started_at,
        final_progress,
    )
}

fn timeout_observation(
    step_index: usize,
    policy: &QuiescencePolicy,
    watchdog: QuiescenceWatchdog,
    iterations: u32,
    work_units: u64,
    started_at: u64,
    final_progress: SubjectProgressSnapshot,
) -> QuiescenceObservation {
    let subsystems = blocker_names(&final_progress);
    observation(
        step_index,
        policy,
        QuiescenceStatus::TimedOut {
            watchdog,
            subsystems,
        },
        iterations,
        work_units,
        started_at,
        final_progress,
    )
}

fn blocker_names(snapshot: &SubjectProgressSnapshot) -> Vec<String> {
    snapshot
        .blocking_subsystems()
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SubjectCapability, SubjectDescriptor};
    use async_trait::async_trait;
    use std::collections::BTreeSet;

    struct StuckSubject {
        snapshot: SubjectProgressSnapshot,
        ticks: usize,
    }

    #[async_trait]
    impl ConvergenceSubject for StuckSubject {
        fn descriptor(&self) -> SubjectDescriptor {
            SubjectDescriptor {
                adapter: "stuck".into(),
                adapter_version: "1".into(),
                storage_backend: "none".into(),
                capabilities: BTreeSet::from([
                    SubjectCapability::StructuralProgress,
                    SubjectCapability::TransportDelivery,
                    SubjectCapability::VirtualTime,
                ]),
            }
        }

        fn structural_progress(&mut self) -> Result<SubjectProgressSnapshot, SubjectError> {
            Ok(self.snapshot.clone())
        }

        async fn tick(&mut self, _clients: &[String]) -> Result<(), SubjectError> {
            self.ticks += 1;
            if self.snapshot.transport_mailbox_messages > 0 {
                self.snapshot.runnable_work = self
                    .snapshot
                    .runnable_work
                    .saturating_sub(self.snapshot.transport_mailbox_messages);
                self.snapshot.transport_mailbox_messages = 0;
            }
            Ok(())
        }

        fn activate_virtual_time(&mut self) -> Result<(), SubjectError> {
            Ok(())
        }

        async fn advance_time(&mut self, delta_ms: u64) -> Result<(), SubjectError> {
            self.snapshot.current_monotonic_ms =
                self.snapshot.current_monotonic_ms.saturating_add(delta_ms);
            Ok(())
        }
    }

    fn progress() -> SubjectProgressSnapshot {
        SubjectProgressSnapshot {
            schema_version: "1".into(),
            structural_token: "unchanged".into(),
            current_monotonic_ms: 0,
            runnable_engine_work: 1,
            runnable_work: 1,
            earliest_next_wake_monotonic_ms: None,
            deferred_retry_work: 0,
            outbound_awaiting_acknowledgement: 0,
            transport_queued_messages: 0,
            transport_delayed_messages: 0,
            transport_mailbox_messages: 0,
            scenario_inputs_pending: 0,
            terminal_blockers: Vec::new(),
            clients: Vec::new(),
        }
    }

    #[tokio::test]
    async fn unchanged_runnable_work_times_out_without_becoming_quiescent() {
        let mut subject = StuckSubject {
            snapshot: progress(),
            ticks: 0,
        };
        let result = drive_subject_to_quiescence(
            &mut subject,
            &["alice".into()],
            &QuiescencePolicy {
                max_iterations: 2,
                max_work_units: 10,
                ..QuiescencePolicy::default()
            },
            3,
        )
        .await
        .expect("watchdog produces an artifact");

        assert_eq!(subject.ticks, 2);
        assert!(matches!(
            result.status,
            QuiescenceStatus::TimedOut {
                watchdog: QuiescenceWatchdog::Iterations,
                ..
            }
        ));
        assert!(!result.final_progress.is_quiescent());
    }

    #[tokio::test]
    async fn virtual_time_budget_is_a_watchdog_not_a_quiescence_definition() {
        let mut pending = progress();
        pending.runnable_engine_work = 0;
        pending.runnable_work = 0;
        pending.earliest_next_wake_monotonic_ms = Some(100);
        let mut subject = StuckSubject {
            snapshot: pending,
            ticks: 0,
        };
        let result = drive_subject_to_quiescence(
            &mut subject,
            &["alice".into()],
            &QuiescencePolicy {
                max_virtual_time_ms: 99,
                ..QuiescencePolicy::default()
            },
            4,
        )
        .await
        .expect("watchdog produces an artifact");

        assert!(matches!(
            result.status,
            QuiescenceStatus::TimedOut {
                watchdog: QuiescenceWatchdog::VirtualTime,
                ..
            }
        ));
        assert_eq!(
            result.final_progress.earliest_next_wake_monotonic_ms,
            Some(100)
        );
        assert!(!result.final_progress.is_quiescent());
    }

    #[tokio::test]
    async fn work_unit_budget_covers_immediate_and_scheduled_actions() {
        let policy = QuiescencePolicy {
            max_work_units: 0,
            ..QuiescencePolicy::default()
        };
        let mut immediate = StuckSubject {
            snapshot: progress(),
            ticks: 0,
        };
        let immediate_result =
            drive_subject_to_quiescence(&mut immediate, &["alice".into()], &policy, 5)
                .await
                .expect("immediate work budget produces an artifact");
        assert!(matches!(
            immediate_result.status,
            QuiescenceStatus::TimedOut {
                watchdog: QuiescenceWatchdog::WorkUnits,
                ..
            }
        ));
        assert_eq!(immediate.ticks, 0);

        let mut scheduled_progress = progress();
        scheduled_progress.runnable_engine_work = 0;
        scheduled_progress.runnable_work = 0;
        scheduled_progress.earliest_next_wake_monotonic_ms = Some(100);
        let mut scheduled = StuckSubject {
            snapshot: scheduled_progress,
            ticks: 0,
        };
        let scheduled_result =
            drive_subject_to_quiescence(&mut scheduled, &["alice".into()], &policy, 6)
                .await
                .expect("scheduled work budget produces an artifact");
        assert!(matches!(
            scheduled_result.status,
            QuiescenceStatus::TimedOut {
                watchdog: QuiescenceWatchdog::WorkUnits,
                ..
            }
        ));
        assert_eq!(scheduled.snapshot.current_monotonic_ms, 0);
        assert_eq!(scheduled.ticks, 0);
    }

    #[tokio::test]
    async fn manual_transport_drains_mailboxes_but_blocks_undelivered_queue() {
        let policy = QuiescencePolicy {
            transport: QuiescenceTransportPolicy::Manual,
            ..QuiescencePolicy::default()
        };
        let mut mailbox_progress = progress();
        mailbox_progress.runnable_engine_work = 0;
        mailbox_progress.transport_mailbox_messages = 1;
        let mut mailbox = StuckSubject {
            snapshot: mailbox_progress,
            ticks: 0,
        };
        let settled = drive_subject_to_quiescence(&mut mailbox, &["alice".into()], &policy, 7)
            .await
            .expect("post-delivery mailbox can drain under manual transport");
        assert_eq!(settled.status, QuiescenceStatus::Quiescent);
        assert_eq!(mailbox.ticks, 1);

        let mut queued_progress = progress();
        queued_progress.runnable_engine_work = 0;
        queued_progress.transport_queued_messages = 1;
        let mut queued = StuckSubject {
            snapshot: queued_progress,
            ticks: 0,
        };
        let blocked = drive_subject_to_quiescence(&mut queued, &["alice".into()], &policy, 8)
            .await
            .expect("undelivered queue is a manual transport blocker");
        assert!(matches!(blocked.status, QuiescenceStatus::Blocked { .. }));
        assert_eq!(queued.ticks, 0);
    }
}
