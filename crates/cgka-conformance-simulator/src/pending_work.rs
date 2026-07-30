//! Instantaneous pending-work observations for strict simulator assertions.
//!
//! This deliberately does not decide quiescence over time. It captures one
//! privacy-safe, client-scoped local execution boundary; Milestone 1.3 will
//! add structural progress tokens and bounded virtual-time fixed-point
//! evaluation. It does not assert end-to-end delivery of transport objects
//! that a scenario dropped.

use cgka_engine::conformance_snapshot::ConformancePendingWorkSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BusPendingWorkSnapshot {
    pub queued_messages: usize,
    pub delayed_messages: usize,
    pub mailbox_messages: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingWorkObservation {
    pub engine: ConformancePendingWorkSnapshot,
    pub bus_queued_messages: usize,
    pub bus_delayed_messages: usize,
    pub bus_mailbox_messages: usize,
    pub scenario_inputs_pending: usize,
}

impl PendingWorkObservation {
    pub fn is_empty(&self) -> bool {
        self.engine.is_empty()
            && self.bus_queued_messages == 0
            && self.bus_delayed_messages == 0
            && self.bus_mailbox_messages == 0
            && self.scenario_inputs_pending == 0
    }

    pub fn blocking_subsystems(&self) -> Vec<&'static str> {
        let mut blockers = Vec::new();
        if !self.engine.is_empty() {
            blockers.push("engine");
        }
        if self.bus_queued_messages > 0 {
            blockers.push("bus_queue");
        }
        if self.bus_delayed_messages > 0 {
            blockers.push("bus_delayed");
        }
        if self.bus_mailbox_messages > 0 {
            blockers.push("bus_mailboxes");
        }
        if self.scenario_inputs_pending > 0 {
            blockers.push("scenario_inputs");
        }
        blockers
    }
}
