//! Instantaneous pending-work observations for strict simulator assertions.
//!
//! The pending-work form captures one privacy-safe, client-scoped local
//! execution boundary. The structural form is consumed by the bounded
//! virtual-time fixed-point driver, but it still does not assert end-to-end
//! delivery of transport objects that a scenario dropped.

use cgka_engine::conformance_snapshot::{
    ConformancePendingWorkSnapshot, ConformanceStructuralProgressSnapshot,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BusPendingWorkSnapshot {
    pub queued_messages: usize,
    pub delayed_messages: usize,
    pub mailbox_messages: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BusStructuralProgressSnapshot {
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

/// One participant's sanitized engine scheduling state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientStructuralProgress {
    pub client: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<ConformanceStructuralProgressSnapshot>,
    pub scenario_inputs_pending: usize,
}

/// Terminal engine state that cannot be resolved by running or advancing the
/// subject. The client label is a scenario-local name, never an account id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectTerminalBlocker {
    EngineUnrecoverable { client: String },
}

/// Adapter-neutral structural state consumed by the virtual-time fixed-point
/// driver. The token is diagnostic and cycle-detection evidence; quiescence is
/// defined by the explicit work/deadline fields, never token equality alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectProgressSnapshot {
    pub schema_version: String,
    pub structural_token: String,
    pub current_monotonic_ms: u64,
    pub runnable_work: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub earliest_next_wake_monotonic_ms: Option<u64>,
    pub deferred_retry_work: usize,
    pub outbound_awaiting_acknowledgement: usize,
    pub transport_queued_messages: usize,
    pub transport_delayed_messages: usize,
    pub transport_mailbox_messages: usize,
    pub scenario_inputs_pending: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_blockers: Vec<SubjectTerminalBlocker>,
    pub clients: Vec<ClientStructuralProgress>,
}

impl SubjectProgressSnapshot {
    pub fn is_quiescent(&self) -> bool {
        self.runnable_work == 0
            && self.earliest_next_wake_monotonic_ms.is_none()
            && self.deferred_retry_work == 0
            && self.outbound_awaiting_acknowledgement == 0
            && self.transport_queued_messages == 0
            && self.transport_delayed_messages == 0
            && self.transport_mailbox_messages == 0
            && self.scenario_inputs_pending == 0
            && self.terminal_blockers.is_empty()
    }

    pub fn blocking_subsystems(&self) -> Vec<&'static str> {
        let mut blockers = Vec::new();
        if self.runnable_work > 0 {
            blockers.push("runnable_work");
        }
        if self.earliest_next_wake_monotonic_ms.is_some() {
            blockers.push("scheduled_wake");
        }
        if self.deferred_retry_work > 0 {
            blockers.push("deferred_retry");
        }
        if self.outbound_awaiting_acknowledgement > 0 {
            blockers.push("outbound_acknowledgement");
        }
        if self.transport_queued_messages > 0 {
            blockers.push("transport_queue");
        }
        if self.transport_delayed_messages > 0 {
            blockers.push("transport_delayed");
        }
        if self.transport_mailbox_messages > 0 {
            blockers.push("transport_mailboxes");
        }
        if self.scenario_inputs_pending > 0 {
            blockers.push("scenario_inputs");
        }
        if !self.terminal_blockers.is_empty() {
            blockers.push("terminal_engine_state");
        }
        blockers
    }
}
