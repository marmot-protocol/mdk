//! Identifier-free connector diagnostic report for `diagnostic_status`.

use serde::{Deserialize, Serialize};

/// How the connector selected a local-signing account for this report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlAccountSelection {
    None,
    Ambiguous,
    ExplicitUnavailable,
    Selected,
}

/// Availability of the account's current KeyPackage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlKeyPackageAvailability {
    Unavailable,
    Absent,
    Present,
    Pending,
    Degraded,
}

/// Current catch-up/replay lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentControlReplayState {
    Idle,
    Running,
    Failed,
}

/// Aggregate KeyPackage metadata without refs, IDs, or failure text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDiagnosticKeyPackage {
    pub availability: AgentControlKeyPackageAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    pub present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    pub accepted_fanout_targets: u32,
    pub unattempted_fanout_targets: u32,
    pub failed_fanout_targets: u32,
    pub policy_prohibited_fanout_targets: u32,
}

impl AgentControlDiagnosticKeyPackage {
    pub fn unavailable() -> Self {
        Self {
            availability: AgentControlKeyPackageAvailability::Unavailable,
            phase: None,
            present: false,
            expired: None,
            accepted_fanout_targets: 0,
            unattempted_fanout_targets: 0,
            failed_fanout_targets: 0,
            policy_prohibited_fanout_targets: 0,
        }
    }
}

/// Connector-wide relay counts. These are not account-specific proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDiagnosticRelays {
    pub configured: u32,
    pub connected: u32,
    pub disconnected: u32,
}

/// Current catch-up/replay observation plus process-lifetime counters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDiagnosticReplay {
    pub state: AgentControlReplayState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<String>,
    /// Completed scheduled or activity-triggered catch-up passes.
    pub success_count: u64,
    /// Failed scheduled or activity-triggered catch-up passes.
    pub failure_count: u64,
    pub resync_count: u64,
    pub cancelled_count: u64,
}

/// Home-group resolution without identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDiagnosticHome {
    pub requested: bool,
    pub resolved: bool,
    pub worker_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_direct: Option<bool>,
}

impl AgentControlDiagnosticHome {
    pub fn not_requested() -> Self {
        Self {
            requested: false,
            resolved: false,
            worker_available: false,
            member_count: None,
            is_direct: None,
        }
    }
}

/// Identifier-free connector diagnostic snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentControlDiagnosticStatus {
    pub protocol: String,
    pub connector_version: String,
    pub account_count: u32,
    pub local_signing_account_count: u32,
    pub selection: AgentControlAccountSelection,
    pub welcomer_count: u32,
    pub allow_any: bool,
    pub key_package: AgentControlDiagnosticKeyPackage,
    pub relays: AgentControlDiagnosticRelays,
    pub replay: AgentControlDiagnosticReplay,
    pub home: AgentControlDiagnosticHome,
}
