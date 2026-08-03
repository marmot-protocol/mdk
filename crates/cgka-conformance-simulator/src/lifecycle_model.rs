//! Small lifecycle state machine shared by bounded model-checking tests.
//!
//! Temporal liveness is specified in `formal/liveness/ConvergenceLifecycle.tla`.
//! This Rust form is the trace bridge: every transition carries a stable action
//! identity that can be projected into Scenario IR.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PassPhase {
    Collecting,
    Frozen,
    Settled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinerState {
    None,
    PendingOnLosingBranch,
    Stranded,
    RejoinedFresh,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LifecycleState {
    pub history_a: u8,
    pub history_b: u8,
    pub input_open: bool,
    pub phase: PassPhase,
    pub frozen_revision: Option<u8>,
    pub crashed: bool,
    pub resource_available: bool,
    pub crash_budget: u8,
    pub resource_failure_budget: u8,
    pub self_updates_remaining: u8,
    pub admin_pending: bool,
    pub admin_applied: bool,
    pub joiner: JoinerState,
}

impl Default for LifecycleState {
    fn default() -> Self {
        Self {
            history_a: 1,
            history_b: 0,
            input_open: true,
            phase: PassPhase::Collecting,
            frozen_revision: None,
            crashed: false,
            resource_available: true,
            crash_budget: 1,
            resource_failure_budget: 1,
            self_updates_remaining: 2,
            admin_pending: true,
            admin_applied: false,
            joiner: JoinerState::None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActionKind {
    DeliverHistory,
    CloseInput,
    SelfUpdate,
    FreezePass,
    SettlePass,
    Crash,
    Restart,
    FailResource,
    RecoverResource,
    InviteOnLosingBranch,
    MarkJoinerStranded,
    RepairJoinerWithFreshState,
    StopUnfairly,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LifecycleAction {
    pub action_id: String,
    pub kind: LifecycleActionKind,
}

impl LifecycleAction {
    pub fn new(index: usize, kind: LifecycleActionKind) -> Self {
        Self {
            action_id: format!("model-step-{index}:{}", kind.as_str()),
            kind,
        }
    }
}

impl LifecycleActionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeliverHistory => "deliver_history",
            Self::CloseInput => "close_input",
            Self::SelfUpdate => "self_update",
            Self::FreezePass => "freeze_pass",
            Self::SettlePass => "settle_pass",
            Self::Crash => "crash",
            Self::Restart => "restart",
            Self::FailResource => "fail_resource",
            Self::RecoverResource => "recover_resource",
            Self::InviteOnLosingBranch => "invite_on_losing_branch",
            Self::MarkJoinerStranded => "mark_joiner_stranded",
            Self::RepairJoinerWithFreshState => "repair_joiner_with_fresh_state",
            Self::StopUnfairly => "stop_unfairly",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleModel {
    /// When true, once input closes the model exposes only the next recovery or
    /// convergence action. This is the bounded executable counterpart of the
    /// explicit fairness assumptions in the TLA+ specification.
    pub fair_after_input_closure: bool,
}

impl LifecycleModel {
    pub fn actions(&self, state: &LifecycleState) -> Vec<LifecycleActionKind> {
        if state.crashed {
            return vec![LifecycleActionKind::Restart];
        }
        if !state.resource_available {
            return vec![LifecycleActionKind::RecoverResource];
        }
        if !state.input_open && self.fair_after_input_closure {
            return self.fair_closed_actions(state);
        }

        let mut actions = Vec::new();
        if state.input_open {
            actions.push(LifecycleActionKind::CloseInput);
            if state.self_updates_remaining > 0 {
                actions.push(LifecycleActionKind::SelfUpdate);
            }
        }
        if state.history_a != state.history_b {
            actions.push(LifecycleActionKind::DeliverHistory);
        }
        if state.phase == PassPhase::Collecting && state.history_a == state.history_b {
            actions.push(LifecycleActionKind::FreezePass);
        }
        if state.phase == PassPhase::Frozen {
            actions.push(LifecycleActionKind::SettlePass);
        }
        if state.crash_budget > 0 {
            actions.push(LifecycleActionKind::Crash);
        }
        if state.resource_failure_budget > 0 {
            actions.push(LifecycleActionKind::FailResource);
        }
        match state.joiner {
            JoinerState::None => actions.push(LifecycleActionKind::InviteOnLosingBranch),
            JoinerState::PendingOnLosingBranch => {
                actions.push(LifecycleActionKind::MarkJoinerStranded)
            }
            JoinerState::Stranded => actions.push(LifecycleActionKind::RepairJoinerWithFreshState),
            JoinerState::RejoinedFresh => {}
        }
        if !self.fair_after_input_closure && state.admin_pending {
            actions.push(LifecycleActionKind::StopUnfairly);
        }
        actions
    }

    fn fair_closed_actions(&self, state: &LifecycleState) -> Vec<LifecycleActionKind> {
        if state.history_a != state.history_b {
            return vec![LifecycleActionKind::DeliverHistory];
        }
        match state.phase {
            PassPhase::Collecting => return vec![LifecycleActionKind::FreezePass],
            PassPhase::Frozen => return vec![LifecycleActionKind::SettlePass],
            PassPhase::Settled => {}
        }
        match state.joiner {
            JoinerState::PendingOnLosingBranch => {
                vec![LifecycleActionKind::MarkJoinerStranded]
            }
            JoinerState::Stranded => vec![LifecycleActionKind::RepairJoinerWithFreshState],
            _ => Vec::new(),
        }
    }

    pub fn next_state(
        &self,
        state: &LifecycleState,
        action: LifecycleActionKind,
    ) -> Option<LifecycleState> {
        if !self.actions(state).contains(&action) {
            return None;
        }
        let mut next = state.clone();
        match action {
            LifecycleActionKind::DeliverHistory => {
                let max = next.history_a.max(next.history_b);
                next.history_a = max;
                next.history_b = max;
            }
            LifecycleActionKind::CloseInput => next.input_open = false,
            LifecycleActionKind::SelfUpdate => {
                next.history_a = next.history_a.saturating_add(1);
                next.self_updates_remaining -= 1;
                next.phase = PassPhase::Collecting;
                next.frozen_revision = None;
            }
            LifecycleActionKind::FreezePass => {
                next.phase = PassPhase::Frozen;
                next.frozen_revision = Some(next.history_a);
            }
            LifecycleActionKind::SettlePass => {
                if next.frozen_revision != Some(next.history_a) || next.history_a != next.history_b
                {
                    return None;
                }
                next.phase = PassPhase::Settled;
                next.admin_applied = next.admin_pending;
                next.admin_pending = false;
                if next.joiner == JoinerState::PendingOnLosingBranch {
                    next.joiner = JoinerState::Stranded;
                }
            }
            LifecycleActionKind::Crash => {
                next.crashed = true;
                next.crash_budget -= 1;
            }
            LifecycleActionKind::Restart => next.crashed = false,
            LifecycleActionKind::FailResource => {
                next.resource_available = false;
                next.resource_failure_budget -= 1;
            }
            LifecycleActionKind::RecoverResource => next.resource_available = true,
            LifecycleActionKind::InviteOnLosingBranch => {
                next.joiner = JoinerState::PendingOnLosingBranch
            }
            LifecycleActionKind::MarkJoinerStranded => next.joiner = JoinerState::Stranded,
            LifecycleActionKind::RepairJoinerWithFreshState => {
                next.joiner = JoinerState::RejoinedFresh
            }
            LifecycleActionKind::StopUnfairly => return None,
        }
        Some(next)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTrace {
    pub violated_assumption: Option<String>,
    pub actions: Vec<LifecycleAction>,
    pub states: Vec<LifecycleState>,
}

/// Minimal finite witness for the administrative-progress non-guarantee.
///
/// The final `StopUnfairly` represents either an execution that never closes
/// its input set or one that never fairly schedules the pending admin action.
pub fn minimal_admin_starvation_trace() -> LifecycleTrace {
    let model = LifecycleModel {
        fair_after_input_closure: false,
    };
    let initial = LifecycleState::default();
    let self_update = LifecycleActionKind::SelfUpdate;
    let after_update = model.next_state(&initial, self_update).unwrap();
    LifecycleTrace {
        violated_assumption: Some("eventual_input_closure_or_fair_admin_scheduling".into()),
        actions: vec![
            LifecycleAction::new(0, self_update),
            LifecycleAction::new(1, LifecycleActionKind::StopUnfairly),
        ],
        states: vec![initial, after_update],
    }
}
