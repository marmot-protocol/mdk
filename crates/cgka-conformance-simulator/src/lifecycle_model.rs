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
    /// Durable frozen-pass revision retained across a process crash.
    pub frozen_revision: Option<u8>,
    /// Volatile in-process copy used to settle the active frozen pass.
    pub staged_revision: Option<u8>,
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
            staged_revision: None,
            crashed: false,
            resource_available: true,
            crash_budget: 1,
            resource_failure_budget: 1,
            self_updates_remaining: 3,
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
    RepairJoinerWithFreshState,
    StopUnfairly,
}

/// Simulator-only alternate lifecycle rules used by mutation adequacy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleMutation {
    LoseDurableFrozenRevisionOnCrash,
    SuppressRearmAfterSettlement,
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
            Self::RepairJoinerWithFreshState => "repair_joiner_with_fresh_state",
            Self::StopUnfairly => "stop_unfairly",
        }
    }

    /// Canonical Scenario IR step kind used when projecting a model trace.
    pub const fn scenario_step_kind(self) -> Option<&'static str> {
        match self {
            Self::SelfUpdate => Some("self_update"),
            Self::StopUnfairly => Some("barrier"),
            _ => None,
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
        if !state.input_open
            && state.phase == PassPhase::Collecting
            && state.history_a == state.history_b
        {
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
            JoinerState::None if state.phase != PassPhase::Settled => {
                actions.push(LifecycleActionKind::InviteOnLosingBranch)
            }
            JoinerState::None | JoinerState::PendingOnLosingBranch => {}
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
                next.staged_revision = None;
            }
            LifecycleActionKind::FreezePass => {
                next.phase = PassPhase::Frozen;
                next.frozen_revision = Some(next.history_a);
                next.staged_revision = Some(next.history_a);
            }
            LifecycleActionKind::SettlePass => {
                if next.frozen_revision != Some(next.history_a)
                    || next.staged_revision != next.frozen_revision
                    || next.history_a != next.history_b
                {
                    return None;
                }
                next.phase = PassPhase::Settled;
                next.admin_applied = next.admin_applied || next.admin_pending;
                next.admin_pending = false;
                if next.joiner == JoinerState::PendingOnLosingBranch {
                    next.joiner = JoinerState::Stranded;
                }
            }
            LifecycleActionKind::Crash => {
                next.crashed = true;
                next.crash_budget -= 1;
                next.staged_revision = None;
            }
            LifecycleActionKind::Restart => {
                next.crashed = false;
                if next.phase == PassPhase::Frozen {
                    next.staged_revision = next.frozen_revision;
                }
            }
            LifecycleActionKind::FailResource => {
                next.resource_available = false;
                next.resource_failure_budget -= 1;
            }
            LifecycleActionKind::RecoverResource => next.resource_available = true,
            LifecycleActionKind::InviteOnLosingBranch => {
                next.joiner = JoinerState::PendingOnLosingBranch
            }
            LifecycleActionKind::RepairJoinerWithFreshState => {
                next.joiner = JoinerState::RejoinedFresh
            }
            LifecycleActionKind::StopUnfairly => return None,
        }
        Some(next)
    }

    pub(crate) fn next_state_with_mutation(
        &self,
        state: &LifecycleState,
        action: LifecycleActionKind,
        mutation: LifecycleMutation,
    ) -> Option<LifecycleState> {
        if mutation == LifecycleMutation::SuppressRearmAfterSettlement
            && action == LifecycleActionKind::SelfUpdate
            && state.phase == PassPhase::Settled
            && self.actions(state).contains(&action)
        {
            return Some(state.clone());
        }

        let mut next = self.next_state(state, action)?;
        if mutation == LifecycleMutation::LoseDurableFrozenRevisionOnCrash
            && action == LifecycleActionKind::Crash
        {
            next.frozen_revision = None;
        }
        Some(next)
    }
}

/// Named production seam that first observed a competing commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRouteKind {
    OrdinaryIngest,
    PairwiseForkRecovery,
    StoredConvergence,
    RetainedHistoryReplay,
    CrashRestartRecovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteBranch {
    pub id: u8,
    pub effective_depth: u8,
    /// Lower values win after depth, mirroring the deterministic ordering key.
    pub ordering_key: u8,
}

/// Bounded lifecycle model for route choice and restart. Durable candidate
/// input survives; the route-specific provisional winner is volatile.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteLifecycleState {
    pub durable_branches: Vec<RouteBranch>,
    pub volatile_route: Option<DecisionRouteKind>,
    pub volatile_provisional_winner: Option<u8>,
    pub canonical_winner: Option<u8>,
    pub crashed: bool,
}

impl RouteLifecycleState {
    pub fn new(mut durable_branches: Vec<RouteBranch>) -> Self {
        durable_branches.sort_by_key(|branch| branch.id);
        Self {
            durable_branches,
            volatile_route: None,
            volatile_provisional_winner: None,
            canonical_winner: None,
            crashed: false,
        }
    }

    pub fn observe_route(
        mut self,
        route: DecisionRouteKind,
        provisional_winner: Option<u8>,
    ) -> Self {
        self.volatile_route = Some(route);
        self.volatile_provisional_winner = provisional_winner;
        self
    }

    pub fn crash(mut self) -> Self {
        self.crashed = true;
        self.volatile_route = None;
        self.volatile_provisional_winner = None;
        self
    }

    pub fn restart(mut self) -> Self {
        self.crashed = false;
        self
    }

    pub fn settle(mut self) -> Self {
        if self.crashed {
            return self;
        }
        self.canonical_winner = self
            .durable_branches
            .iter()
            .max_by(|left, right| {
                left.effective_depth
                    .cmp(&right.effective_depth)
                    .then_with(|| right.ordering_key.cmp(&left.ordering_key))
            })
            .map(|branch| branch.id);
        self
    }

    /// Deliberately inconsistent seam used only by mutation adequacy: pairwise
    /// routing terminalizes its provisional result instead of reconsidering the
    /// complete durable candidate set.
    pub(crate) fn settle_with_terminal_pairwise_loser(mut self) -> Self {
        if self.volatile_route == Some(DecisionRouteKind::PairwiseForkRecovery) {
            self.canonical_winner = self.volatile_provisional_winner;
            return self;
        }
        self.settle()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleTrace {
    pub violated_assumption: Option<String>,
    pub actions: Vec<LifecycleAction>,
    pub states: Vec<LifecycleState>,
}

impl LifecycleTrace {
    /// Scenario IR kinds, in order, that are represented by this model trace.
    pub fn scenario_step_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.actions
            .iter()
            .filter_map(|action| action.kind.scenario_step_kind())
    }
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
