use cgka_conformance_simulator::lifecycle_model::{
    JoinerState, LifecycleActionKind, LifecycleModel, LifecycleState, PassPhase,
    minimal_admin_starvation_trace,
};
use cgka_conformance_simulator::{ScenarioSpec, compile_scenario};
use stateright::{Checker, Model, Property};

#[derive(Clone)]
struct StaterightLifecycle {
    model: LifecycleModel,
    initial: LifecycleState,
}

fn settled_history_is_equal(_: &StaterightLifecycle, state: &LifecycleState) -> bool {
    state.phase != PassPhase::Settled || state.history_a == state.history_b
}

fn frozen_revision_is_partitioned(_: &StaterightLifecycle, state: &LifecycleState) -> bool {
    state.phase != PassPhase::Frozen
        || match state.crashed {
            true => state.frozen_revision.is_some() && state.staged_revision.is_none(),
            false => {
                state.frozen_revision.is_some() && state.staged_revision == state.frozen_revision
            }
        }
}

fn pending_admin_eventually_applies(_: &StaterightLifecycle, state: &LifecycleState) -> bool {
    state.admin_applied
}

fn losing_branch_joiner_can_be_stranded(_: &StaterightLifecycle, state: &LifecycleState) -> bool {
    state.joiner == JoinerState::Stranded
}

fn stranded_joiner_can_rejoin_with_fresh_state(
    _: &StaterightLifecycle,
    state: &LifecycleState,
) -> bool {
    state.joiner == JoinerState::RejoinedFresh
}

impl Model for StaterightLifecycle {
    type State = LifecycleState;
    type Action = LifecycleActionKind;

    fn init_states(&self) -> Vec<Self::State> {
        vec![self.initial.clone()]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        actions.extend(self.model.actions(state));
    }

    fn next_state(&self, state: &Self::State, action: Self::Action) -> Option<Self::State> {
        self.model.next_state(state, action)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::always("settled_history_is_equal", settled_history_is_equal),
            Property::always(
                "frozen_revision_is_partitioned_and_recovered_across_crash",
                frozen_revision_is_partitioned,
            ),
            Property::eventually(
                "pending_admin_eventually_applies",
                pending_admin_eventually_applies,
            ),
            Property::sometimes(
                "losing_branch_joiner_can_be_stranded",
                losing_branch_joiner_can_be_stranded,
            ),
            Property::sometimes(
                "stranded_joiner_can_rejoin_with_fresh_state",
                stranded_joiner_can_rejoin_with_fresh_state,
            ),
        ]
    }
}

#[test]
fn stateright_fair_closed_input_model_satisfies_bounded_lifecycle_properties() {
    let checker = StaterightLifecycle {
        model: LifecycleModel {
            fair_after_input_closure: true,
        },
        initial: LifecycleState::default(),
    }
    .checker()
    .spawn_bfs()
    .join();

    checker.assert_properties();
    assert!(checker.unique_state_count() > 20);
}

#[test]
fn administrative_starvation_trace_names_the_violated_assumption() {
    let trace = minimal_admin_starvation_trace();
    assert_eq!(
        trace.violated_assumption.as_deref(),
        Some("eventual_input_closure_or_fair_admin_scheduling")
    );
    assert_eq!(trace.actions[0].kind, LifecycleActionKind::SelfUpdate);
    assert_eq!(trace.actions[0].action_id, "model-step-0:self_update");
    assert!(trace.states.last().unwrap().admin_pending);
    assert!(!trace.states.last().unwrap().admin_applied);
}

#[test]
fn crash_and_resource_recovery_preserve_frozen_membership() {
    let model = LifecycleModel {
        fair_after_input_closure: false,
    };
    let mut state = LifecycleState {
        history_a: 2,
        history_b: 2,
        input_open: false,
        ..LifecycleState::default()
    };
    state = model
        .next_state(&state, LifecycleActionKind::FreezePass)
        .unwrap();
    let frozen = state.frozen_revision;
    assert_eq!(state.staged_revision, frozen);
    state = model
        .next_state(&state, LifecycleActionKind::Crash)
        .unwrap();
    assert_eq!(state.frozen_revision, frozen);
    assert_eq!(state.staged_revision, None);
    state = model
        .next_state(&state, LifecycleActionKind::Restart)
        .unwrap();
    assert_eq!(state.staged_revision, frozen);
    state = model
        .next_state(&state, LifecycleActionKind::FailResource)
        .unwrap();
    state = model
        .next_state(&state, LifecycleActionKind::RecoverResource)
        .unwrap();
    assert_eq!(state.phase, PassPhase::Frozen);
    assert_eq!(state.frozen_revision, frozen);
}

#[test]
fn applied_admin_progress_is_monotonic_across_later_settlement() {
    let model = LifecycleModel {
        fair_after_input_closure: false,
    };
    let state = LifecycleState {
        history_a: 2,
        history_b: 2,
        input_open: false,
        phase: PassPhase::Frozen,
        frozen_revision: Some(2),
        staged_revision: Some(2),
        admin_pending: false,
        admin_applied: true,
        ..LifecycleState::default()
    };
    let settled = model
        .next_state(&state, LifecycleActionKind::SettlePass)
        .expect("a valid later pass settles");
    assert!(settled.admin_applied);
}

#[test]
fn committed_counterexample_is_canonical_scenario_ir_with_stable_action_ids() {
    let trace = minimal_admin_starvation_trace();
    let spec: ScenarioSpec = serde_json::from_str(include_str!(
        "../../../formal/liveness/counterexamples/admin-starvation.scenario.json"
    ))
    .expect("counterexample is Scenario IR JSON");
    let compiled = compile_scenario(&spec).expect("counterexample compiles");
    let mut compiled_actions = compiled.actions.iter();
    let projected_ids = trace
        .scenario_step_kinds()
        .map(|expected_kind| {
            compiled_actions
                .find(|action| {
                    action
                        .schedule
                        .action_id
                        .rsplit_once(':')
                        .is_some_and(|(_, kind)| kind == expected_kind)
                })
                .unwrap_or_else(|| panic!("counterexample has no {expected_kind} projection"))
                .schedule
                .action_id
                .clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(projected_ids.len(), trace.actions.len());
    assert_eq!(
        projected_ids
            .iter()
            .map(|action_id| action_id.rsplit_once(':').unwrap().1)
            .collect::<Vec<_>>(),
        trace.scenario_step_kinds().collect::<Vec<_>>()
    );
}
