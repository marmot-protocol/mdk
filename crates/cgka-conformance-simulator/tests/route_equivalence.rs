//! Route-equivalence assurance derived from mdk#1236.

use std::collections::BTreeSet;

use cgka_conformance_simulator::lifecycle_model::{
    DecisionRouteKind, RouteBranch, RouteLifecycleState,
};
use cgka_conformance_simulator::reference_convergence::{
    ReferenceCandidate, ReferenceDecisionRoute, ReferenceInput, ReferencePolicy, ReferencePriority,
    WitnessMode, evaluate_via_route,
};
use cgka_conformance_simulator::{
    APP_RUNTIME_OBSERVATION_SCHEMA_VERSION, AppRuntimeHarness, AssuranceClaimRecordV1,
    AssuranceClaimStatus, ROUTE_ASSURANCE_CLAIMS, RouteCampaignAdapter, RouteRestartCheckpoint,
    ScenarioInputDisposition, generate_cross_route_regression_family, run_scenario_report,
    run_scenario_report_with_subject, scenario_for_route_adapter,
};
#[cfg(feature = "test-policy-overrides")]
use cgka_conformance_simulator::{EngineHarnessSubject, HarnessStorageMode};
#[cfg(feature = "test-policy-overrides")]
use cgka_traits::group::ProtocolProfile;

fn route_input() -> ReferenceInput {
    ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![
            ReferenceCandidate {
                id: "ordering-winner".into(),
                fork_epoch: 1,
                tip_epoch: 2,
                tip_priority: ReferencePriority::Ordinary,
                tip_committer: vec![0],
                tip_digest: [0; 32],
                app_witnesses: Vec::new(),
            },
            ReferenceCandidate {
                id: "deeper-winner".into(),
                fork_epoch: 1,
                tip_epoch: 3,
                tip_priority: ReferencePriority::Ordinary,
                tip_committer: vec![1],
                tip_digest: [1; 32],
                app_witnesses: Vec::new(),
            },
        ],
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: Vec::new(),
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    }
}

#[test]
fn every_decision_route_reaches_the_same_reference_result() {
    let input = route_input();
    let routes = [
        ReferenceDecisionRoute::OrdinaryIngest,
        ReferenceDecisionRoute::PairwiseForkRecovery {
            provisional_winner: "ordering-winner".into(),
        },
        ReferenceDecisionRoute::StoredConvergence,
        ReferenceDecisionRoute::RetainedHistoryReplay,
        ReferenceDecisionRoute::CrashRestartRecovery,
    ];
    let results = routes
        .into_iter()
        .map(|route| evaluate_via_route(&input, route))
        .collect::<Vec<_>>();
    for result in &results {
        assert_eq!(
            result.canonical.selected_branch_id.as_deref(),
            Some("deeper-winner")
        );
        assert_eq!(
            result.reconsiderable_branch_ids,
            BTreeSet::from(["ordering-winner".into()])
        );
        assert_eq!(result.canonical, results[0].canonical);
    }
}

#[test]
fn route_choice_and_restart_do_not_change_the_canonical_winner() {
    let branches = vec![
        RouteBranch {
            id: 1,
            effective_depth: 1,
            ordering_key: 0,
        },
        RouteBranch {
            id: 2,
            effective_depth: 2,
            ordering_key: 1,
        },
    ];
    for route in [
        DecisionRouteKind::OrdinaryIngest,
        DecisionRouteKind::PairwiseForkRecovery,
        DecisionRouteKind::StoredConvergence,
        DecisionRouteKind::RetainedHistoryReplay,
        DecisionRouteKind::CrashRestartRecovery,
    ] {
        let uninterrupted = RouteLifecycleState::new(branches.clone())
            .observe_route(route, Some(1))
            .settle();
        let restarted = RouteLifecycleState::new(branches.clone())
            .observe_route(route, Some(1))
            .crash()
            .restart()
            .settle();
        assert_eq!(uninterrupted.canonical_winner, Some(2));
        assert_eq!(restarted.canonical_winner, Some(2));
        assert_eq!(restarted.volatile_route, None);
        assert_eq!(restarted.volatile_provisional_winner, None);
    }
}

#[test]
fn cross_route_catalog_covers_the_full_incident_matrix_and_reopens_claims() {
    let campaigns = generate_cross_route_regression_family();
    assert_eq!(campaigns.len(), 24);
    let checkpoints = campaigns
        .iter()
        .map(|campaign| campaign.restart_checkpoint)
        .collect::<BTreeSet<_>>();
    assert_eq!(checkpoints.len(), 6);
    assert!(checkpoints.contains(&RouteRestartCheckpoint::AfterAliceRoot));
    assert!(checkpoints.contains(&RouteRestartCheckpoint::AfterBobRoot));
    assert!(checkpoints.contains(&RouteRestartCheckpoint::AfterBranchGrowth));
    assert!(checkpoints.contains(&RouteRestartCheckpoint::AfterObserverRouting));
    assert!(checkpoints.contains(&RouteRestartCheckpoint::AfterCommitterRouting));
    for campaign in &campaigns {
        assert_eq!(
            campaign
                .covered_claims
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ROUTE_ASSURANCE_CLAIMS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
        cgka_conformance_simulator::compile_scenario(&campaign.scenario).unwrap();
    }

    let mut claim = AssuranceClaimRecordV1::open("route-equivalence");
    claim.cover(&campaigns[0].campaign_id);
    assert_eq!(claim.status, AssuranceClaimStatus::Covered);
    claim.reopen("field_counterexample");
    assert_eq!(claim.status, AssuranceClaimStatus::Reopened);
    assert_eq!(claim.falsification.as_deref(), Some("field_counterexample"));
}

#[test]
fn route_matrix_names_every_production_owner_and_executable_mutation() {
    let matrix = include_str!("../CONVERGENCE_ROUTE_MATRIX.md");
    for route in [
        "ordinary_ingest",
        "pairwise_fork_recovery",
        "stored_convergence",
        "candidate_materialization",
        "retained_history_replay",
        "crash_restart_recovery",
        "application_disposition",
    ] {
        assert_eq!(
            matrix.matches(&format!("| `{route}`")).count(),
            1,
            "{route}"
        );
    }
    for owner in [
        "crates/cgka-engine/src/message_processor/ingest.rs",
        "crates/cgka-engine/src/fork_recovery.rs",
        "crates/cgka-engine/src/distributed_convergence.rs",
        "crates/cgka-engine/src/openmls_projection.rs",
        "pairwise_losing_branch_terminalization",
        "cross-route-1236/v1",
    ] {
        assert!(matrix.contains(owner), "missing route owner {owner}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheduler_route_recovers_the_deeper_branch_through_candidate_peel_contexts() {
    let campaign = generate_cross_route_regression_family()
        .into_iter()
        .find(|campaign| campaign.restart_checkpoint == RouteRestartCheckpoint::None)
        .unwrap();
    let scenario = scenario_for_route_adapter(&campaign, RouteCampaignAdapter::Engine);
    let report = run_scenario_report(&scenario, None).await.unwrap();
    assert!(report.invariant_failures.is_empty(), "{report:#?}");
    assert!(report.expectation_failures.is_empty(), "{report:#?}");
    assert!(
        report
            .step_log
            .iter()
            .all(|step| step.status.is_completed()),
        "observations before failure: {:#?}; step log: {:#?}",
        report
            .observed_trace
            .as_ref()
            .map(|trace| &trace.observations),
        report.step_log,
    );
    let trace = report.observed_trace.as_ref().unwrap();
    assert!(trace.errors.is_empty(), "{trace:#?}");
    assert_eq!(trace.decryptability_probes.len(), 1);
    assert!(
        trace.decryptability_probes[0].succeeded(),
        "decryptability probe: {:#?}; observations: {:#?}",
        trace.decryptability_probes[0],
        trace.observations
    );
    let pre_follow_on = &trace.observations[..4];
    let bob_alice_root = pre_follow_on
        .iter()
        .find(|observation| observation.client == "bob")
        .unwrap()
        .scenario_input_ledger
        .iter()
        .find(|entry| entry.scenario_id == "step-5:invite_members@main")
        .unwrap();
    assert_eq!(
        bob_alice_root.disposition,
        ScenarioInputDisposition::Deferred,
        "pairwise loser must remain reconsiderable before its follow-on arrives: {bob_alice_root:#?}"
    );
    let final_observations = &trace.observations[trace.observations.len() - 4..];
    let exact = final_observations
        .iter()
        .map(|observation| {
            serde_json::to_string(observation.canonical_state.as_ref().unwrap()).unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(exact.len(), 1, "{final_observations:#?}");
    for observation in final_observations {
        assert_eq!(observation.epoch, 3, "{observation:#?}");
        assert_eq!(observation.member_count, 6, "{observation:#?}");
        assert_eq!(observation.group_name, "cross-route-base");
        assert!(
            observation
                .scenario_input_ledger
                .iter()
                .filter(|entry| entry.kind
                    == cgka_conformance_simulator::ScenarioInputKind::Application)
                .all(|entry| {
                    !entry.pending
                        && matches!(
                            entry.disposition,
                            ScenarioInputDisposition::Accepted
                                | ScenarioInputDisposition::Delivered
                                | ScenarioInputDisposition::Invalidated
                                | ScenarioInputDisposition::Rejected
                                | ScenarioInputDisposition::ResourceRefused
                        )
                }),
            "{observation:#?}"
        );
    }
    let mut claim =
        AssuranceClaimRecordV1::open(cgka_conformance_simulator::RECONSIDERABLE_LOSER_CLAIM);
    claim.cover(&campaign.campaign_id);
    assert_eq!(claim.status, AssuranceClaimStatus::Covered);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_route_family_reaches_exact_decryptable_app_runtime_state() {
    let campaign = generate_cross_route_regression_family()
        .into_iter()
        .find(|campaign| campaign.restart_checkpoint == RouteRestartCheckpoint::None)
        .unwrap();
    let scenario = scenario_for_route_adapter(&campaign, RouteCampaignAdapter::AppRuntime);
    let mut subject = AppRuntimeHarness::new(&scenario.clients).await.unwrap();
    let report = run_scenario_report_with_subject(&scenario, None, Vec::new(), &mut subject)
        .await
        .unwrap();
    assert!(report.invariant_failures.is_empty(), "{report:#?}");
    assert!(report.expectation_failures.is_empty(), "{report:#?}");
    assert!(
        report
            .step_log
            .iter()
            .all(|step| step.status.is_completed()),
        "{report:#?}"
    );
    assert_eq!(
        report.metadata.subject.as_ref().unwrap().adapter,
        "marmot_app_runtime"
    );
    let trace = report.observed_trace.as_ref().unwrap();
    assert!(trace.errors.is_empty(), "{trace:#?}");
    assert_eq!(trace.decryptability_probes.len(), 1, "{trace:#?}");
    assert!(trace.decryptability_probes[0].succeeded(), "{trace:#?}");
    let final_observations = &trace.observations[trace.observations.len() - 4..];
    let exact = final_observations
        .iter()
        .map(|observation| {
            serde_json::to_string(observation.canonical_state.as_ref().unwrap()).unwrap()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(exact.len(), 1, "{final_observations:#?}");
    assert!(final_observations.iter().all(|observation| {
        observation
            .scenario_input_ledger
            .iter()
            .filter(|entry| {
                entry.kind == cgka_conformance_simulator::ScenarioInputKind::Application
            })
            .all(|entry| !entry.pending)
    }));
    assert_eq!(APP_RUNTIME_OBSERVATION_SCHEMA_VERSION, "2");
}

#[cfg(feature = "test-policy-overrides")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scheduler_route_recovers_the_deeper_branch_without_application_witnesses() {
    let campaign = generate_cross_route_regression_family()
        .into_iter()
        .find(|campaign| campaign.restart_checkpoint == RouteRestartCheckpoint::None)
        .unwrap();
    let scenario = scenario_for_route_adapter(&campaign, RouteCampaignAdapter::Engine);
    let mut subject = EngineHarnessSubject::new_without_app_witnesses_for_tests(
        &scenario.clients,
        &scenario.topology,
        ProtocolProfile::Legacy,
        HarnessStorageMode::InMemorySqlite,
    )
    .unwrap();
    let report = run_scenario_report_with_subject(&scenario, None, Vec::new(), &mut subject)
        .await
        .unwrap();
    assert!(report.invariant_failures.is_empty(), "{report:#?}");
    let trace = report.observed_trace.unwrap();
    let final_observations = &trace.observations[trace.observations.len() - 4..];
    assert!(
        final_observations
            .iter()
            .all(|observation| observation.epoch == 3),
        "{final_observations:#?}"
    );
}
