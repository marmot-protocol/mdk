use std::collections::BTreeSet;
use std::path::PathBuf;

use cgka_conformance_simulator::route_assurance::{
    AssuranceClaimId, AssuranceClaimRecordV1, AssuranceClaimStatus, AssuranceOwnershipStatus,
    DECISION_ROUTE_INVENTORY, DecisionRouteId, ROUTE_ASSURANCE_SCHEMA_VERSION, RouteBranchV1,
    RouteLifecycleStateV1, open_route_assurance_claims,
};

#[test]
fn every_registered_route_has_live_source_and_named_owners() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let registered: BTreeSet<_> = DECISION_ROUTE_INVENTORY
        .iter()
        .map(|entry| entry.route)
        .collect();
    assert_eq!(registered, DecisionRouteId::ALL.into_iter().collect());
    assert_eq!(registered.len(), DECISION_ROUTE_INVENTORY.len());

    for entry in DECISION_ROUTE_INVENTORY {
        assert!(!entry.production_sites.is_empty(), "{:?}", entry.route);
        assert!(!entry.adopted_rule.trim().is_empty(), "{:?}", entry.route);
        for site in entry.production_sites {
            let source = std::fs::read_to_string(workspace.join(site.path))
                .unwrap_or_else(|error| panic!("{}: {error}", site.path));
            assert!(
                source.contains(site.marker),
                "{} no longer contains route marker {}; review the inventory instead of silently carrying its evidence forward",
                site.path,
                site.marker
            );
        }
        for owner in [
            entry.reference_model,
            entry.mutation_sentinel,
            entry.campaign,
        ] {
            assert!(!owner.owner.trim().is_empty(), "{:?}", entry.route);
            match owner.status {
                AssuranceOwnershipStatus::Covered => assert!(owner.limitation.is_empty()),
                AssuranceOwnershipStatus::Partial | AssuranceOwnershipStatus::Gap => assert!(
                    !owner.limitation.trim().is_empty(),
                    "partial and gap ownership must explain the residual limitation for {:?}",
                    entry.route
                ),
            }
        }
    }
}

#[test]
fn route_choice_and_restart_do_not_change_the_closed_input_winner() {
    let branches = vec![
        RouteBranchV1 {
            id: 1,
            effective_depth: 1,
            ordering_key: 0,
        },
        RouteBranchV1 {
            id: 2,
            effective_depth: 2,
            ordering_key: 1,
        },
    ];
    for route in [
        DecisionRouteId::OrdinaryIngest,
        DecisionRouteId::PairwiseForkRecovery,
        DecisionRouteId::StoredConvergence,
        DecisionRouteId::RetainedHistoryReplay,
        DecisionRouteId::CrashRestartRecovery,
    ] {
        let uninterrupted = RouteLifecycleStateV1::new(branches.clone())
            .observe_route(route, Some(1))
            .settle();
        let restarted = RouteLifecycleStateV1::new(branches.clone())
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
fn human_route_matrix_has_exactly_one_row_per_registered_route() {
    let matrix = include_str!("../CONVERGENCE_ROUTE_MATRIX.md");
    for route in DecisionRouteId::ALL {
        assert_eq!(
            matrix.matches(&format!("`{}`", route.as_str())).count(),
            1,
            "matrix must contain exactly one row for {}",
            route.as_str()
        );
    }
    assert_eq!(
        matrix
            .lines()
            .filter(|line| line.starts_with("| `"))
            .count(),
        DecisionRouteId::ALL.len()
    );
}

#[test]
fn every_stable_claim_starts_open_and_round_trips() {
    let claims = open_route_assurance_claims();
    assert_eq!(claims.len(), AssuranceClaimId::ALL.len());
    assert_eq!(
        claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect::<BTreeSet<_>>(),
        AssuranceClaimId::ALL.into_iter().collect()
    );
    assert!(claims.iter().all(|claim| {
        claim.schema_version == ROUTE_ASSURANCE_SCHEMA_VERSION
            && claim.status == AssuranceClaimStatus::Open
            && claim.passing_evidence.is_empty()
            && claim.falsifications.is_empty()
    }));
    let encoded = serde_json::to_vec(&claims).expect("serialize claims");
    let decoded: Vec<AssuranceClaimRecordV1> =
        serde_json::from_slice(&encoded).expect("deserialize claims");
    assert_eq!(decoded, claims);
}

#[test]
fn a_green_run_cannot_silently_close_a_known_counterexample() {
    let mut claim = AssuranceClaimRecordV1::open(AssuranceClaimId::RouteEquivalence);
    claim.record_passing_evidence("campaign-before-counterexample");
    assert_eq!(claim.status, AssuranceClaimStatus::Covered);

    claim.reopen("counterexample-a");
    claim.reopen("counterexample-b");
    claim.record_passing_evidence("unrelated-green-rerun");
    assert_eq!(claim.status, AssuranceClaimStatus::Reopened);

    assert!(claim.resolve_falsification("counterexample-a", "reviewed-fix-a"));
    assert_eq!(claim.status, AssuranceClaimStatus::Reopened);
    assert!(claim.resolve_falsification("counterexample-b", "reviewed-fix-b"));
    assert_eq!(claim.status, AssuranceClaimStatus::Covered);
    assert!(!claim.resolve_falsification("counterexample-b", "duplicate-resolution"));
    assert_eq!(
        claim.passing_evidence,
        vec![
            "campaign-before-counterexample",
            "reviewed-fix-a",
            "reviewed-fix-b",
            "unrelated-green-rerun",
        ]
    );
}
