//! Cheap contracts for opt-in process-backed recovery workloads.
use cgka_conformance_simulator::{
    ScenarioStep, ScenarioStimulusObservation as Evidence, compile_scenario, generate_family_case,
    validate_scenario_stimulus_evidence,
};
use std::collections::BTreeSet;

const FAMILIES: [&str; 3] = [
    "public-app-invite-profile-recovery/v1",
    "public-app-longevity/v1",
    "public-app-retained-traffic/v1",
];

#[test]
fn expansion_replay_prefix_diversity_and_reachability() {
    for family in FAMILIES {
        let mut shapes = BTreeSet::new();
        for seed in 0..32 {
            let case = generate_family_case(family, seed, 0).unwrap();
            assert_eq!(case, generate_family_case(family, seed, 0).unwrap());
            assert_eq!(
                case,
                serde_json::from_slice(&serde_json::to_vec(&case).unwrap()).unwrap()
            );
            let oracle = cgka_conformance_simulator::build_scenario_oracle_report(
                &case.scenario,
                None,
                &case.expected_outcomes,
                &serde_json::from_value(serde_json::json!({"name": "empty", "observations": []}))
                    .unwrap(),
                &[],
                &[],
            );
            assert!(
                oracle.weak_oracle_warnings.is_empty(),
                "{family}: {:?}",
                oracle.weak_oracle_warnings
            );
            let compiled = compile_scenario(&case.scenario).unwrap();
            let shape = compiled
                .actions
                .iter()
                .map(|a| a.step.kind())
                .collect::<Vec<_>>();
            assert_eq!(shape.iter().filter(|s| **s == "create_group").count(), 1);
            assert!(shape.contains(&"send_app_message"));
            if family == FAMILIES[0] {
                assert!(shape.contains(&"race_invite_profile"));
                assert!(validate_scenario_stimulus_evidence(&case.scenario, &[]).is_err());
            } else {
                for action in [
                    "remove_members",
                    "invite_members",
                    "interrupt_relay",
                    "restart_client",
                    "sync_relay_history",
                ] {
                    assert!(shape.contains(&action), "{family} lacks {action}");
                }
                assert!(shape.iter().filter(|s| **s == "set_client_offline").count() >= 2);
                if family == FAMILIES[2] {
                    assert!(shape.contains(&"set_relay_event_visibility"));
                }
            }
            shapes.insert(shape.into_iter().map(str::to_owned).collect::<Vec<_>>());
        }
        assert!(
            shapes.len() >= 8,
            "{family} has only {} operation schedules",
            shapes.len()
        );
        let prefix = (0..2)
            .map(|i| generate_family_case(family, 7, i).unwrap())
            .collect::<Vec<_>>();
        let longer = (0..6)
            .map(|i| generate_family_case(family, 7, i).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(prefix, longer[..2]);
    }
}

#[test]
fn invite_recovery_evidence_rejects_unexercised_races_and_lost_consent() {
    let mut case = generate_family_case(FAMILIES[0], 7, 0).unwrap();
    case.scenario
        .steps
        .retain(|s| matches!(s, ScenarioStep::RaceInviteProfile { .. }));
    let action = compile_scenario(&case.scenario).unwrap().actions.remove(0);
    let ScenarioStep::RaceInviteProfile { actors, .. } = action.step else {
        panic!("race")
    };
    let good = Evidence::InviteProfileRecovery {
        action_id: action.schedule.action_id,
        inviter: actors[0].clone(),
        renamer: actors[1].clone(),
        outcomes: actors
            .iter()
            .map(
                |client| cgka_conformance_simulator::app_runtime::ConcurrentMutationOutcome {
                    client: client.clone(),
                    accepted: true,
                    error_kind: None,
                },
            )
            .collect(),
        admitted_publications: 3,
        explicit_rejoin: true,
        offer_survived_restart: true,
        confirmation_survived_restart: true,
    };
    validate_scenario_stimulus_evidence(&case.scenario, &[good.clone()]).unwrap();
    for mutation in 0..6 {
        let mut bad = good.clone();
        if let Evidence::InviteProfileRecovery {
            outcomes,
            admitted_publications,
            explicit_rejoin,
            offer_survived_restart,
            confirmation_survived_restart,
            renamer,
            inviter,
            ..
        } = &mut bad
        {
            match mutation {
                0 => outcomes[0].accepted = false,
                1 => *admitted_publications = 0,
                2 => *explicit_rejoin = false,
                3 => *offer_survived_restart = false,
                4 => *confirmation_survived_restart = false,
                5 => *renamer = inviter.clone(),
                _ => unreachable!(),
            }
        }
        assert!(validate_scenario_stimulus_evidence(&case.scenario, &[bad]).is_err());
    }
}
