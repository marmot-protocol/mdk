use cgka_conformance_simulator::{ScenarioStep, semantic_reduction_units};

#[test]
fn dependency_aware_reducer_pairs_faults_with_their_recovery() {
    let steps = vec![
        ScenarioStep::SetPartition {
            allow: vec!["alice".into()],
        },
        ScenarioStep::SetClientOffline {
            client: "bob".into(),
        },
        ScenarioStep::ClearPartition,
        ScenarioStep::ReconnectClient {
            client: "bob".into(),
        },
        ScenarioStep::CrashProcess {
            process: "process:carol".into(),
        },
        ScenarioStep::RestartProcess {
            process: "process:carol".into(),
        },
    ];
    assert_eq!(
        semantic_reduction_units(&steps),
        vec![vec![0, 2], vec![1, 3], vec![4, 5]]
    );
}

#[test]
fn group_scoped_withheld_labels_do_not_cross_pair() {
    let in_group = |group: &str, action| ScenarioStep::InGroup {
        group: group.into(),
        action: Box::new(action),
    };
    let selector = cgka_conformance_simulator::ScenarioMessageSelectorV2 {
        action_id: Some("send".into()),
        ..Default::default()
    };
    let steps = vec![
        in_group(
            "one",
            ScenarioStep::WithholdMessage {
                selector: selector.clone(),
                label: "held".into(),
            },
        ),
        in_group(
            "two",
            ScenarioStep::ReleaseWithheld {
                label: "held".into(),
            },
        ),
        in_group(
            "one",
            ScenarioStep::ReleaseWithheld {
                label: "held".into(),
            },
        ),
    ];
    assert_eq!(semantic_reduction_units(&steps), vec![vec![0, 2]]);
}

#[test]
fn nested_group_paths_do_not_cross_pair() {
    let in_group = |group: &str, action| ScenarioStep::InGroup {
        group: group.into(),
        action: Box::new(action),
    };
    let nested = |outer: &str, action| in_group(outer, in_group("shared", action));
    let selector = cgka_conformance_simulator::ScenarioMessageSelectorV2 {
        action_id: Some("send".into()),
        ..Default::default()
    };
    let steps = vec![
        nested(
            "one",
            ScenarioStep::WithholdMessage {
                selector,
                label: "held".into(),
            },
        ),
        nested(
            "two",
            ScenarioStep::ReleaseWithheld {
                label: "held".into(),
            },
        ),
        nested(
            "one",
            ScenarioStep::ReleaseWithheld {
                label: "held".into(),
            },
        ),
    ];
    assert_eq!(semantic_reduction_units(&steps), vec![vec![0, 2]]);
}

#[test]
fn repeated_same_key_faults_remain_paired() {
    let steps = vec![
        ScenarioStep::SetPartition {
            allow: vec!["alice".into()],
        },
        ScenarioStep::SetPartition {
            allow: vec!["bob".into()],
        },
        ScenarioStep::ClearPartition,
        ScenarioStep::ClearPartition,
    ];
    assert_eq!(
        semantic_reduction_units(&steps),
        vec![vec![1, 2], vec![0, 3]]
    );
}
