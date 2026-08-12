use std::collections::BTreeSet;

use cgka_conformance_simulator::conformance_constant_snapshot;
use cgka_conformance_simulator::policy_contract::{
    ACTIVE_CONVERGENCE_POLICY_ID, ADOPTED_MARMOT_CONVERGENCE_COMMIT, CONSTANT_DECISIONS,
    VersioningRule, future_policy_change_requires_new_required_app_component,
};
use cgka_conformance_simulator::reference_convergence::{
    ReferenceAppMessage, ReferenceCandidate, ReferenceInput, ReferencePolicy, ReferencePriority,
    WitnessMode, evaluate,
};

#[test]
fn adopted_v1_policy_identity_and_values_are_pinned() {
    assert_eq!(
        ADOPTED_MARMOT_CONVERGENCE_COMMIT,
        "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1"
    );
    assert_eq!(
        ACTIVE_CONVERGENCE_POLICY_ID,
        "marmot-convergence-v1-implicit"
    );
    let snapshot = conformance_constant_snapshot();
    assert_eq!(snapshot.schema_version, "1");
    let expected = [
        ("P1.max_rewind_commits", 5),
        ("P2.app_message_past_epoch_limit", 5),
        ("P3.max_past_epochs", 5),
        ("P4.settlement_quiescence_ms", 1_000),
        ("P5.max_convergence_pass_ms", 5_000),
        ("P6.witness_quorum_senders_per_epoch", 2),
        ("P7.witness_quorum_epochs", 1),
        ("P8.max_witness_override_depth", 1),
        ("P9.sender_ratchet_out_of_order_tolerance", 100),
        ("P10.sender_ratchet_maximum_forward_distance", 1_000),
    ];
    for (id, value) in expected {
        assert_eq!(snapshot.values[id], value, "{id}");
    }
}

#[test]
fn every_ledger_id_has_one_versioning_decision() {
    let inventory =
        include_str!("../../../docs/marmot-architecture/convergence-constant-inventory.txt");
    let inventory_ids: BTreeSet<&str> = inventory
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            line.split_once('|')
                .unwrap_or_else(|| panic!("malformed convergence constant inventory row: {line}"))
                .0
                .trim()
        })
        .collect();
    let decision_ids: BTreeSet<&str> = CONSTANT_DECISIONS.iter().map(|entry| entry.id).collect();
    assert_eq!(decision_ids, inventory_ids);
    assert_eq!(decision_ids.len(), CONSTANT_DECISIONS.len());
}

#[test]
fn semantic_or_coupled_change_requires_a_new_required_component() {
    for id in ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10"] {
        assert!(
            future_policy_change_requires_new_required_app_component(&[id]),
            "{id}"
        );
    }
    for id in ["E1", "E8", "A1", "A8"] {
        assert!(
            !future_policy_change_requires_new_required_app_component(&[id]),
            "{id}"
        );
        assert_eq!(
            CONSTANT_DECISIONS
                .iter()
                .find(|entry| entry.id == id)
                .unwrap()
                .versioning,
            VersioningRule::OperationalNonInterference
        );
    }
    assert!(
        future_policy_change_requires_new_required_app_component(&["UNCLASSIFIED"]),
        "unknown constants fail closed until they receive a versioning decision"
    );
}

#[derive(Clone, Copy)]
struct OperationalVariant {
    admitted_per_pass: usize,
    fail_resource_before_pass: Option<usize>,
    wake_delay_ticks: usize,
}

#[derive(Debug)]
struct DriveReport {
    intermediate_winners: Vec<Option<String>>,
    settled_winner: Option<String>,
    resource_refusals: usize,
    idle_ticks: usize,
}

fn candidate(id: &str, depth: u64, digest: u8) -> ReferenceCandidate {
    ReferenceCandidate {
        id: id.into(),
        fork_epoch: 1,
        tip_epoch: 1 + depth,
        tip_priority: ReferencePriority::Ordinary,
        tip_committer: b"alice".to_vec(),
        tip_digest: [digest; 32],
        app_witnesses: Vec::new(),
    }
}

fn closed_input() -> ReferenceInput {
    ReferenceInput {
        current_tip_epoch: 3,
        retained_anchor_epoch: 1,
        candidates: vec![candidate("online", 1, 0xff), candidate("deeper", 2, 0x00)],
        commits: Vec::new(),
        proposals: Vec::new(),
        app_messages: vec![
            ReferenceAppMessage {
                message_id: "app-a".into(),
                sender: b"alice".to_vec(),
                epoch: 2,
                decrypts_on_branches: vec!["online".into()],
                authenticated: true,
                authorized: true,
            },
            ReferenceAppMessage {
                message_id: "app-b".into(),
                sender: b"bob".to_vec(),
                epoch: 2,
                decrypts_on_branches: vec!["online".into()],
                authenticated: true,
                authorized: true,
            },
        ],
        policy: ReferencePolicy::default(),
        witness_mode: WitnessMode::Enabled,
    }
}

fn drive_closed_input(input: &ReferenceInput, variant: OperationalVariant) -> DriveReport {
    assert!(variant.admitted_per_pass > 0);
    let mut admitted = 0usize;
    let mut pass = 0usize;
    let mut resource_refusals = 0usize;
    let mut idle_ticks = 0usize;
    let mut intermediate_winners = Vec::new();
    let mut failed_once = false;
    while admitted < input.app_messages.len() {
        // Scheduler delay is observable latency only; no input is admitted and
        // no result is called settled during these ticks.
        idle_ticks += variant.wake_delay_ticks;
        if !failed_once && variant.fail_resource_before_pass == Some(pass) {
            resource_refusals += 1;
            failed_once = true;
            pass += 1;
            continue;
        }
        admitted = (admitted + variant.admitted_per_pass).min(input.app_messages.len());
        let partial = ReferenceInput {
            app_messages: input.app_messages[..admitted].to_vec(),
            ..input.clone()
        };
        intermediate_winners.push(evaluate(&partial).selected_branch_id);
        pass += 1;
    }
    DriveReport {
        settled_winner: evaluate(input).selected_branch_id,
        intermediate_winners,
        resource_refusals,
        idle_ticks,
    }
}

#[test]
fn scheduler_and_resource_variants_cannot_change_closed_input_settlement() {
    let input = closed_input();
    let variants = [
        OperationalVariant {
            admitted_per_pass: 2,
            fail_resource_before_pass: None,
            wake_delay_ticks: 0,
        },
        OperationalVariant {
            admitted_per_pass: 1,
            fail_resource_before_pass: None,
            wake_delay_ticks: 7,
        },
        OperationalVariant {
            admitted_per_pass: 1,
            fail_resource_before_pass: Some(0),
            wake_delay_ticks: 2,
        },
    ];
    let reports: Vec<_> = variants
        .into_iter()
        .map(|variant| drive_closed_input(&input, variant))
        .collect();
    assert_eq!(reports[0].settled_winner.as_deref(), Some("online"));
    assert!(
        reports
            .iter()
            .all(|report| report.settled_winner == reports[0].settled_winner)
    );
    assert_ne!(
        reports[0].intermediate_winners,
        reports[1].intermediate_winners
    );
    assert_eq!(reports[2].resource_refusals, 1);
    assert_eq!(reports[2].intermediate_winners.len(), 2);
    assert_eq!(reports[0].idle_ticks, 0);
    assert_eq!(reports[1].idle_ticks, 14);
    assert_eq!(reports[2].idle_ticks, 6);
}

#[test]
fn protocol_decision_record_names_the_adopted_non_guarantee() {
    let record = include_str!("../PROTOCOL_DECISIONS.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(record.contains(ADOPTED_MARMOT_CONVERGENCE_COMMIT));
    assert!(record.contains("no administrative-progress"));
    assert!(record.contains("guarantee while valid selection-relevant input"));
    assert!(record.contains("new required"));
    assert!(record.contains("app component and capability"));
}
