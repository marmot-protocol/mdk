//! Deterministic high-volume retained-history catch-up workloads.
//!
//! Every case makes a founding member offline before the workload, retains the
//! complete event stream in a relay, and reconnects that member only in the
//! terminal phase. Volume, commit pressure, relay ordering/duplication, and
//! recovery shape are explicit replay metadata.

use crate::family::{add_strict_reliability_oracle, push_labelled_confirmation_expectations};
use crate::{
    GeneratedScenarioCase, GeneratedSubjectKind, GeneratedWorkloadProfileV1, ScenarioAccountV2,
    ScenarioAssertionV2, ScenarioDeviceV2, ScenarioOutboundSelection, ScenarioPredicateV2,
    ScenarioProcessV2, ScenarioRelayOrderV2, ScenarioRelaySyncModeV2, ScenarioRelayV2,
    ScenarioSpec, ScenarioStep, ScenarioTopologyV2, SubjectOutboundOutcome, TraceExpectation,
};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

/// Stable family identifier recorded in generated inputs and reports.
pub const OFFLINE_CATCHUP_PRESSURE_FAMILY: &str = "offline-catchup-pressure/v1";
/// Generator revision for replaying an exact seeded case.
pub const OFFLINE_CATCHUP_PRESSURE_GENERATOR_VERSION: &str = "1";
/// Workload-profile schema revision emitted by this family.
pub const OFFLINE_CATCHUP_PRESSURE_PROFILE_VERSION: &str = "1";

const ARM_COUNT: u64 = 6;
const OFFLINE_CLIENT: &str = "bob";
const RELAY_ID: &str = "relay:offline-catchup";

#[derive(Clone, Copy)]
struct VolumeProfile {
    name: &'static str,
    tier: &'static str,
    application_messages: usize,
    commit_rounds: usize,
}

// Prefix selection stays useful: ordinary tests execute the first block,
// while manual campaigns opt into the larger retained histories deliberately.
const VOLUME_PROFILES: [VolumeProfile; 4] = [
    VolumeProfile {
        name: "smoke-24",
        tier: "smoke",
        application_messages: 24,
        commit_rounds: 4,
    },
    VolumeProfile {
        name: "medium-96",
        tier: "medium",
        application_messages: 96,
        commit_rounds: 8,
    },
    VolumeProfile {
        name: "large-384",
        tier: "large",
        application_messages: 384,
        commit_rounds: 12,
    },
    VolumeProfile {
        name: "xlarge-1024",
        tier: "xlarge",
        application_messages: 1_024,
        commit_rounds: 16,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CatchupArm {
    NaturalFullHistory,
    ReverseFullHistory,
    ReverseDuplicateHistory,
    IncrementalThenFull,
    RestartBeforeProcessing,
    CompetingCommitWaves,
}

impl CatchupArm {
    /// Maps consecutive case indices onto the six recovery shapes.
    fn from_index(case_index: u64) -> Self {
        match case_index % ARM_COUNT {
            0 => Self::NaturalFullHistory,
            1 => Self::ReverseFullHistory,
            2 => Self::ReverseDuplicateHistory,
            3 => Self::IncrementalThenFull,
            4 => Self::RestartBeforeProcessing,
            _ => Self::CompetingCommitWaves,
        }
    }

    /// Returns the replay-stable arm label used in scenario metadata.
    fn name(self) -> &'static str {
        match self {
            Self::NaturalFullHistory => "natural-full-history",
            Self::ReverseFullHistory => "reverse-full-history",
            Self::ReverseDuplicateHistory => "reverse-duplicate-history",
            Self::IncrementalThenFull => "incremental-then-full",
            Self::RestartBeforeProcessing => "restart-before-processing",
            Self::CompetingCommitWaves => "competing-commit-waves",
        }
    }

    /// Selects the retained-relay ordering applied during catch-up.
    fn relay_order(self) -> ScenarioRelayOrderV2 {
        match self {
            Self::NaturalFullHistory | Self::IncrementalThenFull => ScenarioRelayOrderV2::Natural,
            _ => ScenarioRelayOrderV2::Reverse,
        }
    }

    /// Returns how many copies of each matching retained event a query returns.
    fn duplicate_copies(self) -> usize {
        match self {
            Self::ReverseDuplicateHistory | Self::CompetingCommitWaves => 3,
            Self::IncrementalThenFull | Self::RestartBeforeProcessing => 2,
            _ => 1,
        }
    }

    /// Names the recovery shape and exact retained-event multiplicity.
    fn disruption(self) -> String {
        format!("{}/copies-{}", self.name(), self.duplicate_copies())
    }
}

/// Generates a stable prefix of offline catch-up pressure cases.
pub fn generate_offline_catchup_pressure_family(
    seed: u64,
    cases: usize,
) -> Vec<GeneratedScenarioCase> {
    (0..cases)
        .map(|case_index| generate_offline_catchup_pressure_case(seed, case_index as u64))
        .collect()
}

/// Generates one replay-stable offline catch-up pressure case.
pub fn generate_offline_catchup_pressure_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x0FF1_1ECA_7C4D_0001 ^ case_index.rotate_left(29));
    let arm = CatchupArm::from_index(case_index);
    let volume_slot = usize::try_from(case_index / ARM_COUNT).expect("case index fits usize")
        % VOLUME_PROFILES.len();
    let volume = VOLUME_PROFILES[volume_slot];
    let clients = labels(["alice", OFFLINE_CLIENT, "carol", "david"]);
    let online_clients = labels(["alice", "carol", "david"]);

    let mut steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("offline-catchup-{case_index}"),
            invitees: labels([OFFLINE_CLIENT, "carol", "david"]),
            required_features: vec![],
            initial_admins: Some(clients.clone()),
            pending: "create".into(),
        },
        accepted_publication("alice", "create"),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: labels([OFFLINE_CLIENT, "carol", "david"]),
        },
        ScenarioStep::ClearEvents {
            clients: clients.clone(),
        },
        ScenarioStep::SetClientOffline {
            client: OFFLINE_CLIENT.into(),
        },
    ];

    let mut bob_payloads = Vec::with_capacity(volume.application_messages + 2);
    let mut remaining_messages = volume.application_messages;
    let mut message_index = 0_usize;
    let mut workload_commit_count = 0_usize;
    let mut active_committers = std::collections::BTreeSet::new();
    let active_senders = ["alice", "carol", "david"];

    for round in 0..volume.commit_rounds {
        let rounds_left = volume.commit_rounds - round;
        let messages_this_round = remaining_messages.div_ceil(rounds_left);
        for _ in 0..messages_this_round {
            let sender = active_senders[rng.gen_range(0..active_senders.len())];
            let payload = format!("offline-catchup:{case_index}:{message_index}:{sender}");
            bob_payloads.push(payload.clone());
            steps.push(ScenarioStep::SendAppMessage {
                sender: sender.into(),
                payload,
            });
            steps.push(accept_all_outbound(sender));
            message_index += 1;
        }
        remaining_messages -= messages_this_round;

        let mut committers = active_senders;
        committers.shuffle(&mut rng);
        let commits_this_round = if arm == CatchupArm::CompetingCommitWaves {
            2
        } else {
            1
        };
        for (branch, committer) in committers.iter().take(commits_this_round).enumerate() {
            active_committers.insert(*committer);
            let pending = format!("state-{round}-{branch}");
            steps.push(ScenarioStep::UpdateGroupData {
                client: (*committer).into(),
                name: format!("offline-catchup-{case_index}-round-{round}-branch-{branch}"),
                pending: pending.clone(),
            });
            steps.push(accepted_publication(committer, &pending));
            workload_commit_count += 1;
        }
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: online_clients.clone(),
        });
    }
    debug_assert_eq!(message_index, volume.application_messages);
    debug_assert_eq!(remaining_messages, 0);

    let first_payload = bob_payloads.first().expect("non-empty workload").clone();
    steps.push(ScenarioStep::Assert {
        assertion: ScenarioAssertionV2::Exactly {
            predicate: ScenarioPredicateV2::PayloadCount {
                client: OFFLINE_CLIENT.into(),
                payload: first_payload,
                count: 0,
            },
        },
    });

    if arm.relay_order() != ScenarioRelayOrderV2::Natural || arm.duplicate_copies() != 1 {
        steps.push(ScenarioStep::ConfigureRelay {
            relay: RELAY_ID.into(),
            order: arm.relay_order(),
            duplicate_copies: arm.duplicate_copies(),
        });
    }
    steps.push(ScenarioStep::ReconnectClient {
        client: OFFLINE_CLIENT.into(),
    });
    match arm {
        CatchupArm::IncrementalThenFull => {
            sync_and_tick(&mut steps, ScenarioRelaySyncModeV2::Incremental);
            sync_and_tick(&mut steps, ScenarioRelaySyncModeV2::FullHistory);
        }
        CatchupArm::RestartBeforeProcessing => {
            steps.push(ScenarioStep::SyncRelayHistory {
                clients: vec![OFFLINE_CLIENT.into()],
                sync: ScenarioRelaySyncModeV2::Incremental,
            });
            steps.push(ScenarioStep::RestartClient {
                client: OFFLINE_CLIENT.into(),
            });
            sync_and_tick(&mut steps, ScenarioRelaySyncModeV2::FullHistory);
        }
        _ => sync_and_tick(&mut steps, ScenarioRelaySyncModeV2::FullHistory),
    }

    let last_payload = bob_payloads.last().expect("non-empty workload").clone();
    steps.push(ScenarioStep::Assert {
        // One catch-up tick starts processing, but the deliberately bounded
        // engine may need several scheduler turns to drain a large retained
        // history. Keep the exact-one predicate while granting a deterministic
        // number of progress turns before declaring the client stuck.
        assertion: ScenarioAssertionV2::Eventually {
            predicate: ScenarioPredicateV2::PayloadCount {
                client: OFFLINE_CLIENT.into(),
                payload: last_payload,
                count: 1,
            },
            max_iterations: 128,
        },
    });

    let probe_clients = labels(["alice", OFFLINE_CLIENT, "carol"]);
    let probe_step_index = steps.len();
    steps.push(ScenarioStep::ProbeBidirectionalDecryptability {
        clients: probe_clients.clone(),
    });
    bob_payloads.extend(
        probe_clients
            .iter()
            .filter(|sender| sender.as_str() != OFFLINE_CLIENT)
            .map(|sender| format!("cgka-decryptability-probe/v1/{probe_step_index}/{sender}")),
    );

    let mut scenario = ScenarioSpec {
        name: format!(
            "{OFFLINE_CATCHUP_PRESSURE_FAMILY}/case-{case_index}/{}/{}",
            volume.name,
            arm.name()
        ),
        spec_version: "2".into(),
        clients: clients.clone(),
        topology: retained_relay_topology(&clients),
        steps,
    };
    let mut expected_outcomes = vec![
        TraceExpectation::ClientsConverged {
            clients: clients.clone(),
            epoch: None,
            member_count: Some(clients.len()),
        },
        TraceExpectation::ApplicationPayloadMultiset {
            client: OFFLINE_CLIENT.into(),
            payloads: bob_payloads,
        },
        TraceExpectation::ClientsBidirectionallyDecryptable {
            clients: probe_clients,
        },
    ];
    push_labelled_confirmation_expectations(&scenario, &mut expected_outcomes);
    add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);

    GeneratedScenarioCase {
        family_name: OFFLINE_CATCHUP_PRESSURE_FAMILY.into(),
        generator_version: OFFLINE_CATCHUP_PRESSURE_GENERATOR_VERSION.into(),
        seed,
        case_index,
        workload_profile: Some(GeneratedWorkloadProfileV1 {
            name: format!("{}/{}", volume.name, arm.name()),
            version: OFFLINE_CATCHUP_PRESSURE_PROFILE_VERSION.into(),
            size_tier: volume.tier.into(),
            member_count: clients.len(),
            admin_regime: "all-members".into(),
            initial_admin_count: clients.len(),
            final_admin_count: clients.len(),
            committer_mode: if arm == CatchupArm::CompetingCommitWaves {
                "rival-pair-per-round".into()
            } else {
                "rotating-sequential".into()
            },
            active_committer_count: active_committers.len(),
            traffic_profile: format!(
                "offline-backlog-{}-applications",
                volume.application_messages
            ),
            application_message_count: volume.application_messages,
            workload_commit_count,
            formation: "founding-member-before-offline".into(),
            disruption: arm.disruption(),
        }),
        subject: GeneratedSubjectKind::RetainedRelay,
        scenario,
        expected_outcomes,
    }
}

/// Appends one retained-history query followed by a processing tick.
fn sync_and_tick(steps: &mut Vec<ScenarioStep>, sync: ScenarioRelaySyncModeV2) {
    steps.push(ScenarioStep::SyncRelayHistory {
        clients: vec![OFFLINE_CLIENT.into()],
        sync,
    });
    steps.push(ScenarioStep::Tick {
        clients: vec![OFFLINE_CLIENT.into()],
    });
}

/// Builds an accepted acknowledgement for one named publication.
fn accepted_publication(client: &str, publication: &str) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: Some(publication.into()),
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    }
}

/// Builds an accepted acknowledgement for every pending outbound artifact.
fn accept_all_outbound(client: &str) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: None,
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    }
}

/// Builds the explicit four-client, retain-all relay topology used by the family.
fn retained_relay_topology(clients: &[String]) -> ScenarioTopologyV2 {
    ScenarioTopologyV2 {
        accounts: clients
            .iter()
            .map(|client| ScenarioAccountV2 {
                id: format!("account:{client}"),
                roles: vec!["member".into()],
            })
            .collect(),
        devices: clients
            .iter()
            .map(|client| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: format!("account:{client}"),
                process: format!("process:{client}"),
                client: client.clone(),
            })
            .collect(),
        processes: clients
            .iter()
            .map(|client| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "mdk-current".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec![RELAY_ID.into()],
            })
            .collect(),
        groups: vec![],
        relays: vec![ScenarioRelayV2 {
            id: RELAY_ID.into(),
            implementation_version: "memory/v1".into(),
            policy_version: "retain-all/v1".into(),
        }],
    }
}

/// Converts a fixed array of labels into owned scenario strings.
fn labels<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(String::from).collect()
}
