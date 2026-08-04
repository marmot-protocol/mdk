//! Decision-route assurance catalog and permanent cross-seam regressions.

use serde::{Deserialize, Serialize};

use crate::{
    ScenarioAccountV2, ScenarioDeviceV2, ScenarioMessageSelectorV2, ScenarioProcessV2,
    ScenarioRelaySyncModeV2, ScenarioRelayV2, ScenarioSpec, ScenarioStep, ScenarioTopologyV2,
    ScenarioTransportClass, SubjectOutboundOutcome,
};

pub const ROUTE_EQUIVALENCE_CLAIM: &str = "route-equivalence";
pub const RECONSIDERABLE_LOSER_CLAIM: &str = "reconsiderable-loser";
pub const RESTART_INVARIANCE_CLAIM: &str = "restart-invariance";
pub const EXACT_CRYPTOGRAPHIC_AGREEMENT_CLAIM: &str = "exact-cryptographic-agreement";
pub const ACTIVE_DECRYPTABILITY_CLAIM: &str = "active-bidirectional-decryptability";
pub const COMPLETE_APPLICATION_DISPOSITION_CLAIM: &str = "complete-application-disposition";

pub const ROUTE_ASSURANCE_CLAIMS: &[&str] = &[
    ROUTE_EQUIVALENCE_CLAIM,
    RECONSIDERABLE_LOSER_CLAIM,
    RESTART_INVARIANCE_CLAIM,
    EXACT_CRYPTOGRAPHIC_AGREEMENT_CLAIM,
    ACTIVE_DECRYPTABILITY_CLAIM,
    COMPLETE_APPLICATION_DISPOSITION_CLAIM,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeeperBranch {
    Alice,
    Bob,
}

impl DeeperBranch {
    fn label(self) -> &'static str {
        match self {
            Self::Alice => "alice",
            Self::Bob => "bob",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverDeliveryOrder {
    CarolThenDavid,
    DavidThenCarol,
}

impl ObserverDeliveryOrder {
    fn observers(self) -> [&'static str; 2] {
        match self {
            Self::CarolThenDavid => ["carol", "david"],
            Self::DavidThenCarol => ["david", "carol"],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteRestartCheckpoint {
    None,
    AfterAliceRoot,
    AfterBobRoot,
    AfterBranchGrowth,
    AfterObserverRouting,
    AfterCommitterRouting,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEquivalenceCampaignV1 {
    pub campaign_id: String,
    pub incident: String,
    pub deeper_branch: DeeperBranch,
    pub observer_delivery_order: ObserverDeliveryOrder,
    pub restart_checkpoint: RouteRestartCheckpoint,
    pub covered_claims: Vec<String>,
    pub scenario: ScenarioSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteCampaignAdapter {
    Engine,
    AppRuntime,
    Process,
    Distributed,
}

/// Lower adapter-owned publication/history mechanics while preserving the
/// incident's logical inputs, restart points, exact observations, and probes.
/// Retained-history adapters cannot yet hide one already-published relay event;
/// barriers retain the two delivery boundaries and make that residual adapter
/// difference explicit in the compiled schedule.
pub fn scenario_for_route_adapter(
    campaign: &RouteEquivalenceCampaignV1,
    adapter: RouteCampaignAdapter,
) -> ScenarioSpec {
    let mut scenario = campaign.scenario.clone();
    let mut steps = Vec::with_capacity(scenario.steps.len() + 2);
    for step in scenario.steps {
        match (&adapter, step) {
            (RouteCampaignAdapter::AppRuntime, ScenarioStep::AcknowledgeOutbound { .. }) => {}
            (
                RouteCampaignAdapter::AppRuntime
                | RouteCampaignAdapter::Process
                | RouteCampaignAdapter::Distributed,
                ScenarioStep::AdvanceTime { .. },
            ) => {}
            (
                RouteCampaignAdapter::AppRuntime
                | RouteCampaignAdapter::Process
                | RouteCampaignAdapter::Distributed,
                ScenarioStep::WithholdMessage { .. },
            ) => steps.push(ScenarioStep::Barrier {
                name: "retained-history-adapter-follow-on-visible".into(),
            }),
            (
                RouteCampaignAdapter::AppRuntime
                | RouteCampaignAdapter::Process
                | RouteCampaignAdapter::Distributed,
                ScenarioStep::ReleaseWithheld { .. },
            ) => steps.push(ScenarioStep::Barrier {
                name: "retained-history-adapter-follow-on-release".into(),
            }),
            (RouteCampaignAdapter::Engine, ScenarioStep::SyncRelayHistory { clients, .. }) => {
                steps.push(ScenarioStep::DeliverAll);
                steps.push(ScenarioStep::Tick { clients });
            }
            (_, step) => steps.push(step),
        }
    }
    scenario.steps = steps;
    scenario
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceClaimStatus {
    Open,
    Covered,
    Reopened,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceClaimRecordV1 {
    pub claim_id: String,
    pub status: AssuranceClaimStatus,
    pub covering_campaigns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub falsification: Option<String>,
}

impl AssuranceClaimRecordV1 {
    pub fn open(claim_id: impl Into<String>) -> Self {
        Self {
            claim_id: claim_id.into(),
            status: AssuranceClaimStatus::Open,
            covering_campaigns: Vec::new(),
            falsification: None,
        }
    }

    pub fn cover(&mut self, campaign_id: &str) {
        if !self
            .covering_campaigns
            .iter()
            .any(|existing| existing == campaign_id)
        {
            self.covering_campaigns.push(campaign_id.into());
            self.covering_campaigns.sort();
        }
        if self.status != AssuranceClaimStatus::Reopened {
            self.status = AssuranceClaimStatus::Covered;
        }
    }

    pub fn reopen(&mut self, falsification: impl Into<String>) {
        self.status = AssuranceClaimStatus::Reopened;
        self.falsification = Some(falsification.into());
    }
}

/// Permanent synthetic family derived from mdk#1236. The full matrix mirrors
/// which root branch grows, observer delivery order, and a restart after every
/// durable transition represented by the scenario.
pub fn generate_cross_route_regression_family() -> Vec<RouteEquivalenceCampaignV1> {
    let mut campaigns = Vec::new();
    for deeper_branch in [DeeperBranch::Alice, DeeperBranch::Bob] {
        for observer_delivery_order in [
            ObserverDeliveryOrder::CarolThenDavid,
            ObserverDeliveryOrder::DavidThenCarol,
        ] {
            for restart_checkpoint in [
                RouteRestartCheckpoint::None,
                RouteRestartCheckpoint::AfterAliceRoot,
                RouteRestartCheckpoint::AfterBobRoot,
                RouteRestartCheckpoint::AfterBranchGrowth,
                RouteRestartCheckpoint::AfterObserverRouting,
                RouteRestartCheckpoint::AfterCommitterRouting,
            ] {
                let campaign_id = format!(
                    "cross-route-1236/v1/deeper-{}/order-{:?}/restart-{:?}",
                    deeper_branch.label(),
                    observer_delivery_order,
                    restart_checkpoint
                )
                .to_ascii_lowercase();
                campaigns.push(RouteEquivalenceCampaignV1 {
                    campaign_id: campaign_id.clone(),
                    incident: "mdk#1236".into(),
                    deeper_branch,
                    observer_delivery_order,
                    restart_checkpoint,
                    covered_claims: ROUTE_ASSURANCE_CLAIMS
                        .iter()
                        .map(|claim| (*claim).into())
                        .collect(),
                    scenario: cross_route_scenario(
                        &campaign_id,
                        deeper_branch,
                        observer_delivery_order,
                        restart_checkpoint,
                    ),
                });
            }
        }
    }
    campaigns
}

fn cross_route_scenario(
    name: &str,
    deeper_branch: DeeperBranch,
    observer_order: ObserverDeliveryOrder,
    restart_checkpoint: RouteRestartCheckpoint,
) -> ScenarioSpec {
    let clients = ["alice", "bob", "carol", "david", "eve", "frank", "grace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let core_clients = ["alice", "bob", "carol", "david"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut steps = vec![
        // Select controlled time before any convergence tick. Engine-harness
        // compatibility mode otherwise substitutes a far-future timestamp.
        ScenarioStep::AdvanceTime { delta_ms: 0 },
        in_group(ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: "cross-route-base".into(),
            invitees: vec!["bob".into(), "carol".into(), "david".into()],
            required_features: Vec::new(),
            initial_admins: Some(vec!["alice".into(), "bob".into()]),
            pending: "create".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "alice".into(),
            publication: Some("create".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: core_clients.clone(),
        },
        in_group(ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: vec!["eve".into()],
            pending: "alice-root".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "alice".into(),
            publication: Some("alice-root".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
    ];
    push_restart(
        &mut steps,
        restart_checkpoint,
        RouteRestartCheckpoint::AfterAliceRoot,
        "alice",
    );
    steps.extend([
        in_group(ScenarioStep::InviteMembers {
            inviter: "bob".into(),
            invitees: vec!["frank".into()],
            pending: "bob-root".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: "bob".into(),
            publication: Some("bob-root".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
    ]);
    push_restart(
        &mut steps,
        restart_checkpoint,
        RouteRestartCheckpoint::AfterBobRoot,
        "bob",
    );
    steps.extend([
        in_group(ScenarioStep::InviteMembers {
            inviter: deeper_branch.label().into(),
            invitees: vec!["grace".into()],
            pending: "branch-growth".into(),
        }),
        ScenarioStep::AcknowledgeOutbound {
            client: deeper_branch.label().into(),
            publication: Some("branch-growth".into()),
            selection: Default::default(),
            outcome: SubjectOutboundOutcome::Accepted,
        },
    ]);
    push_restart(
        &mut steps,
        restart_checkpoint,
        RouteRestartCheckpoint::AfterBranchGrowth,
        deeper_branch.label(),
    );
    steps.push(ScenarioStep::WithholdMessage {
        selector: ScenarioMessageSelectorV2 {
            publication: Some("branch-growth".into()),
            class: Some(ScenarioTransportClass::Commit),
            ..Default::default()
        },
        label: "deeper-follow-on".into(),
    });
    steps.push(ScenarioStep::DeliverAll);
    for observer in observer_order.observers() {
        steps.push(ScenarioStep::Tick {
            clients: vec![observer.into()],
        });
    }
    push_restart(
        &mut steps,
        restart_checkpoint,
        RouteRestartCheckpoint::AfterObserverRouting,
        observer_order.observers()[0],
    );
    for committer in ["bob", "alice"] {
        steps.push(ScenarioStep::Tick {
            clients: vec![committer.into()],
        });
    }
    push_restart(
        &mut steps,
        restart_checkpoint,
        RouteRestartCheckpoint::AfterCommitterRouting,
        if deeper_branch == DeeperBranch::Alice {
            "bob"
        } else {
            "alice"
        },
    );
    steps.extend([
        in_group(ScenarioStep::ObserveExact {
            clients: core_clients.clone(),
        }),
        ScenarioStep::ReleaseWithheld {
            label: "deeper-follow-on".into(),
        },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: core_clients.clone(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: core_clients.clone(),
            sync: ScenarioRelaySyncModeV2::FullHistory,
        },
        ScenarioStep::AdvanceTime { delta_ms: 1_000 },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: core_clients.clone(),
        },
        // Candidate-branch outer decryption is deliberately admitted through
        // the bounded deferred-peel sweep rather than attacker-paced initial
        // ingest. That sweep can open a fresh convergence pass, so advance a
        // second quiescence window before asserting the fixed point.
        ScenarioStep::AdvanceTime { delta_ms: 1_000 },
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: core_clients.clone(),
        },
        in_group(ScenarioStep::ObserveExact {
            clients: core_clients.clone(),
        }),
        in_group(ScenarioStep::SendAppMessage {
            sender: "alice".into(),
            payload: "application-after-cross-route-settlement/alice".into(),
        }),
        in_group(ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: "application-after-cross-route-settlement/bob".into(),
        }),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: core_clients.clone(),
        },
        in_group(ScenarioStep::ObserveExact {
            clients: core_clients.clone(),
        }),
        in_group(ScenarioStep::ProbeBidirectionalDecryptability {
            clients: core_clients.clone(),
        }),
        in_group(ScenarioStep::ObserveExact {
            clients: core_clients,
        }),
    ]);
    ScenarioSpec {
        name: name.into(),
        spec_version: "2".into(),
        clients,
        topology: four_process_topology(),
        steps,
    }
}

fn in_group(action: ScenarioStep) -> ScenarioStep {
    ScenarioStep::InGroup {
        group: "main".into(),
        action: Box::new(action),
    }
}

fn push_restart(
    steps: &mut Vec<ScenarioStep>,
    selected: RouteRestartCheckpoint,
    checkpoint: RouteRestartCheckpoint,
    client: &str,
) {
    if selected == checkpoint {
        steps.push(ScenarioStep::RestartClient {
            client: client.into(),
        });
    }
}

fn four_process_topology() -> ScenarioTopologyV2 {
    let clients = ["alice", "bob", "carol", "david", "eve", "frank", "grace"];
    ScenarioTopologyV2 {
        accounts: clients
            .iter()
            .map(|client| ScenarioAccountV2 {
                id: (*client).into(),
                roles: vec!["member".into()],
            })
            .collect(),
        devices: clients
            .iter()
            .map(|client| ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: (*client).into(),
                process: format!("process:{client}"),
                client: (*client).into(),
            })
            .collect(),
        processes: clients
            .iter()
            .map(|client| ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: "current-test-node".into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec!["relay:primary".into()],
            })
            .collect(),
        groups: Vec::new(),
        relays: vec![ScenarioRelayV2 {
            id: "relay:primary".into(),
            implementation_version: "retained-mock-v1".into(),
            policy_version: "retain-all-v1".into(),
        }],
    }
}
