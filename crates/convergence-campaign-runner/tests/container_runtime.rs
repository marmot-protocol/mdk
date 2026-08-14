//! Real OCI runtime coverage. Kept ignored in the default lane because it
//! requires a prebuilt Linux campaign image and a Docker/Podman daemon.

use std::path::{Path, PathBuf};

use cgka_conformance_simulator::process_orchestrator::ProcessScenarioReportV1;
use cgka_conformance_simulator::{
    QuiescencePolicy, ScenarioAccountV2, ScenarioDeviceV2, ScenarioProcessV2, ScenarioRelayV2,
    ScenarioSpec, ScenarioStep, ScenarioTopologyV2, canonical_scenario_ir_sha256,
    cross_route_app_runtime_recovery_public_scenario, validate_cross_route_public_process_report,
};
use convergence_campaign_runner::{
    ContainerBackendV1, DistributedBackendV1, DistributedCampaignManifestV1, DistributedFaultV1,
    DistributedParticipantV1, OciRuntimeV1, ScenarioArtifactV1, ScheduledFaultV1, run_manifest,
};
use sha2::Digest;

struct ContainerArtifactRoot {
    _temporary: Option<tempfile::TempDir>,
    path: PathBuf,
}

impl ContainerArtifactRoot {
    fn for_campaign(campaign: &str) -> Self {
        if let Some(base) = std::env::var_os("CGKA_DISTRIBUTED_ARTIFACTS_DIR") {
            let path = PathBuf::from(base).join(campaign);
            fs_private::create_dir_all_private(&path).unwrap();
            return Self {
                _temporary: None,
                path,
            };
        }
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().to_path_buf();
        Self {
            _temporary: Some(temporary),
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn in_group(action: ScenarioStep) -> ScenarioStep {
    ScenarioStep::InGroup {
        group: "main".into(),
        action: Box::new(action),
    }
}

fn smoke_scenario() -> ScenarioSpec {
    let clients = vec!["alice".to_owned(), "bob".to_owned()];
    ScenarioSpec {
        name: "distributed-container-smoke/v1".into(),
        spec_version: "2".into(),
        clients: clients.clone(),
        topology: ScenarioTopologyV2 {
            accounts: clients
                .iter()
                .map(|id| ScenarioAccountV2 {
                    id: id.clone(),
                    roles: vec!["member".into()],
                })
                .collect(),
            devices: clients
                .iter()
                .map(|id| ScenarioDeviceV2 {
                    id: format!("device:{id}"),
                    account: id.clone(),
                    process: format!("process:{id}"),
                    client: id.clone(),
                })
                .collect(),
            processes: clients
                .iter()
                .map(|id| ScenarioProcessV2 {
                    id: format!("process:{id}"),
                    binary_version: "container-current".into(),
                    policy_version: "marmot-convergence-v1".into(),
                    relays: vec!["relay:primary".into()],
                })
                .collect(),
            groups: Vec::new(),
            relays: vec![ScenarioRelayV2 {
                id: "relay:primary".into(),
                implementation_version: "retained-container-v1".into(),
                policy_version: "retain-all-v1".into(),
            }],
        },
        steps: vec![
            in_group(ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "container smoke".into(),
                invitees: vec!["bob".into()],
                required_features: Vec::new(),
                initial_admins: Some(vec!["alice".into()]),
                pending: "create".into(),
            }),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: clients.clone(),
            },
            ScenarioStep::Barrier {
                name: "shape-network".into(),
            },
            in_group(ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: "synthetic-container-message".into(),
            }),
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: clients.clone(),
            },
            ScenarioStep::Barrier {
                name: "reset-network".into(),
            },
            ScenarioStep::DeliverAll,
            ScenarioStep::Tick {
                clients: clients.clone(),
            },
            // The marmot_app_process adapter deliberately omits
            // ExactConformanceObservation. AwaitQuiescence is its supported
            // exactness gate: it fails unless every node reports one shared
            // state_commitment_sha256 and an observably quiescent projection.
            ScenarioStep::AwaitQuiescence {
                policy: QuiescencePolicy::default(),
            },
        ],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires `docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .`"]
async fn real_container_nodes_survive_network_shaping_and_reach_exact_state() {
    let root = tempfile::tempdir().unwrap();
    let scenario_path = root.path().join("scenario.json");
    let scenario_bytes = serde_json::to_vec_pretty(&smoke_scenario()).unwrap();
    fs_private::write_private(&scenario_path, &scenario_bytes).unwrap();
    let image = std::env::var("CGKA_CONVERGENCE_IMAGE")
        .unwrap_or_else(|_| "marmot-conformance:local".into());
    let manifest = DistributedCampaignManifestV1 {
        schema_version: "1".into(),
        campaign_id: "distributed-container-smoke-v1".into(),
        scenario: ScenarioArtifactV1 {
            path: scenario_path,
            sha256: hex::encode(sha2::Sha256::digest(&scenario_bytes)),
            canonical_ir_sha256: None,
        },
        participants: ["alice", "bob"]
            .into_iter()
            .map(|id| DistributedParticipantV1 {
                id: id.into(),
                build_id: "current".into(),
                container_image: None,
            })
            .collect(),
        backend: DistributedBackendV1::Container(ContainerBackendV1 {
            runtime: OciRuntimeV1::Docker,
            namespace: format!("marmot-smoke-{}", std::process::id()),
            allow_mutable_image_references: true,
            allow_cleartext_isolated_relay: true,
            enable_retained_relay_control: false,
            default_participant_image: image.clone(),
            relay_image: image,
            relay_command: vec![
                "cgka-conformance-relay".into(),
                "--bind".into(),
                "0.0.0.0:8080".into(),
            ],
            node_command: vec!["cgka-conformance-node".into()],
        }),
        faults: vec![
            ScheduledFaultV1 {
                at_barrier: "shape-network".into(),
                action: DistributedFaultV1::NetworkShape {
                    participant: "bob".into(),
                    latency_ms: 50,
                    jitter_ms: 5,
                    loss_basis_points: 0,
                    bandwidth_kbit: 10_000,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "reset-network".into(),
                action: DistributedFaultV1::NetworkReset {
                    participant: "bob".into(),
                },
            },
        ],
        output_dir: root.path().join("output"),
    };
    let receipt = run_manifest(&manifest).await.unwrap();
    assert!(receipt.completed, "{receipt:#?}");
    let process_report: ProcessScenarioReportV1 =
        serde_json::from_slice(&std::fs::read(receipt.process_report.as_ref().unwrap()).unwrap())
            .unwrap();
    assert!(process_report.completed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires `docker build -f Dockerfile.convergence-campaign -t marmot-conformance:local .`"]
async fn four_party_cross_route_recovery_containers_match_unified_route() {
    let root = ContainerArtifactRoot::for_campaign("cross-route-container-v1");
    let scenario = cross_route_app_runtime_recovery_public_scenario();
    let scenario_path = root.path().join("canonical-scenario.json");
    let scenario_bytes = serde_json::to_vec_pretty(&scenario).unwrap();
    fs_private::write_private(&scenario_path, &scenario_bytes).unwrap();
    let canonical_ir_sha256 = canonical_scenario_ir_sha256(&scenario).unwrap();
    let image = std::env::var("CGKA_CONVERGENCE_IMAGE")
        .unwrap_or_else(|_| "marmot-conformance:local".into());
    let manifest = DistributedCampaignManifestV1 {
        schema_version: "1".into(),
        campaign_id: "cross-route-container-v1".into(),
        scenario: ScenarioArtifactV1 {
            path: scenario_path,
            sha256: hex::encode(sha2::Sha256::digest(&scenario_bytes)),
            canonical_ir_sha256: Some(canonical_ir_sha256.clone()),
        },
        participants: scenario
            .clients
            .iter()
            .map(|id| DistributedParticipantV1 {
                id: id.clone(),
                build_id: "current".into(),
                container_image: None,
            })
            .collect(),
        backend: DistributedBackendV1::Container(ContainerBackendV1 {
            runtime: OciRuntimeV1::Docker,
            namespace: format!("marmot-cross-route-{}", std::process::id()),
            allow_mutable_image_references: true,
            allow_cleartext_isolated_relay: true,
            enable_retained_relay_control: true,
            default_participant_image: image.clone(),
            relay_image: image,
            relay_command: vec![
                "cgka-conformance-relay".into(),
                "--bind".into(),
                "0.0.0.0:8080".into(),
            ],
            node_command: vec!["cgka-conformance-node".into()],
        }),
        faults: Vec::new(),
        output_dir: root.path().join("output"),
    };

    let receipt = run_manifest(&manifest).await.unwrap();
    assert!(receipt.completed, "{receipt:#?}");
    assert_eq!(receipt.backend, "container");
    assert!(receipt.cleanup_failures.is_empty(), "{receipt:#?}");
    let process_report: ProcessScenarioReportV1 =
        serde_json::from_slice(&std::fs::read(receipt.process_report.as_ref().unwrap()).unwrap())
            .unwrap();
    validate_cross_route_public_process_report(&scenario, &process_report).unwrap();
    assert_eq!(
        process_report.executed_scenario_ir_sha256.as_deref(),
        Some(canonical_ir_sha256.as_str())
    );

    let normalized: DistributedCampaignManifestV1 = serde_json::from_slice(
        &std::fs::read(manifest.output_dir.join("normalized-manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        normalized.scenario.canonical_ir_sha256.as_deref(),
        Some(canonical_ir_sha256.as_str())
    );
}
