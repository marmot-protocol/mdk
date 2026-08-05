use std::collections::BTreeSet;

use convergence_campaign_runner::{
    ContainerBackendV1, DistributedBackendV1, DistributedCampaignManifestV1, DistributedFaultV1,
    DistributedParticipantV1, FaultPeerV1, OciRuntimeV1, ScenarioArtifactV1, ScheduledFaultV1,
    VirtualMachineBackendV1, VirtualMachineCapabilityV1, build_execution_plan,
    container_node_launch, load_manifest, verify_manifest_inputs,
};
use sha2::Digest;

fn container_manifest() -> (tempfile::TempDir, DistributedCampaignManifestV1) {
    let root = tempfile::tempdir().unwrap();
    let scenario = root.path().join("scenario.json");
    let bytes = br#"{"name":"distributed-smoke"}"#;
    fs_private::write_private(&scenario, bytes).unwrap();
    let sha256 = hex::encode(sha2::Sha256::digest(bytes));
    let manifest = DistributedCampaignManifestV1 {
        schema_version: "1".into(),
        campaign_id: "distributed-smoke-v1".into(),
        scenario: ScenarioArtifactV1 {
            path: scenario,
            sha256,
        },
        participants: vec![
            DistributedParticipantV1 {
                id: "alice".into(),
                build_id: "current".into(),
                container_image: None,
            },
            DistributedParticipantV1 {
                id: "bob".into(),
                build_id: "previous".into(),
                container_image: Some("marmot-conformance:previous".into()),
            },
        ],
        backend: DistributedBackendV1::Container(ContainerBackendV1 {
            runtime: OciRuntimeV1::Docker,
            namespace: "marmot-campaign-test".into(),
            allow_mutable_image_references: true,
            allow_cleartext_isolated_relay: true,
            default_participant_image: "marmot-conformance:current".into(),
            relay_image: "marmot-conformance:current".into(),
            relay_command: vec!["cgka-conformance-relay".into()],
            node_command: vec!["cgka-conformance-node".into()],
        }),
        faults: vec![
            ScheduledFaultV1 {
                at_barrier: "partition".into(),
                action: DistributedFaultV1::NetworkPartition {
                    participant: "alice".into(),
                    peer: FaultPeerV1::Relay,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "heal".into(),
                action: DistributedFaultV1::NetworkHeal {
                    participant: "alice".into(),
                    peer: FaultPeerV1::Relay,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "shape".into(),
                action: DistributedFaultV1::NetworkShape {
                    participant: "bob".into(),
                    latency_ms: 250,
                    jitter_ms: 25,
                    loss_basis_points: 125,
                    bandwidth_kbit: 512,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "relay-restart".into(),
                action: DistributedFaultV1::RestartRelay,
            },
            ScheduledFaultV1 {
                at_barrier: "disk-full".into(),
                action: DistributedFaultV1::FillDisk {
                    participant: "alice".into(),
                    bytes: 1024,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "disk-release".into(),
                action: DistributedFaultV1::ReleaseDisk {
                    participant: "alice".into(),
                },
            },
            ScheduledFaultV1 {
                at_barrier: "database-contention".into(),
                action: DistributedFaultV1::DatabaseContention {
                    participant: "bob".into(),
                    workers: 2,
                    bytes_per_worker: 4096,
                    duration_ms: 5_000,
                },
            },
            ScheduledFaultV1 {
                at_barrier: "host-crash".into(),
                action: DistributedFaultV1::CrashParticipantHost {
                    participant: "bob".into(),
                },
            },
        ],
        output_dir: root.path().join("output"),
    };
    (root, manifest)
}

fn fault_commands<'a>(
    plan: &'a convergence_campaign_runner::DistributedExecutionPlanV1,
    barrier: &str,
) -> &'a [convergence_campaign_runner::PlannedCommandV1] {
    &plan.faults[barrier][0].commands
}

fn fault_rollbacks<'a>(
    plan: &'a convergence_campaign_runner::DistributedExecutionPlanV1,
    barrier: &str,
) -> &'a [convergence_campaign_runner::PlannedCommandV1] {
    &plan.faults[barrier][0].rollbacks
}

#[test]
fn container_plan_covers_network_restart_disk_and_contention_without_shell() {
    let (_root, manifest) = container_manifest();
    verify_manifest_inputs(&manifest).unwrap();
    let plan = build_execution_plan(&manifest).unwrap();
    assert_eq!(plan.backend, "container");
    assert_eq!(plan.setup.len(), 2);
    assert_eq!(plan.cleanup.len(), 2);
    assert!(plan.setup[1].args.windows(2).any(|window| {
        window
            == [
                "--network-alias".to_owned(),
                "marmot-campaign-relay".to_owned(),
            ]
    }));
    for barrier in [
        "partition",
        "heal",
        "shape",
        "relay-restart",
        "disk-full",
        "disk-release",
        "database-contention",
        "host-crash",
    ] {
        assert!(plan.faults.contains_key(barrier), "{barrier}");
    }
    let contention = &fault_commands(&plan, "database-contention")[0];
    let timeout_index = contention
        .args
        .iter()
        .position(|argument| argument == "--timeout")
        .unwrap();
    assert_eq!(contention.args[timeout_index + 1], "5s");
    for command in plan
        .setup
        .iter()
        .chain(
            plan.faults
                .values()
                .flatten()
                .flat_map(|fault| fault.commands.iter().chain(fault.rollbacks.iter())),
        )
        .chain(&plan.cleanup)
    {
        assert_ne!(command.program, "sh");
        assert_ne!(command.program, "bash");
        assert!(!command.args.iter().any(|arg| arg == "-c"));
    }
    let shape = &fault_commands(&plan, "shape")[0];
    assert!(shape.args.contains(&"1.25%".into()));
    assert!(shape.args.contains(&"512kbit".into()));
    let partition = fault_commands(&plan, "partition");
    assert!(partition.iter().all(|command| {
        command
            .args
            .windows(2)
            .any(|pair| pair == ["--cap-add", "NET_ADMIN"])
            && command.args.windows(2).any(|pair| {
                pair[0] == "--network" && pair[1].starts_with("container:{run_token}-participant-")
            })
    }));
    assert!(
        partition
            .iter()
            .any(|command| { command.args.iter().any(|argument| argument == "INPUT") })
    );
    assert!(
        partition
            .iter()
            .any(|command| { command.args.iter().any(|argument| argument == "OUTPUT") })
    );
    assert!(partition.iter().all(|command| {
        command
            .args
            .windows(2)
            .any(|pair| pair == ["--user", "0:0"])
    }));
    assert_eq!(
        partition
            .iter()
            .filter(|command| command.purpose == "record_network_partition_peer_address")
            .count(),
        1
    );
    let heal = fault_commands(&plan, "heal");
    assert!(
        partition
            .iter()
            .chain(heal)
            .chain(fault_rollbacks(&plan, "partition"))
            .chain(fault_rollbacks(&plan, "heal"))
            .all(|command| command.success_exit_codes != [0, 1, 2])
    );
    for purpose in [
        "reset_network_partition_peer_set",
        "reset_network_partition_chain",
        "partition_network_inbound",
        "partition_network_outbound",
        "activate_inbound_partition",
        "activate_outbound_partition",
        "verify_network_partition_inbound_rule",
        "verify_network_partition_outbound_rule",
        "verify_inbound_partition_active",
        "verify_outbound_partition_active",
    ] {
        assert_eq!(
            partition
                .iter()
                .find(|command| command.purpose == purpose)
                .unwrap()
                .success_exit_codes,
            [0],
            "{purpose}"
        );
    }
    for purpose in [
        "heal_inbound_network_partition",
        "heal_outbound_network_partition",
        "flush_network_partition_chain",
        "remove_network_partition_chain",
        "remove_network_partition_peer_set",
    ] {
        assert_eq!(
            heal.iter()
                .find(|command| command.purpose == purpose)
                .unwrap()
                .success_exit_codes,
            [0],
            "{purpose}"
        );
    }
    for purpose in [
        "verify_inbound_partition_healed",
        "verify_outbound_partition_healed",
        "verify_network_partition_chain_removed",
        "verify_network_partition_peer_set_removed",
    ] {
        assert_eq!(
            heal.iter()
                .find(|command| command.purpose == purpose)
                .unwrap()
                .success_exit_codes,
            [1],
            "{purpose}"
        );
    }
    assert!(
        fault_rollbacks(&plan, "partition")
            .iter()
            .any(|command| command.purpose == "verify_outbound_partition_healed")
    );
    assert!(
        fault_rollbacks(&plan, "heal")
            .iter()
            .any(|command| command.purpose == "verify_outbound_partition_active")
    );
    let release = &fault_commands(&plan, "disk-release")[0];
    assert_eq!(release.program, "rm");
    assert!(
        release
            .args
            .iter()
            .any(|argument| argument.contains("{host_run_root}"))
    );
}

#[test]
fn scenario_digest_accepts_uppercase_hex() {
    let (_root, mut manifest) = container_manifest();
    manifest.scenario.sha256.make_ascii_uppercase();
    verify_manifest_inputs(&manifest).unwrap();
}

#[test]
fn uppercase_yaml_extension_uses_the_yaml_parser() {
    let (root, manifest) = container_manifest();
    let path = root.path().join("campaign.YAML");
    fs_private::write_private(
        &path,
        serde_yaml_ng::to_string(&manifest).unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(load_manifest(&path).unwrap(), manifest);
}

#[test]
fn manifest_rejects_empty_output_and_participant_image_override() {
    let (_root, mut manifest) = container_manifest();
    manifest.output_dir = std::path::PathBuf::new();
    assert_eq!(manifest.validate().unwrap_err().code, "output_dir");

    let (root, mut manifest) = container_manifest();
    manifest.participants[0].container_image = Some("  ".into());
    assert_eq!(
        manifest.validate().unwrap_err().code,
        "participant_container_image"
    );
    drop(root);
}

#[test]
fn container_namespace_rejects_docker_name_separators_and_edge_punctuation() {
    let (_root, mut manifest) = container_manifest();
    for invalid in ["campaign:one", "-campaign", "campaign-"] {
        let DistributedBackendV1::Container(container) = &mut manifest.backend else {
            unreachable!();
        };
        container.namespace = invalid.into();
        assert_eq!(
            manifest.validate().unwrap_err().code,
            "unsafe_container_namespace"
        );
    }
}

#[test]
fn cleartext_isolated_relay_requires_manifest_level_operator_approval() {
    let (_root, mut manifest) = container_manifest();
    let DistributedBackendV1::Container(container) = &mut manifest.backend else {
        unreachable!();
    };
    container.allow_cleartext_isolated_relay = false;
    assert_eq!(
        manifest.validate().unwrap_err().code,
        "cleartext_isolated_relay_not_approved"
    );
}

#[test]
fn container_backend_rejects_vacuous_participant_partitions() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![ScheduledFaultV1 {
        at_barrier: "partition".into(),
        action: DistributedFaultV1::NetworkPartition {
            participant: "alice".into(),
            peer: FaultPeerV1::Participant("bob".into()),
        },
    }];
    assert_eq!(
        manifest.validate().unwrap_err().code,
        "container_participant_partition_unsupported"
    );
}

#[test]
fn mutable_container_images_require_an_explicit_local_opt_out() {
    let (_root, mut manifest) = container_manifest();
    let DistributedBackendV1::Container(container) = &mut manifest.backend else {
        unreachable!();
    };
    container.allow_mutable_image_references = false;
    assert_eq!(
        manifest.validate().unwrap_err().code,
        "mutable_container_image"
    );

    let digest = "ab".repeat(32);
    let DistributedBackendV1::Container(container) = &mut manifest.backend else {
        unreachable!();
    };
    container.default_participant_image = format!("marmot-conformance@sha256:{digest}");
    container.relay_image = format!("marmot-conformance@sha256:{digest}");
    for participant in &mut manifest.participants {
        participant.container_image = Some(format!("marmot-conformance@sha256:{digest}"));
    }
    manifest.validate().unwrap();
}

#[test]
fn faults_sharing_a_barrier_keep_distinct_compensation_boundaries() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![
        ScheduledFaultV1 {
            at_barrier: "shared".into(),
            action: DistributedFaultV1::NetworkShape {
                participant: "alice".into(),
                latency_ms: 10,
                jitter_ms: 0,
                loss_basis_points: 0,
                bandwidth_kbit: 1000,
            },
        },
        ScheduledFaultV1 {
            at_barrier: "shared".into(),
            action: DistributedFaultV1::FillDisk {
                participant: "bob".into(),
                bytes: 1024,
            },
        },
    ];
    let plan = build_execution_plan(&manifest).unwrap();
    assert_eq!(plan.faults["shared"].len(), 2);
    assert_eq!(plan.faults["shared"][0].manifest_index, 0);
    assert_eq!(plan.faults["shared"][1].manifest_index, 1);
}

#[cfg(unix)]
#[test]
fn vm_plan_rejects_non_utf8_argv_paths() {
    use std::os::unix::ffi::OsStringExt;

    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![ScheduledFaultV1 {
        at_barrier: "slow-disk".into(),
        action: DistributedFaultV1::SlowBlockDevice {
            participant: "alice".into(),
            latency_ms: 50,
        },
    }];
    manifest.backend = DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
        driver: "/tmp/driver".into(),
        driver_args: vec!["{scenario}".into()],
        timeout_seconds: 7_200,
        capabilities: BTreeSet::from([VirtualMachineCapabilityV1::BlockDeviceLatency]),
    });
    manifest.scenario.path = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));
    let error = build_execution_plan(&manifest).unwrap_err();
    assert_eq!(error.code, "non_utf8_path");
}

#[test]
fn mixed_builds_select_an_exact_image_per_participant() {
    let (_root, manifest) = container_manifest();
    let launch = container_node_launch(&manifest).unwrap();
    assert!(launch.args_by_participant["alice"].contains(&"marmot-conformance:current".into()));
    assert!(launch.args_by_participant["bob"].contains(&"marmot-conformance:previous".into()));
    assert_eq!(
        launch.child_run_root.as_deref(),
        Some(std::path::Path::new("/campaign"))
    );
    assert!(
        launch
            .args_by_participant
            .values()
            .all(|args| !args.iter().any(|arg| arg == "NET_ADMIN"))
    );
    assert!(launch.args_by_participant.values().all(|args| {
        args.iter()
            .any(|argument| argument == "--allow-cleartext-isolated-relay")
            && !args.iter().any(|argument| argument == "--relay-proxy")
    }));
    assert!(launch.args_by_participant.values().all(|args| {
        args.windows(2).any(|window| {
            window[0] == "--user" && window[1] != "0:0" && !window[1].starts_with("0:")
        })
    }));
    assert!(launch.args_by_participant.values().all(|args| {
        args.windows(2).any(|window| {
            window
                == [
                    "--relay-proxy-listen".to_owned(),
                    "127.0.0.1:18080".to_owned(),
                ]
        })
    }));
}

#[test]
fn database_contention_requires_whole_second_duration() {
    let (_root, mut manifest) = container_manifest();
    let contention = manifest
        .faults
        .iter_mut()
        .find(|fault| fault.at_barrier == "database-contention")
        .unwrap();
    let DistributedFaultV1::DatabaseContention { duration_ms, .. } = &mut contention.action else {
        unreachable!();
    };
    *duration_ms = 1_500;
    let error = manifest.validate().unwrap_err();
    assert_eq!(error.code, "database_contention_duration");
}

#[test]
fn slow_block_devices_require_a_capable_vm_backend() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![ScheduledFaultV1 {
        at_barrier: "slow-disk".into(),
        action: DistributedFaultV1::SlowBlockDevice {
            participant: "alice".into(),
            latency_ms: 50,
        },
    }];
    let error = manifest.validate().unwrap_err();
    assert_eq!(error.code, "vm_required_for_block_latency");

    manifest.backend = DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
        driver: "/usr/local/bin/cgka-vm-campaign".into(),
        driver_args: vec![
            "campaign".into(),
            "--scenario".into(),
            "{scenario}".into(),
            "--participants".into(),
            "{participant_count}".into(),
            "--output".into(),
            "{output_dir}".into(),
        ],
        timeout_seconds: 7_200,
        capabilities: BTreeSet::from([VirtualMachineCapabilityV1::BlockDeviceLatency]),
    });
    manifest.validate().unwrap();
    let plan = build_execution_plan(&manifest).unwrap();
    assert_eq!(plan.backend, "virtual_machine");
    assert!(plan.vm_driver.unwrap().args.contains(&"2".into()));
}

#[test]
fn vm_faults_require_each_backend_capability_they_use() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![
        ScheduledFaultV1 {
            at_barrier: "network".into(),
            action: DistributedFaultV1::NetworkReset {
                participant: "alice".into(),
            },
        },
        ScheduledFaultV1 {
            at_barrier: "filesystem".into(),
            action: DistributedFaultV1::FillDisk {
                participant: "alice".into(),
                bytes: 1024,
            },
        },
        ScheduledFaultV1 {
            at_barrier: "host".into(),
            action: DistributedFaultV1::CrashParticipantHost {
                participant: "bob".into(),
            },
        },
    ];
    let required = BTreeSet::from([
        VirtualMachineCapabilityV1::KernelNetworkIsolation,
        VirtualMachineCapabilityV1::FilesystemFaults,
        VirtualMachineCapabilityV1::HostIsolation,
    ]);
    assert_eq!(manifest.required_vm_capabilities(), required);
    manifest.backend = DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
        driver: "/tmp/driver".into(),
        driver_args: Vec::new(),
        timeout_seconds: 7_200,
        capabilities: BTreeSet::from([VirtualMachineCapabilityV1::HostIsolation]),
    });
    assert_eq!(
        manifest.validate().unwrap_err().code,
        "missing_vm_capability"
    );
    let DistributedBackendV1::VirtualMachine(vm) = &mut manifest.backend else {
        unreachable!();
    };
    vm.capabilities = required;
    manifest.validate().unwrap();
}

#[test]
fn vm_backend_is_rejected_when_containers_can_represent_the_campaign() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults.clear();
    manifest.backend = DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
        driver: "/tmp/driver".into(),
        driver_args: Vec::new(),
        timeout_seconds: 7_200,
        capabilities: BTreeSet::from([VirtualMachineCapabilityV1::HostIsolation]),
    });
    let error = manifest.validate().unwrap_err();
    assert_eq!(error.code, "unnecessary_vm_backend");
}

#[test]
fn vm_backend_requires_a_campaign_scale_timeout() {
    let (_root, mut manifest) = container_manifest();
    manifest.faults = vec![ScheduledFaultV1 {
        at_barrier: "slow-disk".into(),
        action: DistributedFaultV1::SlowBlockDevice {
            participant: "alice".into(),
            latency_ms: 50,
        },
    }];
    manifest.backend = DistributedBackendV1::VirtualMachine(VirtualMachineBackendV1 {
        driver: "/tmp/driver".into(),
        driver_args: Vec::new(),
        timeout_seconds: 0,
        capabilities: BTreeSet::from([VirtualMachineCapabilityV1::BlockDeviceLatency]),
    });
    let error = manifest.validate().unwrap_err();
    assert_eq!(error.code, "vm_timeout");
}
