use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use clap::{Parser, Subcommand};
use convergence_campaign_runner::{
    CampaignAdapterV1, CampaignLaneConfigV1, CampaignLaneObservationV1, CampaignLaneV1,
    ConvergenceEvidenceBundleV1, DistributedBackendV1, FailureClassificationV1,
    INFRASTRUCTURE_COMMAND_TIMEOUT, build_execution_plan, collect_lane_observation,
    evidence_bundle_base_dir, load_manifest, observation_from_capsule, observe_lane_step,
    promote_capsule_into_corpus, run_manifest, update_failure_corpus, validate_scenario_bytes,
    verify_manifest_inputs, write_lane_observation_private,
};
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Debug, Parser)]
#[command(name = "cgka-distributed-campaign")]
#[command(about = "Run versioned container or VM convergence campaigns")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Validate the manifest and pinned scenario bytes without side effects.
    Validate {
        manifest: PathBuf,
        /// Require at least two participant builds and effective container images.
        #[arg(long)]
        require_mixed_builds: bool,
    },
    /// Print or privately write the exact argv execution plan.
    Plan {
        manifest: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Check that the selected container runtime or VM driver is executable.
    Doctor { manifest: PathBuf },
    /// Execute the campaign and write owner-only reports under output_dir.
    Run { manifest: PathBuf },
    /// Print or privately write the reviewed policy for an execution lane.
    Lane {
        lane: CampaignLaneV1,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Fail when observed campaign usage exceeds the selected lane budget.
    CheckBudget {
        lane: CampaignLaneV1,
        observation: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run one trusted workflow command and privately record its resource and retry evidence.
    ObserveStep {
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Aggregate measured workflow steps and retained artifact roots into one budget observation.
    CollectObservation {
        #[arg(long)]
        step_dir: PathBuf,
        #[arg(long, required = true)]
        artifact_root: Vec<PathBuf>,
        #[arg(long, required = true)]
        disk_root: Vec<PathBuf>,
        #[arg(long)]
        campaign_manifest: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate that an evidence bundle contains every required assurance section.
    CheckEvidence { bundle: PathBuf },
    /// Add an automatically written simulator capsule to the durable failure corpus.
    IndexCapsule {
        corpus: PathBuf,
        capsule: PathBuf,
        adapter: String,
        build_id: String,
    },
    /// Index a process-node capsule together with its pinned canonical scenario.
    IndexNodeCapsule {
        corpus: PathBuf,
        capsule: PathBuf,
        scenario: PathBuf,
        build_id: String,
    },
    /// Apply the reviewed four-way classification to a corpus entry.
    ClassifyFailure {
        corpus: PathBuf,
        fingerprint: String,
        classification: String,
    },
    /// Record time-to-diagnosis for a corpus entry.
    DiagnoseFailure {
        corpus: PathBuf,
        fingerprint: String,
        elapsed_seconds: u64,
    },
    /// Turn a stable synthetic failure capsule into a fixed vector candidate.
    PromoteCapsule {
        corpus: PathBuf,
        fingerprint: String,
        capsule: PathBuf,
        output: PathBuf,
        #[arg(long)]
        generator_version: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("distributed campaign failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate {
            manifest,
            require_mixed_builds,
        } => {
            let manifest = load_manifest(&manifest)?;
            if require_mixed_builds {
                manifest.validate_mixed_builds()?;
            }
            let scenario = verify_manifest_inputs(&manifest)?;
            validate_scenario_bytes(&manifest, &scenario)?;
            println!("valid {}", manifest.campaign_id);
        }
        Commands::Plan { manifest, output } => {
            let manifest = load_manifest(&manifest)?;
            let scenario = verify_manifest_inputs(&manifest)?;
            validate_scenario_bytes(&manifest, &scenario)?;
            let bytes = serde_json::to_vec_pretty(&build_execution_plan(&manifest)?)?;
            if let Some(path) = output {
                fs_private::write_private(&path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Commands::Doctor { manifest } => {
            let manifest = load_manifest(&manifest)?;
            let scenario = verify_manifest_inputs(&manifest)?;
            validate_scenario_bytes(&manifest, &scenario)?;
            let program = match &manifest.backend {
                DistributedBackendV1::Container(container) => {
                    PathBuf::from(container.runtime.executable())
                }
                DistributedBackendV1::VirtualMachine(vm) => vm.driver.clone(),
            };
            let mut command = Command::new(program);
            command
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let status = timeout(INFRASTRUCTURE_COMMAND_TIMEOUT, command.status())
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "backend version probe timed out",
                    )
                })??;
            if !status.success() {
                return Err("selected execution backend failed its version probe".into());
            }
            println!("backend-ready {}", manifest.campaign_id);
        }
        Commands::Run { manifest } => {
            let manifest = load_manifest(&manifest)?;
            let receipt = run_manifest(&manifest).await?;
            if !receipt.completed {
                return Err("campaign did not complete; inspect private run artifacts".into());
            }
            println!("completed {}", receipt.campaign_id);
        }
        Commands::Lane { lane, output } => {
            let config = CampaignLaneConfigV1::builtin(lane);
            let bytes = serde_json::to_vec_pretty(&config)?;
            if let Some(path) = output {
                fs_private::write_private(&path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Commands::CheckBudget {
            lane,
            observation,
            output,
        } => {
            let observed: CampaignLaneObservationV1 =
                serde_json::from_slice(&std::fs::read(observation)?)?;
            let evaluation = CampaignLaneConfigV1::builtin(lane).evaluate(observed);
            let bytes = serde_json::to_vec_pretty(&evaluation)?;
            if let Some(path) = output {
                fs_private::write_private(&path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
            if !evaluation.passed {
                return Err("campaign exceeded its reviewed lane budget".into());
            }
        }
        Commands::ObserveStep {
            name,
            output,
            command,
        } => {
            let observation = observe_lane_step(name, &command)?;
            observation.write_private(&output)?;
            println!("lane-step-observation {}", output.display());
            if !observation.succeeded() {
                return Err("observed lane step failed".into());
            }
        }
        Commands::CollectObservation {
            step_dir,
            artifact_root,
            disk_root,
            campaign_manifest,
            output,
        } => {
            let collected = collect_lane_observation(
                &step_dir,
                &artifact_root,
                &disk_root,
                &campaign_manifest,
            )?;
            write_lane_observation_private(&collected.observation, &output)?;
            println!("lane-observation {}", output.display());
            if !collected.failed_steps.is_empty() {
                return Err(format!(
                    "observed lane steps failed: {}",
                    collected.failed_steps.join(",")
                )
                .into());
            }
        }
        Commands::CheckEvidence {
            bundle: bundle_path,
        } => {
            let base_dir = evidence_bundle_base_dir(&bundle_path);
            let bundle: ConvergenceEvidenceBundleV1 =
                serde_json::from_slice(&std::fs::read(&bundle_path)?)?;
            bundle.validate_artifacts(base_dir)?;
            println!("valid-evidence {}", bundle.source_revision);
        }
        Commands::IndexCapsule {
            corpus,
            capsule,
            adapter,
            build_id,
        } => {
            let failure = cgka_conformance_simulator::read_failure_capsule(&capsule)?;
            let observation = observation_from_capsule(
                &failure,
                capsule,
                adapter.parse::<CampaignAdapterV1>()?,
                BTreeMap::from([("indexed_build".into(), build_id)]),
            );
            let fingerprint = observation.fingerprint.clone();
            update_failure_corpus(&corpus, |index| index.record(observation))?;
            println!("indexed-failure {fingerprint}");
        }
        Commands::IndexNodeCapsule {
            corpus,
            capsule,
            scenario,
            build_id,
        } => {
            let node_capsule: cgka_conformance_simulator::node_protocol::NodeFailureCapsuleV1 =
                serde_json::from_slice(&std::fs::read(&capsule)?)?;
            let scenario_bytes = std::fs::read(scenario)?;
            let scenario =
                cgka_conformance_simulator::resolve_scenario_input_bytes(&scenario_bytes)?;
            let scenario_digest = node_capsule_scenario_digest(&scenario).to_owned();
            let observation = convergence_campaign_runner::observation_from_node_capsule(
                &node_capsule,
                capsule,
                scenario.scenario,
                &scenario_digest,
                BTreeMap::from([("indexed_build".into(), build_id)]),
            );
            let fingerprint = observation.fingerprint.clone();
            update_failure_corpus(&corpus, |index| index.record(observation))?;
            println!("indexed-failure {fingerprint}");
        }
        Commands::ClassifyFailure {
            corpus,
            fingerprint,
            classification,
        } => {
            let classification = classification.parse::<FailureClassificationV1>()?;
            update_failure_corpus(&corpus, |index| {
                index.reclassify(&fingerprint, classification)
            })?;
            println!("classified-failure {fingerprint}");
        }
        Commands::DiagnoseFailure {
            corpus,
            fingerprint,
            elapsed_seconds,
        } => {
            update_failure_corpus(&corpus, |index| {
                index.mark_diagnosed(&fingerprint, elapsed_seconds)
            })?;
            println!("diagnosed-failure {fingerprint}");
        }
        Commands::PromoteCapsule {
            corpus,
            fingerprint,
            capsule,
            output,
            generator_version,
        } => {
            promote_capsule_into_corpus(
                &corpus,
                &fingerprint,
                &capsule,
                &output,
                &generator_version,
            )?;
            println!("promoted-vector {}", output.display());
        }
    }
    Ok(())
}

fn node_capsule_scenario_digest(
    input: &cgka_conformance_simulator::ResolvedScenarioInputV1,
) -> &str {
    &input.provenance.source_sha256
}

#[cfg(test)]
mod tests {
    use cgka_conformance_simulator::{ScenarioSpec, ScenarioStep, resolve_scenario_input_bytes};
    use sha2::Digest;

    use super::node_capsule_scenario_digest;

    #[test]
    fn node_capsule_index_preserves_pretty_printed_raw_ir_fingerprint_identity() {
        let scenario = ScenarioSpec {
            name: "pretty-raw-index".into(),
            spec_version: "2".into(),
            clients: vec!["alice".into()],
            topology: Default::default(),
            steps: vec![ScenarioStep::DeliverAll],
        };
        let bytes = serde_json::to_vec_pretty(&scenario).unwrap();
        let input = resolve_scenario_input_bytes(&bytes).unwrap();
        let source_sha256 = hex::encode(sha2::Sha256::digest(&bytes));

        assert_eq!(node_capsule_scenario_digest(&input), source_sha256);
        assert_ne!(
            node_capsule_scenario_digest(&input),
            input.provenance.canonical_ir_sha256
        );
    }
}
