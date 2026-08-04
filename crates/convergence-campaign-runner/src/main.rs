use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use clap::{Parser, Subcommand};
use convergence_campaign_runner::{
    CampaignAdapterV1, CampaignLaneConfigV1, CampaignLaneObservationV1, CampaignLaneV1,
    ConvergenceEvidenceBundleV1, DistributedBackendV1, FailureClassificationV1,
    build_execution_plan, load_manifest, observation_from_capsule, read_failure_corpus,
    run_manifest, verify_manifest_inputs, write_failure_corpus,
};

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
    Validate { manifest: PathBuf },
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
        lane: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Fail when observed campaign usage exceeds the selected lane budget.
    CheckBudget {
        lane: String,
        observation: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
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
    /// Record time-to-diagnosis and an optional promoted vector.
    DiagnoseFailure {
        corpus: PathBuf,
        fingerprint: String,
        elapsed_seconds: u64,
        #[arg(long)]
        promoted_vector: Option<PathBuf>,
    },
    /// Turn a stable synthetic failure capsule into a fixed vector candidate.
    PromoteCapsule {
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
        Commands::Validate { manifest } => {
            let manifest = load_manifest(&manifest)?;
            verify_manifest_inputs(&manifest)?;
            println!("valid {}", manifest.campaign_id);
        }
        Commands::Plan { manifest, output } => {
            let manifest = load_manifest(&manifest)?;
            verify_manifest_inputs(&manifest)?;
            let bytes = serde_json::to_vec_pretty(&build_execution_plan(&manifest)?)?;
            if let Some(path) = output {
                fs_private::write_private(&path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Commands::Doctor { manifest } => {
            let manifest = load_manifest(&manifest)?;
            verify_manifest_inputs(&manifest)?;
            let program = match &manifest.backend {
                DistributedBackendV1::Container(container) => {
                    PathBuf::from(container.runtime.executable())
                }
                DistributedBackendV1::VirtualMachine(vm) => vm.driver.clone(),
            };
            let status = std::process::Command::new(program)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
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
            let lane = lane.parse::<CampaignLaneV1>()?;
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
            let lane = lane.parse::<CampaignLaneV1>()?;
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
        Commands::CheckEvidence { bundle } => {
            let bundle: ConvergenceEvidenceBundleV1 =
                serde_json::from_slice(&std::fs::read(bundle)?)?;
            bundle.validate()?;
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
            let mut index = read_failure_corpus(&corpus)?;
            index.record(observation)?;
            write_failure_corpus(&corpus, &index)?;
            println!("indexed-failure {fingerprint}");
        }
        Commands::IndexNodeCapsule {
            corpus,
            capsule,
            scenario,
            build_id,
        } => {
            use sha2::Digest;

            let node_capsule: cgka_conformance_simulator::node_protocol::NodeFailureCapsuleV1 =
                serde_json::from_slice(&std::fs::read(&capsule)?)?;
            let scenario_bytes = std::fs::read(scenario)?;
            let scenario = serde_json::from_slice(&scenario_bytes)?;
            let observation = convergence_campaign_runner::observation_from_node_capsule(
                &node_capsule,
                capsule,
                scenario,
                &hex::encode(sha2::Sha256::digest(&scenario_bytes)),
                BTreeMap::from([("indexed_build".into(), build_id)]),
            );
            let fingerprint = observation.fingerprint.clone();
            let mut index = read_failure_corpus(&corpus)?;
            index.record(observation)?;
            write_failure_corpus(&corpus, &index)?;
            println!("indexed-failure {fingerprint}");
        }
        Commands::ClassifyFailure {
            corpus,
            fingerprint,
            classification,
        } => {
            let mut index = read_failure_corpus(&corpus)?;
            index.reclassify(
                &fingerprint,
                classification.parse::<FailureClassificationV1>()?,
            )?;
            write_failure_corpus(&corpus, &index)?;
            println!("classified-failure {fingerprint}");
        }
        Commands::DiagnoseFailure {
            corpus,
            fingerprint,
            elapsed_seconds,
            promoted_vector,
        } => {
            let mut index = read_failure_corpus(&corpus)?;
            index.mark_diagnosed(&fingerprint, elapsed_seconds, promoted_vector)?;
            write_failure_corpus(&corpus, &index)?;
            println!("diagnosed-failure {fingerprint}");
        }
        Commands::PromoteCapsule {
            capsule,
            output,
            generator_version,
        } => {
            let capsule = cgka_conformance_simulator::read_failure_capsule(&capsule)?;
            let vector = cgka_conformance_simulator::promote_failure_capsule_to_vector(
                &capsule,
                &generator_version,
            )?;
            let bytes = serde_json::to_vec_pretty(&vector)?;
            fs_private::write_private(&output, &bytes)?;
            println!("promoted-vector {}", output.display());
        }
    }
    Ok(())
}
