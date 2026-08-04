use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use clap::{Parser, Subcommand};
use convergence_campaign_runner::{
    CampaignLaneConfigV1, CampaignLaneObservationV1, CampaignLaneV1, ConvergenceEvidenceBundleV1,
    DistributedBackendV1, build_execution_plan, load_manifest, run_manifest,
    verify_manifest_inputs,
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
    }
    Ok(())
}
