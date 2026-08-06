use std::path::PathBuf;
use std::process::{ExitCode, Stdio};

use clap::{Parser, Subcommand};
use convergence_campaign_runner::{
    DistributedBackendV1, INFRASTRUCTURE_COMMAND_TIMEOUT, build_execution_plan, load_manifest,
    run_manifest, validate_scenario_bytes, verify_manifest_inputs,
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
    }
    Ok(())
}
