use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use convergence_campaign_runner::{
    REGRESSION_CAMPAIGN_REPORT_FILE, RegressionCampaignInputV1, run_regression_campaign,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "cgka-regression-campaign")]
#[command(about = "Run focused convergence regressions and retain digest-bound evidence")]
struct Args {
    /// Owner-only directory to create for the immutable campaign artifacts.
    #[arg(long)]
    out: PathBuf,
    /// Per-regression timeout in seconds.
    #[arg(long, default_value_t = 300)]
    case_timeout_secs: u64,
    /// Cargo executable or wrapper used to run the exact named tests.
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("regression campaign failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<bool, Box<dyn std::error::Error>> {
    let args = Args::parse();
    let workspace_root = workspace_root()?;
    require_clean_source(&workspace_root)?;
    let source_revision = git_stdout(&workspace_root, &["rev-parse", "HEAD"])?;
    let cargo_lock = std::fs::read(workspace_root.join("Cargo.lock"))?;
    let input = RegressionCampaignInputV1::focused_convergence(
        source_revision,
        hex::encode(Sha256::digest(cargo_lock)),
        Duration::from_secs(args.case_timeout_secs),
    )?;
    let report = run_regression_campaign(&workspace_root, &args.out, &args.cargo, &input).await?;
    println!(
        "Focused convergence report: {}",
        args.out.join(REGRESSION_CAMPAIGN_REPORT_FILE).display()
    );
    Ok(report.passed)
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let current_dir = std::env::current_dir()?;
    Ok(PathBuf::from(git_stdout(
        &current_dir,
        &["rev-parse", "--show-toplevel"],
    )?))
}

fn require_clean_source(workspace_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = git_stdout(
        workspace_root,
        &["status", "--porcelain=v1", "--untracked-files=all"],
    )?;
    if !status.is_empty() {
        return Err(
            "refusing to label evidence with a revision while the source tree is dirty".into(),
        );
    }
    Ok(())
}

fn git_stdout(workspace_root: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("git")
        .current_dir(workspace_root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(Into::into)
}
