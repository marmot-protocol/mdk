mod bridge;
mod chunking;
mod config;
mod control;
mod error;
mod opencode;
mod repo_picker;
mod store;

use std::process::ExitCode;

use clap::Parser;
use error::Result;
use tracing::error;

#[derive(Debug, Parser)]
#[command(
    name = "wn-opencode",
    version,
    about = "Marmot harness that routes allowed group messages to opencode"
)]
struct Cli {}

#[tokio::main]
async fn main() -> ExitCode {
    let _cli = Cli::parse();
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!(
                target: bridge::TRACE_TARGET,
                method = "main",
                error_kind = err.privacy_safe_kind(),
                "wn-opencode exiting after error"
            );
            eprintln!("wn-opencode: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let config = config::Config::from_env()?;
    bridge::run(config).await
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wn_opencode=info")),
        )
        .init();
}
